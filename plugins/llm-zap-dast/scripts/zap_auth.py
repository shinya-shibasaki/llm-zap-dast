#!/usr/bin/env python3
"""Thin ZAP authentication wrapper for llm-zap-dast (authenticated DAST; stops on failure).

This script performs NO judgement. The LLM inspects the target (source / login page / DOM /
HTTP history), decides the concrete authentication method and settings, and this script
mechanically applies those settings to ZAP's REST API. Design rules enforced here:

  * `configure-authentication` REFUSES `method: auto` — the LLM must resolve `auto` to a
    concrete method before calling the script.
  * `test-authentication` returns RAW EVIDENCE (statuses, indicator-match booleans, identity
    echo), never a pass/fail verdict. The verdict is the caller's job, using a differential
    rule (indicator present in the authed response AND absent in the unauth response). It
    reads both sides the SAME way — response header and body, redirects followed on both —
    and reports `evidence_complete: false` (exit 1) when either read did not happen, since a
    missing response is not an absent indicator.
  * `active-scan-as-user` requires `--gate-passed` — the authenticated Active Scan double
    gate + step-5 confirmation live above this script; it will not launch otherwise.
  * `set-credentials` reads credentials from environment variables by NAME and never prints
    or returns their values.
  * `clear-authentication` removes the temporary User/Context so the credential-bearing ZAP
    session state does not linger.
  * `configure-verification` REFUSES `AUTO_DETECT` and refuses a config with no indicator at
    all, requires an explicit `--strategy`, and reads the context back to confirm the
    settings actually landed (`applied`). Both refusals guard measured, silent failures —
    see resolve_checking_strategy() and require_indicator().
  * `include-in-context` must be called: ZAP applies authentication only inside the context,
    so an empty include list makes every other auth setting silently inert.
  * `verify-canary` asks ZAP what IT concluded (stats.auth.state.*) instead of re-deriving a
    verdict from response text, and `spider-as-user` / `ajax-spider-as-user` /
    `active-scan-as-user` re-read those counters themselves and refuse to launch during a
    re-authentication storm. The guard is not a caller-supplied flag on purpose — a flag
    would be self-attestation by the same actor that chose the configuration.
  * Exit code: 0 = did what it promises; 1 = did not (`applied`/`ok`/`complete` false);
    2 = caller misuse. With `authentication.enabled: true` the skill STOPS on 1 rather than
    continuing unauthenticated — an authenticated run that quietly turns anonymous reports
    findings whose authentication state is unknown.

API names/params below were verified against a live ZAP 2.17.0. Non-obvious facts:
  * the "authentication verification strategy" is `context/action/setContextCheckingStrategy`
    and takes the context NAME (there is no authentication/.../VerificationStrategy action);
  * POLL_URL needs ALL FIVE poll parameters — pollUrl alone gives `illegal_parameter`, four
    of five gives `internal_error`; pollData/pollHeaders accept empty strings, so they must
    be sent even when empty;
  * `ajaxSpider/action/scanAsUser` takes contextName/userName, unlike spider/ascan (ids);
  * a newly created ZAP user is NOT enabled — `set-user-enabled` must be called or
    forced-user mode silently does nothing;
  * `setAuthenticationMethod` RESETS the whole verification config — measured: POLL_URL +
    indicators came back as EACH_RESP with both patterns empty — so verification must be
    configured AFTER the authentication method, and re-running the method setting silently
    discards it;
  * ZAP matches the logged-in/out patterns against the response HEADER as well as the body —
    measured on a session app whose body is identical either way: an indicator that exists
    only in the `X-Authenticated-User` header gives one login over five requests, a
    body-only indicator that never matches gives six (a storm). `test-authentication`
    matches the same surface so its evidence agrees with the scanner;
  * `core/action/accessUrl` RETURNS the message it sent (request/response headers, body,
    history id) — the response does not have to be searched for in the history afterwards,
    which is what used to let ZAP's own login traffic stand in for the page under test;
  * the indicators are REGULAR EXPRESSIONS (`loggedInIndicatorRegex`) — measured:
    `Signed ?in as` gives a healthy single login against "Signed in as alice", where a
    literal match would fail and ZAP would storm;
  * `core/view/messages` takes `start` as an ID, not an offset — `start=numberOfMessages`
    returns the last message from BEFORE the call;
  * ZAP decodes a charset-less `text/html` body as UTF-8, while `requests` applies the RFC
    default of ISO-8859-1 — reading the two sides with different decoders turned one
    anonymous page into a perfect differential.

Usage:
    python3 zap_auth.py --config dast.yaml <command> [options] [--json]

Dependencies: PyYAML (config); requests optional (falls back to urllib).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import NamedTuple
from urllib.parse import (quote, unquote, urlencode, urljoin, urlparse, urlsplit,
                          urlunsplit)

# LLM-facing method names -> ZAP authentication method API names.
AUTH_METHOD_MAP = {
    "browser": "browserBasedAuthentication",
    "form": "formBasedAuthentication",
    "json": "jsonBasedAuthentication",
    "basic": "httpAuthentication",
    "script": "scriptBasedAuthentication",
}
SESSION_METHOD_MAP = {
    "cookie": "cookieBasedSessionManagement",
    "header": "headerBasedSessionManagement",
    "script": "scriptBasedSessionManagement",
}
# ZAP's "authentication verification strategy" is the context CHECKING strategy
# (context/action/setContextCheckingStrategy). Verified against ZAP 2.17.0; there is no
# authentication/action/setAuthenticationVerificationStrategy endpoint.
CHECKING_STRATEGIES = {"EACH_REQ", "EACH_RESP", "EACH_REQ_RESP", "AUTO_DETECT", "POLL_URL"}
POLL_FREQUENCY_UNITS = {"REQUESTS", "SECONDS"}
# Redirect hops test-authentication follows, on BOTH sides of the differential read. A
# session app answers an unauthenticated request with a redirect to the login page and often
# answers the authenticated one with a redirect too (trailing slash, post-login landing), so
# a limit of 1 would compare a login page against an empty 301 body.
MAX_REDIRECT_HOPS = 5
DEFAULT_PORTS = {"http": 80, "https": 443}
# Path segments that end a session. Redirect targets matching these are never followed, with
# or without `exclude.paths` — see is_session_ending().
LOGOUT_SEGMENTS = {"logout", "log-out", "log_out", "logoff", "signout", "sign-out",
                   "sign_out", "signoff"}
# What context/view/context calls the fields we set through three different actions.
VERIFICATION_READBACK_KEYS = ("checkingStrategy", "loggedInPattern", "loggedOutPattern",
                              "pollUrl", "pollData", "pollHeaders", "pollFrequency",
                              "pollFrequencyUnits")


class AuthUsageError(Exception):
    """Raised for caller misuse (bad args) — maps to exit code 2, before any ZAP call."""


# --- config / http -----------------------------------------------------------
def _load_cfg(path):
    try:
        import yaml
    except ImportError:
        return None, "PyYAML not installed"
    if not os.path.isfile(path):
        return None, f"config not found: {path}"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}, None
    except Exception as exc:  # noqa: BLE001
        return None, f"YAML parse error: {exc}"


def _get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _api_base(cfg):
    return _get(cfg, "zap", "api_url", default="http://localhost:8080").rstrip("/")


def _api_key(cfg):
    env_name = _get(cfg, "zap", "api_key_env")
    return os.environ.get(str(env_name), "").strip() if env_name else ""


def decode_body(raw: bytes, content_type) -> str:
    """Decode a response body the way ZAP does, not the way RFC 2616 says.

    Measured on a live ZAP against a `text/html` page with NO charset parameter: ZAP decoded
    it as UTF-8 while `requests` applied the RFC default of ISO-8859-1, so a Japanese page
    came back as mojibake on the direct side ONLY. The consequence is a false pass, not a
    cosmetic one: two reads of the SAME anonymous page then produced
    `indicator_in_authed: true` / `indicator_in_unauth: false` — a perfect differential built
    entirely out of a decoding difference. Anything undecodable falls back to replacement
    characters so a binary body cannot fail the read outright.
    """
    charset = None
    for part in str(content_type or "").split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset":
            charset = value.strip().strip('"') or None
    for enc in ([charset] if charset else []) + ["utf-8"]:
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError, AttributeError):
            continue
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def _wire_header(status, reason, items) -> str:
    """A response header in wire form. ZAP matches its patterns against this surface too."""
    head = f"HTTP/1.1 {status}" + (f" {reason}" if reason else "")
    return "\r\n".join([head] + [f"{k}: {v}" for k, v in items])


class DirectReader:
    """The unauthenticated side of the differential: a reader that bypasses ZAP.

    It also bypasses everything else that could quietly put a session or a middlebox in the
    way of the "unauthenticated" read:

      * PROXY ENVIRONMENT VARIABLES are ignored (`trust_env = False`). On a DAST workstation
        `HTTP_PROXY` very often points AT ZAP — which would make this read authenticated and
        turn a working setup into a permanent verification failure — and a corporate proxy's
        block page would otherwise be accepted as "the application's anonymous response".
      * `~/.netrc` is ignored for the same reason: it would send credentials.
      * It carries its OWN cookie jar across redirect hops, the way ZAP does on its side, so
        a session app that bootstraps an anonymous session on the first hop is followed the
        same way instead of ping-ponging until the hop limit.
      * It sends ZAP's User-Agent, so a WAF or CDN cannot answer the two sides differently on
        that alone (a 403 bot-block page reads as a perfectly good "anonymous response").

    One instance per `test-authentication` call; the jar must not outlive it.
    """

    # What ZAP's accessUrl sends (measured), so both sides look identical to a filter.
    USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

    def __init__(self, timeout=30):
        self.timeout = timeout
        self._session = None
        self._opener = None
        try:
            import requests  # type: ignore
            self._session = requests.Session()
            self._session.trust_env = False          # no proxy env, no netrc, no env CA
        except ImportError:
            import http.cookiejar
            import ssl
            import urllib.request
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None

            self._opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),                      # ignore proxy env
                urllib.request.HTTPSHandler(context=ctx),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                _NoRedirect)

    def fetch(self, url) -> "Response":
        ok, status, header, body = self._get(url)
        return Response(ok=bool(ok) and status is not None, status=status, header=header,
                        body=body, url=url,
                        via="direct request (bypasses ZAP; no proxy env, no netrc)")

    def _get(self, url):
        if self._session is not None:
            try:
                r = self._session.get(url, timeout=self.timeout, verify=False,
                                      allow_redirects=False,
                                      headers={"User-Agent": self.USER_AGENT})
                return (True, r.status_code,
                        _wire_header(r.status_code, r.reason, r.headers.items()),
                        decode_body(r.content, r.headers.get("Content-Type")))
            except Exception:  # noqa: BLE001
                return False, None, "", ""
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": self.USER_AGENT})
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return (True, r.status, _wire_header(r.status, r.reason, r.headers.items()),
                        decode_body(r.read(), r.headers.get("Content-Type")))
        except urllib.error.HTTPError as exc:
            # urllib raises on 4xx/5xx and on an unfollowed redirect. Those ARE responses.
            return (True, exc.code, _wire_header(exc.code, exc.reason, exc.headers.items()),
                    decode_body(exc.read(), exc.headers.get("Content-Type")))
        except Exception:  # noqa: BLE001
            return False, None, "", ""


def _http_get(url, timeout=30):
    """Return (ok, status, text). Used for the ZAP API itself.

    `ok` means A RESPONSE ARRIVED — ZAP answers its refusals with HTTP 400 and a JSON body
    that says why, and that body is the answer. Proxy environment variables are ignored here
    too: the ZAP API is a local control channel, not something to route through a proxy.
    """
    try:
        import requests  # type: ignore
        try:
            session = requests.Session()
            session.trust_env = False
            r = session.get(url, timeout=timeout, verify=False)
            return True, r.status_code, decode_body(r.content, r.headers.get("Content-Type"))
        except Exception:  # noqa: BLE001
            return False, None, ""
    except ImportError:
        import ssl
        import urllib.error
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=ctx))
        try:
            with opener.open(url, timeout=timeout) as r:
                return True, r.status, decode_body(r.read(), r.headers.get("Content-Type"))
        except urllib.error.HTTPError as exc:
            return True, exc.code, decode_body(exc.read(), exc.headers.get("Content-Type"))
        except Exception:  # noqa: BLE001
            return False, None, ""


def zap_call(cfg, fmt, component, kind, name, params=None):
    """Call ZAP: /{fmt}/{component}/{kind}/{name}/?params  (kind = view|action)."""
    params = dict(params or {})
    key = _api_key(cfg)
    if key:
        params["apikey"] = key
    url = f"{_api_base(cfg)}/{fmt}/{component}/{kind}/{name}/"
    if params:
        url += "?" + urlencode(params)
    reached, status, text = _http_get(url)
    data = None
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    # `ok` must mean "ZAP accepted the call", not merely "we got a response": ZAP answers
    # errors with HTTP 400 + {"code": ..., "message": ...}, and treating those as success
    # would let the caller believe auth was configured when it was not.
    zap_error = isinstance(data, dict) and "code" in data and "message" in data
    # ZAP also reports some failures as HTTP 200 + {"Result": "FAIL"} (e.g. removeUser with
    # an id that does not exist), so that must count as a failure too.
    result_fail = isinstance(data, dict) and str(data.get("Result", "")).upper() == "FAIL"
    # A JSON object is what "ZAP answered" looks like. Requiring it also closes a gap the
    # urllib fallback opens: an unfollowable redirect (loop, non-http scheme) surfaces as a
    # 3xx *response*, which would otherwise satisfy `status < 400` and report a call that
    # never reached ZAP as ok.
    ok = (bool(reached) and not zap_error and not result_fail and isinstance(data, dict)
          and (status is None or int(status) < 400))
    out = {"ok": ok, "status": status, "data": data}
    if zap_error:
        out["error"] = {"code": data.get("code"), "message": data.get("message")}
    elif result_fail:
        out["error"] = {"code": "result_fail", "message": "ZAP returned Result=FAIL"}
    return out


# --- pure helpers (unit-testable, no network) --------------------------------
def resolve_auth_method_name(method) -> str:
    """Map an LLM-resolved method to the ZAP API name. Refuse 'auto' and unknowns."""
    m = str(method or "").lower()
    if m == "auto":
        raise AuthUsageError(
            "configure-authentication received method 'auto'. The LLM must resolve 'auto' to "
            "a concrete method (browser/form/json/basic/script) before calling this script."
        )
    if m not in AUTH_METHOD_MAP:
        raise AuthUsageError(
            f"unknown authentication method {method!r}; expected one of "
            f"{sorted(AUTH_METHOD_MAP)}"
        )
    return AUTH_METHOD_MAP[m]


def build_config_params(pairs, verbatim=None) -> str:
    """Build ZAP's *ConfigParams string from key=value pairs.

    ZAP expects a `k=v&k2=v2` string whose VALUES are individually URL-encoded (the whole
    string is then encoded again as a normal query parameter). Passing raw values is the
    classic ZAP trap — it fails with a bare "Missing Parameter". `--param k=v` goes through
    here; `--config-params` is passed verbatim for callers who already encoded it.
    """
    if verbatim:
        return verbatim
    out = []
    for pair in pairs or []:
        if "=" not in str(pair):
            raise AuthUsageError(f"--param must be key=value, got {pair!r}")
        key, val = str(pair).split("=", 1)
        out.append(f"{key}={quote(val, safe='')}")
    return "&".join(out)


def _contains(haystack: str, needle) -> bool:
    if not needle:
        return False
    return str(needle).lower() in (haystack or "").lower()


def indicator_matches(haystack: str, needle) -> bool:
    """Match an indicator the way ZAP matches it: as a REGULAR EXPRESSION.

    ZAP's parameters are named `loggedInIndicatorRegex` / `loggedOutIndicatorRegex`, and
    measured behaviour agrees: `Signed ?in as` and `Signed in as|Logged in as` each give a
    healthy single login against a page reading "Signed in as alice" — as literals neither
    would match and ZAP would re-authenticate on every response. Judging the same string as
    a literal substring here reported "indicator absent" for a configuration ZAP is happy
    with, and under the stop-on-unverified rule that ends the run.

    A pattern that does not compile falls back to a literal search rather than throwing away
    the caller's intent.
    """
    if not needle:
        return False
    try:
        return re.search(str(needle), haystack or "", re.IGNORECASE | re.DOTALL) is not None
    except re.error:
        return _contains(haystack, needle)


def header_fields(header: str) -> str:
    """The header block WITHOUT its status line.

    The status line is excluded on purpose. It is part of what ZAP matches, but an indicator
    that only matches "HTTP/1.1 200 OK" is a status-only pass — the first thing
    references/authentication.md forbids — and `200`/`OK` are easy strings to reach for.
    """
    return "\n".join(str(header or "").splitlines()[1:])


class Response(NamedTuple):
    """One side of the differential read.

    `ok=False` means no response arrived at all — kept distinct from an empty response
    everywhere below, because "we could not look" and "we looked and it was absent" are
    opposite pieces of evidence.
    """
    ok: bool = False
    status: int = None
    header: str = ""
    body: str = ""
    url: str = ""
    chain: tuple = ()
    via: str = ""
    # Response headers of the redirect hops walked to get here. Kept for matching only —
    # they are never returned, because they carry Set-Cookie and one-time URLs.
    hop_headers: tuple = ()


def _match_where(resp: Response, needle):
    """Where `needle` appears: 'header' | 'body' | 'both' | 'redirect' | None.

    Header AND body, because that is what ZAP does with the logged-in/out patterns —
    measured: an indicator present only in the `X-Authenticated-User` response header is
    enough for ZAP to call the response authenticated (one login over five requests, versus
    six for a body-only indicator that never matches). Evidence judged on the body alone
    contradicts the scanner it is supposed to be vouching for, and on a session app —
    where the differences often live in Set-Cookie, Location or a user header — it rejects
    configurations that work.

    'redirect' means it matched in a hop we followed rather than in the response we landed
    on. ZAP evaluates every response it sees, so a `Location`-based indicator is a match for
    ZAP; without this, following redirects would have made exactly those indicators
    invisible here.
    """
    if not needle or not resp.ok:
        return None
    in_header = indicator_matches(header_fields(resp.header), needle)
    in_body = indicator_matches(resp.body, needle)
    if in_header and in_body:
        return "both"
    if in_header:
        return "header"
    if in_body:
        return "body"
    if any(indicator_matches(header_fields(h), needle) for h in resp.hop_headers):
        return "redirect"
    return None


def _chain_cut(resp: Response):
    """The reason this side's redirect chain was cut short, or None if it ran to a page."""
    for hop in resp.chain:
        if isinstance(hop, dict) and hop.get("stopped"):
            return hop["stopped"]
    return None


def evidence_from_responses(authed: Response, unauth: Response, logged_in_indicator=None,
                            identity_markers=None):
    """Build RAW verification evidence — deliberately NO verdict field.

    The caller applies the differential rule (indicator in authed AND not in unauth) plus
    identity confirmation; this function only reports observations so the safety decision
    stays with the LLM + fixed rule.

    Every comparison is None unless BOTH sides were actually read. A comparison against a
    response that never arrived is not evidence, and `None` is the only value the caller
    cannot mistake for one.
    """
    identity_markers = identity_markers or []
    both = bool(authed.ok and unauth.ok)
    where_a = _match_where(authed, logged_in_indicator)
    where_u = _match_where(unauth, logged_in_indicator)
    in_a = None if not authed.ok or not logged_in_indicator else where_a is not None
    in_u = None if not unauth.ok or not logged_in_indicator else where_u is not None
    return {
        "authed_read_ok": authed.ok,
        "unauth_read_ok": unauth.ok,
        "evidence_complete": both,
        "status_authed": authed.status,
        "status_unauth": unauth.status,
        "authed_read_url": safe_url(authed.url),
        "unauth_read_url": safe_url(unauth.url),
        "authed_redirect_chain": list(authed.chain),
        "unauth_redirect_chain": list(unauth.chain),
        # A cut chain means the read stopped on a bodiless 3xx instead of reaching a page.
        # The differential then degenerates into "the other side was a real page", which
        # almost any indicator satisfies — so it is a top-level fact, not a detail buried
        # in the chain.
        "authed_chain_cut": _chain_cut(authed),
        "unauth_chain_cut": _chain_cut(unauth),
        "indicator_in_authed": in_a,
        "indicator_in_unauth": in_u,
        "indicator_where_authed": where_a,
        "indicator_where_unauth": where_u,
        # Differential precondition; the verdict is still the caller's.
        "indicator_is_differential": (
            (in_a is True) and (in_u is False)
        ) if (both and logged_in_indicator) else None,
        "identity_markers_in_authed": {
            str(m): (_match_where(authed, m) is not None) if authed.ok else None
            for m in identity_markers
        },
        "identity_markers_in_unauth": {
            str(m): (_match_where(unauth, m) is not None) if unauth.ok else None
            for m in identity_markers
        },
        "status_differs": (authed.status != unauth.status) if both else None,
        "matched_on": "response header + body (the same surface ZAP matches its patterns on)",
        "note": "evidence only — apply the differential + identity rule to decide auth; "
                "null means NOT OBSERVED, never 'absent'",
    }


# --- commands ----------------------------------------------------------------
def cmd_detect_capabilities(cfg, _args):
    """What this ZAP can authenticate with. Exits non-zero when it cannot answer.

    `ok` is not decoration: references/authentication.md makes this command the test for
    "ZAP's authentication features are unusable", which is a STOP condition under
    `authentication.enabled: true`. Without a top-level ok/applied/complete key, main()
    returns 0 (see its exit-code contract), so an unreachable ZAP would pass the very check
    meant to catch it.

    `ok` means both calls were ACCEPTED (zap_call already refuses ZAP's HTTP 400 + error
    body). It deliberately does not judge the CONTENT of the method list: which methods a
    given build offers, and how that list is shaped, is a ZAP fact this repo has not
    measured. The caller reads `supported_authentication_methods` and decides.
    """
    version = zap_call(cfg, "JSON", "core", "view", "version")
    auth_methods = zap_call(cfg, "JSON", "authentication", "view",
                            "getSupportedAuthenticationMethods")
    session_methods = zap_call(cfg, "JSON", "sessionManagement", "view",
                               "getSupportedSessionManagementMethods")
    return {
        "version": _get(version, "data"),
        "supported_authentication_methods": _get(auth_methods, "data"),
        "supported_session_management_methods": _get(session_methods, "data"),
        "reachable": bool(version.get("ok")),
        "ok": bool(version.get("ok")) and bool(auth_methods.get("ok")),
    }


def cmd_create_context(cfg, args):
    return zap_call(cfg, "JSON", "context", "action", "newContext",
                    {"contextName": args.context})


def cmd_include_in_context(cfg, args):
    """Register which URLs the context covers. Without this, authentication does NOTHING.

    VERIFIED ON ZAP 2.17.0, same setup with only this call added or removed:

        includeRegexs []           -> 0 login attempts, the request goes out ANONYMOUS
                                      (HTTP 401) with no error of any kind
        includeRegexs [<regex>]    -> 1 login attempt, credentials applied, HTTP 200

    ZAP applies the forced user only to URLs inside the context, so an empty include list
    means every setting made by configure-authentication / set-credentials / set-forced-user
    is silently inert. `spider-as-user` fails loudly (`url_not_in_context`), but a plain
    request through ZAP does not — it just scans unauthenticated.

    The regex is supplied by the caller verbatim (it is the run's scope boundary and belongs
    to the LLM's judgement, see references/zap-integration.md). This returns the resulting
    include list so the caller can confirm the scope ZAP actually holds.
    """
    if not args.context:
        raise AuthUsageError("include-in-context requires --context (the context NAME)")
    regexes = list(args.regex or [])
    if not regexes:
        raise AuthUsageError(
            "include-in-context requires at least one --regex (repeatable). Without an "
            "include regex ZAP treats every URL as out of context and applies no "
            "authentication at all — silently."
        )
    out = {"applied_regexes": {}}
    for rgx in regexes:
        out["applied_regexes"][rgx] = zap_call(
            cfg, "JSON", "context", "action", "includeInContext",
            {"contextName": args.context, "regex": rgx})
    read = zap_call(cfg, "JSON", "context", "view", "context",
                    {"contextName": args.context})
    in_zap = parse_include_regexs(_get(read, "data", "context", "includeRegexs"))
    out["include_regexs"] = in_zap
    missing = [rgx for rgx in regexes if rgx not in in_zap]
    out["applied"] = (bool(read.get("ok"))
                      and all(r.get("ok") for r in out["applied_regexes"].values())
                      and not missing)
    if missing:
        out["not_applied"] = missing
    return out


def cmd_configure_authentication(cfg, args):
    zap_name = resolve_auth_method_name(args.method)  # refuses 'auto'
    params = {"contextId": args.context_id, "authMethodName": zap_name}
    cfg_params = build_config_params(args.param, args.config_params)
    if cfg_params:
        params["authMethodConfigParams"] = cfg_params
    return zap_call(cfg, "JSON", "authentication", "action",
                    "setAuthenticationMethod", params)


def cmd_configure_session_management(cfg, args):
    m = str(args.method or "").lower()
    if m == "auto":
        raise AuthUsageError("configure-session-management received 'auto'; resolve it first")
    zap_name = SESSION_METHOD_MAP.get(m)
    if not zap_name:
        raise AuthUsageError(f"unknown session method {args.method!r}")
    params = {"contextId": args.context_id, "methodName": zap_name}
    cfg_params = build_config_params(args.param, args.config_params)
    if cfg_params:
        params["methodConfigParams"] = cfg_params
    return zap_call(cfg, "JSON", "sessionManagement", "action",
                    "setSessionManagementMethod", params)


def resolve_checking_strategy(strategy) -> str:
    """Validate ZAP's context checking strategy (a.k.a. verification strategy).

    There is deliberately NO default. AUTO_DETECT is refused outright — measured on ZAP
    2.17.0, `AuthenticationMethod.isAuthenticated()` returns false unconditionally while the
    strategy is AUTO_DETECT, so ZAP re-authenticates on every request AND scores each of its
    own successful logins as a failure. In one measurement that drove the auth failure rate
    to 100% within 10 requests and the insights add-on shut the daemon down. ZAP is only
    meant to resolve AUTO_DETECT into a real strategy for the browser-driven login methods,
    and even there the resolution is best-effort (measured: browser-based auth kept
    AUTO_DETECT after login attempts, and re-authenticating launched a browser per request).
    """
    s = str(strategy or "").upper().strip()
    if not s:
        raise AuthUsageError(
            "configure-verification requires --strategy. Prefer POLL_URL against an "
            "authentication-only endpoint; there is no safe default to fall back to."
        )
    if s not in CHECKING_STRATEGIES:
        raise AuthUsageError(
            f"unknown verification/checking strategy {strategy!r}; expected one of "
            f"{sorted(CHECKING_STRATEGIES)}"
        )
    if s == "AUTO_DETECT":
        raise AuthUsageError(
            "checkingStrategy AUTO_DETECT is refused: ZAP then treats every response as "
            "unauthenticated, re-authenticates on every request and counts each successful "
            "login as a failure (measured on 2.17.0: 100% auth failure rate in 10 requests, "
            "daemon shut down by the insights add-on). Use POLL_URL with an "
            "authentication-only endpoint, or EACH_RESP with indicators derived from the "
            "target's own responses."
        )
    return s


def build_poll_params(args) -> dict:
    """Build the POLL_URL parameters.

    VERIFIED ON ZAP 2.17.0: setContextCheckingStrategy requires ALL FIVE poll parameters
    when the strategy is POLL_URL. Sending pollUrl alone fails with `illegal_parameter`;
    sending four of the five fails with `internal_error`; all five succeed. Empty strings
    are accepted for pollData/pollHeaders, so they must NOT be dropped for being falsy —
    doing so is what silently defeated POLL_URL and forced the fallback this guard exists
    to prevent. 60/REQUESTS are ZAP's own defaults, not a choice made here.
    """
    if not args.poll_url:
        raise AuthUsageError("checkingStrategy POLL_URL requires --poll-url")
    raw_freq = getattr(args, "poll_frequency", None)
    try:
        freq = 60 if raw_freq in (None, "") else int(raw_freq)
    except (TypeError, ValueError):
        raise AuthUsageError(f"--poll-frequency must be an integer, got {raw_freq!r}") from None
    if freq <= 0:
        raise AuthUsageError(
            f"--poll-frequency must be a positive integer (ZAP rejects {freq} with "
            "illegal_parameter)"
        )
    units = str(getattr(args, "poll_frequency_units", None) or "REQUESTS").upper()
    if units not in POLL_FREQUENCY_UNITS:
        raise AuthUsageError(
            f"--poll-frequency-units must be one of {sorted(POLL_FREQUENCY_UNITS)}, "
            f"got {units!r}"
        )
    return {
        "pollUrl": args.poll_url,
        "pollData": args.poll_data or "",
        "pollHeaders": args.poll_headers or "",
        "pollFrequency": freq,
        "pollFrequencyUnits": units,
    }


def require_indicator(logged_in, logged_out) -> None:
    """At least one indicator must be set, whatever the strategy.

    VERIFIED ON ZAP 2.17.0: with neither indicator configured, ZAP short-circuits to
    "authenticated" on its no-indicator branch before it reaches the check. Under POLL_URL
    that means the poll URL is never requested at all (measured: 0 poll hits), so an expired
    session is never noticed and the scan continues silently unauthenticated. This is the
    failure the whole verification step exists to prevent, and it produces no error.
    """
    if not (logged_in or logged_out):
        raise AuthUsageError(
            "configure-verification requires at least one of --logged-in-indicator / "
            "--logged-out-indicator. With neither set ZAP skips the check entirely and "
            "reports 'authenticated' forever, so session expiry is never detected."
        )


# ZAP's own verdict census. Each evaluated response lands in exactly one state counter, so
# these say what ZAP concluded — no string matching of our own required. Verified on 2.17.0.
AUTH_STATE_KEYS = ("stats.auth.state.loggedin", "stats.auth.state.loggedout",
                   "stats.auth.state.unknown", "stats.auth.state.assumedin",
                   "stats.auth.state.noindicator")
AUTH_LOGIN_KEYS = ("stats.auth.success", "stats.auth.failure")
# Thresholds derived from measurement, not taste. A healthy config logs in exactly once for a
# fresh user (0 on a repeat), so more than one login over a short canary means ZAP is
# re-authenticating. For the running ratio: a healthy EACH_RESP run measured 0-5%
# logged-out responses, a storming one 48%. The minimum sample mirrors what ZAP's own
# insights add-on requires before it will judge an auth failure rate.
CANARY_MAX_LOGINS = 1
LOGGED_OUT_RATIO_LIMIT = 25.0
MIN_AUTH_SAMPLE = 10


def flatten_site_stats(data):
    """Parse ZAP's allSitesStats into {site: {key: value}}.

    VERIFIED ON ZAP 2.17.0 — the shape is nested lists, not the dict it looks like:
        {"allSitesStats": [ {"http://host:port": [ {"stats.auth.x": 1}, ... ]} ]}
    Treating it as a dict yields an empty result, which reads as "no auth failures" and is
    exactly the vacuous pass this census exists to prevent.
    """
    out = {}
    entries = data.get("allSitesStats") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for site, values in entry.items():
            bucket = out.setdefault(str(site), {})
            items = values if isinstance(values, list) else [values]
            for item in items:
                if isinstance(item, dict):
                    for key, val in item.items():
                        try:
                            bucket[str(key)] = bucket.get(str(key), 0) + int(val)
                        except (TypeError, ValueError):
                            continue
    return out


def site_key_for(sites, base_url):
    """Pick the stats site that matches target.base_url (scheme + netloc)."""
    try:
        want = urlparse(str(base_url or ""))
    except ValueError:
        return None
    if not want.netloc:
        return None
    for site in sites:
        try:
            got = urlparse(str(site))
        except ValueError:
            continue
        if got.scheme == want.scheme and got.netloc == want.netloc:
            return site
    return None


def summarize_auth_counters(counters: dict) -> dict:
    """Turn raw stats.auth.* into the two numbers a decision needs."""
    counters = counters or {}
    states = {k.rsplit(".", 1)[-1]: int(counters.get(k, 0) or 0) for k in AUTH_STATE_KEYS}
    logins = sum(int(counters.get(k, 0) or 0) for k in AUTH_LOGIN_KEYS)
    evaluated = sum(states.values())
    logged_out = states["loggedout"]
    return {
        "states": states,
        "logins": logins,
        "evaluated": evaluated,
        "logged_out": logged_out,
        "logged_out_ratio": round(100.0 * logged_out / evaluated, 1) if evaluated else None,
    }


def storm_verdict(summary: dict) -> dict:
    """Is ZAP re-authenticating its way through the scan? Ratio-based, with a minimum sample.

    Only the storm direction is decidable this way. A LOW logged-out ratio is not proof the
    verification config is right — it only says nothing went wrong on the responses ZAP has
    actually judged so far.
    """
    ratio = summary.get("logged_out_ratio")
    enough = (summary.get("evaluated") or 0) >= MIN_AUTH_SAMPLE
    storm = bool(enough and ratio is not None and ratio >= LOGGED_OUT_RATIO_LIMIT)
    return {
        "storm": storm,
        "sample_sufficient": enough,
        "logged_out_ratio": ratio,
        "limit": LOGGED_OUT_RATIO_LIMIT,
        "note": ("re-authentication storm: ZAP judged this share of responses logged-out"
                 if storm else
                 "no storm signal; a low ratio does NOT prove the indicators are correct"),
    }


def canary_verdict(before: dict, after: dict, strategy, driven: int) -> dict:
    """Compare two counter snapshots taken around a small burst of authenticated traffic.

    Measured on ZAP 2.17.0:
      * a healthy config logs in exactly ONCE for a fresh user, and zero times on a repeat
        canary, whatever the strategy -> more than one login means re-authentication;
      * under POLL_URL a healthy first canary always polls, so loggedin+assumedin > 0;
        a config whose indicators never match polls zero times and reports "authenticated"
        forever (the silent-anonymisation shape) -> loggedin+assumedin == 0 catches it.
        Both are 0 for EACH_* even when healthy, so that check is POLL_URL only.
    """
    b, a = summarize_auth_counters(before), summarize_auth_counters(after)
    delta_states = {k: a["states"][k] - b["states"][k] for k in a["states"]}
    logins = a["logins"] - b["logins"]
    is_poll = str(strategy or "").upper() == "POLL_URL"
    verified = delta_states["loggedin"] + delta_states["assumedin"]
    problems = []
    if logins > CANARY_MAX_LOGINS:
        problems.append(
            f"re-authentication storm: {logins} logins for {driven} driven URLs "
            f"(a healthy config logs in at most {CANARY_MAX_LOGINS} time)")
    if is_poll and verified == 0:
        problems.append(
            "verification never ran: ZAP polled 0 times, so it cannot notice an expired "
            "session (indicators that match nothing, or a poll URL ZAP never reaches)")
    if delta_states["noindicator"] > 0:
        problems.append(
            f"{delta_states['noindicator']} responses judged with NO indicator configured — "
            "ZAP answers 'authenticated' unconditionally in that branch")
    return {
        "driven_urls": driven,
        "logins": logins,
        "state_delta": delta_states,
        "strategy": str(strategy or "").upper() or None,
        "problems": problems,
        "ok": not problems,
        "limits": ("a clean canary only covers the response shapes actually driven; under "
                   "EACH_* it says nothing about shapes that were not"),
    }


def parse_include_regexs(value):
    """Normalise ZAP's includeRegexs into a list of strings.

    ZAP 2.17.0 returns it as a JSON array, but some views hand it back as a STRING holding
    that array ("[]"). Comparing with `x in str(value)` looks fine and is wrong: repr() of a
    list doubles the backslashes, so a perfectly applied `\\d` regex reads as missing.
    """
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return [value] if value else []
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
        return [value]
    return []


def seed_url(url) -> str:
    """Give a bare origin an explicit '/' path before handing it to a ZAP scanner.

    VERIFIED ON ZAP 2.17.0: the include regexes this skill recommends require a '/' right
    after the host (`^https?://localhost(:\\d+)?/.*$` — that mandatory slash is what pins the
    host boundary), so `http://host:3000` is judged OUT of context and scanAsUser fails with
    `url_not_in_context`, while `http://host:3000/` is accepted. `target.base_url` is written
    without a trailing slash, so the seed URL needs the canonical form. In HTTP a missing
    path already MEANS '/', so this changes notation only — never the scope.
    """
    text = str(url or "")
    try:
        parts = urlparse(text)
    except ValueError:
        return text
    if parts.scheme and parts.netloc and not parts.path:
        return text + "/"
    return text


def compare_verification(expected: dict, in_zap: dict) -> dict:
    """Return {field: {sent, in_zap}} for every setting that did not actually take."""
    mismatch = {}
    for key, want in expected.items():
        have = in_zap.get(key)
        if str("" if have is None else have) != str(want):
            mismatch[key] = {"sent": want, "in_zap": have}
    return mismatch


def cmd_configure_verification(cfg, args):
    """Set the context checking strategy + logged-in/out indicators.

    NOTE: setContextCheckingStrategy takes the context NAME (not the id); the indicator
    actions take the context id. Both verified against ZAP 2.17.0.
    """
    out = {}
    strategy = resolve_checking_strategy(args.strategy)
    if not args.context:
        raise AuthUsageError(
            "configure-verification requires --context (the context NAME; "
            "setContextCheckingStrategy takes a name, not an id)"
        )
    require_indicator(args.logged_in_indicator, args.logged_out_indicator)

    params = {"contextName": args.context, "checkingStrategy": strategy}
    expected = {"checkingStrategy": strategy}
    if strategy == "POLL_URL":
        poll = build_poll_params(args)
        params.update(poll)
        expected.update(poll)

    out["verification"] = zap_call(cfg, "JSON", "context", "action",
                                   "setContextCheckingStrategy", params)
    if not out["verification"].get("ok"):
        # Stop here. The context still carries whatever strategy it had before, and applying
        # indicators on top of a strategy ZAP never accepted is exactly how a run ends up
        # believing a verification config that does not exist.
        out["applied"] = False
        out["aborted"] = ("setContextCheckingStrategy failed; indicators were NOT set. "
                          "Do not treat verification as configured.")
        return out

    if args.logged_in_indicator:
        out["logged_in"] = zap_call(
            cfg, "JSON", "authentication", "action", "setLoggedInIndicator",
            {"contextId": args.context_id, "loggedInIndicatorRegex": args.logged_in_indicator},
        )
        expected["loggedInPattern"] = args.logged_in_indicator
    if args.logged_out_indicator:
        out["logged_out"] = zap_call(
            cfg, "JSON", "authentication", "action", "setLoggedOutIndicator",
            {"contextId": args.context_id, "loggedOutIndicatorRegex": args.logged_out_indicator},
        )
        expected["loggedOutPattern"] = args.logged_out_indicator

    # Read the context back and confirm the settings actually landed. "ZAP accepted the call"
    # is not the same as "ZAP holds this configuration": setAuthenticationMethod resets the
    # whole verification config (verified on 2.17.0 — POLL_URL + indicators came back as
    # EACH_RESP with empty patterns), so a caller that reconfigures the auth method after
    # this point silently loses it. Comparing against what we sent is the only way to say
    # the verification config is real.
    read = zap_call(cfg, "JSON", "context", "view", "context", {"contextName": args.context})
    ctx = _get(read, "data", "context") or {}
    in_zap = {k: ctx.get(k) for k in VERIFICATION_READBACK_KEYS if k in ctx}
    out["readback"] = in_zap
    mismatch = compare_verification(expected, in_zap)
    out["applied"] = bool(read.get("ok")) and not mismatch
    if mismatch:
        out["mismatch"] = mismatch
    if not read.get("ok"):
        out["readback_error"] = read.get("error")
    return out


def cmd_create_user(cfg, args):
    return zap_call(cfg, "JSON", "users", "action", "newUser",
                    {"contextId": args.context_id, "name": args.username or "dast-user"})


def cmd_set_user_enabled(cfg, args):
    """Enable (or disable) a ZAP user. A newly created user is NOT enabled by default, and
    forced-user mode silently does nothing for a disabled user — so this must be called
    after set-credentials."""
    enabled = "true" if str(args.state or "on").lower() in (
        "on", "true", "1", "enable", "enabled") else "false"
    return zap_call(cfg, "JSON", "users", "action", "setUserEnabled",
                    {"contextId": args.context_id, "userId": args.user_id,
                     "enabled": enabled})


def cmd_set_credentials(cfg, args):
    """Read credentials from env by NAME and set them on the ZAP User. Never echo values."""
    if not args.username_env or not args.password_env:
        raise AuthUsageError("set-credentials requires --username-env and --password-env")
    username = os.environ.get(args.username_env, "")
    password = os.environ.get(args.password_env, "")
    missing = [n for n, v in ((args.username_env, username), (args.password_env, password))
               if not v]
    if missing:
        return {"ok": False, "reason": f"env var(s) empty/unset: {missing}"}
    # authCredentialsConfigParams format depends on the auth method (so the auth method must
    # be configured FIRST — otherwise ZAP still expects the manual-auth credential fields and
    # rejects these with "Missing Parameter"). The LLM supplies the field names; we fill the
    # values from env, URL-encoding each one as ZAP requires. Values are never returned/logged.
    cred_params = args.cred_template or "username={u}&password={p}"
    filled = (cred_params
              .replace("{u}", quote(username, safe=""))
              .replace("{p}", quote(password, safe="")))
    res = zap_call(cfg, "JSON", "users", "action", "setAuthenticationCredentials",
                   {"contextId": args.context_id, "userId": args.user_id,
                    "authCredentialsConfigParams": filled})
    # Strip any echo of the filled params defensively; return only ok/status/error.
    out = {"ok": res.get("ok"), "status": res.get("status"),
           "note": "credentials set from env; values not returned"}
    if res.get("error"):
        out["error"] = res["error"]
    return out


def status_from_response_header(header: str):
    """Parse the status code out of a raw HTTP response header block ('HTTP/1.1 200 OK')."""
    if not header:
        return None
    first = str(header).splitlines()[0] if str(header).splitlines() else ""
    parts = first.split()
    for token in parts[1:2]:
        try:
            return int(token)
        except ValueError:
            return None
    return None


def _message_count(cfg):
    """How many messages ZAP's history holds, or None if it would not say.

    None, not 0: a failed read used to become a 0, which turned the history fallback below
    into a search of the WHOLE history — where an authenticated response to the same URL
    from earlier in the run (ZAP's own poll of `pollUrl` is the obvious one) would be
    accepted as the response to a request that may have gone out anonymous.
    """
    res = zap_call(cfg, "JSON", "core", "view", "numberOfMessages")
    if not res.get("ok"):
        return None
    try:
        return int(_get(res, "data", "numberOfMessages"))
    except (TypeError, ValueError):
        return None


def _last_message_id(cfg):
    """The newest history id before we send anything, or None if it cannot be established.

    Measured on ZAP 2.17.0: `core/view/messages` selects by ID, not by offset —
    `start=numberOfMessages` returns the LAST PRE-EXISTING message (and `start=N+1` returns
    nothing until we send something). Dating entries by id is what makes "recorded after our
    call" true rather than approximately true; asking for one past the count is what makes
    the window start at our own request.
    """
    count = _message_count(cfg)
    if not count:
        return 0 if count == 0 else None
    res = zap_call(cfg, "JSON", "core", "view", "messages",
                   {"start": str(count), "count": "1"})
    entries = _get(res, "data", "messages") or []
    try:
        return int(entries[-1]["id"])
    except (IndexError, KeyError, TypeError, ValueError):
        return None


def request_line_url(request_header: str):
    """The absolute URL out of a ZAP history request line ('GET http://h/p HTTP/1.1')."""
    first = str(request_header or "").splitlines()[:1]
    parts = first[0].split() if first else []
    return parts[1] if len(parts) >= 2 else None


def same_url(a, b) -> bool:
    """URL equality for history matching. Deliberately strict.

    The old matcher asked whether the target's path appeared ANYWHERE in the request line,
    after deriving that path with `url.split('://')[1].split('/', 1)[-1]` — which for the
    default verification URL (`/`, and for any bare origin) is the EMPTY STRING, and an
    empty string is in every request line there is. ZAP's history around one accessUrl call
    is not just our request: measured, it interleaves ZAP's own `GET /login`, `POST /login`,
    poll requests, and site-tree placeholder entries with no response at all. Whichever of
    those happened to be newest was returned as "the authenticated response" — a login page
    or a poll body standing in for the page we never looked at.
    """
    if not a or not b:
        return False
    return str(a).rstrip("/") == str(b).rstrip("/")


def header_value(header: str, name: str):
    """Value of a response header field, or None. Case-insensitive, first wins."""
    for line in str(header or "").splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == str(name).lower():
            return value.strip()
    return None


def _origin(url):
    """(scheme, host, port) with the case and default port normalised away."""
    parts = urlparse(str(url or ""))
    scheme = (parts.scheme or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    return scheme, (parts.hostname or "").lower(), port or DEFAULT_PORTS.get(scheme)


def same_origin(a, b) -> bool:
    return _origin(a) == _origin(b)


def is_safe_upgrade(target, origin_url) -> bool:
    """http -> https on the SAME host: the one cross-origin hop worth following.

    Django's `SECURE_SSL_REDIRECT`, Rails' `force_ssl`, Spring's `requires-channel=https`
    and the standard nginx `return 301 https://$host$request_uri` all answer a plain-http
    `base_url` this way. Refusing it stops both sides on an empty 301 and blames
    authentication for a scheme redirect.
    """
    scheme_t, host_t, _ = _origin(target)
    scheme_o, host_o, _ = _origin(origin_url)
    return scheme_o == "http" and scheme_t == "https" and host_t == host_o and bool(host_t)


def _normalised_path(url) -> str:
    """Path only, percent-decoded and case-folded — how a server routes it, not how it is
    spelled. `/Logout` and `/log%6Fut` reach the same handler on IIS, Django, Rails and
    Express; a guard that compares the spelling guards nothing."""
    path = unquote(urlparse(str(url or "")).path or "")
    return "/" + path.strip("/").casefold()


def is_session_ending(url):
    """The session-terminating path this redirect leads to, or None. Built in, deliberately.

    `exclude.paths` is optional and nothing requires `/logout` to be in it, but following a
    redirect into logout destroys the very session this command exists to verify — and does
    it as the forced user, through ZAP, leaving every later step to fail for a reason that
    is no longer visible. Segment-wise so `/accounts/logout/`, `/api/v1/logout` and Devise's
    `/users/sign_out` are all covered, while `/logout-report` is not.
    """
    segments = [s for s in _normalised_path(url).split("/") if s]
    for seg in segments:
        if seg in LOGOUT_SEGMENTS:
            return "/" + seg
    if segments[-2:] == ["session", "destroy"]:
        return "/session/destroy"
    return None


def path_is_excluded(url, exclude_paths):
    """The `exclude.paths` entry covering `url`, or None. Conservative prefix match, the
    same rule validate_config.py applies to the auth URLs — but percent-decoded and
    case-folded, because here the input is an app-controlled `Location` header rather than a
    human-written config value.

    The verification URL is checked against the excludes at config time; a redirect TARGET
    is a URL nobody chose.
    """
    path = _normalised_path(url)
    for entry in exclude_paths or []:
        if not str(entry).strip().strip("/"):
            continue        # an empty entry would normalise to "/" and exclude everything
        ent = _normalised_path(entry if str(entry).startswith("/") else "/" + str(entry))
        if ent == "/" or path == ent or path.startswith(ent + "/"):
            return str(entry)
    return None


def safe_url(url) -> str:
    """A URL fit to appear in evidence: no query string, no fragment.

    A redirect target is chosen by the application. On an OIDC/SAML flow its query carries
    the authorization `code`, `state`, `nonce`, `code_challenge` or an `id_token`; on a
    password-reset or magic-link flow it carries a single-use token. This command's output is
    read by an LLM and copied into `authentication.md` and `run.log`, and `redact.py` does
    not cover it — so the query never leaves this function.
    """
    parts = urlsplit(str(url or ""))
    shown = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return shown + ("?<query omitted>" if parts.query else "")


def next_hop(resp: Response, origin_url, hops_taken, max_hops=MAX_REDIRECT_HOPS,
             exclude_paths=()):
    """(next_url, stop_reason) for a redirect. Exactly one of the two is None.

    Applied to BOTH sides. The reads used to be asymmetric — ZAP was told
    `followRedirects=false` while the unauthenticated read followed silently — so on a
    session app the authenticated 301 to `/profile/` was compared against the *login page*
    the other side had been redirected to. Measured on a working session: authed 301 with
    an empty body, unauth 200 with the login page, indicator found on neither side, and a
    correctly authenticated run refused.
    """
    if not resp.ok or not resp.status or not 300 <= resp.status < 400:
        return None, None
    location = header_value(resp.header, "location")
    if not location:
        return None, "3xx without a Location header"
    target = urljoin(resp.url or origin_url, location)
    if hops_taken >= max_hops:
        return None, f"redirect limit reached ({max_hops} hops)"
    if not (same_origin(target, origin_url) or is_safe_upgrade(target, origin_url)):
        # The origin, not the URL: the target of an SSO bounce carries the whole authorize
        # query with it (see safe_url).
        scheme, host, port = _origin(target)
        return None, f"redirect leaves the target origin ({scheme}://{host}:{port})"
    ending = is_session_ending(target)
    if ending:
        return None, f"redirect target ends the session ({ending})"
    excluded = path_is_excluded(target, exclude_paths)
    if excluded:
        return None, f"redirect target is covered by exclude.paths ({excluded})"
    return target, None


def follow_redirects(fetch_one, url, max_hops=MAX_REDIRECT_HOPS, exclude_paths=()):
    """Walk a redirect chain with `fetch_one`, recording every hop.

    One loop drives both sides, so the authenticated and unauthenticated reads cannot drift
    apart again: same hop limit, same origin rule, same recorded chain.
    """
    chain, hop_headers = [], []
    current = url
    while True:
        resp = fetch_one(current)
        resp = resp._replace(url=resp.url or current, chain=tuple(chain),
                             hop_headers=tuple(hop_headers))
        target, stop = next_hop(resp, url, len(chain), max_hops, exclude_paths)
        hop = {"url": safe_url(current), "status": resp.status,
               "location": safe_url(header_value(resp.header, "location"))}
        if stop:
            hop["followed"] = False
            hop["stopped"] = stop
            return resp._replace(chain=tuple(chain + [hop]))
        if not target:
            return resp
        hop["followed"] = True
        chain, hop_headers = chain + [hop], hop_headers + [resp.header]
        current = target


def _fetch_through_zap(cfg, url) -> Response:
    """Fetch `url` THROUGH ZAP once, so the forced user (if enabled) applies.

    ZAP 2.17.0's `core/action/accessUrl` RETURNS the message it sent — request header,
    response header, body and history id — so the response can be read straight off the
    call that produced it instead of being searched for afterwards. Older daemons answer
    with a bare "OK"; for those we fall back to the history, matching the request line URL
    exactly and only accepting entries recorded after our call.
    """
    last_id = _last_message_id(cfg)
    res = zap_call(cfg, "JSON", "core", "action", "accessUrl",
                   {"url": url, "followRedirects": "false"})
    if not res.get("ok"):
        return Response(ok=False, url=url, via="accessUrl refused by ZAP")
    returned = _get(res, "data", "accessUrl")
    entries = [e for e in (returned if isinstance(returned, list) else [])
               if isinstance(e, dict) and "responseHeader" in e]
    if entries:
        # ZAP handed us the message it just sent. Its request line is the provenance of the
        # response, so it is what the evidence reports as the URL that was read.
        return _response_from(entries[-1], url,
                              "zap accessUrl response (forced user applies)")
    if last_id is None:
        return Response(ok=False, url=url,
                        via="accessUrl returned no message and ZAP's history could not be "
                            "dated; refusing to guess which entry is ours")
    for entry in reversed(_history_entries_after(cfg, last_id)):
        if not same_url(request_line_url(entry.get("requestHeader", "")), url):
            continue
        out = _response_from(entry, url,
                             "zap history lookup, exact URL match (forced user applies)")
        if out.ok:
            return out
    return Response(ok=False, url=url,
                    via="no response for this URL in ZAP's answer or history")


def _response_from(entry, requested_url, via) -> Response:
    """A Response from a ZAP history/accessUrl message, or ok=False for a placeholder.

    ZAP records site-tree nodes as entries whose response is `HTTP/1.0 0` with no body.
    They are not responses, and returning one as an empty authenticated read would fail
    verification for a session that works.
    """
    status = status_from_response_header(entry.get("responseHeader", ""))
    if not status:
        return Response(ok=False, url=requested_url, via=via)
    return Response(ok=True, status=status, header=str(entry.get("responseHeader", "")),
                    body=str(entry.get("responseBody", "")),
                    url=request_line_url(entry.get("requestHeader", "")) or requested_url,
                    via=via)


def _history_entries_after(cfg, last_id):
    """History entries recorded after `last_id` — by id, not by window position.

    The id filter is not redundant with the `start` we ask for: if a ZAP version treats
    `start` as an offset (or the history has been pruned so ids and positions diverge), the
    window silently begins one message early, and that message is the last one from BEFORE
    our call — a response to the same URL that may have gone out under a different session.
    """
    msgs = zap_call(cfg, "JSON", "core", "view", "messages",
                    {"start": str(int(last_id) + 1), "count": "50"})
    out = []
    for entry in _get(msgs, "data", "messages") or []:
        try:
            if isinstance(entry, dict) and int(entry.get("id")) > int(last_id):
                out.append(entry)
        except (TypeError, ValueError):
            continue
    return out


def cmd_test_authentication(cfg, args):
    """Fetch verification_url as the user and unauthenticated; return RAW EVIDENCE only.

    The authenticated read goes THROUGH ZAP (forced user applies, so the session/credentials
    ZAP holds are used); the unauthenticated read is a direct request that bypasses ZAP
    entirely. Comparing the two is what makes the caller's differential rule meaningful —
    two identical fetches would always look non-differential and fail verification.

    Both sides are read the same way: same redirect rules, header and body both matched.
    `evidence_complete` is false (exit code 1) when either side could not be read at all —
    the differential rule cannot be applied to a response that does not exist, and reading
    a failed fetch as "the indicator was absent there" is a false pass.
    """
    if not str(args.logged_in_indicator or "").strip():
        raise AuthUsageError(
            "test-authentication requires --logged-in-indicator: the differential rule is "
            "about an indicator, and evidence with none is not evidence — it exits 0 with "
            "every comparison null, which reads like a pass.")
    base = _get(cfg, "target", "base_url", default="").rstrip("/")
    path = args.verification_url or "/"
    target = path if "://" in path else base + ("" if path.startswith("/") else "/") + path

    # The scope boundary applies to a URL passed on the command line too: `--verification-url`
    # may carry a full URL, and everything below (the same-origin rule for redirects) is
    # anchored to it.
    allowed = _get(cfg, "target", "allowed_hosts", default=[]) or []
    host = (urlparse(target).hostname or "").lower()
    if allowed and host and host not in [str(h).strip().lower() for h in allowed]:
        raise AuthUsageError(
            f"verification URL host {host!r} is not in target.allowed_hosts {allowed!r}")

    excludes = _get(cfg, "exclude", "paths", default=[]) or []
    excludes = excludes if isinstance(excludes, list) else []
    unauth_reader = DirectReader()
    authed = follow_redirects(lambda u: _fetch_through_zap(cfg, u), target,
                              exclude_paths=excludes)
    unauth = follow_redirects(unauth_reader.fetch, target, exclude_paths=excludes)

    evidence = evidence_from_responses(
        authed, unauth,
        logged_in_indicator=args.logged_in_indicator,
        identity_markers=[m.strip() for m in (args.identity_markers or "").split(",")
                          if m.strip()],
    )
    evidence["verification_url"] = safe_url(target)
    evidence["authed_read_via"] = authed.via
    evidence["unauth_read_via"] = unauth.via
    evidence["redirects_followed"] = f"both sides, same-origin, up to {MAX_REDIRECT_HOPS} hops"
    return evidence


def cmd_set_forced_user(cfg, args):
    """Enable/disable forced-user mode. Disable before any scan that is NOT gated as authed.

    A failure here has to be loud. `test-authentication` and `verify-canary` both drive their
    authenticated side through ZAP with `core/action/accessUrl`, which only carries the
    credentials while forced-user mode is on — so a silently failed `setForcedUser` turns the
    differential read into unauthenticated-vs-unauthenticated, which looks exactly like a
    correctly configured target that cannot authenticate, and stops the run. `ok` is
    top-level because that is the key main() maps to the exit code.
    """
    enabled = str(args.state).lower() in ("on", "true", "1", "enable", "enabled")
    out = {}
    if enabled:
        if not args.user_id:
            raise AuthUsageError("set-forced-user on requires --user-id")
        out["set_user"] = zap_call(cfg, "JSON", "forcedUser", "action", "setForcedUser",
                                   {"contextId": args.context_id, "userId": args.user_id})
    out["mode"] = zap_call(cfg, "JSON", "forcedUser", "action", "setForcedUserModeEnabled",
                           {"boolean": "true" if enabled else "false"})
    out["forced_user_enabled"] = enabled
    out["ok"] = all(bool(out[k].get("ok")) for k in ("set_user", "mode") if k in out)
    return out


def _read_auth_counters(cfg):
    """Return (per_site, global_only, site_key_for_target). Both views are needed: most
    stats.auth.* keys are site-scoped, a few are written globally."""
    allsites = zap_call(cfg, "JSON", "stats", "view", "allSitesStats",
                        {"keyPrefix": "stats.auth"})
    glob = zap_call(cfg, "JSON", "stats", "view", "stats", {"keyPrefix": "stats.auth"})
    sites = flatten_site_stats(_get(allsites, "data") or {})
    key = site_key_for(sites, _get(cfg, "target", "base_url", default=""))
    return sites, (_get(glob, "data", "stats") or {}), key


def cmd_auth_state(cfg, args):
    """Report ZAP's own authentication verdict counters. Raw; no judgement here."""
    sites, glob, key = _read_auth_counters(cfg)
    counters = sites.get(key, {}) if key else {}
    return {
        "target_site": key,
        "counters": counters,
        "summary": summarize_auth_counters(counters),
        "all_sites": sites,
        "global_scope": glob,
    }


def cmd_verify_canary(cfg, args):
    """Drive a few authenticated requests and read ZAP's verdicts before/after.

    This is the pre-flight check for step 2.5: it catches a re-authentication storm and a
    verification that never runs BEFORE the spider turns either one into a whole scan's worth
    of damage. It needs a HETEROGENEOUS URL set — measured on ZAP 2.17.0, a broken config and
    a healthy one produce bit-identical counters when the canary drives only one kind of
    response (JSON-only: both give logins=1, loggedout=0; the same broken config over HTML
    pages gives logins=11, loggedout=10). Pass at least an HTML page, an authenticated
    JSON/API endpoint, and a URL that returns a non-auth error.
    """
    urls = [u for u in (args.canary_url or []) if u]
    if len(urls) < 3:
        raise AuthUsageError(
            "verify-canary requires at least 3 --canary-url values covering DIFFERENT "
            "response shapes (an HTML page, an authenticated JSON/API endpoint, and a "
            "non-auth error such as a 404). With a single shape a storming config and a "
            "healthy one return identical counters, so the check would pass vacuously."
        )
    ctx = {}
    if args.context:
        read = zap_call(cfg, "JSON", "context", "view", "context",
                        {"contextName": args.context})
        ctx = _get(read, "data", "context") or {}
    before, _g, key = _read_auth_counters(cfg)
    accessed = {}
    for url in urls:
        res = zap_call(cfg, "JSON", "core", "action", "accessUrl",
                       {"url": seed_url(url), "followRedirects": "false"})
        accessed[url] = bool(res.get("ok"))
    after, _g2, key2 = _read_auth_counters(cfg)
    site = key or key2
    verdict = canary_verdict(before.get(site, {}), after.get(site, {}),
                             ctx.get("checkingStrategy"), len(urls))
    verdict["target_site"] = site
    verdict["urls_driven"] = accessed
    if not all(accessed.values()):
        verdict["problems"] = list(verdict["problems"]) + [
            "some canary URLs could not be fetched through ZAP; the counters below cover "
            "fewer response shapes than requested"]
        verdict["ok"] = False
    return verdict


def _refuse_if_storming(cfg, command):
    """Consumer-side guard: an authenticated scan checks ZAP's counters itself.

    Deliberately NOT a flag the caller passes. A flag would be self-attestation — the same
    actor that chose the configuration would assert it is fine. Reading ZAP's own verdicts at
    call time cannot be talked past.
    """
    sites, _glob, key = _read_auth_counters(cfg)
    summary = summarize_auth_counters(sites.get(key, {}) if key else {})
    verdict = storm_verdict(summary)
    if verdict["storm"]:
        raise AuthUsageError(
            f"{command} refused: ZAP judged {verdict['logged_out_ratio']}% of responses for "
            f"{key} 'logged out' (limit {LOGGED_OUT_RATIO_LIMIT}%), i.e. it is "
            "re-authenticating instead of holding a session. Running now would flood the "
            "target with logins and produce results of unknown authentication state. Fix the "
            "verification config (references/authentication.md) and retry."
        )


def cmd_spider_as_user(cfg, args):
    _refuse_if_storming(cfg, "spider-as-user")
    return zap_call(cfg, "JSON", "spider", "action", "scanAsUser",
                    {"contextId": args.context_id, "userId": args.user_id,
                     "url": seed_url(args.url or _get(cfg, "target", "base_url", default=""))})


def cmd_ajax_spider_as_user(cfg, args):
    # NOTE: unlike spider/ascan, ajaxSpider.scanAsUser takes NAMES (contextName/userName),
    # not ids. Verified against ZAP 2.17.0.
    if not args.context or not (args.user_name or args.username):
        raise AuthUsageError(
            "ajax-spider-as-user requires --context (name) and --user-name; the ZAP "
            "ajaxSpider API takes names, not ids"
        )
    _refuse_if_storming(cfg, "ajax-spider-as-user")
    return zap_call(cfg, "JSON", "ajaxSpider", "action", "scanAsUser",
                    {"contextName": args.context,
                     "userName": args.user_name or args.username,
                     "url": seed_url(args.url or _get(cfg, "target", "base_url", default=""))})


def cmd_active_scan_as_user(cfg, args):
    # The authenticated Active Scan double gate + step-5 confirmation live above this script.
    if not args.gate_passed:
        raise AuthUsageError(
            "active-scan-as-user requires --gate-passed. Authenticated Active Scan needs "
            "scan.active_scan AND authentication.active_scan true AND step-5 user "
            "confirmation. Refusing to launch."
        )
    _refuse_if_storming(cfg, "active-scan-as-user")
    return zap_call(cfg, "JSON", "ascan", "action", "scanAsUser",
                    {"contextId": args.context_id, "userId": args.user_id,
                     "url": seed_url(args.url or _get(cfg, "target", "base_url", default="")),
                     "scanPolicyName": args.policy or ""})


def scrub_users_list(users_data):
    """Drop the credentials blob from ZAP's usersList.

    VERIFIED ON ZAP 2.17.0: users/view/usersList returns the user's credentials with the
    PASSWORD IN CLEARTEXT. Returning that would pipe the password straight into run.log /
    artifacts / stdout, which the plugin forbids. Keep only the non-secret fields.
    """
    if not isinstance(users_data, dict):
        return users_data
    entries = users_data.get("usersList")
    if not isinstance(entries, list):
        return users_data
    scrubbed = []
    for u in entries:
        if not isinstance(u, dict):
            continue
        safe = {k: v for k, v in u.items() if k != "credentials"}
        # Keep the credential TYPE (useful signal) but never the values.
        raw = str(u.get("credentials", ""))
        for kind in ("UsernamePasswordAuthenticationCredentials",
                     "ManualAuthenticationCredentials",
                     "GenericAuthenticationCredentials"):
            if kind in raw:
                safe["credentials_type"] = kind
                break
        safe["credentials"] = "***REDACTED:field***"
        scrubbed.append(safe)
    return {**users_data, "usersList": scrubbed}


def cmd_auth_status(cfg, args):
    method = zap_call(cfg, "JSON", "authentication", "view", "getAuthenticationMethod",
                      {"contextId": args.context_id})
    forced = zap_call(cfg, "JSON", "forcedUser", "view", "isForcedUserModeEnabled")
    # usersList exposes each user's `enabled` flag — a new ZAP user is disabled by default
    # and forced-user mode silently does nothing for it, so surface it here. The same
    # response carries the cleartext password, so it goes through scrub_users_list first.
    users = zap_call(cfg, "JSON", "users", "view", "usersList",
                     {"contextId": args.context_id})
    return {"authentication_method": _get(method, "data"),
            "forced_user_mode": _get(forced, "data"),
            "users": scrub_users_list(_get(users, "data"))}


def _user_id_list(args):
    """Collect user ids to remove from --user-id and/or --user-ids (comma-separated).

    Multi-account runs create several ZAP users in one context; teardown must remove them
    all. removeContext is still the backstop (it drops the context's users with it), but we
    remove each known user explicitly first so a caller that omits --context still cleans up.
    """
    ids = []
    if args.user_id is not None and str(args.user_id) != "":
        ids.append(str(args.user_id))
    for chunk in str(getattr(args, "user_ids", "") or "").split(","):
        chunk = chunk.strip()
        if chunk:
            ids.append(chunk)
    # de-dup, preserve order
    seen = set()
    return [i for i in ids if not (i in seen or seen.add(i))]


def cmd_clear_authentication(cfg, args):
    """Teardown: drop forced-user, then every User, then the Context, so the credential-
    bearing ZAP state does not linger.

    Order matters: forced-user mode must go OFF first (removing a user still in forced-user
    mode fails). Each account's user is removed explicitly (multi-account runs create
    several). removeContext takes the context NAME (not the id) and removes the context's
    users with it, so it is the backstop when a user id is unknown. Verified on ZAP 2.17.0.
    """
    out = {}
    out["forced_off"] = zap_call(cfg, "JSON", "forcedUser", "action",
                                 "setForcedUserModeEnabled", {"boolean": "false"})
    user_ids = _user_id_list(args)
    if user_ids and args.context_id:
        removed = {}
        for uid in user_ids:
            removed[uid] = zap_call(cfg, "JSON", "users", "action", "removeUser",
                                    {"contextId": args.context_id, "userId": uid})
        out["remove_users"] = removed
    if args.context:
        out["remove_context"] = zap_call(cfg, "JSON", "context", "action", "removeContext",
                                         {"contextName": args.context})
    else:
        out["remove_context"] = {
            "ok": False,
            "error": {"code": "missing_context_name",
                      "message": "pass --context <name>: removeContext takes the context "
                                 "NAME. Without it the credential-bearing context is left "
                                 "in the ZAP session."},
        }
    # remove_users is a {uid: result} map; every other entry is a single result dict.
    def _all_ok(v):
        if not isinstance(v, dict):
            return True
        if "ok" in v:
            return bool(v.get("ok"))
        return all(_all_ok(sub) for sub in v.values())
    out["complete"] = all(_all_ok(v) for v in out.values())
    return out


COMMANDS = {
    "detect-capabilities": cmd_detect_capabilities,
    "create-context": cmd_create_context,
    "include-in-context": cmd_include_in_context,
    "configure-authentication": cmd_configure_authentication,
    "configure-session-management": cmd_configure_session_management,
    "configure-verification": cmd_configure_verification,
    "create-user": cmd_create_user,
    "set-user-enabled": cmd_set_user_enabled,
    "set-credentials": cmd_set_credentials,
    "test-authentication": cmd_test_authentication,
    "auth-state": cmd_auth_state,
    "verify-canary": cmd_verify_canary,
    "set-forced-user": cmd_set_forced_user,
    "spider-as-user": cmd_spider_as_user,
    "ajax-spider-as-user": cmd_ajax_spider_as_user,
    "active-scan-as-user": cmd_active_scan_as_user,
    "auth-status": cmd_auth_status,
    "clear-authentication": cmd_clear_authentication,
}


def build_parser():
    p = argparse.ArgumentParser(description="Thin ZAP authentication wrapper (no judgement)")
    p.add_argument("command", choices=sorted(COMMANDS))
    p.add_argument("--config", default="dast.yaml")
    p.add_argument("--json", action="store_true")
    p.add_argument("--context")
    p.add_argument("--context-id", dest="context_id")
    p.add_argument("--user-id", dest="user_id")
    p.add_argument("--user-ids", dest="user_ids",
                   help="comma-separated ZAP user ids for multi-account teardown "
                        "(clear-authentication removes them all)")
    p.add_argument("--username")
    p.add_argument("--user-name", dest="user_name",
                   help="ZAP user NAME (ajaxSpider takes names, not ids)")
    p.add_argument("--method")
    p.add_argument("--poll-url", dest="poll_url")
    p.add_argument("--poll-data", dest="poll_data")
    p.add_argument("--poll-headers", dest="poll_headers")
    p.add_argument("--poll-frequency", dest="poll_frequency")
    p.add_argument("--poll-frequency-units", dest="poll_frequency_units")
    p.add_argument("--canary-url", dest="canary_url", action="append", default=[],
                   help="repeatable URL for verify-canary; pass at least 3 covering "
                        "DIFFERENT response shapes (HTML page / authenticated JSON API / "
                        "non-auth error)")
    p.add_argument("--regex", action="append", default=[],
                   help="repeatable include regex for include-in-context (the run's scope "
                        "boundary; one per allowed host)")
    p.add_argument("--config-params", dest="config_params",
                   help="verbatim ZAP *ConfigParams string (values already URL-encoded)")
    p.add_argument("--param", action="append", default=[],
                   help="repeatable key=value; values are URL-encoded for ZAP "
                        "(e.g. --param loginUrl=http://host/login)")
    p.add_argument("--strategy",
                   help="context checking strategy: EACH_REQ|EACH_RESP|EACH_REQ_RESP|"
                        "POLL_URL. REQUIRED — there is no default, and AUTO_DETECT is "
                        "refused (it makes ZAP re-authenticate on every request)")
    p.add_argument("--logged-in-indicator", dest="logged_in_indicator")
    p.add_argument("--logged-out-indicator", dest="logged_out_indicator")
    p.add_argument("--username-env", dest="username_env")
    p.add_argument("--password-env", dest="password_env")
    p.add_argument("--cred-template", dest="cred_template")
    p.add_argument("--verification-url", dest="verification_url")
    p.add_argument("--identity-markers", dest="identity_markers")
    p.add_argument("--url")
    p.add_argument("--policy")
    p.add_argument("--state")
    p.add_argument("--gate-passed", dest="gate_passed", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg, load_err = _load_cfg(args.config)
    if load_err:
        msg = {"error": load_err}
        print(json.dumps(msg) if args.json else f"ERROR: {load_err}", file=sys.stderr)
        return 2

    try:
        result = COMMANDS[args.command](cfg, args)
    except AuthUsageError as exc:
        print(json.dumps({"error": str(exc)}) if args.json else f"ERROR: {exc}",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        for k, v in result.items():
            print(f"{k}: {v}")
    # Exit non-zero whenever the command could not deliver what it promises, so a caller that
    # only checks the exit status cannot mistake it for success:
    #   applied           — ZAP does not hold the configuration we asked for
    #   ok                — the ZAP call itself was rejected, or the canary found a problem
    #   complete          — teardown left credential-bearing state behind
    #   evidence_complete — one side of the differential read never happened, so there is
    #                       nothing to apply the rule to (NOT a failed authentication)
    if isinstance(result, dict) and any(
            result.get(k) is False
            for k in ("applied", "ok", "complete", "evidence_complete")):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
