#!/usr/bin/env python3
"""Thin ZAP authentication wrapper for llm-zap-dast (v2, best-effort authenticated DAST).

This script performs NO judgement. The LLM inspects the target (source / login page / DOM /
HTTP history), decides the concrete authentication method and settings, and this script
mechanically applies those settings to ZAP's REST API. Design rules enforced here:

  * `configure-authentication` REFUSES `method: auto` — the LLM must resolve `auto` to a
    concrete method before calling the script.
  * `test-authentication` returns RAW EVIDENCE (statuses, indicator-match booleans, identity
    echo), never a pass/fail verdict. The verdict is the caller's job, using a differential
    rule (indicator present in the authed response AND absent in the unauth response).
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
    discards it.

Usage:
    python3 zap_auth.py --config dast.yaml <command> [options] [--json]

Dependencies: PyYAML (config); requests optional (falls back to urllib).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import quote, urlencode, urlparse

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


def _http_get(url, timeout=30):
    """Return (ok, status, text)."""
    try:
        import requests  # type: ignore
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            return True, r.status_code, r.text
        except Exception:  # noqa: BLE001
            return False, None, ""
    except ImportError:
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
                return True, r.status, r.read().decode("utf-8", "replace")
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
    ok = (bool(reached) and not zap_error and not result_fail
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


def evidence_from_responses(authed, unauth, logged_in_indicator=None,
                            identity_markers=None):
    """Build RAW verification evidence — deliberately NO verdict field.

    `authed` / `unauth` are (status, body) tuples. The caller applies the differential
    rule (indicator in authed AND not in unauth) plus identity confirmation; this function
    only reports observations so the safety decision stays with the LLM + fixed rule.
    """
    a_status, a_body = authed
    u_status, u_body = unauth
    identity_markers = identity_markers or []
    return {
        "status_authed": a_status,
        "status_unauth": u_status,
        "indicator_in_authed": _contains(a_body, logged_in_indicator),
        "indicator_in_unauth": _contains(u_body, logged_in_indicator),
        # Differential precondition; the verdict is still the caller's.
        "indicator_is_differential": (
            _contains(a_body, logged_in_indicator)
            and not _contains(u_body, logged_in_indicator)
        ) if logged_in_indicator else None,
        "identity_markers_in_authed": {
            str(m): _contains(a_body, m) for m in identity_markers
        },
        "status_differs": a_status != u_status,
        "note": "evidence only — apply the differential + identity rule to decide auth",
    }


# --- commands ----------------------------------------------------------------
def cmd_detect_capabilities(cfg, _args):
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
    res = zap_call(cfg, "JSON", "core", "view", "numberOfMessages")
    try:
        return int(_get(res, "data", "numberOfMessages") or 0)
    except (TypeError, ValueError):
        return 0


def _fetch_through_zap(cfg, url):
    """Access `url` THROUGH ZAP so the forced user (if enabled) applies, then read the
    response back out of ZAP's history. Returns (status, body, ok)."""
    before = _message_count(cfg)
    res = zap_call(cfg, "JSON", "core", "action", "accessUrl",
                   {"url": url, "followRedirects": "false"})
    if not res.get("ok"):
        return None, "", False
    msgs = zap_call(cfg, "JSON", "core", "view", "messages",
                    {"start": str(before), "count": "20"})
    entries = _get(msgs, "data", "messages") or []
    # The request we just made is the newest entry mentioning this URL.
    for entry in reversed(entries if isinstance(entries, list) else []):
        if not isinstance(entry, dict):
            continue
        if url.split("://", 1)[-1].split("/", 1)[-1] in str(entry.get("requestHeader", "")) \
                or url in str(entry.get("requestHeader", "")):
            return (status_from_response_header(entry.get("responseHeader", "")),
                    str(entry.get("responseBody", "")), True)
    return None, "", True


def cmd_test_authentication(cfg, args):
    """Fetch verification_url as the user and unauthenticated; return RAW EVIDENCE only.

    The authenticated read goes THROUGH ZAP (forced user applies, so the session/credentials
    ZAP holds are used); the unauthenticated read is a direct request that bypasses ZAP
    entirely. Comparing the two is what makes the caller's differential rule meaningful —
    two identical fetches would always look non-differential and fail verification.
    """
    base = _get(cfg, "target", "base_url", default="").rstrip("/")
    path = args.verification_url or "/"
    target = path if "://" in path else base + ("" if path.startswith("/") else "/") + path

    st_a, body_a, access_ok = _fetch_through_zap(cfg, target)   # authenticated (via ZAP)
    ok_u, st_u, body_u = _http_get(target)                      # unauthenticated (direct)

    evidence = evidence_from_responses(
        (st_a, body_a),
        (st_u if ok_u else None, body_u),
        logged_in_indicator=args.logged_in_indicator,
        identity_markers=(args.identity_markers or "").split(",") if args.identity_markers else [],
    )
    evidence["access_ok"] = bool(access_ok)
    evidence["authed_read_via"] = "zap-history (forced user applies)"
    evidence["unauth_read_via"] = "direct request (bypasses ZAP)"
    return evidence


def cmd_set_forced_user(cfg, args):
    """Enable/disable forced-user mode. Disable before any scan that is NOT gated as authed."""
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
    #   applied  — ZAP does not hold the configuration we asked for
    #   ok       — the ZAP call itself was rejected, or the canary found a problem
    #   complete — teardown left credential-bearing state behind
    if isinstance(result, dict) and any(result.get(k) is False
                                        for k in ("applied", "ok", "complete")):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
