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

Usage:
    python3 zap_auth.py --config dast.yaml <command> [options] [--json]

Dependencies: PyYAML (config); requests optional (falls back to urllib).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlencode, urlparse

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
    ok, status, text = _http_get(url)
    data = None
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    return {"ok": ok, "status": status, "data": data}


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


def cmd_configure_authentication(cfg, args):
    zap_name = resolve_auth_method_name(args.method)  # refuses 'auto'
    params = {"contextId": args.context_id, "authMethodName": zap_name}
    if args.config_params:
        params["authMethodConfigParams"] = args.config_params
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
    if args.config_params:
        params["methodConfigParams"] = args.config_params
    return zap_call(cfg, "JSON", "sessionManagement", "action",
                    "setSessionManagementMethod", params)


def cmd_configure_verification(cfg, args):
    out = {}
    out["verification"] = zap_call(
        cfg, "JSON", "authentication", "action", "setAuthenticationVerificationStrategy",
        {"contextId": args.context_id, "verificationStrategy": args.strategy or "response"},
    )
    if args.logged_in_indicator:
        out["logged_in"] = zap_call(
            cfg, "JSON", "authentication", "action", "setLoggedInIndicator",
            {"contextId": args.context_id, "loggedInIndicatorRegex": args.logged_in_indicator},
        )
    if args.logged_out_indicator:
        out["logged_out"] = zap_call(
            cfg, "JSON", "authentication", "action", "setLoggedOutIndicator",
            {"contextId": args.context_id, "loggedOutIndicatorRegex": args.logged_out_indicator},
        )
    return out


def cmd_create_user(cfg, args):
    return zap_call(cfg, "JSON", "users", "action", "newUser",
                    {"contextId": args.context_id, "name": args.username or "dast-user"})


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
    # authCredentialsConfigParams format depends on the auth method; the LLM supplies the
    # field names, we fill the values from env. Values are never returned or logged.
    cred_params = args.cred_template or "username={u}&password={p}"
    filled = cred_params.replace("{u}", username).replace("{p}", password)
    res = zap_call(cfg, "JSON", "users", "action", "setAuthenticationCredentials",
                   {"contextId": args.context_id, "userId": args.user_id,
                    "authCredentialsConfigParams": filled})
    # Strip any echo of the filled params defensively; return only ok/status.
    return {"ok": res.get("ok"), "status": res.get("status"),
            "note": "credentials set from env; values not returned"}


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


def cmd_spider_as_user(cfg, args):
    return zap_call(cfg, "JSON", "spider", "action", "scanAsUser",
                    {"contextId": args.context_id, "userId": args.user_id,
                     "url": args.url or _get(cfg, "target", "base_url", default="")})


def cmd_ajax_spider_as_user(cfg, args):
    return zap_call(cfg, "JSON", "ajaxSpider", "action", "scanAsUser",
                    {"contextId": args.context_id, "userId": args.user_id,
                     "url": args.url or _get(cfg, "target", "base_url", default="")})


def cmd_active_scan_as_user(cfg, args):
    # The authenticated Active Scan double gate + step-5 confirmation live above this script.
    if not args.gate_passed:
        raise AuthUsageError(
            "active-scan-as-user requires --gate-passed. Authenticated Active Scan needs "
            "scan.active_scan AND authentication.active_scan true AND step-5 user "
            "confirmation. Refusing to launch."
        )
    return zap_call(cfg, "JSON", "ascan", "action", "scanAsUser",
                    {"contextId": args.context_id, "userId": args.user_id,
                     "url": args.url or _get(cfg, "target", "base_url", default=""),
                     "scanPolicyName": args.policy or ""})


def cmd_auth_status(cfg, args):
    method = zap_call(cfg, "JSON", "authentication", "view", "getAuthenticationMethod",
                      {"contextId": args.context_id})
    forced = zap_call(cfg, "JSON", "forcedUser", "view", "isForcedUserModeEnabled")
    return {"authentication_method": _get(method, "data"),
            "forced_user_mode": _get(forced, "data")}


def cmd_clear_authentication(cfg, args):
    """Teardown: remove the temporary User and Context so credentials don't linger."""
    out = {}
    if args.user_id:
        out["remove_user"] = zap_call(cfg, "JSON", "users", "action", "removeUser",
                                      {"contextId": args.context_id, "userId": args.user_id})
    out["forced_off"] = zap_call(cfg, "JSON", "forcedUser", "action",
                                 "setForcedUserModeEnabled", {"boolean": "false"})
    if args.context_id:
        out["remove_context"] = zap_call(cfg, "JSON", "context", "action", "removeContext",
                                         {"contextId": args.context_id})
    return out


COMMANDS = {
    "detect-capabilities": cmd_detect_capabilities,
    "create-context": cmd_create_context,
    "configure-authentication": cmd_configure_authentication,
    "configure-session-management": cmd_configure_session_management,
    "configure-verification": cmd_configure_verification,
    "create-user": cmd_create_user,
    "set-credentials": cmd_set_credentials,
    "test-authentication": cmd_test_authentication,
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
    p.add_argument("--username")
    p.add_argument("--method")
    p.add_argument("--config-params", dest="config_params")
    p.add_argument("--strategy")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
