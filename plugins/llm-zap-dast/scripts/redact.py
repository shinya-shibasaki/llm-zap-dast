#!/usr/bin/env python3
"""Redact secrets/PII from an exported ZAP JSON (alerts + HTTP history), whole-structure.

Default posture: mask, do not keep raw. Combines an allowlist-by-key-name approach with
removal of known secret/PII patterns inside string values (raw header blocks, bodies,
cookie/param strings). Masking two header names is deliberately NOT enough.

Usage:
    python3 redact.py < raw.json > masked.json
    python3 redact.py --in raw.json --out masked.json

Masked values become "***REDACTED:<kind>***" so structure and presence remain visible
without leaking the value. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# Keys whose entire value is sensitive regardless of content.
SENSITIVE_KEYS = {
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-csrf-token", "csrf-token", "csrftoken", "x-xsrf-token", "xsrf-token",
    "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token", "authtoken",
    "token", "access_token", "refresh_token", "id_token", "id-token",
    "password", "passwd", "pwd", "secret", "client_secret",
    "session", "sessionid", "session_id", "jsessionid", "phpsessid", "asp.net_sessionid",
    # Auth adds a credential-bearing login request every run: mask usernames too.
    "username", "user_name", "userid", "user_id", "login", "j_username", "j_password",
}

_MARK = "***REDACTED:{kind}***"

# --- string-level patterns ---------------------------------------------------
# Raw header lines inside requestHeader/responseHeader blocks.
_HEADER_LINE = re.compile(
    r"(?im)^(Cookie|Set-Cookie|Authorization|Proxy-Authorization|X-Api-Key|"
    r"X-Auth-Token|X-Csrf-Token|X-Xsrf-Token)(\s*:\s*).*$"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
# key=value pairs in cookie/query/body strings. The password/username alternatives allow a
# leading prefix so non-standard field names (user_password, login_password, j_username) are
# caught — a bare \bpassword misses user_password because '_' is a word char.
_KV = re.compile(
    r"(?i)\b([a-z0-9_]*passw(?:or)?d|[a-z0-9_]*username|[a-z0-9_]*user_name|"
    r"sessionid|session_id|session|sid|jsessionid|phpsessid|csrf|csrftoken|"
    r"xsrf|_token|token|access_token|refresh_token|id_token|api_key|apikey|"
    r"pwd|secret|client_secret|auth)"
    r"(=)([^;&\s\"']+)"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _extra_kv_re(fields):
    """Compile a key=value matcher for caller-supplied login field names, or None."""
    fset = {str(f).lower() for f in (fields or []) if f}
    if not fset:
        return None
    alt = "|".join(re.escape(f) for f in sorted(fset, key=len, reverse=True))
    return re.compile(r"(?i)\b(" + alt + r")(=)([^;&\s\"']+)")


def redact_string(s: str, extra_kv=None) -> str:
    if not s:
        return s
    s = _HEADER_LINE.sub(lambda m: f"{m.group(1)}{m.group(2)}" + _MARK.format(kind="header"), s)
    s = _BEARER.sub(_MARK.format(kind="bearer"), s)
    s = _JWT.sub(_MARK.format(kind="jwt"), s)
    s = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}" + _MARK.format(kind="token"), s)
    if extra_kv is not None:
        s = extra_kv.sub(lambda m: f"{m.group(1)}{m.group(2)}" + _MARK.format(kind="field"), s)
    s = _EMAIL.sub(_MARK.format(kind="email"), s)
    return s


def _walk(obj, key, sensitive, extra_kv):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in sensitive:
                out[k] = _MARK.format(kind="field")
            else:
                out[k] = _walk(v, k, sensitive, extra_kv)
        return out
    if isinstance(obj, list):
        return [_walk(v, key, sensitive, extra_kv) for v in obj]
    if isinstance(obj, str):
        if isinstance(key, str) and key.lower() in sensitive:
            return _MARK.format(kind="field")
        return redact_string(obj, extra_kv)
    return obj


def redact(obj, fields=None):
    """Mask secrets/PII whole-structure. `fields` = extra login field names to mask."""
    fset = {str(f).lower() for f in (fields or []) if f}
    sensitive = SENSITIVE_KEYS | fset
    return _walk(obj, None, sensitive, _extra_kv_re(fset))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Redact secrets/PII from ZAP JSON")
    parser.add_argument("--in", dest="infile", help="input JSON (default stdin)")
    parser.add_argument("--out", dest="outfile", help="output JSON (default stdout)")
    parser.add_argument(
        "--fields", default="",
        help="comma-separated extra login field names to mask (e.g. user_password,email)",
    )
    args = parser.parse_args(argv)

    raw = open(args.infile, "r", encoding="utf-8").read() if args.infile else sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"redact.py: input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    masked = redact(data, fields=fields)
    text = json.dumps(masked, indent=2, ensure_ascii=False)

    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
