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
# key=value pairs in cookie/query/body strings.
_KV = re.compile(
    r"(?i)\b(sessionid|session_id|session|sid|jsessionid|phpsessid|csrf|csrftoken|"
    r"xsrf|_token|token|access_token|refresh_token|id_token|api_key|apikey|"
    r"password|passwd|pwd|secret|client_secret|auth)"
    r"(=)([^;&\s\"']+)"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def redact_string(s: str) -> str:
    if not s:
        return s
    s = _HEADER_LINE.sub(lambda m: f"{m.group(1)}{m.group(2)}" + _MARK.format(kind="header"), s)
    s = _BEARER.sub(_MARK.format(kind="bearer"), s)
    s = _JWT.sub(_MARK.format(kind="jwt"), s)
    s = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}" + _MARK.format(kind="token"), s)
    s = _EMAIL.sub(_MARK.format(kind="email"), s)
    return s


def redact(obj, key=None):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                out[k] = _MARK.format(kind="field")
            else:
                out[k] = redact(v, k)
        return out
    if isinstance(obj, list):
        return [redact(v, key) for v in obj]
    if isinstance(obj, str):
        if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
            return _MARK.format(kind="field")
        return redact_string(obj)
    return obj


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Redact secrets/PII from ZAP JSON")
    parser.add_argument("--in", dest="infile", help="input JSON (default stdin)")
    parser.add_argument("--out", dest="outfile", help="output JSON (default stdout)")
    args = parser.parse_args(argv)

    raw = open(args.infile, "r", encoding="utf-8").read() if args.infile else sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"redact.py: input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    masked = redact(data)
    text = json.dumps(masked, indent=2, ensure_ascii=False)

    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
