"""Redaction smoke tests: secrets and PII in a ZAP-shaped JSON are masked whole-structure,
including raw header blocks, cookie/token key=value pairs, JWTs, and emails."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts")
sys.path.insert(0, SCRIPTS)

import redact  # noqa: E402

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-DEF_123"


def _sample():
    return {
        "alerts": [
            {
                "alert": "Test",
                "requestHeader": (
                    "GET /a HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Cookie: sessionid=SECRETSESSION; other=ok\r\n"
                    "Authorization: Bearer " + JWT + "\r\n"
                ),
                "responseHeader": "HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=ABC123; Path=/\r\n",
                "requestBody": "username=alice&password=hunter2&email=alice@example.com",
            }
        ],
        "cookieParams": "sessionid=DEADBEEF",
        "Authorization": "Bearer " + JWT,
    }


def _flatten(obj):
    if isinstance(obj, dict):
        return " ".join(_flatten(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten(v) for v in obj)
    return str(obj)


def test_secrets_masked():
    out = redact.redact(_sample())
    blob = _flatten(out)
    for leaked in ("SECRETSESSION", "hunter2", "DEADBEEF", "ABC123", "alice@example.com", JWT):
        assert leaked not in blob, f"secret leaked: {leaked}"
    assert "REDACTED" in blob


def test_sensitive_key_value_fully_masked():
    out = redact.redact(_sample())
    assert "REDACTED" in out["Authorization"]
    assert JWT not in out["Authorization"]


def test_non_secret_preserved():
    out = redact.redact(_sample())
    blob = _flatten(out)
    # Host header and structural content should survive.
    assert "localhost" in blob
    assert "Test" in blob


def test_output_is_json_serializable():
    out = redact.redact(_sample())
    json.dumps(out)  # must not raise
