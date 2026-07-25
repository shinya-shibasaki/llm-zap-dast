"""Unit tests for zap_auth.py invariants that need no live ZAP: the safety guards
(no 'auto' into the script, gated Active Scan), evidence-not-verdict, and no credential
leakage. Anything requiring a real ZAP is out of scope for the offline suite."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts")
EXAMPLE_CFG = os.path.join(ROOT, "examples", "dast.yaml")
sys.path.insert(0, SCRIPTS)

import zap_auth  # noqa: E402


# --- pure helpers ------------------------------------------------------------
def test_resolve_method_rejects_auto():
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.resolve_auth_method_name("auto")


def test_resolve_method_maps_known():
    assert zap_auth.resolve_auth_method_name("browser") == "browserBasedAuthentication"
    assert zap_auth.resolve_auth_method_name("basic") == "httpAuthentication"


def test_resolve_method_rejects_unknown():
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.resolve_auth_method_name("oauth")


def test_evidence_has_no_verdict():
    ev = zap_auth.evidence_from_responses(
        (200, "Welcome alice, Logout"), (200, "Please log in"),
        logged_in_indicator="Logout", identity_markers=["alice"],
    )
    # The script must not decide auth; no verdict/authenticated key may exist.
    for forbidden in ("authenticated", "verdict", "success", "passed"):
        assert forbidden not in ev
    assert ev["indicator_in_authed"] is True
    assert ev["indicator_in_unauth"] is False
    assert ev["indicator_is_differential"] is True
    assert ev["identity_markers_in_authed"]["alice"] is True


def test_status_from_response_header():
    assert zap_auth.status_from_response_header("HTTP/1.1 200 OK\r\nX: y") == 200
    assert zap_auth.status_from_response_header("HTTP/1.1 302 Found") == 302
    assert zap_auth.status_from_response_header("") is None
    assert zap_auth.status_from_response_header("garbage") is None


def test_test_authentication_reads_authed_via_zap(monkeypatch):
    """The authed read must come from ZAP history (forced user applies), NOT a second
    direct fetch — otherwise both sides are identical and verification can never pass."""
    calls = []

    def fake_zap_call(cfg, fmt, component, kind, name, params=None):
        calls.append(name)
        if name == "numberOfMessages":
            return {"ok": True, "data": {"numberOfMessages": "5"}}
        if name == "accessUrl":
            return {"ok": True, "data": {"accessUrl": "OK"}}
        if name == "messages":
            return {"ok": True, "data": {"messages": [{
                "requestHeader": "GET http://localhost:3000/rest/user/whoami HTTP/1.1",
                "responseHeader": "HTTP/1.1 200 OK",
                "responseBody": '{"user":{"email":"alice@juice-sh.op"}}',
            }]}}
        return {"ok": True, "data": {}}

    monkeypatch.setattr(zap_auth, "zap_call", fake_zap_call)
    # Unauthenticated direct read returns the logged-out shape.
    monkeypatch.setattr(zap_auth, "_http_get", lambda url, timeout=30: (True, 401, '{"user":{}}'))

    class Args:
        verification_url = "/rest/user/whoami"
        logged_in_indicator = "alice@juice-sh.op"
        identity_markers = "alice@juice-sh.op"

    cfg = {"target": {"base_url": "http://localhost:3000"}}
    ev = zap_auth.cmd_test_authentication(cfg, Args())

    assert "accessUrl" in calls and "messages" in calls  # went through ZAP
    assert ev["status_authed"] == 200
    assert ev["status_unauth"] == 401
    assert ev["indicator_in_authed"] is True
    assert ev["indicator_in_unauth"] is False
    assert ev["indicator_is_differential"] is True
    assert ev["identity_markers_in_authed"]["alice@juice-sh.op"] is True
    # Still no verdict — the caller decides.
    assert "authenticated" not in ev and "verdict" not in ev


def test_evidence_non_differential_indicator():
    # An indicator present in BOTH responses is not differential (the classic false pass).
    ev = zap_auth.evidence_from_responses(
        (200, "Logout"), (200, "Logout"), logged_in_indicator="Logout",
    )
    assert ev["indicator_is_differential"] is False


# --- CLI guards (reach the guard before any network call) --------------------
def test_configure_auth_refuses_auto_via_cli():
    rc = zap_auth.main([
        "configure-authentication", "--config", EXAMPLE_CFG,
        "--context-id", "1", "--method", "auto",
    ])
    assert rc == 2


def test_active_scan_requires_gate_via_cli():
    rc = zap_auth.main([
        "active-scan-as-user", "--config", EXAMPLE_CFG,
        "--context-id", "1", "--user-id", "0",
    ])
    assert rc == 2


class _Args:
    context_id = "1"
    user_id = "0"
    username_env = "DAST_USERNAME"
    password_env = "DAST_PASSWORD"
    cred_template = None


def test_set_credentials_missing_env_returns_not_ok(monkeypatch):
    monkeypatch.delenv("DAST_USERNAME", raising=False)
    monkeypatch.delenv("DAST_PASSWORD", raising=False)
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    out = zap_auth.cmd_set_credentials(cfg, _Args())
    assert out["ok"] is False
    assert set(out) <= {"ok", "reason"}


def test_set_credentials_does_not_echo_secret_values(monkeypatch):
    # Even on success, the credential VALUES must never appear in the return structure.
    monkeypatch.setenv("DAST_USERNAME", "alice")
    monkeypatch.setenv("DAST_PASSWORD", "sup3r-s3cr3t-value")
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda *a, **k: {"ok": True, "status": 200, "data": {"Result": "OK"}})
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    out = zap_auth.cmd_set_credentials(cfg, _Args())
    assert out["ok"] is True
    blob = str(out)
    assert "sup3r-s3cr3t-value" not in blob
    assert "alice" not in blob
