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


def test_users_list_password_is_scrubbed():
    """ZAP 2.17 usersList returns the password IN CLEARTEXT — it must never reach output."""
    raw = {"usersList": [{
        "name": "dast-user", "id": "5", "contextId": "9", "enabled": "true",
        "credentials": '{"password":"probe-pass-123","type":'
                       '"UsernamePasswordAuthenticationCredentials","username":"a@b.c"}',
    }]}
    out = zap_auth.scrub_users_list(raw)
    blob = str(out)
    assert "probe-pass-123" not in blob
    assert "a@b.c" not in blob
    assert out["usersList"][0]["enabled"] == "true"          # useful signal kept
    assert out["usersList"][0]["credentials_type"] == "UsernamePasswordAuthenticationCredentials"


def test_build_config_params_encodes_values():
    s = zap_auth.build_config_params(["loginUrl=http://h/login", 'data={"a":"b"}'])
    assert s == "loginUrl=http%3A%2F%2Fh%2Flogin&data=%7B%22a%22%3A%22b%22%7D"
    # verbatim passthrough wins when given
    assert zap_auth.build_config_params(["x=1"], verbatim="already%3Dencoded") == "already%3Dencoded"
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.build_config_params(["novalue"])


def test_zap_call_treats_result_fail_and_error_code_as_failure(monkeypatch):
    monkeypatch.setattr(zap_auth, "_http_get",
                        lambda url, timeout=30: (True, 200, '{"Result":"FAIL"}'))
    assert zap_auth.zap_call({}, "JSON", "users", "action", "removeUser")["ok"] is False
    monkeypatch.setattr(zap_auth, "_http_get",
                        lambda url, timeout=30: (True, 400,
                                                 '{"code":"missing_parameter","message":"x"}'))
    res = zap_auth.zap_call({}, "JSON", "context", "action", "removeContext")
    assert res["ok"] is False and res["error"]["code"] == "missing_parameter"
    monkeypatch.setattr(zap_auth, "_http_get",
                        lambda url, timeout=30: (True, 200, '{"Result":"OK"}'))
    assert zap_auth.zap_call({}, "JSON", "context", "action", "newContext")["ok"] is True


def test_checking_strategy_validation():
    assert zap_auth.resolve_checking_strategy(None) == "AUTO_DETECT"
    assert zap_auth.resolve_checking_strategy("each_resp") == "EACH_RESP"
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.resolve_checking_strategy("response")  # the old, non-existent value


def test_configure_verification_uses_context_name(monkeypatch):
    """ZAP 2.17: the strategy lives on context/setContextCheckingStrategy and needs a NAME."""
    seen = {}

    def fake(cfg, fmt, comp, kind, name, params=None):
        seen[name] = params
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        context_id = "1"
        strategy = "EACH_RESP"
        poll_url = poll_data = poll_headers = poll_frequency = poll_frequency_units = None
        logged_in_indicator = "Sign out"
        logged_out_indicator = None

    zap_auth.cmd_configure_verification({}, Args())
    assert seen["setContextCheckingStrategy"]["contextName"] == "dast-run"
    assert seen["setContextCheckingStrategy"]["checkingStrategy"] == "EACH_RESP"
    assert seen["setLoggedInIndicator"]["contextId"] == "1"


def test_ajax_spider_uses_names(monkeypatch):
    seen = {}
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda cfg, f, c, k, n, params=None: seen.update({n: params}) or {"ok": True})

    class Args:
        context = "dast-run"
        user_name = "dast-user"
        username = None
        url = "http://localhost:3000"

    zap_auth.cmd_ajax_spider_as_user({}, Args())
    p = seen["scanAsUser"]
    assert p["contextName"] == "dast-run" and p["userName"] == "dast-user"
    assert "contextId" not in p and "userId" not in p


def test_ajax_spider_requires_names():
    class Args:
        context = None
        user_name = None
        username = None
        url = None

    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.cmd_ajax_spider_as_user({}, Args())


def test_user_id_list_collects_and_dedups():
    class Args:
        user_id = "3"
        user_ids = "3, 4 ,5"
    assert zap_auth._user_id_list(Args()) == ["3", "4", "5"]

    class Args2:
        user_id = None
        user_ids = "7,8"
    assert zap_auth._user_id_list(Args2()) == ["7", "8"]

    class Args3:
        user_id = "9"
        user_ids = None
    assert zap_auth._user_id_list(Args3()) == ["9"]


def test_clear_authentication_removes_all_users(monkeypatch):
    """Multi-account teardown must remove every user, then the context."""
    calls = []

    def fake(cfg, fmt, comp, kind, name, params=None):
        calls.append((name, params))
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        context_id = "1"
        user_id = "10"
        user_ids = "11,12"

    out = zap_auth.cmd_clear_authentication({}, Args())
    removed = [p["userId"] for (n, p) in calls if n == "removeUser"]
    assert removed == ["10", "11", "12"]
    # forced-user off happened before any removeUser
    assert calls[0][0] == "setForcedUserModeEnabled"
    assert any(n == "removeContext" for (n, _p) in calls)
    assert out["complete"] is True
    assert set(out["remove_users"]) == {"10", "11", "12"}


def test_clear_authentication_incomplete_when_a_user_removal_fails(monkeypatch):
    def fake(cfg, fmt, comp, kind, name, params=None):
        if name == "removeUser" and params.get("userId") == "12":
            return {"ok": False, "error": {"code": "result_fail", "message": "x"}}
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        context_id = "1"
        user_id = None
        user_ids = "11,12"

    out = zap_auth.cmd_clear_authentication({}, Args())
    assert out["complete"] is False


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
