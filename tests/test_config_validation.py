"""Config validation tests. These call validate() directly with dict inputs, so they need
no YAML file and no network. Covers the safety-relevant rejection cases."""
import copy
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts")
sys.path.insert(0, SCRIPTS)

import validate_config  # noqa: E402


def _valid_cfg():
    return {
        "target": {
            "base_url": "http://localhost:3000",
            "allowed_hosts": ["localhost", "127.0.0.1"],
            "source_roots": ["src"],
        },
        "zap": {"api_url": "http://localhost:8080", "api_key_env": "ZAP_API_KEY"},
        "authentication": {"enabled": False},
        "scan": {"spider": True, "active_scan": False},
        "safety": {"require_local_target": True, "allow_production": False},
        "exclude": {"paths": ["/logout", "/api/reset"]},
        "output": {"directory": "reports/dast"},
    }


def _errors(cfg):
    errors, _ = validate_config.validate(cfg)
    return errors


def test_valid_config_passes(monkeypatch):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    assert _errors(_valid_cfg()) == []


def test_missing_required_field_fails():
    cfg = _valid_cfg()
    del cfg["target"]["base_url"]
    assert any("base_url" in e for e in _errors(cfg))


def test_disallowed_host_fails():
    cfg = _valid_cfg()
    cfg["target"]["base_url"] = "http://evil.example.com:3000"
    # keep allowed_hosts local so the host is simply not allowed
    assert any("not in target.allowed_hosts" in e for e in _errors(cfg))


def test_keyless_nonlocal_fails(monkeypatch):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["staging.example.com"]
    cfg["target"]["base_url"] = "http://staging.example.com:3000"
    cfg["zap"]["api_url"] = "http://staging.example.com:8080"
    cfg["safety"]["allow_production"] = True  # isolate the keyless rule
    cfg["safety"]["require_local_target"] = False
    assert any("Keyless operation is refused" in e for e in _errors(cfg))


def test_keyless_local_ok(monkeypatch):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    assert _errors(_valid_cfg()) == []


def test_key_present_allows_nonlocal(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["staging.example.com"]
    cfg["target"]["base_url"] = "http://staging.example.com:3000"
    cfg["zap"]["api_url"] = "http://staging.example.com:8080"
    cfg["safety"]["allow_production"] = True
    cfg["safety"]["require_local_target"] = False
    assert not any("Keyless operation is refused" in e for e in _errors(cfg))


def test_active_scan_nonlocal_without_production_fails(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")  # isolate the active-scan rule
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["staging.example.com"]
    cfg["target"]["base_url"] = "http://staging.example.com:3000"
    cfg["zap"]["api_url"] = "http://staging.example.com:8080"
    cfg["scan"]["active_scan"] = True
    cfg["safety"]["allow_production"] = False
    cfg["safety"]["require_local_target"] = False
    assert any("active_scan" in e.lower() for e in _errors(cfg))


def test_attack_mode_fails():
    cfg = _valid_cfg()
    cfg["zap"]["mode"] = "ATTACK"
    assert any("ATTACK" in e for e in _errors(cfg))


def test_auth_enabled_missing_env_fails():
    cfg = _valid_cfg()
    cfg["authentication"] = {"enabled": True, "login_url": "/login"}
    errs = _errors(cfg)
    assert any("username_env" in e for e in errs)
    assert any("password_env" in e for e in errs)


def test_invalid_url_fails():
    cfg = _valid_cfg()
    cfg["target"]["base_url"] = "not-a-url"
    cfg["target"]["allowed_hosts"] = ["localhost", "127.0.0.1"]
    assert any("not a valid http(s) URL" in e for e in _errors(cfg))


def test_exclude_absolute_url_fails():
    cfg = _valid_cfg()
    cfg["exclude"]["paths"] = ["http://localhost:3000/logout"]
    assert any("absolute URL" in e for e in _errors(cfg))


def test_autostart_command_all_interfaces_fails():
    cfg = _valid_cfg()
    cfg["zap"]["start_command"] = "zap.sh -daemon -host 0.0.0.0 -port 8080"
    assert any("0.0.0.0" in e for e in _errors(cfg))


def test_autostart_non_bool_fails():
    cfg = _valid_cfg()
    cfg["zap"]["autostart"] = "yes"
    assert any("autostart" in e for e in _errors(cfg))
