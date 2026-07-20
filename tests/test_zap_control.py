"""Tests for zap_control's start-command construction and detection. Network-free:
we only exercise command building and detection, never actually launch ZAP."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts")
sys.path.insert(0, SCRIPTS)

import zap_control  # noqa: E402


def _cfg(**zap):
    base = {"zap": {"api_url": "http://localhost:8080", "api_key_env": "ZAP_API_KEY"}}
    base["zap"].update(zap)
    return base


def test_binary_command_binds_loopback(monkeypatch):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    # Pretend zap.sh is on PATH.
    monkeypatch.setattr(zap_control.shutil, "which",
                        lambda name: "/usr/bin/zap.sh" if name == "zap.sh" else None)
    argv, method, error = zap_control.build_start_command(_cfg())
    assert error is None
    assert method == "binary"
    assert "-host" in argv and "127.0.0.1" in argv
    assert "0.0.0.0" not in " ".join(argv)


def test_keyless_uses_disablekey(monkeypatch):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    monkeypatch.setattr(zap_control.shutil, "which",
                        lambda name: "/usr/bin/zap.sh" if name == "zap.sh" else None)
    argv, _, _ = zap_control.build_start_command(_cfg())
    assert "api.disablekey=true" in argv
    assert not any(a.startswith("api.key=") for a in argv)


def test_key_present_uses_api_key(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")
    monkeypatch.setattr(zap_control.shutil, "which",
                        lambda name: "/usr/bin/zap.sh" if name == "zap.sh" else None)
    argv, _, _ = zap_control.build_start_command(_cfg())
    assert "api.key=secret-value" in argv
    assert "api.disablekey=true" not in argv


def test_start_command_override_rejects_all_interfaces(monkeypatch):
    cfg = _cfg(start_command="zap.sh -daemon -host 0.0.0.0 -port 8080")
    argv, method, error = zap_control.build_start_command(cfg)
    assert argv is None
    assert error and "0.0.0.0" in error


def test_start_command_override_accepted(monkeypatch):
    cfg = _cfg(start_command="zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true")
    argv, method, error = zap_control.build_start_command(cfg)
    assert error is None
    assert method == "command"
    assert argv[0] == "zap.sh"


def test_no_binary_returns_error(monkeypatch):
    monkeypatch.setattr(zap_control.shutil, "which", lambda name: None)
    argv, method, error = zap_control.build_start_command(_cfg())
    assert argv is None
    assert method is None
    assert error and "no ZAP binary" in error


def test_detect_reports_disabled(monkeypatch):
    monkeypatch.setattr(zap_control.shutil, "which", lambda name: None)
    det = zap_control.detect(_cfg(autostart=False))
    assert det["autostart_enabled"] is False
    assert det["launchable"] is False


def test_port_parsed_from_api_url():
    assert zap_control._api_port(_cfg()) == 8080
    assert zap_control._api_port({"zap": {"api_url": "http://localhost:9090"}}) == 9090
