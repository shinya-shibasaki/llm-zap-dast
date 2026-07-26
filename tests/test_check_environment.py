"""Tests for check_environment's Firefox prerequisite check. Network-free: configs omit
target.base_url / zap.api_url so the reachability checks short-circuit to 'skip'."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts")
sys.path.insert(0, SCRIPTS)

import check_environment  # noqa: E402


def _by_name(checks, name):
    return next((c for c in checks if c["name"] == name), None)


def test_firefox_present_reports_ok(monkeypatch):
    monkeypatch.setattr(check_environment.shutil, "which",
                        lambda n: "/usr/local/bin/firefox" if n == "firefox" else None)
    monkeypatch.setattr(check_environment.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": "Mozilla Firefox 153.0",
                                                       "stderr": ""})())
    status, detail = check_environment.detect_firefox()
    assert status == "ok"
    assert "/usr/local/bin/firefox" in detail
    assert "153.0" in detail


def test_firefox_esr_also_accepted(monkeypatch):
    monkeypatch.setattr(check_environment.shutil, "which",
                        lambda n: "/usr/bin/firefox-esr" if n == "firefox-esr" else None)
    monkeypatch.setattr(check_environment.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": "Mozilla Firefox 128.0esr",
                                                       "stderr": ""})())
    status, _ = check_environment.detect_firefox()
    assert status == "ok"


def test_firefox_missing_warns_and_gives_install_hint(monkeypatch):
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    status, detail = check_environment.detect_firefox()
    # 'warn', never 'fail': a missing browser is a capability gap, and safety-policy.md
    # reserves stopping the run for safety failures.
    assert status == "warn"
    assert "download.mozilla.org" in detail
    # The silent DOM XSS skip is the dangerous part; the operator must be told about it.
    assert "DOM XSS" in detail


def test_version_probe_failure_still_reports_ok(monkeypatch):
    """A binary that is present but will not report its version is still present."""
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: "/opt/firefox/firefox")
    def _boom(*_a, **_k):
        raise OSError("exec format error")
    monkeypatch.setattr(check_environment.subprocess, "run", _boom)
    status, detail = check_environment.detect_firefox()
    assert status == "ok"
    assert "version unknown" in detail


def test_run_checks_includes_browser_check(monkeypatch, tmp_path):
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "dast.yaml")
    entry = _by_name(checks, "browser_firefox")
    assert entry is not None
    assert entry["status"] == "warn"


def test_browser_check_is_not_gated_on_ajax_spider(monkeypatch, tmp_path):
    """The DOM XSS rule and Browser Based Authentication need Firefox even when the Ajax
    Spider is disabled, so the check must not branch on scan.ajax_spider."""
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"scan": {"ajax_spider": False}, "output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "dast.yaml")
    assert _by_name(checks, "browser_firefox")["status"] == "warn"


def test_missing_firefox_does_not_make_the_run_fail(monkeypatch, tmp_path):
    """Exit-code semantics: only hard local failures and the ZAP bind-scope security warning
    are allowed to block step 0. A missing browser must stay non-blocking (fail-soft)."""
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "dast.yaml")
    has_fail = any(c["status"] == "fail" for c in checks)
    has_security_warn = any(
        c["name"] == "zap_bind_scope" and c["status"] == "warn" for c in checks)
    assert not has_fail
    assert not has_security_warn
