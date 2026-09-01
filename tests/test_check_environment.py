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


def test_venv_and_system_python_are_probed_separately(monkeypatch, tmp_path):
    """The regression this check exists for: a project .venv/bin/python is a SYMLINK to the
    system python it must be told apart from. De-duplicating candidates by os.path.realpath
    would collapse the two and re-create the false negative."""
    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    system = tmp_path / "usr" / "bin"
    system.mkdir(parents=True)
    (system / "python3").write_text("#!/bin/sh\n")
    (venv / "python").symlink_to(system / "python3")  # exactly how `python -m venv` links

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(check_environment.sys, "executable", str(venv / "python"))
    monkeypatch.setattr(check_environment.shutil, "which",
                        lambda n: str(system / "python3") if n == "python3" else None)

    probed = [os.path.abspath(p) for p in check_environment.candidate_interpreters()]
    assert str(venv / "python") in probed
    assert str(system / "python3") in probed


def test_browsers_dir_follows_the_platform_default(monkeypatch):
    """Playwright's default cache is per-platform. Hardcoding the Linux path made a healthy
    macOS install look browser-less, and step 4 being fail-soft turned that into silently
    lost coverage instead of an error."""
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setenv("HOME", "/home/u")
    monkeypatch.setattr(check_environment.sys, "platform", "darwin")
    assert check_environment._browsers_dir().endswith("/Library/Caches/ms-playwright")
    monkeypatch.setattr(check_environment.sys, "platform", "linux")
    assert check_environment._browsers_dir().endswith("/.cache/ms-playwright")
    monkeypatch.setattr(check_environment.sys, "platform", "win32")
    assert check_environment._browsers_dir().endswith(os.path.join(
        "AppData", "Local", "ms-playwright"))


def test_browsers_dir_env_var_overrides_every_platform(monkeypatch):
    """The plugin never sets PLAYWRIGHT_BROWSERS_PATH; when the operator's environment does,
    it wins — that is Playwright's own contract."""
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw")
    for plat in ("darwin", "linux", "win32"):
        monkeypatch.setattr(check_environment.sys, "platform", plat)
        assert check_environment._browsers_dir() == "/opt/pw"


def test_playwright_found_reports_the_working_interpreter(monkeypatch, tmp_path):
    browsers = tmp_path / "ms-playwright"
    (browsers / "chromium-1228").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(browsers))
    monkeypatch.setattr(check_environment, "candidate_interpreters",
                        lambda: ["/proj/.venv/bin/python", "/usr/bin/python3"])
    # Only the system interpreter has it — the venv-shadowing case.
    monkeypatch.setattr(check_environment, "_probe_playwright",
                        lambda i: "1.61.0" if i == "/usr/bin/python3" else None)
    status, detail = check_environment.detect_playwright()
    assert status == "ok"
    assert "/usr/bin/python3" in detail
    assert "1.61.0" in detail


def test_playwright_package_without_browsers_warns(monkeypatch, tmp_path):
    """`pip install playwright` does not download browsers; the two are separate facts."""
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "absent"))
    monkeypatch.setattr(check_environment, "candidate_interpreters", lambda: ["/usr/bin/python3"])
    monkeypatch.setattr(check_environment, "_probe_playwright", lambda i: "1.61.0")
    status, detail = check_environment.detect_playwright()
    assert status == "warn"
    assert "playwright install chromium" in detail


def test_playwright_absent_warns_and_names_what_was_probed(monkeypatch, tmp_path):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "absent"))
    monkeypatch.setattr(check_environment, "candidate_interpreters",
                        lambda: ["/proj/.venv/bin/python"])
    monkeypatch.setattr(check_environment, "_probe_playwright", lambda i: None)
    status, detail = check_environment.detect_playwright()
    assert status == "warn"
    # The operator must be able to see WHICH interpreters were tried, and why --user installs
    # go missing, otherwise the false negative is unexplainable.
    assert "/proj/.venv/bin/python" in detail
    assert "--user" in detail


def test_missing_playwright_does_not_make_the_run_fail(monkeypatch, tmp_path):
    """Steps 4/6 are fail-soft: a missing Playwright must not block step 0."""
    monkeypatch.setattr(check_environment, "candidate_interpreters", lambda: [])
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "dast.yaml")
    assert _by_name(checks, "playwright")["status"] == "warn"
    assert not any(c["status"] == "fail" for c in checks)


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


def test_zap_api_key_never_reaches_the_check_output(monkeypatch, tmp_path):
    """The key rides in the version URL's query, and both requests and urllib put the URL
    they failed on into the exception text — so an unreachable ZAP (the common fail-soft
    case) used to write the key into environment-check.json and stdout."""
    monkeypatch.setenv("ZAP_API_KEY", "sup3r-s3cr3t-key")
    monkeypatch.setattr(check_environment, "_http_get",
                        lambda url, timeout=5: (False, None,
                                                f"Max retries exceeded with url: {url}"))
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"zap": {"api_url": "http://localhost:8080", "api_key_env": "ZAP_API_KEY"},
           "output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "dast.yaml")
    assert "sup3r-s3cr3t-key" not in str(checks)
    # The diagnostic itself must survive the scrubbing.
    assert "***REDACTED:apikey***" in _by_name(checks, "zap_reachable")["detail"]


def test_scrub_secret_is_a_noop_without_a_key():
    assert check_environment._scrub_secret("plain text", "") == "plain text"
    assert check_environment._scrub_secret("plain text", None) == "plain text"


# --- SAST profile ---------------------------------------------------------------
# The SAST skill must not open a network connection, so its profile does not merely skip the
# ZAP and browser checks — it never reaches them. "sast.yaml happens to have no base_url" is
# a coincidence, not a property.

def test_sast_profile_runs_no_network_or_browser_checks(monkeypatch, tmp_path):
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: "/usr/bin/semgrep")
    cfg = {"output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "sast.yaml", profile="sast")
    names = {c["name"] for c in checks}
    for absent in ("target_reachable", "zap_reachable", "zap_autostart", "zap_api_key_env",
                   "browser_firefox", "playwright", "zap_bind_scope"):
        assert absent not in names, f"{absent} must not run under the sast profile"
    assert {"python_version", "git_repo", "config_file", "semgrep", "output_writable"} <= names


def test_semgrep_missing_fails_the_sast_profile(monkeypatch, tmp_path):
    """Measured on 1.163.0: rules are not cached, so without semgrep not a single rule runs.
    A report produced anyway would be indistinguishable from a real one."""
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "sast.yaml", profile="sast")
    semgrep = _by_name(checks, "semgrep")
    assert semgrep["status"] == "fail"
    assert "pipx install semgrep" in semgrep["detail"]
    # No curl-piped-to-shell install advice: the stop message is read as a how-to.
    assert "curl" not in semgrep["detail"] and "| sh" not in semgrep["detail"]


def test_semgrep_missing_only_warns_when_the_config_opted_out(monkeypatch, tmp_path):
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"tools": {"semgrep": {"required": False}},
           "output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "sast.yaml", profile="sast")
    assert _by_name(checks, "semgrep")["status"] == "warn"


def test_missing_semgrep_does_not_break_the_dast_profile(monkeypatch, tmp_path):
    """The DAST step 0 treats a 'fail' as a hard stop (exit 1). semgrep is no prerequisite of
    a DAST run, so it must not appear on that side at all."""
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: None)
    cfg = {"output": {"directory": str(tmp_path / "out")}}
    checks = check_environment.run_checks(cfg, "dast.yaml")
    assert _by_name(checks, "semgrep") is None
    assert not any(c["status"] == "fail" for c in checks), checks


def test_semgrep_detection_never_executes_semgrep(monkeypatch):
    """`semgrep --version` writes an anonymous_user_id and calls semgrep.dev (measured on
    1.163.0). An environment check must not be what breaks the no-network promise."""
    monkeypatch.setattr(check_environment.shutil, "which", lambda n: "/usr/bin/semgrep")

    def _forbidden(*a, **k):
        raise AssertionError("detect_semgrep must not run a subprocess")

    monkeypatch.setattr(check_environment.subprocess, "run", _forbidden)
    status, detail = check_environment.detect_semgrep()
    assert status == "ok"
    assert "/usr/bin/semgrep" in detail
