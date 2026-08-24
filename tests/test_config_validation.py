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


# --- destructive / availability gates ----------------------------------------
def test_destructive_local_default_ok(monkeypatch):
    # Destructive defaults ON and is fine on a local target (nothing set = default true).
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    cfg = _valid_cfg()
    assert not any("destructive" in e.lower() for e in _errors(cfg))
    cfg["scan"]["destructive"] = True
    assert not any("destructive" in e.lower() for e in _errors(cfg))


def test_destructive_nonlocal_without_production_fails(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")  # isolate the destructive rule
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["staging.example.com"]
    cfg["target"]["base_url"] = "http://staging.example.com:3000"
    cfg["zap"]["api_url"] = "http://staging.example.com:8080"
    cfg["scan"]["active_scan"] = False  # isolate destructive from the active-scan rule
    cfg["scan"]["destructive"] = True
    cfg["safety"]["allow_production"] = False
    cfg["safety"]["require_local_target"] = False
    assert any("destructive" in e.lower() for e in _errors(cfg))


def test_destructive_nonlocal_with_production_ok(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["staging.example.com"]
    cfg["target"]["base_url"] = "http://staging.example.com:3000"
    cfg["zap"]["api_url"] = "http://staging.example.com:8080"
    cfg["scan"]["active_scan"] = False
    cfg["scan"]["destructive"] = True
    cfg["safety"]["allow_production"] = True
    cfg["safety"]["require_local_target"] = False
    assert not any("destructive" in e.lower() for e in _errors(cfg))


def test_availability_impact_default_off_no_error(monkeypatch):
    # Not set = OFF; even on a local target there is nothing to complain about.
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    cfg = _valid_cfg()
    assert not any("availability_impact" in e for e in _errors(cfg))


def test_availability_impact_nonlocal_without_production_fails(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["staging.example.com"]
    cfg["target"]["base_url"] = "http://staging.example.com:3000"
    cfg["zap"]["api_url"] = "http://staging.example.com:8080"
    cfg["scan"]["active_scan"] = False
    cfg["scan"]["destructive"] = False  # isolate the availability rule
    cfg["scan"]["availability_impact"] = True
    cfg["safety"]["allow_production"] = False
    cfg["safety"]["require_local_target"] = False
    assert any("availability_impact" in e for e in _errors(cfg))


def test_availability_impact_nonlocal_in_allowed_hosts_fails(monkeypatch):
    # base_url local but a non-local host in allowed_hosts (= ZAP attack scope). DoS traffic
    # would still reach it; must be refused like destructive is.
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")
    cfg = _valid_cfg()
    cfg["target"]["base_url"] = "http://localhost:3000"
    cfg["target"]["allowed_hosts"] = ["localhost", "prod.example.com"]
    cfg["scan"]["active_scan"] = False
    cfg["scan"]["destructive"] = False
    cfg["scan"]["availability_impact"] = True
    cfg["safety"]["allow_production"] = False
    cfg["safety"]["require_local_target"] = False
    assert any("availability_impact" in e and "allowed_hosts" in e for e in _errors(cfg))


def test_allow_production_quoted_string_rejected(monkeypatch):
    # bool("false") is True — a quoted allow_production must NOT silently disable the guards.
    monkeypatch.setenv("ZAP_API_KEY", "secret-value")
    cfg = _valid_cfg()
    cfg["target"]["allowed_hosts"] = ["prod.example.com"]
    cfg["target"]["base_url"] = "http://prod.example.com"
    cfg["zap"]["api_url"] = "http://localhost:8080"
    cfg["safety"]["allow_production"] = "false"  # quoted string, the footgun
    cfg["safety"]["require_local_target"] = True
    cfg["scan"]["active_scan"] = True
    cfg["scan"]["destructive"] = True
    errs = _errors(cfg)
    # The type error must fire, and the non-local host must NOT slip through as production-ok.
    assert any("allow_production must be a boolean" in e for e in errs)
    assert any("non-local hosts are in allowed_hosts" in e for e in errs)


def test_auth_enabled_missing_env_fails():
    cfg = _valid_cfg()
    cfg["authentication"] = {"enabled": True, "login_url": "/login"}
    errs = _errors(cfg)
    assert any("username_env" in e for e in errs)
    assert any("password_env" in e for e in errs)


def _auth_cfg():
    cfg = _valid_cfg()
    cfg["authentication"] = {
        "enabled": True,
        "method": "auto",
        "login_url": "/login",
        "username_env": "DAST_USERNAME",
        "password_env": "DAST_PASSWORD",
        "max_attempts": 3,
        "verification": {"method": "auto", "verification_url": "/account"},
        "session_management": {"method": "auto"},
        "active_scan": False,
    }
    return cfg


def test_full_auth_config_passes():
    assert _errors(_auth_cfg()) == []


def test_auth_plaintext_credentials_rejected():
    cfg = _auth_cfg()
    cfg["authentication"]["password"] = "hunter2"
    cfg["authentication"]["username"] = "alice"
    errs = _errors(cfg)
    assert any("authentication.password" in e for e in errs)
    assert any("authentication.username" in e for e in errs)


def test_auth_invalid_method_rejected():
    cfg = _auth_cfg()
    cfg["authentication"]["method"] = "oauth"
    assert any("authentication.method" in e for e in _errors(cfg))


def test_auth_invalid_max_attempts_rejected():
    cfg = _auth_cfg()
    cfg["authentication"]["max_attempts"] = 0
    assert any("max_attempts" in e for e in _errors(cfg))
    cfg["authentication"]["max_attempts"] = "three"
    assert any("max_attempts" in e for e in _errors(cfg))


def test_auth_login_url_under_exclude_rejected():
    cfg = _auth_cfg()
    cfg["exclude"]["paths"] = ["/login"]
    assert any("login_url" in e and "exclude.paths" in e for e in _errors(cfg))


def test_auth_verification_url_under_exclude_rejected():
    cfg = _auth_cfg()
    cfg["exclude"]["paths"] = ["/account"]
    assert any("verification_url" in e and "exclude.paths" in e for e in _errors(cfg))


def test_auth_active_scan_without_global_gate_warns():
    cfg = _auth_cfg()
    cfg["authentication"]["active_scan"] = True
    cfg["scan"]["active_scan"] = False
    _errs, warns = validate_config.validate(cfg)
    assert any("authentication.active_scan" in w for w in warns)


def _multi_user_auth_cfg():
    cfg = _auth_cfg()
    del cfg["authentication"]["username_env"]
    del cfg["authentication"]["password_env"]
    cfg["authentication"]["users"] = [
        {"label": "alice", "role": "user",
         "username_env": "DAST_ALICE_USER", "password_env": "DAST_ALICE_PASS"},
        {"label": "bob", "role": "user",
         "username_env": "DAST_BOB_USER", "password_env": "DAST_BOB_PASS"},
    ]
    return cfg


def test_multi_user_config_passes():
    assert _errors(_multi_user_auth_cfg()) == []


def test_multi_user_missing_env_fails():
    cfg = _multi_user_auth_cfg()
    del cfg["authentication"]["users"][1]["password_env"]
    assert any("users[1].password_env" in e for e in _errors(cfg))


def test_multi_user_plaintext_rejected():
    cfg = _multi_user_auth_cfg()
    cfg["authentication"]["users"][0]["password"] = "hunter2"
    assert any("users[0].password" in e for e in _errors(cfg))


def test_multi_user_duplicate_label_rejected():
    cfg = _multi_user_auth_cfg()
    cfg["authentication"]["users"][1]["label"] = "alice"
    assert any("label" in e and "duplicated" in e for e in _errors(cfg))


def test_multi_user_empty_list_rejected():
    cfg = _multi_user_auth_cfg()
    cfg["authentication"]["users"] = []
    assert any("authentication.users must be a non-empty list" in e for e in _errors(cfg))


def test_multi_user_duplicate_credentials_rejected():
    # Two accounts pointing at the same env vars = same identity = silent IDOR false-negative.
    cfg = _multi_user_auth_cfg()
    cfg["authentication"]["users"][1]["username_env"] = "DAST_ALICE_USER"
    cfg["authentication"]["users"][1]["password_env"] = "DAST_ALICE_PASS"
    assert any("DISTINCT identities" in e for e in _errors(cfg))


def test_multi_user_with_single_form_warns():
    cfg = _multi_user_auth_cfg()
    cfg["authentication"]["username_env"] = "DAST_LEFTOVER_USER"
    cfg["authentication"]["password_env"] = "DAST_LEFTOVER_PASS"
    _errs, warns = validate_config.validate(cfg)
    assert any("top-level username_env/password_env are ignored" in w for w in warns)


def test_single_account_still_supported():
    # Legacy single username_env/password_env keeps working with no users list.
    assert _errors(_auth_cfg()) == []


def test_auth_disabled_ignores_auth_block():
    # A disabled auth block with junk should not raise errors (backward compat).
    cfg = _valid_cfg()
    cfg["authentication"] = {"enabled": False, "method": "nonsense", "password": "x"}
    assert _errors(cfg) == []


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


# --- SAST handoff (sast.enabled / sast.report) --------------------------------------------
# The run-time stop conditions (missing artefacts, wrong repository) belong to step 0. What is
# tested here is the entry-side form check: a reference that could never be safe is refused
# before anything reads it.


def test_sast_defaults_are_accepted():
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": False}
    assert _errors(cfg) == []


def test_sast_explicit_run_directory_is_accepted():
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "reports/sast/20260820-004654-90d8b8"}
    assert _errors(cfg) == []


def test_sast_report_escaping_the_repo_fails():
    """`..` would let the run read another target's SAST results while looking normal."""
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "../other-repo/reports/sast/x"}
    assert any("sast.report" in e and ".." in e for e in _errors(cfg))


def test_sast_report_absolute_path_fails():
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "/var/tmp/sast-run"}
    assert any("sast.report" in e and "absolute" in e for e in _errors(cfg))


def test_sast_report_url_fails():
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "https://example.com/attack-map.md"}
    assert any("sast.report" in e and "URL" in e for e in _errors(cfg))


def test_sast_enabled_must_be_a_real_bool():
    """Same fail-open trap as safety.allow_production: a quoted "false" is truthy."""
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": "false"}
    assert any("sast.enabled must be a boolean" in e for e in _errors(cfg))


def test_sast_method_keys_are_warned_not_accepted_silently():
    """How the artefacts are used is methodology (sast-handoff.md), never a config knob."""
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "latest", "use_attack_map": True}
    errors, warnings = validate_config.validate(cfg)
    assert errors == []
    assert any("use_attack_map" in w for w in warnings)


def test_sast_report_home_or_variable_expansion_fails():
    """`~/x` and `$HOME/x` are absolute once anything expands them, and expansion happens
    outside the validator. Refusing the literal form is the only place the check still bites.
    """
    for value in ("~/sast-run", "$HOME/sast-run", "%APPDATA%/sast-run"):
        cfg = _valid_cfg()
        cfg["sast"] = {"enabled": True, "report": value}
        assert any("sast.report" in e for e in _errors(cfg)), value


def test_sast_report_must_name_a_run_directory():
    for value in ("", "  ", "."):
        cfg = _valid_cfg()
        cfg["sast"] = {"enabled": True, "report": value}
        assert any("sast.report" in e for e in _errors(cfg)), repr(value)


def _pointer_errors(tmp_path, pointer_text):
    """Run validate() with a real base_dir and an optional reports/sast/latest.json."""
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "latest"}
    if pointer_text is not None:
        d = tmp_path / "reports" / "sast"
        d.mkdir(parents=True)
        (d / "latest.json").write_text(pointer_text, encoding="utf-8")
    errors, _ = validate_config.validate(cfg, base_dir=str(tmp_path))
    return errors


def test_sast_latest_pointer_missing_is_refused(tmp_path):
    """`latest` promises a resolvable run. Failing silently here is how a run ends up with no
    SAST denominator while the report still looks normal."""
    assert any("latest.json" in e for e in _pointer_errors(tmp_path, None))


def test_sast_latest_pointer_escaping_the_repo_is_refused(tmp_path):
    """The pointer lives inside the target repository, so its contents are target-side data
    that decides which files the run opens (safety-core.md §5/§8)."""
    errors = _pointer_errors(tmp_path, '{"run_id": "x", "path": "../elsewhere/reports/sast/x"}')
    assert any("latest.json" in e and ".." in e for e in errors)


def test_sast_latest_pointer_without_path_is_refused(tmp_path):
    assert any("latest.json" in e for e in _pointer_errors(tmp_path, '{"run_id": "x"}'))


def test_sast_latest_pointer_unparsable_is_refused(tmp_path):
    assert any("latest.json" in e for e in _pointer_errors(tmp_path, "{not json"))


def test_sast_latest_pointer_valid_passes(tmp_path):
    errors = _pointer_errors(
        tmp_path, '{"run_id": "20260820-004654-90d8b8", "path": "reports/sast/20260820-004654-90d8b8"}'
    )
    assert [e for e in errors if "sast" in e or "latest.json" in e] == []


def test_pointer_check_is_skipped_without_a_base_dir():
    """Callers holding only a dict get the pure form checks, not filesystem ones."""
    cfg = _valid_cfg()
    cfg["sast"] = {"enabled": True, "report": "latest"}
    assert _errors(cfg) == []
