"""Tests for validate_sast_config.py — the read boundary and the rule-source rules.

The boundary these cover is the SAST equivalent of allowed_hosts: a mistyped source_dir is
enough to read outside the repository and quote unrelated files into a report, so it must be
rejected at the entry rather than noticed later.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "plugins", "llm-zap-dast", "scripts",
))

import validate_sast_config as v  # noqa: E402


def _repo(tmp_path):
    """A real git work tree, since the boundary check shells out to git."""
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


def test_empty_config_is_valid():
    """Every key is optional: profiling fills the gaps, so an absent sast.yaml must not stop a run."""
    errors, _ = v.validate({}, base_dir=".")
    assert errors == [], errors


def test_source_dir_inside_the_repo_is_accepted(tmp_path):
    root = _repo(tmp_path)
    errors, _ = v.validate({"target": {"source_dir": "./app"}}, base_dir=str(root))
    assert errors == [], errors


def test_source_dir_outside_the_repo_is_rejected(tmp_path):
    """`source_dir: ../..` or `~` would pull unrelated repositories and dotfiles into scope."""
    root = _repo(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    errors, _ = v.validate({"target": {"source_dir": "../elsewhere"}}, base_dir=str(root))
    assert any("outside the repository" in e for e in errors), errors


def test_outside_the_repo_is_allowed_with_the_explicit_opt_in(tmp_path):
    """Auditing someone else's checkout is legitimate; it just may not happen by typo."""
    root = _repo(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    errors, warnings = v.validate(
        {"target": {"source_dir": "../elsewhere"}, "safety": {"allow_outside_repo": True}},
        base_dir=str(root),
    )
    assert errors == [], errors
    assert any("outside the repository" in w for w in warnings), warnings


def test_symlink_escaping_the_repo_is_rejected(tmp_path):
    """The boundary is checked after realpath, so a link cannot walk out of it."""
    root = _repo(tmp_path)
    (tmp_path / "outside").mkdir()
    (root / "link").symlink_to(tmp_path / "outside")
    errors, _ = v.validate({"target": {"source_dir": "./link"}}, base_dir=str(root))
    assert any("outside the repository" in e for e in errors), errors


def test_missing_source_dir_is_rejected(tmp_path):
    root = _repo(tmp_path)
    errors, _ = v.validate({"target": {"source_dir": "./nope"}}, base_dir=str(root))
    assert any("does not exist" in e for e in errors), errors


def test_non_repository_requires_the_same_opt_in(tmp_path):
    """Without a work tree there is no boundary to speak of, so it needs the same decision."""
    plain = tmp_path / "plain"
    plain.mkdir()
    errors, _ = v.validate({}, base_dir=str(plain))
    assert any("git work tree" in e for e in errors), errors
    errors, _ = v.validate({"safety": {"allow_outside_repo": True}}, base_dir=str(plain))
    assert errors == [], errors


def test_semgrep_config_auto_is_rejected(tmp_path):
    """--config auto lets the server choose the rules, so the three rounds stop sharing a
    denominator and the same code scans differently over time."""
    root = _repo(tmp_path)
    errors, _ = v.validate(
        {"tools": {"semgrep": {"configs": ["auto"]}}}, base_dir=str(root))
    assert any("auto" in e for e in errors), errors


def test_semgrep_config_from_arbitrary_url_is_rejected(tmp_path):
    root = _repo(tmp_path)
    errors, _ = v.validate(
        {"tools": {"semgrep": {"configs": ["https://example.com/rules.yaml"]}}},
        base_dir=str(root))
    assert any("arbitrary" in e or "URL" in e for e in errors), errors


def test_explicit_packs_are_accepted(tmp_path):
    root = _repo(tmp_path)
    errors, _ = v.validate(
        {"tools": {"semgrep": {"configs": ["p/javascript", "p/security-audit"]}}},
        base_dir=str(root))
    assert errors == [], errors


def test_disabling_semgrep_warns_rather_than_passing_quietly(tmp_path):
    root = _repo(tmp_path)
    errors, warnings = v.validate(
        {"tools": {"semgrep": {"required": False}}}, base_dir=str(root))
    assert errors == [], errors
    assert any("no static scan" in w for w in warnings), warnings


def test_output_inside_the_source_tree_warns_about_self_contamination(tmp_path):
    """Second run would otherwise read the first run's reports as source, and the secret
    rules fire on the lines those reports quote."""
    root = _repo(tmp_path)
    errors, warnings = v.validate(
        {"target": {"source_dir": "./"}, "output": {"directory": "reports/sast"}},
        base_dir=str(root))
    assert errors == [], errors
    assert any("excluded from the scan" in w for w in warnings), warnings


def test_unknown_app_kind_is_rejected(tmp_path):
    root = _repo(tmp_path)
    errors, _ = v.validate({"target": {"app_kind": "firmware"}}, base_dir=str(root))
    assert any("app_kind" in e for e in errors), errors


def test_missing_asvs_csv_is_rejected(tmp_path):
    root = _repo(tmp_path)
    errors, _ = v.validate({"standard": {"asvs_csv": "./absent.csv"}}, base_dir=str(root))
    assert any("asvs_csv" in e for e in errors), errors


def test_git_directory_is_always_excluded():
    """Commit history holds secrets that were removed from the working tree, so this one is
    not negotiable by config."""
    assert ".git/" in v.FORCED_EXCLUDES


def test_bundled_example_config_validates():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg, err = v._load_yaml(os.path.join(root, "examples", "sast.yaml"))
    assert err is None, err
    errors, _ = v.validate(cfg, base_dir=root)
    assert errors == [], errors
