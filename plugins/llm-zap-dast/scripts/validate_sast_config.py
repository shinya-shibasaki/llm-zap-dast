#!/usr/bin/env python3
"""Validate a sast.yaml config for the llm-zap-dast plugin's SAST skill.

Entry-side (static) safety checks, deliberately kept out of validate_config.py: that file
makes target.base_url / target.allowed_hosts / zap.api_url unconditionally required, and
relaxing those to let a sast.yaml through would fail-open the DAST boundary checks too.

The boundary this file guards is the SAST equivalent of allowed_hosts: not "where may we
send", but "how far may we read". A mistyped source_dir is enough to walk out of the
repository and pull unrelated files into a report, so the default is the git work tree and
leaving it takes an explicit opt-in (safety.allow_outside_repo), the same shape as
safety.allow_production on the DAST side.

Usage:
    python3 validate_sast_config.py [--config sast.yaml] [--json]

Exit code 0 = valid (may have warnings), 1 = invalid (has errors), 2 = usage/load error.
Dependency: PyYAML.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

APP_KINDS = {
    "auto", "web", "api", "graphql", "cli", "library", "batch", "mobile", "desktop", "infra",
}

# Paths never analysed, whatever the config says. .git carries every secret that was ever
# committed and later deleted, and a symlink out of the tree defeats the source_dir check
# by walking rather than by configuration.
FORCED_EXCLUDES = (".git/",)


def _load_yaml(path: str):
    try:
        import yaml  # PyYAML
    except ImportError:
        return None, "PyYAML is not installed. Install with: pip install pyyaml"
    if not os.path.isfile(path):
        return None, f"Config file not found: {path}"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001
        return None, f"Could not parse {path}: {exc}"
    if data is None:
        return {}, None
    if not isinstance(data, dict):
        return None, f"{path} must contain a YAML mapping at the top level"
    return data, None


def _get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _git_work_tree(start: str):
    """Absolute path of the git work tree containing `start`, or None."""
    try:
        r = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:  # noqa: BLE001
        return None
    if r.returncode != 0:
        return None
    top = r.stdout.strip()
    return os.path.realpath(top) if top else None


def _is_within(child: str, parent: str) -> bool:
    child = os.path.realpath(child)
    parent = os.path.realpath(parent)
    return child == parent or child.startswith(parent + os.sep)


def validate(cfg, base_dir: str = "."):
    errors: list[str] = []
    warnings: list[str] = []
    cfg = cfg or {}

    known_top = {"target", "safety", "standard", "tools", "analysis", "agents", "output"}
    for key in cfg:
        if key not in known_top:
            warnings.append(f"unknown top-level key {key!r} (ignored)")

    # --- read boundary --------------------------------------------------------
    source_dir = _get(cfg, "target", "source_dir", default=".")
    if not isinstance(source_dir, str) or not source_dir.strip():
        errors.append("target.source_dir must be a non-empty string")
        source_dir = "."
    source_abs = os.path.realpath(os.path.join(base_dir, os.path.expanduser(source_dir)))

    if not os.path.isdir(source_abs):
        errors.append(f"target.source_dir does not exist or is not a directory: {source_dir}")
    else:
        allow_outside = bool(_get(cfg, "safety", "allow_outside_repo", default=False))
        work_tree = _git_work_tree(base_dir) or _git_work_tree(source_abs)
        if work_tree is None:
            if not allow_outside:
                errors.append(
                    "not inside a git work tree, so the read boundary cannot be established; "
                    "run from a repository, or set safety.allow_outside_repo: true to accept "
                    "reading an unbounded directory"
                )
        elif not _is_within(source_abs, work_tree):
            if allow_outside:
                warnings.append(
                    f"target.source_dir resolves outside the repository "
                    f"({source_abs} is not under {work_tree}); allowed by "
                    f"safety.allow_outside_repo"
                )
            else:
                errors.append(
                    f"target.source_dir resolves outside the repository: {source_abs} is not "
                    f"under {work_tree}. Point it inside the repo, or set "
                    f"safety.allow_outside_repo: true if reading outside is intended"
                )

    app_kind = _get(cfg, "target", "app_kind", default="auto")
    if str(app_kind) not in APP_KINDS:
        errors.append(
            f"target.app_kind {app_kind!r} is not one of: {', '.join(sorted(APP_KINDS))}"
        )

    # --- standard -------------------------------------------------------------
    asvs = _get(cfg, "standard", "asvs_csv")
    if asvs is not None:
        if not isinstance(asvs, str) or not asvs.strip():
            errors.append("standard.asvs_csv must be a path (omit the key to use the bundled ASVS 5.0)")
        elif not os.path.isfile(os.path.join(base_dir, os.path.expanduser(asvs))):
            errors.append(f"standard.asvs_csv not found: {asvs}")

    # --- semgrep --------------------------------------------------------------
    required = _get(cfg, "tools", "semgrep", "required", default=True)
    if not isinstance(required, bool):
        errors.append("tools.semgrep.required must be true or false")
    elif required is False:
        warnings.append(
            "tools.semgrep.required is false: the run may produce a report with no static "
            "scan behind it. Every report must say so on its first page"
        )

    configs = _get(cfg, "tools", "semgrep", "configs")
    if configs is not None:
        if not isinstance(configs, list) or not configs:
            errors.append(
                "tools.semgrep.configs must be a non-empty list of rule packs "
                "(omit the key to let profiling choose from the detected languages)"
            )
        else:
            for entry in configs:
                text = str(entry)
                if text == "auto":
                    errors.append(
                        "tools.semgrep.configs entry 'auto' is rejected: semgrep's --config auto "
                        "lets the server pick the rules, so the same code scans differently over "
                        "time and the three independent rounds no longer share one denominator. "
                        "List the packs explicitly (e.g. p/javascript)"
                    )
                elif text.startswith(("http://", "https://")):
                    errors.append(
                        f"tools.semgrep.configs entry {text!r} fetches rules from an arbitrary "
                        f"URL; only registry packs and paths inside this repo are allowed"
                    )

    # --- analysis -------------------------------------------------------------
    exclude = _get(cfg, "analysis", "exclude")
    if exclude is not None:
        if not isinstance(exclude, list):
            errors.append("analysis.exclude must be a list of paths")
        else:
            for entry in exclude:
                if not isinstance(entry, str) or not entry.strip():
                    errors.append(f"analysis.exclude entry {entry!r} must be a non-empty string")

    # --- agents ---------------------------------------------------------------
    model = _get(cfg, "agents", "model", default="opus")
    if not isinstance(model, str) or not model.strip():
        errors.append("agents.model must be a non-empty string (default: opus)")

    # --- output ---------------------------------------------------------------
    out_dir = _get(cfg, "output", "directory", default="reports/sast")
    if not isinstance(out_dir, str) or not out_dir.strip():
        errors.append("output.directory must be a non-empty string")
    else:
        out_abs = os.path.realpath(os.path.join(base_dir, os.path.expanduser(out_dir)))
        if os.path.isdir(source_abs) and _is_within(out_abs, source_abs):
            # Not an error: the natural layout puts reports inside the repo being analysed.
            # It has to be excluded from the scan, or the second run reads the first run's
            # reports as if they were source and the secret rules fire on the quoted lines.
            warnings.append(
                f"output.directory ({out_dir}) is inside target.source_dir; it must be "
                f"excluded from the scan so a later run does not analyse earlier reports"
            )

    return errors, warnings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate sast.yaml")
    parser.add_argument("--config", default="sast.yaml", help="path to sast.yaml")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    cfg, load_err = _load_yaml(args.config)
    if load_err:
        result = {"valid": False, "errors": [load_err], "warnings": []}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"ERROR: {load_err}", file=sys.stderr)
        return 2

    errors, warnings = validate(cfg, base_dir=os.path.dirname(os.path.abspath(args.config)) or ".")
    valid = not errors
    result = {
        "valid": valid,
        "config": args.config,
        "errors": errors,
        "warnings": warnings,
        "forced_excludes": list(FORCED_EXCLUDES),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Config: {args.config}")
        print(f"Result: {'VALID' if valid else 'INVALID'}")
        for e in errors:
            print(f"  [ERROR] {e}")
        for w in warnings:
            print(f"  [WARN]  {w}")
        print(f"  Always excluded: {', '.join(FORCED_EXCLUDES)}")
        if valid and not warnings:
            print("  All checks passed.")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
