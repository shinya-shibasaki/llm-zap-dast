#!/usr/bin/env python3
"""Validate a dast.yaml config for the llm-zap-dast plugin.

Entry-side (static) safety checks. This is defense-in-depth: the ZAP Context scope is the
runtime boundary, but many unsafe configs can be rejected before anything talks to ZAP.

Usage:
    python3 validate_config.py [--config dast.yaml] [--json]

Exit code 0 = valid (may have warnings), 1 = invalid (has errors), 2 = usage/load error.
Dependency: PyYAML.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


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
    except Exception as exc:  # noqa: BLE001 - surface the parse error verbatim
        return None, f"YAML parse error in {path}: {exc}"
    if not isinstance(data, dict):
        return None, f"Config root must be a mapping, got {type(data).__name__}"
    return data, None


def _host_of(url: str):
    """Return lowercased host of a URL, or None if it is not a valid http(s) URL."""
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return parsed.hostname.lower()


def _is_local(host: str) -> bool:
    if host in LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def validate(cfg: dict) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    # --- required fields -----------------------------------------------------
    base_url = _get(cfg, "target", "base_url")
    allowed_hosts = _get(cfg, "target", "allowed_hosts")
    zap_api_url = _get(cfg, "zap", "api_url")

    if not base_url:
        errors.append("target.base_url is required")
    if not allowed_hosts or not isinstance(allowed_hosts, list):
        errors.append("target.allowed_hosts is required and must be a non-empty list")
        allowed_hosts = allowed_hosts if isinstance(allowed_hosts, list) else []
    if not zap_api_url:
        errors.append("zap.api_url is required")

    allowed_set = {str(h).lower() for h in (allowed_hosts or [])}

    # --- URL format ----------------------------------------------------------
    base_host = _host_of(base_url) if base_url else None
    if base_url and base_host is None:
        errors.append(f"target.base_url is not a valid http(s) URL: {base_url!r}")
    zap_host = _host_of(zap_api_url) if zap_api_url else None
    if zap_api_url and zap_host is None:
        errors.append(f"zap.api_url is not a valid http(s) URL: {zap_api_url!r}")

    # --- base_url host must be allowed ---------------------------------------
    if base_host and allowed_set and base_host not in allowed_set:
        errors.append(
            f"target.base_url host {base_host!r} is not in target.allowed_hosts "
            f"{sorted(allowed_set)}"
        )

    # --- keyless operation must be local -------------------------------------
    api_key_env = _get(cfg, "zap", "api_key_env")
    key_present = bool(api_key_env) and bool(os.environ.get(str(api_key_env), "").strip())
    if not key_present:
        for label, host in (("zap.api_url", zap_host), ("target.base_url", base_host)):
            if host and not _is_local(host):
                errors.append(
                    f"No ZAP API key available (zap.api_key_env unset or its env var "
                    f"empty), but {label} host {host!r} is not local "
                    f"(localhost/127.0.0.1/::1). Keyless operation is refused for "
                    f"non-local hosts."
                )

    # --- production / external-host guard ------------------------------------
    allow_production = bool(_get(cfg, "safety", "allow_production", default=False))
    require_local = bool(_get(cfg, "safety", "require_local_target", default=True))
    non_local_allowed = sorted(h for h in allowed_set if not _is_local(h))
    if not allow_production and require_local and non_local_allowed:
        errors.append(
            f"safety.allow_production is false and safety.require_local_target is true, "
            f"but non-local hosts are in allowed_hosts: {non_local_allowed}"
        )

    # --- ZAP mode must not be ATTACK -----------------------------------------
    zap_mode = _get(cfg, "zap", "mode")
    if zap_mode is not None and str(zap_mode).strip().lower() == "attack":
        errors.append(
            "zap.mode is set to ATTACK. ATTACK mode active-scans new in-scope nodes on "
            "discovery and bypasses the Active Scan gate. Use 'protect' (default)."
        )

    # --- ZAP autostart -------------------------------------------------------
    autostart = _get(cfg, "zap", "autostart", default=True)
    if not isinstance(autostart, bool):
        errors.append("zap.autostart must be a boolean (true/false)")
    start_command = _get(cfg, "zap", "start_command")
    if start_command is not None:
        joined = start_command if isinstance(start_command, str) else " ".join(map(str, start_command))
        if "0.0.0.0" in joined:
            errors.append(
                "zap.start_command binds 0.0.0.0 (all interfaces). An auto-started ZAP "
                "must bind 127.0.0.1. Refusing."
            )

    # --- Active Scan safety --------------------------------------------------
    active_scan = bool(_get(cfg, "scan", "active_scan", default=True))
    if active_scan:
        if not allowed_set:
            errors.append("scan.active_scan is true but target.allowed_hosts is empty")
        if base_host and not _is_local(base_host) and not allow_production:
            errors.append(
                "scan.active_scan is true against a non-local target while "
                "safety.allow_production is false. Refusing."
            )
        if _get(cfg, "exclude", "paths") is None:
            warnings.append(
                "scan.active_scan is true but exclude.paths is not set; confirm no "
                "dangerous URLs need excluding before running Active Scan."
            )

    # --- authentication coherence (v1 does not run auth, but config must match) -
    if bool(_get(cfg, "authentication", "enabled", default=False)):
        for field in ("username_env", "password_env"):
            if not _get(cfg, "authentication", field):
                errors.append(
                    f"authentication.enabled is true but authentication.{field} "
                    f"(an environment variable NAME) is not set"
                )
        if not _get(cfg, "authentication", "login_url"):
            warnings.append("authentication.enabled is true but login_url is not set")

    # --- exclude path form ---------------------------------------------------
    exclude_paths = _get(cfg, "exclude", "paths", default=[]) or []
    if isinstance(exclude_paths, list):
        for p in exclude_paths:
            ps = str(p)
            if "://" in ps:
                errors.append(
                    f"exclude.paths entry {ps!r} looks like an absolute URL; use a "
                    f"path like '/logout', not a full URL"
                )
            elif not ps.startswith("/"):
                warnings.append(
                    f"exclude.paths entry {ps!r} does not start with '/'; expected a "
                    f"path such as '/logout'"
                )
    else:
        errors.append("exclude.paths must be a list of paths")

    return errors, warnings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate dast.yaml")
    parser.add_argument("--config", default="dast.yaml", help="path to dast.yaml")
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

    errors, warnings = validate(cfg)
    valid = not errors
    result = {"valid": valid, "config": args.config, "errors": errors, "warnings": warnings}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Config: {args.config}")
        print(f"Result: {'VALID' if valid else 'INVALID'}")
        for e in errors:
            print(f"  [ERROR] {e}")
        for w in warnings:
            print(f"  [WARN]  {w}")
        if valid and not warnings:
            print("  All checks passed.")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
