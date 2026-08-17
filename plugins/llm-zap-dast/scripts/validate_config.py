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

# Authentication method vocabulary. 'auto' means the LLM resolves the concrete method from
# the target before zap_auth.py is called; it is a valid config value but never reaches the
# script.
AUTH_METHODS = {"auto", "browser", "form", "json", "basic", "script"}
VERIFY_METHODS = {"auto", "url", "indicator"}
SESSION_METHODS = {"auto", "cookie", "header", "script"}


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


def _norm_path(p) -> str | None:
    """Normalise a config path/URL to a leading-slash path with no trailing slash."""
    if not p:
        return None
    p = str(p)
    if "://" in p:
        try:
            p = urlparse(p).path or "/"
        except Exception:  # noqa: BLE001
            pass
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def _covered_by_excludes(path, exclude_paths) -> str | None:
    """Return the exclude entry that swallows `path`, or None. Conservative prefix match."""
    np = _norm_path(path)
    if np is None:
        return None
    for e in exclude_paths or []:
        ne = _norm_path(e)
        if ne is None:
            continue
        if ne == "/" or np == ne or np.startswith(ne + "/"):
            return e
    return None


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
    # allow_production must be a REAL bool. bool("false") is True in Python, so a quoted
    # `allow_production: "false"` would silently disable EVERY production guard below
    # (production/keyless/active-scan/destructive/availability) — a fail-open. Reject any
    # non-bool so the mistake surfaces instead of loosening the safety posture.
    raw_allow_production = _get(cfg, "safety", "allow_production", default=False)
    if raw_allow_production is not None and not isinstance(raw_allow_production, bool):
        errors.append(
            f"safety.allow_production must be a boolean (true/false), got "
            f"{raw_allow_production!r}. A quoted string like \"false\" is truthy and would "
            f"disable the production guards."
        )
    allow_production = raw_allow_production is True
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

    # --- Destructive testing (target-internal) -------------------------------
    # scan.destructive lifts the "detection-only / no state change" rule for probes against
    # the TARGET APP ITSELF (deletes, password changes, real Mass Assignment, DELETE on real
    # resources). It rides the same local/disposable rail as Active Scan: default ON, but
    # refused on a non-local target unless allow_production is set. This keeps the structural
    # refusal of production harm intact. It does NOT lift the sandbox-escape ban (8C: external
    # mail/billing/registration, SSRF to real infra, open redirect) — and note allowed_hosts
    # does NOT bound those: SSRF fires from the server side and open-redirect from the victim
    # browser, so their destinations ride in the payload, not the scanner's own target list.
    # 8C is a prompt-layer discipline, not something validate_config can enforce. Destructive
    # also does not lift the availability/DoS rule (see scan.availability_impact).
    destructive = bool(_get(cfg, "scan", "destructive", default=True))
    if destructive:
        if base_host and not _is_local(base_host) and not allow_production:
            errors.append(
                "scan.destructive is true against a non-local target while "
                "safety.allow_production is false. Destructive testing is only for "
                "disposable/local targets. Refusing."
            )
        if non_local_allowed and not allow_production:
            errors.append(
                "scan.destructive is true but non-local hosts are in allowed_hosts "
                f"{non_local_allowed} while safety.allow_production is false. Refusing."
            )

    # --- Availability-impacting tests (DoS-equivalent) -----------------------
    # A SEPARATE axis from destructive: heavy time-based probes, rate floods, load. Default
    # OFF even on disposable targets, because knocking the app over mid-run aborts the scan
    # and loses coverage. Turning it on against a non-local target without allow_production is
    # refused for the same reason as the other gates.
    availability_impact = bool(_get(cfg, "scan", "availability_impact", default=False))
    if availability_impact:
        if base_host and not _is_local(base_host) and not allow_production:
            errors.append(
                "scan.availability_impact is true against a non-local target while "
                "safety.allow_production is false. Refusing."
            )
        # ZAP's attack scope is allowed_hosts, so a local base_url with a non-local host in
        # allowed_hosts would still send DoS-equivalent traffic there. Mirror the destructive
        # gate (safety-policy.md promises both are refused for non-local hosts).
        if non_local_allowed and not allow_production:
            errors.append(
                "scan.availability_impact is true but non-local hosts are in allowed_hosts "
                f"{non_local_allowed} while safety.allow_production is false. Refusing."
            )

    # --- authentication coherence -------------------------------------------
    auth = _get(cfg, "authentication", default={}) or {}
    if isinstance(auth, dict) and bool(auth.get("enabled", False)):
        # Credentials must be environment-variable NAMES, never literal values in the file.
        # This applies to the legacy single-account form (top-level username/password) and to
        # every entry of the multi-account authentication.users list.
        for literal_key in ("username", "password"):
            if literal_key in auth:
                errors.append(
                    f"authentication.{literal_key} is set with a literal value. Never put "
                    f"credentials in the config; use authentication.{literal_key}_env with an "
                    f"environment variable NAME instead."
                )

        # Accounts: `authentication.users` is a list (2 same-role for horizontal IDOR/privesc,
        # 2 different roles for vertical, 3 = both). The legacy single account
        # (top-level username_env/password_env) is treated as a one-element list.
        users = auth.get("users")
        if users is not None:
            # A single-account block left alongside a users list is silently ignored (users
            # wins). Warn so a stale/forgotten users list is not mistaken for the single form.
            if auth.get("username_env") or auth.get("password_env"):
                warnings.append(
                    "authentication.users is set, so the top-level username_env/password_env "
                    "are ignored. Remove them to avoid confusion."
                )
            if not isinstance(users, list) or not users:
                errors.append(
                    "authentication.users must be a non-empty list of accounts "
                    "(each with username_env and password_env)"
                )
                users = []
            seen_labels: set[str] = set()
            seen_cred_pairs: dict[tuple[str, str], int] = {}
            for i, u in enumerate(users):
                where = f"authentication.users[{i}]"
                if not isinstance(u, dict):
                    errors.append(f"{where} must be a mapping")
                    continue
                for literal_key in ("username", "password"):
                    if literal_key in u:
                        errors.append(
                            f"{where}.{literal_key} is a literal value. Use {literal_key}_env "
                            f"with an environment variable NAME instead."
                        )
                for field in ("username_env", "password_env"):
                    if not u.get(field):
                        errors.append(
                            f"{where}.{field} (an environment variable NAME) is required"
                        )
                label = u.get("label")
                if label is not None:
                    ls = str(label)
                    if ls in seen_labels:
                        errors.append(
                            f"{where}.label {ls!r} is duplicated; account labels must be unique"
                        )
                    seen_labels.add(ls)
                # Two accounts pointing at the same credential env vars resolve to the SAME
                # identity, which silently neuters horizontal IDOR/privesc (compare alice to
                # alice = false negative). That defeats the whole point of multiple accounts.
                ue, pe = u.get("username_env"), u.get("password_env")
                if ue and pe:
                    pair = (str(ue), str(pe))
                    if pair in seen_cred_pairs:
                        errors.append(
                            f"{where} uses the same username_env/password_env as "
                            f"authentication.users[{seen_cred_pairs[pair]}]; accounts must "
                            f"resolve to DISTINCT identities (or they cannot test IDOR/privesc)"
                        )
                    else:
                        seen_cred_pairs[pair] = i
        else:
            # Legacy single-account form.
            for field in ("username_env", "password_env"):
                if not auth.get(field):
                    errors.append(
                        f"authentication.enabled is true but authentication.{field} "
                        f"(an environment variable NAME) is not set "
                        f"(or provide an authentication.users list)"
                    )

        if not auth.get("login_url"):
            warnings.append("authentication.enabled is true but login_url is not set")

        # Method vocabularies. 'auto' is valid config; the LLM resolves it before the script.
        method = auth.get("method")
        if method is not None and str(method).lower() not in AUTH_METHODS:
            errors.append(
                f"authentication.method {method!r} is not one of {sorted(AUTH_METHODS)}"
            )
        vmethod = _get(auth, "verification", "method")
        if vmethod is not None and str(vmethod).lower() not in VERIFY_METHODS:
            errors.append(
                f"authentication.verification.method {vmethod!r} is not one of "
                f"{sorted(VERIFY_METHODS)}"
            )
        smethod = _get(auth, "session_management", "method")
        if smethod is not None and str(smethod).lower() not in SESSION_METHODS:
            errors.append(
                f"authentication.session_management.method {smethod!r} is not one of "
                f"{sorted(SESSION_METHODS)}"
            )

        # Lockout avoidance: a positive attempt cap.
        max_attempts = auth.get("max_attempts")
        if max_attempts is not None and (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or max_attempts < 1
        ):
            errors.append("authentication.max_attempts must be a positive integer")

        # Auth-critical URLs must not be swallowed by exclude.paths (auth/re-auth would break).
        excl = _get(cfg, "exclude", "paths", default=[]) or []
        excl = excl if isinstance(excl, list) else []
        for label, val in (
            ("authentication.login_url", auth.get("login_url")),
            ("authentication.verification.verification_url",
             _get(auth, "verification", "verification_url")),
        ):
            hit = _covered_by_excludes(val, excl) if val else None
            if hit is not None:
                errors.append(
                    f"{label} ({val!r}) is covered by exclude.paths entry {hit!r}; "
                    f"authentication needs to reach it. Remove the overlap."
                )

        # Authenticated Active Scan is an ADDITIONAL gate on top of scan.active_scan.
        # Default ON (matches scan.active_scan); it still needs both gates plus the step-5
        # gate conditions (which are not an interactive confirmation).
        if bool(auth.get("active_scan", True)) and not active_scan:
            warnings.append(
                "authentication.active_scan is true but scan.active_scan is false; "
                "authenticated Active Scan requires BOTH gates true (and the step-5 gate "
                "conditions)."
            )

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
