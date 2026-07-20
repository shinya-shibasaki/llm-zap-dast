#!/usr/bin/env python3
"""Check the runtime environment for an llm-zap-dast run.

Informational primary evidence for Step 0. Connectivity failures are reported (fail-soft
downstream), not raised. One security-relevant check is active: detecting a ZAP that is
bound to all interfaces (0.0.0.0 / ::) even when the config string says localhost.

Usage:
    python3 check_environment.py [--config dast.yaml] [--json]

Dependencies: PyYAML (config), requests (optional; falls back to urllib for HTTP checks).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

MIN_PY = (3, 8)


def _load_cfg(path):
    try:
        import yaml
    except ImportError:
        return None, "PyYAML not installed"
    if not os.path.isfile(path):
        return None, f"config not found: {path}"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}, None
    except Exception as exc:  # noqa: BLE001
        return None, f"YAML parse error: {exc}"


def _get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _http_get(url, timeout=5):
    """Return (ok, status_or_none, detail). Uses requests if present, else urllib."""
    try:
        import requests  # type: ignore
        try:
            resp = requests.get(url, timeout=timeout, verify=False)
            return True, resp.status_code, f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            return False, None, str(exc)
    except ImportError:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
                return True, r.status, f"HTTP {r.status}"
        except Exception as exc:  # noqa: BLE001
            return False, None, str(exc)


def _check(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def _detect_zap_all_interfaces(port):
    """Best-effort: is something listening on 0.0.0.0:<port> or [::]:<port>?

    Returns (status, detail): status in {'ok','warn','unknown'}.
    """
    if not port:
        return "unknown", "ZAP port unknown"
    tool = shutil.which("ss") or shutil.which("netstat")
    if not tool:
        return "unknown", "neither ss nor netstat available to inspect listeners"
    try:
        if tool.endswith("ss"):
            out = subprocess.run([tool, "-ltnH"], capture_output=True, text=True, timeout=5)
        else:
            out = subprocess.run([tool, "-ltn"], capture_output=True, text=True, timeout=5)
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"could not run {tool}: {exc}"
    listens_all = False
    listens_local = False
    for line in out.stdout.splitlines():
        if f":{port}" not in line:
            continue
        # local address column contains the bind address
        if f"0.0.0.0:{port}" in line or f"*:{port}" in line or f":::{port}" in line or f"[::]:{port}" in line:
            listens_all = True
        if f"127.0.0.1:{port}" in line or f"[::1]:{port}" in line:
            listens_local = True
    if listens_all:
        return "warn", (
            f"ZAP port {port} appears bound to ALL interfaces (0.0.0.0/::). Even if the "
            f"config says localhost, ZAP is reachable from the network. Bind ZAP to "
            f"127.0.0.1 (-host 127.0.0.1) or firewall the port."
        )
    if listens_local:
        return "ok", f"ZAP port {port} bound to loopback only"
    return "unknown", f"no listener found on port {port} (ZAP may be remote or not running)"


def run_checks(cfg, config_path):
    checks = []

    # Python version
    ok_py = sys.version_info[:2] >= MIN_PY
    checks.append(_check(
        "python_version",
        "ok" if ok_py else "fail",
        f"{sys.version.split()[0]} (min {'.'.join(map(str, MIN_PY))})",
    ))

    # Git repo
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
        is_git = r.returncode == 0 and r.stdout.strip() == "true"
    except Exception:  # noqa: BLE001
        is_git = os.path.isdir(".git")
    checks.append(_check(
        "git_repo", "ok" if is_git else "warn",
        "inside a git work tree" if is_git else "not a git repository",
    ))

    # Config file
    checks.append(_check(
        "config_file", "ok" if os.path.isfile(config_path) else "warn",
        f"{config_path} {'exists' if os.path.isfile(config_path) else 'missing (defaults will be assumed)'}",
    ))

    base_url = _get(cfg or {}, "target", "base_url")
    zap_api_url = _get(cfg or {}, "zap", "api_url")

    # Target reachability
    if base_url:
        ok, _, detail = _http_get(base_url)
        checks.append(_check("target_reachable", "ok" if ok else "warn",
                             f"{base_url} -> {detail}"))
    else:
        checks.append(_check("target_reachable", "skip", "target.base_url not set"))

    # ZAP reachability (version endpoint)
    if zap_api_url:
        version_url = zap_api_url.rstrip("/") + "/JSON/core/view/version/"
        api_key_env = _get(cfg or {}, "zap", "api_key_env")
        key = os.environ.get(str(api_key_env), "") if api_key_env else ""
        if key:
            version_url += "?apikey=" + key
        ok, _, detail = _http_get(version_url)
        hint = ""
        if not ok:
            hint = (" | WSL note: 'localhost' may not reach a ZAP running on the Windows "
                    "host; try the Windows host IP or run ZAP inside WSL.")
        checks.append(_check("zap_reachable", "ok" if ok else "warn",
                             f"{zap_api_url} -> {detail}{hint}"))
    else:
        checks.append(_check("zap_reachable", "skip", "zap.api_url not set"))

    # Required env var (only when key operation is intended)
    api_key_env = _get(cfg or {}, "zap", "api_key_env")
    if api_key_env:
        present = bool(os.environ.get(str(api_key_env), "").strip())
        checks.append(_check(
            "zap_api_key_env",
            "ok" if present else "warn",
            f"${api_key_env} {'set' if present else 'not set (keyless; local hosts only)'}",
        ))
    else:
        checks.append(_check("zap_api_key_env", "skip", "zap.api_key_env not configured"))

    # Output writable
    out_dir = _get(cfg or {}, "output", "directory", default="reports/dast")
    try:
        os.makedirs(out_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=out_dir, delete=True):
            pass
        checks.append(_check("output_writable", "ok", f"{out_dir} is writable"))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("output_writable", "fail", f"{out_dir}: {exc}"))

    # ZAP bound to all interfaces (security check)
    zap_port = None
    if zap_api_url:
        try:
            zap_port = urlparse(zap_api_url).port or (443 if zap_api_url.startswith("https") else 80)
        except Exception:  # noqa: BLE001
            zap_port = None
    status, detail = _detect_zap_all_interfaces(zap_port)
    checks.append(_check("zap_bind_scope", status, detail))

    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check llm-zap-dast environment")
    parser.add_argument("--config", default="dast.yaml")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    cfg, load_err = _load_cfg(args.config)
    checks = run_checks(cfg or {}, args.config)
    if load_err:
        checks.insert(0, _check("config_load", "warn", load_err))

    has_fail = any(c["status"] == "fail" for c in checks)
    has_security_warn = any(c["name"] == "zap_bind_scope" and c["status"] == "warn" for c in checks)
    result = {
        "ok": not (has_fail or has_security_warn),
        "config": args.config,
        "checks": checks,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Environment check ({args.config}):")
        symbol = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "skip": "skip", "unknown": "?   "}
        for c in checks:
            print(f"  [{symbol.get(c['status'], c['status'])}] {c['name']}: {c['detail']}")
    # Exit 0 always for connectivity (fail-soft); exit 1 only for hard local failures
    # or the security binding warning, so Step 0 can react.
    return 1 if (has_fail or has_security_warn) else 0


if __name__ == "__main__":
    raise SystemExit(main())
