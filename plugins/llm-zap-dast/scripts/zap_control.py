#!/usr/bin/env python3
"""Optionally start / stop a local OWASP ZAP daemon for an llm-zap-dast run.

The plugin still prefers a ZAP the user already started. When ZAP is NOT reachable and
`zap.autostart` is enabled (default true), the skill uses this script to launch a local
ZAP daemon, then shuts down ONLY the daemon it started. If ZAP cannot be launched
(binary/Docker not found, or start fails), the caller falls back to manual instructions
(fail-soft).

Safety: an auto-started ZAP is always bound to 127.0.0.1 (loopback only) — never
0.0.0.0. Keyless operation stays local-only (see validate_config.py). A user-provided
`zap.start_command` that binds 0.0.0.0 is refused.

Usage:
    python3 zap_control.py --config dast.yaml detect   [--json]
    python3 zap_control.py --config dast.yaml status    [--json]
    python3 zap_control.py --config dast.yaml start      [--json] [--timeout 90]
    python3 zap_control.py --config dast.yaml shutdown   [--json]

Dependencies: PyYAML (config); requests optional (falls back to urllib).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse

# Binaries we know how to launch, in preference order.
ZAP_BINARIES = ("zap.sh", "zap", "owasp-zap", "zaproxy", "ZAP.sh")


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


def _api_port(cfg):
    api_url = _get(cfg, "zap", "api_url", default="http://localhost:8080")
    parsed = urlparse(api_url)
    return parsed.port or (443 if parsed.scheme == "https" else 8080)


def _api_key(cfg):
    env_name = _get(cfg, "zap", "api_key_env")
    if env_name:
        return os.environ.get(str(env_name), "").strip()
    return ""


def _http_get(url, timeout=5):
    try:
        import requests  # type: ignore
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            return True, r.status_code
        except Exception:  # noqa: BLE001
            return False, None
    except ImportError:
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
                return True, r.status
        except Exception:  # noqa: BLE001
            return False, None


def _version_url(cfg):
    api_url = _get(cfg, "zap", "api_url", default="http://localhost:8080").rstrip("/")
    url = api_url + "/JSON/core/view/version/"
    key = _api_key(cfg)
    if key:
        url += "?apikey=" + key
    return url


def is_reachable(cfg, timeout=5):
    ok, _ = _http_get(_version_url(cfg), timeout=timeout)
    return ok


def build_start_command(cfg):
    """Return (argv, method, error). argv is None when ZAP cannot be launched."""
    port = _api_port(cfg)
    key = _api_key(cfg)

    # 1) explicit user override
    override = _get(cfg, "zap", "start_command")
    if override:
        argv = shlex.split(override) if isinstance(override, str) else list(override)
        joined = " ".join(argv)
        if "0.0.0.0" in joined:
            return None, "command", (
                "zap.start_command binds 0.0.0.0 (all interfaces); refused. Bind to "
                "127.0.0.1."
            )
        return argv, "command", None

    # 2) a known binary on PATH
    for name in ZAP_BINARIES:
        found = shutil.which(name)
        if found:
            argv = [found, "-daemon", "-host", "127.0.0.1", "-port", str(port)]
            argv += ["-config", ("api.key=" + key) if key else "api.disablekey=true"]
            return argv, "binary", None

    # 3) explicit Docker image
    docker_image = _get(cfg, "zap", "docker")
    if docker_image and shutil.which("docker"):
        image = docker_image if isinstance(docker_image, str) else "ghcr.io/zaproxy/zaproxy:stable"
        # Published only to loopback on the host; -host 0.0.0.0 is INSIDE the container.
        argv = [
            "docker", "run", "--rm", "-d",
            "-p", f"127.0.0.1:{port}:{port}",
            image, "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", str(port),
            "-config", ("api.key=" + key) if key else "api.disablekey=true",
        ]
        return argv, "docker", None

    return None, None, (
        "no ZAP binary found on PATH (looked for: " + ", ".join(ZAP_BINARIES) + ") and "
        "no zap.docker image configured. Start ZAP manually, or install it."
    )


def detect(cfg):
    argv, method, error = build_start_command(cfg)
    return {
        "autostart_enabled": bool(_get(cfg, "zap", "autostart", default=True)),
        "launchable": argv is not None,
        "method": method,
        "command": argv,
        "error": error,
    }


def wait_ready(cfg, timeout=90):
    url = _version_url(cfg)
    deadline_steps = max(1, int(timeout / 2))
    for _ in range(deadline_steps):
        ok, _status = _http_get(url, timeout=5)
        if ok:
            return True
        time.sleep(2)
    return False


def start(cfg, timeout=90):
    if not bool(_get(cfg, "zap", "autostart", default=True)):
        return {"started": False, "reason": "zap.autostart is disabled; start ZAP manually"}
    if is_reachable(cfg):
        return {"started": False, "reason": "ZAP already reachable; using the existing instance"}

    argv, method, error = build_start_command(cfg)
    if argv is None:
        return {"started": False, "reason": error, "method": None}

    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is built from config, not shell
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"started": False, "reason": f"failed to launch ZAP: {exc}", "method": method}

    ready = wait_ready(cfg, timeout=timeout)
    if not ready:
        return {
            "started": False,
            "reason": f"launched ZAP ({method}) but it did not become ready within "
                      f"{timeout}s",
            "method": method,
            "pid": proc.pid,
        }
    return {
        "started": True,
        "method": method,
        "pid": proc.pid,
        "host": "127.0.0.1",
        "port": _api_port(cfg),
        "note": "started by the skill; shut down only this instance at the end of the run",
    }


def shutdown(cfg):
    if not is_reachable(cfg):
        return {"shutdown": False, "reason": "ZAP not reachable; nothing to shut down"}
    api_url = _get(cfg, "zap", "api_url", default="http://localhost:8080").rstrip("/")
    url = api_url + "/JSON/core/action/shutdown/"
    key = _api_key(cfg)
    if key:
        url += "?apikey=" + key
    ok, _ = _http_get(url, timeout=10)
    return {"shutdown": bool(ok), "reason": "" if ok else "shutdown API call failed"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Control a local ZAP daemon")
    parser.add_argument("action", choices=["detect", "status", "start", "shutdown"])
    parser.add_argument("--config", default="dast.yaml")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args(argv)

    cfg, load_err = _load_cfg(args.config)
    if load_err:
        out = {"error": load_err}
        print(json.dumps(out, indent=2) if args.json else f"ERROR: {load_err}",
              file=sys.stderr)
        return 2

    if args.action == "detect":
        result = detect(cfg)
    elif args.action == "status":
        result = {"reachable": is_reachable(cfg)}
    elif args.action == "start":
        result = start(cfg, timeout=args.timeout)
    else:
        result = shutdown(cfg)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for k, v in result.items():
            print(f"{k}: {v}")

    # Exit non-zero when an intended action did not achieve its goal, so the skill reacts.
    if args.action == "start" and not result.get("started") and \
            "already reachable" not in str(result.get("reason", "")):
        return 1
    if args.action == "shutdown" and not result.get("shutdown") and \
            "nothing to shut down" not in str(result.get("reason", "")):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
