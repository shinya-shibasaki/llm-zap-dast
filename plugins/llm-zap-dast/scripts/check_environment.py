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

# Firefox is a PREREQUISITE, not an option: ZAP launches it through Selenium for the Ajax
# Spider, the DOM XSS active scan rule, Browser Based Authentication and the client add-on.
# Playwright's Chromium does NOT substitute — ZAP starts a browser from its own process and
# never looks at ~/.cache/ms-playwright. Checked unconditionally (not gated on
# scan.ajax_spider) because the DOM XSS rule and BBA need it regardless of that setting.
FIREFOX_BINARIES = ("firefox", "firefox-esr")
FIREFOX_INSTALL_HINT = (
    "wget -O /tmp/firefox.tar.xz "
    "'https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US' && "
    "sudo tar -xJf /tmp/firefox.tar.xz -C /opt && "
    "sudo ln -sf /opt/firefox/firefox /usr/local/bin/firefox"
)


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


# Playwright (the PYTHON package — not the Node package, not the Playwright MCP) drives
# steps 4 and 6. Detection probes SEVERAL interpreters on purpose: the README installs it
# with `pip install --user`, which lands in ~/.local/lib/pythonX.Y/site-packages, and a
# target project's .venv created without --system-site-packages deliberately hides that
# directory. Probing only one "python" therefore yields a FALSE NEGATIVE in most target
# repos — and because step 4 is fail-soft, the wrong answer is silently dropped instead of
# challenged. Report WHICH interpreter can import it so step 4 uses that one and stops
# guessing.
PLAYWRIGHT_PROBE = (
    "import playwright, importlib.metadata as m; print(m.version('playwright'))"
)


def _browsers_dir():
    return os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or os.path.expanduser(
        "~/.cache/ms-playwright")


def candidate_interpreters():
    """Interpreters to probe, in order, de-duplicated by INVOCATION path.

    Deliberately NOT de-duplicated by os.path.realpath: `.venv/bin/python` is a symlink to
    the very system python it must be distinguished from, and the two have different
    sys.path. Collapsing them by real path would erase exactly the distinction this check
    exists to make.
    """
    cands = [
        sys.executable,
        shutil.which("python3"),
        shutil.which("python"),
        os.path.join(".venv", "bin", "python"),
        os.path.join("venv", "bin", "python"),
    ]
    seen, out = set(), []
    for c in cands:
        if not c or not os.path.exists(c):
            continue
        key = os.path.abspath(c)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _probe_playwright(interpreter):
    """Return the playwright version importable by `interpreter`, or None."""
    try:
        r = subprocess.run([interpreter, "-c", PLAYWRIGHT_PROBE],
                           capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001
        return None
    return r.stdout.strip() or "unknown" if r.returncode == 0 else None


def detect_playwright():
    """Return (status, detail) for Playwright. Never raises.

    Package presence and browser presence are separate facts: `pip install playwright`
    does not download browsers, so both are reported.
    """
    probed = candidate_interpreters()
    found = next(((i, v) for i, v in ((i, _probe_playwright(i)) for i in probed) if v), None)
    browsers = _browsers_dir()
    has_browsers = os.path.isdir(browsers) and any(
        n.startswith(("chromium", "chrome", "firefox", "webkit"))
        for n in os.listdir(browsers)
    ) if os.path.isdir(browsers) else False

    if not found:
        return "warn", (
            f"Playwright (Python package) not importable by any of: {probed}. Steps 4 and 6 "
            f"lose browser-driven exploration and are skipped (fail-soft). NOTE: a `pip "
            f"install --user` lands in ~/.local and is INVISIBLE to a project .venv, so "
            f"install it into the interpreter the run will actually use. Install: "
            f"python3 -m pip install --user --break-system-packages playwright && "
            f"python3 -m playwright install chromium"
        )
    interpreter, version = found
    if not has_browsers:
        return "warn", (
            f"playwright {version} importable via {interpreter}, but no browsers found in "
            f"{browsers}. The package alone cannot launch a browser. Run: "
            f"{interpreter} -m playwright install chromium"
        )
    return "ok", (
        f"playwright {version} via {interpreter}; browsers in {browsers}. "
        f"Use THIS interpreter for steps 4/6 — do not assume a bare 'python3' has it."
    )


def detect_firefox():
    """Return (status, detail) for the Firefox prerequisite. Never raises.

    Status is 'warn' (not 'fail') when missing: a missing browser is a CAPABILITY gap, and
    safety-policy.md reserves stopping the run for SAFETY failures. Reporting it here turns
    a step-3 Selenium stack trace — and a silently skipped DOM XSS rule in step 5 — into a
    known, recordable condition at step 0.
    """
    found = next((p for p in (shutil.which(n) for n in FIREFOX_BINARIES) if p), None)
    if not found:
        return "warn", (
            "Firefox not found on PATH. ZAP needs it for the Ajax Spider, the DOM XSS active "
            "scan rule, Browser Based Authentication and the client add-on; Playwright's "
            "Chromium does not substitute. The Ajax Spider fails loudly, but the DOM XSS rule "
            "is skipped SILENTLY while Active Scan still reports success — record that gap in "
            "the report. Install: " + FIREFOX_INSTALL_HINT
        )
    try:
        r = subprocess.run([found, "--version"], capture_output=True, text=True, timeout=15)
        version = (r.stdout or r.stderr).strip() or "version unknown"
    except Exception as exc:  # noqa: BLE001
        version = f"version unknown ({exc})"
    return "ok", f"{found} — {version} (geckodriver ships with ZAP's webdriverlinux add-on)"


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
        # When ZAP is not reachable, report whether the skill can auto-start it.
        if not ok:
            try:
                import zap_control  # sibling script
                det = zap_control.detect(cfg or {})
                if not det["autostart_enabled"]:
                    checks.append(_check("zap_autostart", "skip",
                                         "zap.autostart disabled; start ZAP manually"))
                elif det["launchable"]:
                    checks.append(_check(
                        "zap_autostart", "ok",
                        f"can auto-start ZAP ({det['method']}); the skill will launch it "
                        f"on 127.0.0.1"))
                else:
                    checks.append(_check("zap_autostart", "warn",
                                         det.get("error") or "cannot auto-start ZAP"))
            except Exception as exc:  # noqa: BLE001
                checks.append(_check("zap_autostart", "unknown",
                                     f"autostart detection failed: {exc}"))
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

    # Firefox (prerequisite for every ZAP-driven browser feature)
    status, detail = detect_firefox()
    checks.append(_check("browser_firefox", status, detail))

    # Playwright (steps 4/6). Reports which interpreter can import it.
    status, detail = detect_playwright()
    checks.append(_check("playwright", status, detail))

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
