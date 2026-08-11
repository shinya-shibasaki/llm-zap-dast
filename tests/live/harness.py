"""Shared plumbing for the live suite: talking to a real ZAP and starting a target app.

Kept in one place so the token-auth and cookie-session suites cannot drift apart in how
they configure ZAP — the two are only useful as a pair, because most of the defects these
tests pin were invisible in one shape and fatal in the other.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts"))

# Imported here, and re-exported, so the tests get it without depending on the order in
# which their own imports run the path insert above.
import zap_auth  # noqa: E402

ZAP_API = os.environ.get("DAST_LIVE_ZAP", "").rstrip("/")

requires_live_zap = pytest.mark.skipif(
    not ZAP_API,
    reason="live ZAP not configured; set DAST_LIVE_ZAP=http://127.0.0.1:8090 to run",
)


def get_json(url, timeout=10):
    """GET and parse JSON. ZAP reports refusals as HTTP 400 with a JSON body
    ({"code": "illegal_parameter", ...}) — that body IS the answer some of these tests are
    asserting on, so it must be returned rather than raised."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return json.loads(body)
        except ValueError:
            return {"http_status": exc.code, "body": body[:200]}


def zap(component, kind, action, **params):
    url = f"{ZAP_API}/JSON/{component}/{kind}/{action}/?{urllib.parse.urlencode(params)}"
    try:
        return get_json(url, timeout=30)
    except OSError as exc:  # connection refused / reset
        pytest.fail(
            f"ZAP at {ZAP_API} is unreachable ({exc}). If it was up a moment ago, the "
            "insights add-on most likely shut it down in response to the storm these tests "
            "provoke — restart it with `-config insights.exitAuto=false` (see the README)."
        )


def cfg_params(**kw):
    """ZAP's *ConfigParams: k=v pairs whose VALUES are individually URL-encoded."""
    return "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in kw.items())


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_target(script, *extra):
    """Start tests/live/<script> on a free port; yield (base_url, counts, reset)."""
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, script), str(port), *[str(a) for a in extra]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            get_json(f"{base}/__counts", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail(f"{script} did not come up on {base}")

    try:
        yield base, lambda: get_json(f"{base}/__counts"), lambda: get_json(f"{base}/__reset")
    finally:
        proc.kill()
        proc.wait(timeout=10)


def drive(base, paths):
    """Send a few requests through ZAP (forced user applies) and let the counters settle."""
    for p in paths:
        zap("core", "action", "accessUrl", url=base + p, followRedirects="false")
    time.sleep(0.5)


class Args:
    """Stand-in for the argparse namespace the cmd_* functions take."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
