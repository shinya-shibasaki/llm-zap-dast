"""Live regression tests for zap_auth.py against a REAL ZAP. Skipped by default.

The offline suite can only assert what the wrapper SENDS. These pin the ZAP behaviours the
wrapper exists to work around — every one of them was found by measurement, not by reading
the API docs, and every one of them fails silently in production:

  * POLL_URL needs all five poll parameters (dropping an empty one broke a whole run);
  * an empty context include list makes authentication inert with no error at all;
  * a per-response strategy with no logged-out indicator re-authenticates on every request;
  * a healthy configuration logs in exactly once.

Run them when touching authentication, and after a ZAP upgrade:

    ZAP_HOME=$(mktemp -d)
    zap.sh -daemon -host 127.0.0.1 -port 8090 -dir "$ZAP_HOME" \
           -config api.disablekey=true -config insights.exitAuto=false &
    DAST_LIVE_ZAP=http://127.0.0.1:8090 python -m pytest tests/live -v

`insights.exitAuto=false` is REQUIRED: one of these tests provokes a real re-authentication
storm, and the insights add-on responds by shutting the daemon down mid-suite (measured —
`insight.auth.failure : 83`, and every later test then fails with a connection error). That
switch belongs in this harness and nowhere else; in a real run the shutdown is a true signal
and turning it off would only hide a broken scan.

The target app is started by the tests themselves (tests/live/target.py) on a free port.
Contexts and users are named with a unique prefix and removed in teardown, so running this
against a ZAP you are also using for something else does not disturb it.
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

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts"))

import zap_auth  # noqa: E402

ZAP_API = os.environ.get("DAST_LIVE_ZAP", "").rstrip("/")

pytestmark = pytest.mark.skipif(
    not ZAP_API,
    reason="live ZAP not configured; set DAST_LIVE_ZAP=http://127.0.0.1:8090 to run",
)


# --- helpers -----------------------------------------------------------------
def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get_json(url, timeout=10):
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
        return _get_json(url, timeout=30)
    except OSError as exc:  # connection refused / reset
        pytest.fail(
            f"ZAP at {ZAP_API} is unreachable ({exc}). If it was up a moment ago, the "
            "insights add-on most likely shut it down in response to the storm these tests "
            "provoke — restart it with `-config insights.exitAuto=false` (see the module "
            "docstring)."
        )


def cfg_params(**kw):
    """ZAP's *ConfigParams: k=v pairs whose VALUES are individually URL-encoded."""
    return "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in kw.items())


@pytest.fixture(scope="module")
def target():
    """Start tests/live/target.py on a free port; yield (base_url, counts_fn)."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "target.py"),
         str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            _get_json(f"{base}/__counts", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail(f"target app did not come up on {base}")

    def counts():
        return _get_json(f"{base}/__counts")

    def reset():
        _get_json(f"{base}/__reset")

    try:
        yield base, counts, reset
    finally:
        proc.kill()
        proc.wait(timeout=10)


@pytest.fixture
def context(target):
    """A uniquely named ZAP context, torn down afterwards whatever the test did."""
    base, _counts, _reset = target
    name = f"dast-live-{os.getpid()}-{int(time.time() * 1000) % 100000}"
    created = zap("context", "action", "newContext", contextName=name)
    cid = created["contextId"]
    state = {"name": name, "id": cid, "user_id": None, "base": base,
             "cfg": {"target": {"base_url": base}, "zap": {"api_url": ZAP_API}}}
    try:
        yield state
    finally:
        zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="false")
        if state["user_id"] is not None:
            zap("users", "action", "removeUser", contextId=cid, userId=state["user_id"])
        zap("context", "action", "removeContext", contextName=name)


def configure_auth(state, *, include=True, strategy="POLL_URL",
                   logged_in="lastLoginTime", logged_out=None):
    """The step-2.5 sequence, in the order references/authentication.md prescribes."""
    base, name, cid = state["base"], state["name"], state["id"]
    if include:
        zap("context", "action", "includeInContext", contextName=name,
            regex=r"http://127\.0\.0\.1:\d+/.*")
    zap("authentication", "action", "setAuthenticationMethod",
        contextId=cid, authMethodName="jsonBasedAuthentication",
        authMethodConfigParams=cfg_params(
            loginUrl=f"{base}/rest/user/login",
            loginRequestData='{"email":"{%username%}","password":"{%password%}"}'))
    zap("sessionManagement", "action", "setSessionManagementMethod",
        contextId=cid, methodName="headerBasedSessionManagement",
        methodConfigParams=cfg_params(
            headers="Authorization: Bearer {%json:authentication.token%}"))

    class Args:
        pass
    args = Args()
    args.context, args.context_id, args.strategy = name, cid, strategy
    args.poll_url = f"{base}/rest/user/auth-details" if strategy == "POLL_URL" else None
    args.poll_data = args.poll_headers = None
    args.poll_frequency = args.poll_frequency_units = None
    args.logged_in_indicator, args.logged_out_indicator = logged_in, logged_out
    verification = zap_auth.cmd_configure_verification(state["cfg"], args)

    uid = zap("users", "action", "newUser", contextId=cid, name=f"u-{name}")["userId"]
    state["user_id"] = uid
    zap("users", "action", "setAuthenticationCredentials", contextId=cid, userId=uid,
        authCredentialsConfigParams=cfg_params(username="jim@test.local", password="pw"))
    zap("users", "action", "setUserEnabled", contextId=cid, userId=uid, enabled="true")
    zap("forcedUser", "action", "setForcedUser", contextId=cid, userId=uid)
    zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="true")
    return verification


def drive(base, paths):
    for p in paths:
        zap("core", "action", "accessUrl", url=base + p, followRedirects="false")
    time.sleep(0.5)


# --- the measured behaviours -------------------------------------------------
def test_poll_url_needs_all_five_parameters(context):
    """The original defect: dropping an empty pollData made ZAP reject the whole call."""
    verification = configure_auth(context, strategy="POLL_URL")
    assert verification["applied"] is True, verification
    read = verification["readback"]
    assert read["checkingStrategy"] == "POLL_URL"
    assert read["pollData"] == "" and read["pollHeaders"] == ""
    assert read["loggedInPattern"] == "lastLoginTime"

    # ...and the five really are all mandatory: sending only pollUrl is refused.
    bare = zap("context", "action", "setContextCheckingStrategy",
               contextName=context["name"], checkingStrategy="POLL_URL",
               pollUrl=f"{context['base']}/rest/user/auth-details")
    assert bare.get("code") == "illegal_parameter", bare


def test_authentication_is_inert_without_an_include_regex(context, target):
    """No include list -> no login attempt, request goes out anonymous, and NO error."""
    base, counts, reset = target
    reset()
    configure_auth(context, include=False)
    drive(base, ["/rest/products"])
    c = counts()
    assert c["login"] == 0, "credentials were used despite an empty context scope"
    assert c["served_401"] == 1, "the request was not sent anonymously"

    # The loud half of the same defect.
    spider = zap("spider", "action", "scanAsUser",
                 contextId=context["id"], userId=context["user_id"], url=base + "/")
    assert spider.get("code") == "url_not_in_context", spider


def test_healthy_configuration_logs_in_exactly_once(context, target):
    base, counts, reset = target
    reset()
    configure_auth(context, strategy="POLL_URL", logged_in="lastLoginTime")
    drive(base, ["/rest/products", "/", "/page2", "/rest/boom", "/rest/products"])
    assert counts()["login"] == 1, "a healthy config must not re-authenticate"
    assert counts()["served_401"] == 0


def test_per_response_checking_without_logged_out_indicator_storms(context, target):
    """loggedIn set + loggedOut unset + EACH_* is a guaranteed re-authentication storm:
    every response lacking the marker is judged logged-out."""
    base, counts, reset = target
    reset()
    configure_auth(context, strategy="EACH_RESP", logged_in="lastLoginTime")
    paths = ["/rest/products", "/", "/page2", "/rest/boom", "/rest/products"]
    drive(base, paths)
    assert counts()["login"] > 1, "expected re-authentication on every non-matching response"


def test_canary_separates_a_healthy_config_from_a_storming_one(context, target):
    """The detection signal: ZAP's own verdict counters, read around a small burst."""
    base, counts, reset = target
    reset()
    configure_auth(context, strategy="EACH_RESP", logged_in="lastLoginTime")

    class Args:
        pass
    args = Args()
    args.context = context["name"]
    # Heterogeneous on purpose: one shape cannot tell the two configurations apart.
    args.canary_url = [base + "/", base + "/rest/products", base + "/rest/boom"]
    verdict = zap_auth.cmd_verify_canary(context["cfg"], args)
    assert verdict["ok"] is False, verdict
    assert any("storm" in p for p in verdict["problems"]), verdict

    # And the authenticated scanners refuse on their own reading of the counters.
    class ScanArgs:
        pass
    scan = ScanArgs()
    scan.context_id, scan.user_id, scan.url = context["id"], context["user_id"], None
    with pytest.raises(zap_auth.AuthUsageError, match="refused"):
        zap_auth.cmd_spider_as_user(context["cfg"], scan)


def test_setting_the_auth_method_resets_the_verification_config(context):
    """Why the order matters: re-applying the auth method silently discards verification."""
    assert configure_auth(context, strategy="POLL_URL")["applied"] is True
    zap("authentication", "action", "setAuthenticationMethod",
        contextId=context["id"], authMethodName="jsonBasedAuthentication",
        authMethodConfigParams=cfg_params(
            loginUrl=f"{context['base']}/rest/user/login", loginRequestData="{}"))
    after = zap("context", "view", "context", contextName=context["name"])["context"]
    assert after["checkingStrategy"] == "EACH_RESP", after
    assert after["loggedInPattern"] == "", after
