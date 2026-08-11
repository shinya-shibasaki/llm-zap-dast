"""Live regression tests for zap_auth.py against a REAL ZAP, over a TOKEN-auth target.

The offline suite can only assert what the wrapper SENDS. These pin the ZAP behaviours the
wrapper exists to work around — every one of them was found by measurement, not by reading
the API docs, and every one of them fails silently in production:

  * POLL_URL needs all five poll parameters (dropping an empty one broke a whole run);
  * an empty context include list makes authentication inert with no error at all;
  * a per-response strategy with no logged-out indicator re-authenticates on every request;
  * a healthy configuration logs in exactly once.

The session-shaped half of the suite is in test_live_auth_cookie.py; run both. See README.md
for how to start ZAP (`insights.exitAuto=false` is required — one of these tests provokes a
real re-authentication storm and the insights add-on answers it by shutting the daemon down).

The target app is started by the tests themselves (tests/live/target.py) on a free port.
Contexts and users are named with a unique prefix and removed in teardown, so running this
against a ZAP you are also using for something else does not disturb it.
"""
import pytest
from harness import Args, ZAP_API, cfg_params, drive, requires_live_zap, zap, zap_auth

pytestmark = requires_live_zap


def configure_auth(state, base, *, include=True, strategy="POLL_URL",
                   logged_in="lastLoginTime", logged_out=None):
    """The step-2.5 sequence, in the order references/authentication.md prescribes."""
    name, cid = state["name"], state["id"]
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

    verification = zap_auth.cmd_configure_verification(state["cfg"], Args(
        context=name, context_id=cid, strategy=strategy,
        poll_url=f"{base}/rest/user/auth-details" if strategy == "POLL_URL" else None,
        poll_data=None, poll_headers=None, poll_frequency=None, poll_frequency_units=None,
        logged_in_indicator=logged_in, logged_out_indicator=logged_out))

    uid = zap("users", "action", "newUser", contextId=cid, name=f"u-{name}")["userId"]
    state["user_ids"].append(uid)
    state["user_id"] = uid
    zap("users", "action", "setAuthenticationCredentials", contextId=cid, userId=uid,
        authCredentialsConfigParams=cfg_params(username="jim@test.local", password="pw"))
    zap("users", "action", "setUserEnabled", contextId=cid, userId=uid, enabled="true")
    zap("forcedUser", "action", "setForcedUser", contextId=cid, userId=uid)
    zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="true")
    return verification


@pytest.fixture
def context(zap_context, token_target):
    """zap_context plus the config the cmd_* functions read the target/ZAP URLs from."""
    base, _counts, _reset = token_target
    zap_context["base"] = base
    zap_context["cfg"] = {"target": {"base_url": base}, "zap": {"api_url": ZAP_API}}
    return zap_context


# --- the measured behaviours -------------------------------------------------
def test_poll_url_needs_all_five_parameters(context):
    """The original defect: dropping an empty pollData made ZAP reject the whole call."""
    verification = configure_auth(context, context["base"], strategy="POLL_URL")
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


def test_authentication_is_inert_without_an_include_regex(context, token_target):
    """No include list -> no login attempt, request goes out anonymous, and NO error."""
    base, counts, reset = token_target
    reset()
    configure_auth(context, base, include=False)
    drive(base, ["/rest/products"])
    c = counts()
    assert c["login"] == 0, "credentials were used despite an empty context scope"
    assert c["served_401"] == 1, "the request was not sent anonymously"

    # The loud half of the same defect.
    spider = zap("spider", "action", "scanAsUser",
                 contextId=context["id"], userId=context["user_id"], url=base + "/")
    assert spider.get("code") == "url_not_in_context", spider


def test_healthy_configuration_logs_in_exactly_once(context, token_target):
    base, counts, reset = token_target
    reset()
    configure_auth(context, base, strategy="POLL_URL", logged_in="lastLoginTime")
    drive(base, ["/rest/products", "/", "/page2", "/rest/boom", "/rest/products"])
    assert counts()["login"] == 1, "a healthy config must not re-authenticate"
    assert counts()["served_401"] == 0


def test_per_response_checking_without_logged_out_indicator_storms(context, token_target):
    """loggedIn set + loggedOut unset + EACH_* is a guaranteed re-authentication storm:
    every response lacking the marker is judged logged-out."""
    base, counts, reset = token_target
    reset()
    configure_auth(context, base, strategy="EACH_RESP", logged_in="lastLoginTime")
    drive(base, ["/rest/products", "/", "/page2", "/rest/boom", "/rest/products"])
    assert counts()["login"] > 1, "expected re-authentication on every non-matching response"


def test_canary_separates_a_healthy_config_from_a_storming_one(context, token_target):
    """The detection signal: ZAP's own verdict counters, read around a small burst."""
    base, counts, reset = token_target
    reset()
    configure_auth(context, base, strategy="EACH_RESP", logged_in="lastLoginTime")

    verdict = zap_auth.cmd_verify_canary(context["cfg"], Args(
        context=context["name"],
        # Heterogeneous on purpose: one shape cannot tell the two configurations apart.
        canary_url=[base + "/", base + "/rest/products", base + "/rest/boom"]))
    assert verdict["ok"] is False, verdict
    assert any("storm" in p for p in verdict["problems"]), verdict

    # And the authenticated scanners refuse on their own reading of the counters.
    with pytest.raises(zap_auth.AuthUsageError, match="refused"):
        zap_auth.cmd_spider_as_user(context["cfg"], Args(
            context_id=context["id"], user_id=context["user_id"], url=None))


def test_setting_the_auth_method_resets_the_verification_config(context):
    """Why the order matters: re-applying the auth method silently discards verification."""
    assert configure_auth(context, context["base"], strategy="POLL_URL")["applied"] is True
    zap("authentication", "action", "setAuthenticationMethod",
        contextId=context["id"], authMethodName="jsonBasedAuthentication",
        authMethodConfigParams=cfg_params(
            loginUrl=f"{context['base']}/rest/user/login", loginRequestData="{}"))
    after = zap("context", "view", "context", contextName=context["name"])["context"]
    assert after["checkingStrategy"] == "EACH_RESP", after
    assert after["loggedInPattern"] == "", after
