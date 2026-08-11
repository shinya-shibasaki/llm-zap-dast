"""Live tests over a COOKIE-SESSION target (Rails/Django/Laravel shape).

Everything the authentication work had been measured against until now was token-shaped
(Juice Shop): a Bearer header, JSON bodies, and a 401 *with a body* for an anonymous
request. A session app answers differently — it REDIRECTS an anonymous request to the login
page, and the difference between a signed-in and a signed-out response often lives in a
response HEADER rather than in the body — and four defects in `test-authentication` only
show up in that shape:

  * the unauthenticated read failing was reported as a differential PASS;
  * only the body was matched, while ZAP matches the header too;
  * the authenticated response was searched for in ZAP's history with a match so loose that
    ZAP's own login traffic could stand in for it;
  * redirects were followed on the unauthenticated side only, so the two sides compared
    different pages.

The first is a false pass. The other three make a correctly authenticated session
unverifiable, and since an unverified run now STOPS rather than degrading to anonymous, a
session app was simply not diagnosable.

Run with the token suite; see README.md.
"""
import pytest
from harness import Args, ZAP_API, cfg_params, drive, requires_live_zap, zap, zap_auth

pytestmark = requires_live_zap


@pytest.fixture
def context(zap_context, cookie_target):
    base, _counts, _reset = cookie_target
    zap_context["base"] = base
    zap_context["cfg"] = {"target": {"base_url": base}, "zap": {"api_url": ZAP_API}}
    return zap_context


def configure_auth(state, *, strategy="POLL_URL", logged_in="alice",
                   logged_out="unauthenticated", account="alice"):
    """Step 2.5 against the session app: form login + cookie session management."""
    base, name, cid = state["base"], state["name"], state["id"]
    zap("context", "action", "includeInContext", contextName=name,
        regex=r"http://127\.0\.0\.1:\d+/.*")
    zap("authentication", "action", "setAuthenticationMethod",
        contextId=cid, authMethodName="formBasedAuthentication",
        authMethodConfigParams=cfg_params(
            loginUrl=f"{base}/login",
            loginRequestData="username={%username%}&password={%password%}"))
    zap("sessionManagement", "action", "setSessionManagementMethod",
        contextId=cid, methodName="cookieBasedSessionManagement", methodConfigParams="")

    verification = zap_auth.cmd_configure_verification(state["cfg"], Args(
        context=name, context_id=cid, strategy=strategy,
        poll_url=f"{base}/api/me" if strategy == "POLL_URL" else None,
        poll_data=None, poll_headers=None, poll_frequency=None, poll_frequency_units=None,
        logged_in_indicator=logged_in, logged_out_indicator=logged_out))
    assert verification["applied"] is True, verification

    uid = zap("users", "action", "newUser", contextId=cid,
              name=f"u-{account}-{len(state['user_ids'])}")["userId"]
    state["user_ids"].append(uid)
    state["user_id"] = uid
    zap("users", "action", "setAuthenticationCredentials", contextId=cid, userId=uid,
        authCredentialsConfigParams=cfg_params(username=f"{account}@test.local",
                                               password=f"pw-{account}"))
    zap("users", "action", "setUserEnabled", contextId=cid, userId=uid, enabled="true")
    zap("forcedUser", "action", "setForcedUser", contextId=cid, userId=uid)
    zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="true")
    return uid


def run_test_authentication(context, url, indicator, markers="alice"):
    """`test-authentication` as the skill calls it."""
    return zap_auth.cmd_test_authentication(context["cfg"], Args(
        verification_url=url, logged_in_indicator=indicator, identity_markers=markers))


# --- what ZAP itself matches on ----------------------------------------------
def test_zap_matches_its_indicator_against_the_response_header(context, cookie_target):
    """The reason `test-authentication` must not match the body alone.

    /app returns a byte-identical SPA shell either way; the only difference is the
    `X-Authenticated-User` response header. With a logged-in indicator and no logged-out
    indicator, ZAP re-authenticates on every response the indicator does not match (the
    storm rule pinned in the token suite) — so the login count says exactly which surface
    ZAP looked at.
    """
    base, counts, reset = cookie_target

    reset()
    configure_auth(context, strategy="EACH_RESP", logged_in="X-Authenticated-User",
                   logged_out=None)
    drive(base, ["/app"] * 5)
    header_logins = counts()["login_ok"]

    reset()
    configure_auth(context, strategy="EACH_RESP", logged_in="Signed in as", logged_out=None)
    drive(base, ["/app"] * 5)
    body_logins = counts()["login_ok"]

    assert header_logins == 1, (
        "a header-only indicator was treated as no match: ZAP re-authenticated "
        f"{header_logins} times over 5 requests")
    assert body_logins > 1, (
        "control failed: an indicator present in NEITHER header nor body must storm, "
        f"got {body_logins} logins")


# --- the four defects, in the shape that exposes them ------------------------
def test_a_header_only_difference_is_visible_to_test_authentication(context, cookie_target):
    """Defect 2. Body-only matching reported "no difference" for a working session."""
    _base, _counts, reset = cookie_target
    reset()
    configure_auth(context)
    ev = run_test_authentication(context, "/app", "X-Authenticated-User")

    assert ev["evidence_complete"] is True
    assert ev["indicator_is_differential"] is True
    assert ev["indicator_where_authed"] == "header"
    assert ev["indicator_where_unauth"] is None
    # ...and the body really is identical, which is what defeats body-only matching.
    assert ev["status_authed"] == ev["status_unauth"] == 200


def test_both_sides_follow_redirects_so_a_session_page_can_be_verified(context,
                                                                       cookie_target):
    """Defect 4. /profile redirects BOTH ways — 301 to /profile/ for the signed-in user,
    302 to /login for everyone else. Following one side only compared an empty 301 body
    against the login page and found the indicator on neither."""
    base, _counts, reset = cookie_target
    reset()
    configure_auth(context)
    ev = run_test_authentication(context, "/profile", "alice")

    assert ev["evidence_complete"] is True
    assert ev["indicator_is_differential"] is True
    assert ev["authed_read_url"] == base + "/profile/"
    assert ev["unauth_read_url"] == base + "/login"
    assert [h["status"] for h in ev["authed_redirect_chain"]] == [301]
    assert [h["status"] for h in ev["unauth_redirect_chain"]] == [302]
    assert all(h["followed"] for h in ev["authed_redirect_chain"])
    # The statuses now agree (200 both sides) — the chain is where the difference shows,
    # which is why it is in the evidence rather than being resolved away.
    assert ev["status_differs"] is False


def test_an_unreadable_unauthenticated_read_is_not_a_pass(context, cookie_target):
    """Defect 1. /guarded drops anonymous connections with no response at all: the read
    fails, and 'the indicator was not in the response we never got' used to be reported as
    indicator_is_differential=true."""
    _base, _counts, reset = cookie_target
    reset()
    configure_auth(context)
    ev = run_test_authentication(context, "/guarded", "guarded")

    assert ev["authed_read_ok"] is True
    assert ev["unauth_read_ok"] is False
    assert ev["evidence_complete"] is False          # -> exit code 1
    assert ev["indicator_is_differential"] is None   # not True
    assert ev["indicator_in_unauth"] is None
    assert ev["status_differs"] is None


def test_the_authenticated_read_is_the_verification_url_not_zaps_own_traffic(context,
                                                                             cookie_target):
    """Defect 3. The window of history around one accessUrl call also holds ZAP's login
    requests; the old matcher compared the target's PATH against the whole request line,
    which for the default verification URL ('/') is the empty string — a match against
    every entry — and then took the newest one."""
    base, _counts, reset = cookie_target
    reset()
    # No session yet and a per-response check with no logged-out indicator: ZAP will log in
    # while this very call is in flight, so its login traffic lands in the same window.
    configure_auth(context, strategy="EACH_RESP", logged_in="no-such-marker",
                   logged_out=None)
    before = zap_auth._message_count(context["cfg"])
    ev = run_test_authentication(context, "/", "Sign in")
    window = zap("core", "view", "messages", start=str(before), count="50")["messages"]
    lines = [m["requestHeader"].splitlines()[0] for m in window]

    assert any("POST " in line and "/login" in line for line in lines), (
        "expected ZAP's own login traffic in the same history window; without it this "
        f"test proves nothing. Window: {lines}")
    assert ev["authed_read_url"] == base + "/"
    # The login page is what the loose matcher used to return here.
    assert ev["indicator_in_authed"] is False, (
        "the authenticated read picked up a response that is not the verification URL's "
        "(the login page contains 'Sign in'; the SPA shell does not)")


def test_a_redirect_into_logout_is_not_followed_and_the_session_survives(context,
                                                                        cookie_target):
    """The guard that has to fire against a real app, not just a stub.

    `/expired` answers "your session has expired" the way a session app does — a redirect
    into `/logout`, which clears the session server-side. Following it would destroy the
    session as the forced user, through ZAP, and every later step would then fail for a
    reason no longer visible in the evidence.
    """
    _base, counts, reset = cookie_target
    reset()
    configure_auth(context)
    ev = run_test_authentication(context, "/expired", "Signed in as")

    assert counts()["logout"] == 0, "the probe walked into /logout and ended the session"
    for side in ("authed", "unauth"):
        assert "ends the session" in (ev[f"{side}_chain_cut"] or ""), ev[f"{side}_chain_cut"]
    # And the session really is still usable afterwards.
    after = run_test_authentication(context, "/account", "Signed in as")
    assert after["indicator_is_differential"] is True, after


def test_a_session_page_verifies_and_reports_the_identity(context, cookie_target):
    """The healthy path on a session app, end to end."""
    _base, _counts, reset = cookie_target
    reset()
    configure_auth(context)
    ev = run_test_authentication(context, "/account", "Signed in as")

    assert ev["evidence_complete"] is True
    assert ev["indicator_is_differential"] is True
    assert ev["identity_markers_in_authed"]["alice"] is True
    assert ev["identity_markers_in_unauth"]["alice"] is False
    assert "authenticated" not in ev and "verdict" not in ev   # still evidence, not a verdict


def test_mutual_identity_differential_between_two_accounts(context, cookie_target):
    """Two accounts must come back as two identities. If both read as the same user the
    sessions are crossed and every horizontal-IDOR conclusion built on them is void."""
    _base, _counts, reset = cookie_target
    reset()
    configure_auth(context, account="alice")
    as_alice = run_test_authentication(context, "/account", "Signed in as", "alice,bob")

    configure_auth(context, account="bob", logged_in="bob")
    as_bob = run_test_authentication(context, "/account", "Signed in as", "alice,bob")

    assert as_alice["identity_markers_in_authed"] == {"alice": True, "bob": False}
    assert as_bob["identity_markers_in_authed"] == {"alice": False, "bob": True}
