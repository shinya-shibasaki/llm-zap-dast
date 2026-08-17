"""Live tests for the SCOPE layer: Protected mode, the Active Scan seed, and exclusions.

Every behaviour here was found by measuring ZAP 2.17.0, and every one of them decides
something written in references/. They are worth their runtime because the failure modes are
quiet: a scan that reports 100% having attacked nothing, an exclusion that stops the forced
user's credentials, a scanner exclusion left behind in someone else's ZAP.

What each test protects is named in its docstring. If ZAP changes one of these, the reference
it supports is wrong, and the offline suite cannot tell — it only knows what we believe ZAP
requires.

See README.md: these touch ZAP's MODE and its SITE TREE, so run them against a throwaway
daemon, never against a ZAP you are also using.
"""
import pytest
from harness import (Args, ZAP_API, ascan_and_wait, cfg_params, include_regex,
                     requires_live_zap, spider_and_wait, zap, zap_auth)

pytestmark = requires_live_zap

# The shape that does NOT match the bare site node. Built locally on purpose: it is the
# recommended shape (harness.include_regex), and these tests exist to pin what it costs.
SLASH_ONLY = include_regex


def widened(base):
    """The include shape that DOES match the bare site node — deliberately not recommended.

    It keeps the host boundary (`(/.*)?` cannot swallow `localhost.example.com`), but adopting
    it would trade this refusal for an order dependency: see
    test_widening_the_include_after_the_tree_is_populated_is_not_recoverable.
    """
    host = base.split("//", 1)[1]
    return r"^https?://" + host.replace(".", r"\.") + r"(/.*)?$"


def include_this_port_only(base):
    """An include regex pinned to ONE port, for the tests that need two separable scopes.

    The recommended shape allows any port on the host (`(:\\d+)?`) and that is deliberate —
    `allowed_hosts` is host-based, so every port on an allowed host is in scope. Both targets
    here are loopback ports, so the documented shape would put the "out of scope" one in scope
    as well; pinning the port is the only way to tell two scopes apart on 127.0.0.1.
    """
    return r"^" + base.replace(".", r"\.") + r"/.*$"


def crawl(base, name, regex):
    """Context with `regex` included, target crawled into the tree. Returns the context id."""
    cid = zap("context", "view", "context", contextName=name)["context"]["id"]
    zap("context", "action", "includeInContext", contextName=name, regex=regex)
    spider_and_wait(base + "/", name)
    return cid


# --- Protected mode and the Active Scan seed ---------------------------------
def test_a_new_context_is_in_scope_by_default(contexts):
    """Why references/ does NOT tell the run to call setContextInScope.

    If the default ever flips, "include the hosts and you are in scope" stops being true and
    every scanner starts refusing with mode_violation for a reason no step accounts for.
    """
    name, _cid = contexts()
    assert zap("context", "view", "context", contextName=name)["context"]["inScope"] == "true"


def test_protect_mode_refuses_a_root_recursive_active_scan(own_target, contexts, zap_mode):
    """Why active-scan-as-user sends no url: the documented setup cannot scan from the root.

    Protected mode is mandated by safety-policy.md and the recommended include regex requires
    a slash after the host, so ZAP evaluates the recursive scan's starting node as the bare
    site node and refuses. Both the plain and the user-scoped call, since step 5 uses both.
    """
    base, _counts, _reset = own_target
    name, cid = contexts()
    crawl(base, name, SLASH_ONLY(base))
    uid = zap("users", "action", "newUser", contextId=cid, name=f"u-{name}")["userId"]
    zap_mode("protect")

    scan_id, refusal = ascan_and_wait(url=base + "/", contextId=cid)
    assert scan_id is None and refusal == "mode_violation"
    scan_id, refusal = ascan_and_wait(_action="scanAsUser", url=base + "/",
                                      contextId=cid, userId=uid)
    assert scan_id is None and refusal == "mode_violation"

    # The context form — what the plugin now sends — is accepted.
    scan_id, refusal = ascan_and_wait(contextId=cid)
    assert refusal is None, f"context-scoped Active Scan refused: {refusal}"


def test_recurse_false_scans_only_the_seed_node(own_target, contexts, zap_mode):
    """The trap a future reader will fall into when they meet mode_violation.

    recurse=false makes the refusal go away, the scan runs to 100%, and NOTHING under the root
    is attacked. It is not a workaround, and a run that took it would report a completed
    Active Scan having tested one page.
    """
    base, counts, reset = own_target
    name, cid = contexts()
    crawl(base, name, SLASH_ONLY(base))
    zap_mode("protect")

    reset()
    scan_id, refusal = ascan_and_wait(url=base + "/", contextId=cid, recurse="false")
    assert refusal is None and scan_id is not None
    seed_only = counts()
    assert seed_only["html"] > 0, "the seed page itself should have been attacked"
    assert seed_only["products"] == 0 and seed_only["boom"] == 0, (
        f"recurse=false unexpectedly reached children: {seed_only}")

    reset()
    scan_id, refusal = ascan_and_wait(contextId=cid)
    assert refusal is None
    whole_context = counts()
    assert whole_context["products"] > 0 and whole_context["boom"] > 0, (
        f"the context form failed to reach the children: {whole_context}")


def test_active_scan_needs_a_context_when_no_url_is_given(own_target, contexts, zap_mode):
    """There is no "scan everything ZAP knows" form to fall into.

    Omitting url is safe partly because omitting the context TOO is refused by ZAP, so the
    call cannot silently widen to the whole site tree.
    """
    base, _counts, _reset = own_target
    name, cid = contexts()
    crawl(base, name, SLASH_ONLY(base))
    zap_mode("protect")
    scan_id, refusal = ascan_and_wait()
    assert scan_id is None and refusal == "missing_parameter"


def test_the_context_form_honours_context_exclusions(own_target, contexts, zap_mode):
    """Dropping the url must not drop exclude.paths with it.

    This is the property that made the substitution acceptable: the endpoint excluded from the
    context takes no attacks while its neighbour does.
    """
    base, counts, reset = own_target
    name, cid = contexts()
    zap("context", "action", "includeInContext", contextName=name, regex=SLASH_ONLY(base))
    zap("context", "action", "excludeFromContext", contextName=name,
        regex=r"^https?://127\.0\.0\.1(:\d+)?/rest/boom.*$")
    spider_and_wait(base + "/", name)
    zap_mode("protect")

    reset()
    _scan_id, refusal = ascan_and_wait(contextId=cid)
    assert refusal is None
    after = counts()
    assert after["boom"] == 0, f"an excluded endpoint was attacked: {after}"
    assert after["products"] > 0, f"control endpoint was not attacked either: {after}"


def test_the_context_form_leaves_hosts_outside_the_context_alone(own_target, contexts,
                                                                zap_mode):
    """A host in ZAP's site tree but outside the context must not be attacked.

    The context form scans "the context's nodes that are in the site tree", so the tree is the
    other half of the scope question. Uses a second local target as the out-of-scope host, so
    nothing leaves the machine — and a port-pinned include, since both are loopback.
    """
    base, counts, reset = own_target
    from harness import start_target
    outsider = start_target("target.py")
    other, other_counts, other_reset = next(outsider)
    try:
        name, cid = contexts()
        crawl(base, name, include_this_port_only(base))
        spider_and_wait(other + "/")          # in the tree, in no context
        zap_mode("protect")
        reset(); other_reset()
        _scan_id, refusal = ascan_and_wait(contextId=cid)
        assert refusal is None
        assert counts()["products"] > 0, "the in-scope target was not scanned"
        out = other_counts()
        assert out["html"] == 0 and out["products"] == 0, (
            f"an out-of-context host was attacked: {out}")
    finally:
        try:
            next(outsider)
        except StopIteration:
            pass


def test_the_crawlers_are_not_subject_to_the_root_recursion_rule(own_target, contexts,
                                                                zap_mode):
    """Only the Active Scan needs the context form; step 3 keeps passing a seed URL.

    Measured separately because step 3 reaches the root before step 5 does — if the crawlers
    were affected too, the first thing a run would hit is a failed spider, not a failed scan.
    """
    base, _counts, _reset = own_target
    name, cid = contexts()
    crawl(base, name, SLASH_ONLY(base))
    uid = zap("users", "action", "newUser", contextId=cid, name=f"u-{name}")["userId"]
    zap_mode("protect")

    assert zap("spider", "action", "scan", url=base + "/",
               contextName=name).get("code") != "mode_violation"
    assert zap("spider", "action", "scanAsUser", contextId=cid, userId=uid,
               url=base + "/").get("code") != "mode_violation"
    assert zap("ajaxSpider", "action", "scan", url=base + "/",
               contextName=name).get("code") != "mode_violation"
    zap("ajaxSpider", "action", "stop")


def test_widening_the_include_after_the_tree_is_populated_is_not_recoverable(
        own_target, contexts, zap_mode):
    """Why the include regex was NOT widened instead of changing the scan call.

    Widening works — but only if it is in place before the target's site node exists.
    Afterwards the refusal changes from mode_violation to internal_error, and neither
    re-crawling nor a fresh context clears it; only deleting the site node does. Both shapes
    of "afterwards" are measured, because both happen in real runs: reusing a ZAP daemon for a
    second run (teardown removes the context, never the tree) and re-entering with --from.
    """
    base, _counts, _reset = own_target
    zap_mode("protect")

    # (i) the same context, widened after the crawl
    name_a, cid_a = contexts("-a")
    crawl(base, name_a, SLASH_ONLY(base))
    assert ascan_and_wait(url=base + "/", contextId=cid_a)[1] == "mode_violation"
    zap("context", "action", "includeInContext", contextName=name_a, regex=widened(base))
    assert ascan_and_wait(url=base + "/", contextId=cid_a)[1] == "internal_error"
    spider_and_wait(base + "/", name_a)
    assert ascan_and_wait(url=base + "/", contextId=cid_a)[1] == "internal_error", (
        "re-crawling recovered it; the reference says only deleteSiteNode does")

    # (ii) a brand-new context with the right shape, on the tree the first one left behind
    name_b, cid_b = contexts("-b")
    zap("context", "action", "includeInContext", contextName=name_b, regex=widened(base))
    assert ascan_and_wait(url=base + "/", contextId=cid_b)[1] == "internal_error"

    # deleteSiteNode + a fresh crawl is the recovery — and it needs the BARE origin.
    zap("core", "action", "deleteSiteNode", url=base + "/", recurse="true")
    assert base in zap("core", "view", "sites").get("sites"), (
        "deleteSiteNode with a trailing slash answered OK and removed nothing")
    zap("core", "action", "deleteSiteNode", url=base, recurse="true")
    assert base not in zap("core", "view", "sites").get("sites")
    spider_and_wait(base + "/", name_b)
    assert ascan_and_wait(url=base + "/", contextId=cid_b)[1] is None


# --- what Protected mode does NOT bound -------------------------------------
@pytest.mark.parametrize("mode", ["protect", "safe"])
def test_access_url_reaches_an_out_of_context_host_in_any_mode(own_target, contexts,
                                                              zap_mode, mode):
    """Why safety-policy.md says the boundary of this path is our code, not ZAP's mode.

    core/action/accessUrl is what test-authentication, verify-canary and the step-6 probes use.
    It is not gated by the mode or by the context, so the allowed_hosts check in the wrapper
    (and prompt discipline where there is none — verify-canary) is the whole boundary.
    """
    base, _counts, _reset = own_target
    from harness import start_target
    outsider = start_target("target.py")
    other, other_counts, _r = next(outsider)
    try:
        name, cid = contexts()
        crawl(base, name, include_this_port_only(base))
        zap_mode(mode)
        assert zap("spider", "action", "scan",
                   url=other + "/").get("code") == "mode_violation"
        res = zap("core", "action", "accessUrl", url=other + "/", followRedirects="false")
        assert "accessUrl" in res, f"accessUrl was refused in {mode} mode: {res}"
        assert other_counts()["html"] == 1, (
            f"accessUrl did not actually reach the out-of-context host in {mode} mode")
    finally:
        try:
            next(outsider)
        except StopIteration:
            pass


# --- exclusions: reach, side effects, lifetime -------------------------------
def test_an_excluded_url_gets_no_forced_user_credentials(own_target, contexts):
    """Why login_url / verification_url / the canary URLs / base_url must never be excluded.

    Excluding a URL from the context also stops the forced user's credentials reaching it —
    401, no Authorization header, no login attempt, and no error anywhere. Excluding the
    verification URL or a canary therefore ends the run with "cannot authenticate" while the
    authentication configuration is perfectly correct.
    """
    base, counts, reset = own_target
    name, cid = contexts()
    zap("context", "action", "includeInContext", contextName=name, regex=SLASH_ONLY(base))
    zap("authentication", "action", "setAuthenticationMethod",
        contextId=cid, authMethodName="jsonBasedAuthentication",
        authMethodConfigParams=cfg_params(
            loginUrl=f"{base}/rest/user/login",
            loginRequestData='{"email":"{%username%}","password":"{%password%}"}'))
    zap("sessionManagement", "action", "setSessionManagementMethod",
        contextId=cid, methodName="headerBasedSessionManagement",
        methodConfigParams=cfg_params(
            headers="Authorization: Bearer {%json:authentication.token%}"))
    zap_auth.cmd_configure_verification(
        {"zap": {"api_url": ZAP_API}},
        Args(context=name, context_id=cid, strategy="POLL_URL",
             poll_url=f"{base}/rest/user/auth-details", poll_data=None, poll_headers=None,
             poll_frequency=None, poll_frequency_units=None,
             logged_in_indicator="lastLoginTime", logged_out_indicator=None))
    uid = zap("users", "action", "newUser", contextId=cid, name=f"u-{name}")["userId"]
    zap("users", "action", "setAuthenticationCredentials", contextId=cid, userId=uid,
        authCredentialsConfigParams=cfg_params(username="jim@test.local", password="pw"))
    zap("users", "action", "setUserEnabled", contextId=cid, userId=uid, enabled="true")
    zap("forcedUser", "action", "setForcedUser", contextId=cid, userId=uid)
    zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="true")

    def read(url):
        msgs = zap("core", "action", "accessUrl", url=url,
                   followRedirects="false").get("accessUrl", [])
        last = msgs[-1] if msgs else {}
        head = str(last.get("responseHeader", ""))
        return (zap_auth.status_from_response_header(head),
                "Authorization" in str(last.get("requestHeader", "")))

    reset()
    status, authorized = read(base + "/rest/products")
    assert (status, authorized) == (200, True), "the baseline read was not authenticated"

    zap("context", "action", "excludeFromContext", contextName=name,
        regex=r"^https?://127\.0\.0\.1(:\d+)?/rest/products.*$")
    reset()
    status, authorized = read(base + "/rest/products")
    assert status == 401 and not authorized, (
        "an excluded URL still received the forced user's credentials")
    assert counts()["login"] == 0, "ZAP tried to log in for an excluded URL"


def test_scanner_exclusions_are_session_scoped_and_ignore_context_name(own_target, contexts):
    """Why teardown has to call clearExcludedFromScan, and why contextName is a trap.

    These exclusions belong to the SESSION, not to a context: they outlive the context and
    leak into the ZAP of whoever is running the daemon, where they silently drop part of every
    later scan. Passing contextName does not scope them — ZAP answers OK and ignores it.
    """
    base, _counts, _reset = own_target
    name, _cid = contexts()
    rgx = r"^https?://127\.0\.0\.1(:\d+)?/rest/products.*$"
    try:
        # contextName is accepted and ignored: the entry lands in the session-wide list.
        assert zap("spider", "action", "excludeFromScan",
                   regex=rgx, contextName=name).get("Result") == "OK"
        assert rgx in zap("spider", "view", "excludedFromScan").get("excludedFromScan", [])
        zap("ascan", "action", "excludeFromScan", regex=rgx)
        assert rgx in zap("ascan", "view", "excludedFromScan").get("excludedFromScan", [])

        # Removing the context does not remove them.
        zap("context", "action", "removeContext", contextName=name)
        assert rgx in zap("spider", "view", "excludedFromScan").get("excludedFromScan", [])
    finally:
        zap("spider", "action", "clearExcludedFromScan")
        zap("ascan", "action", "clearExcludedFromScan")
    assert zap("spider", "view", "excludedFromScan").get("excludedFromScan") == []
    assert zap("ascan", "view", "excludedFromScan").get("excludedFromScan") == []
