"""Unit tests for zap_auth.py invariants that need no live ZAP: the safety guards
(no 'auto' into the script, gated Active Scan), evidence-not-verdict, and no credential
leakage. Anything requiring a real ZAP is out of scope for the offline suite."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "llm-zap-dast", "scripts")
EXAMPLE_CFG = os.path.join(ROOT, "examples", "dast.yaml")
sys.path.insert(0, SCRIPTS)

import zap_auth  # noqa: E402


# --- pure helpers ------------------------------------------------------------
def test_resolve_method_rejects_auto():
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.resolve_auth_method_name("auto")


def test_resolve_method_maps_known():
    assert zap_auth.resolve_auth_method_name("browser") == "browserBasedAuthentication"
    assert zap_auth.resolve_auth_method_name("basic") == "httpAuthentication"


def test_resolve_method_rejects_unknown():
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.resolve_auth_method_name("oauth")


def _resp(status, body, header=None, ok=True, url="http://h/probe", chain=()):
    """A read of one side of the differential, as the fetchers return it."""
    return zap_auth.Response(ok=ok, status=status, body=body, url=url, chain=chain,
                             header=header if header is not None
                             else f"HTTP/1.1 {status} X\r\nContent-Type: text/html")


def test_evidence_has_no_verdict():
    ev = zap_auth.evidence_from_responses(
        _resp(200, "Welcome alice, Logout"), _resp(200, "Please log in"),
        logged_in_indicator="Logout", identity_markers=["alice"],
    )
    # The script must not decide auth; no verdict/authenticated key may exist.
    for forbidden in ("authenticated", "verdict", "success", "passed"):
        assert forbidden not in ev
    assert ev["indicator_in_authed"] is True
    assert ev["indicator_in_unauth"] is False
    assert ev["indicator_is_differential"] is True
    assert ev["identity_markers_in_authed"]["alice"] is True


def test_users_list_password_is_scrubbed():
    """ZAP 2.17 usersList returns the password IN CLEARTEXT — it must never reach output."""
    raw = {"usersList": [{
        "name": "dast-user", "id": "5", "contextId": "9", "enabled": "true",
        "credentials": '{"password":"probe-pass-123","type":'
                       '"UsernamePasswordAuthenticationCredentials","username":"a@b.c"}',
    }]}
    out = zap_auth.scrub_users_list(raw)
    blob = str(out)
    assert "probe-pass-123" not in blob
    assert "a@b.c" not in blob
    assert out["usersList"][0]["enabled"] == "true"          # useful signal kept
    assert out["usersList"][0]["credentials_type"] == "UsernamePasswordAuthenticationCredentials"


def test_build_config_params_encodes_values():
    s = zap_auth.build_config_params(["loginUrl=http://h/login", 'data={"a":"b"}'])
    assert s == "loginUrl=http%3A%2F%2Fh%2Flogin&data=%7B%22a%22%3A%22b%22%7D"
    # verbatim passthrough wins when given
    assert zap_auth.build_config_params(["x=1"], verbatim="already%3Dencoded") == "already%3Dencoded"
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.build_config_params(["novalue"])


def test_zap_call_treats_result_fail_and_error_code_as_failure(monkeypatch):
    monkeypatch.setattr(zap_auth, "_http_get",
                        lambda url, timeout=30: (True, 200, '{"Result":"FAIL"}'))
    assert zap_auth.zap_call({}, "JSON", "users", "action", "removeUser")["ok"] is False
    monkeypatch.setattr(zap_auth, "_http_get",
                        lambda url, timeout=30: (True, 400,
                                                 '{"code":"missing_parameter","message":"x"}'))
    res = zap_auth.zap_call({}, "JSON", "context", "action", "removeContext")
    assert res["ok"] is False and res["error"]["code"] == "missing_parameter"
    monkeypatch.setattr(zap_auth, "_http_get",
                        lambda url, timeout=30: (True, 200, '{"Result":"OK"}'))
    assert zap_auth.zap_call({}, "JSON", "context", "action", "newContext")["ok"] is True


def test_checking_strategy_validation():
    assert zap_auth.resolve_checking_strategy("each_resp") == "EACH_RESP"
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.resolve_checking_strategy("response")  # the old, non-existent value


def test_checking_strategy_requires_explicit_choice():
    """No default: falling back silently is what put a run into AUTO_DETECT."""
    for empty in (None, "", "   "):
        with pytest.raises(zap_auth.AuthUsageError):
            zap_auth.resolve_checking_strategy(empty)


def test_checking_strategy_refuses_auto_detect():
    """Measured on ZAP 2.17.0: AUTO_DETECT makes isAuthenticated() always false, so ZAP
    re-authenticates on every request and scores its own logins as failures."""
    with pytest.raises(zap_auth.AuthUsageError, match="AUTO_DETECT"):
        zap_auth.resolve_checking_strategy("AUTO_DETECT")


def test_poll_params_always_sends_all_five():
    """POLL_URL needs all five params; empty pollData/pollHeaders must NOT be dropped."""
    class Args:
        poll_url = "http://localhost:3000/rest/user/authentication-details"
        poll_data = poll_headers = poll_frequency = poll_frequency_units = None

    params = zap_auth.build_poll_params(Args())
    assert set(params) == {"pollUrl", "pollData", "pollHeaders", "pollFrequency",
                           "pollFrequencyUnits"}
    assert params["pollData"] == "" and params["pollHeaders"] == ""
    assert params["pollFrequency"] == 60 and params["pollFrequencyUnits"] == "REQUESTS"


def test_poll_params_rejects_non_positive_frequency():
    class Args:
        poll_url = "http://localhost:3000/whoami"
        poll_data = poll_headers = poll_frequency_units = None
        poll_frequency = 0

    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.build_poll_params(Args())


def test_poll_params_rejects_unknown_units():
    class Args:
        poll_url = "http://localhost:3000/whoami"
        poll_data = poll_headers = poll_frequency = None
        poll_frequency_units = "MINUTES"

    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.build_poll_params(Args())


def test_require_indicator_refuses_when_none_set():
    """With neither indicator ZAP short-circuits to 'authenticated' and never checks."""
    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.require_indicator(None, None)
    zap_auth.require_indicator("lastLoginTime", None)   # one is enough
    zap_auth.require_indicator(None, "unauthorized")


def _verification_args(**over):
    class Args:
        context = "dast-run"
        context_id = "1"
        strategy = "EACH_RESP"
        poll_url = poll_data = poll_headers = poll_frequency = poll_frequency_units = None
        logged_in_indicator = "Sign out"
        logged_out_indicator = None

    for k, v in over.items():
        setattr(Args, k, v)
    return Args()


def _fake_zap(seen, context_view):
    """zap_call stub: records params and serves a context/view/context readback."""
    def fake(cfg, fmt, comp, kind, name, params=None):
        seen[name] = params
        if name == "context" and kind == "view":
            return {"ok": True, "status": 200, "data": {"context": context_view}}
        return {"ok": True, "status": 200, "data": {"Result": "OK"}}
    return fake


def test_configure_verification_uses_context_name(monkeypatch):
    """ZAP 2.17: the strategy lives on context/setContextCheckingStrategy and needs a NAME."""
    seen = {}
    monkeypatch.setattr(zap_auth, "zap_call", _fake_zap(
        seen, {"checkingStrategy": "EACH_RESP", "loggedInPattern": "Sign out"}))

    out = zap_auth.cmd_configure_verification({}, _verification_args())
    assert seen["setContextCheckingStrategy"]["contextName"] == "dast-run"
    assert seen["setContextCheckingStrategy"]["checkingStrategy"] == "EACH_RESP"
    assert seen["setLoggedInIndicator"]["contextId"] == "1"
    assert out["applied"] is True


def test_configure_verification_sends_all_poll_params(monkeypatch):
    seen = {}
    ctx = {"checkingStrategy": "POLL_URL", "loggedInPattern": "lastLoginTime",
           "pollUrl": "http://t/auth", "pollData": "", "pollHeaders": "",
           "pollFrequency": "60", "pollFrequencyUnits": "REQUESTS"}
    monkeypatch.setattr(zap_auth, "zap_call", _fake_zap(seen, ctx))

    out = zap_auth.cmd_configure_verification({}, _verification_args(
        strategy="POLL_URL", poll_url="http://t/auth", logged_in_indicator="lastLoginTime"))
    sent = seen["setContextCheckingStrategy"]
    assert sent["pollData"] == "" and sent["pollHeaders"] == ""
    assert sent["pollFrequency"] == 60 and sent["pollFrequencyUnits"] == "REQUESTS"
    assert out["applied"] is True


def test_configure_verification_aborts_before_indicators_on_failure(monkeypatch):
    """If the strategy call fails, the indicators must NOT be applied on top of it."""
    seen = {}

    def fake(cfg, fmt, comp, kind, name, params=None):
        seen[name] = params
        if name == "setContextCheckingStrategy":
            return {"ok": False, "status": 400,
                    "error": {"code": "illegal_parameter", "message": "bad"}}
        return {"ok": True, "data": {}}

    monkeypatch.setattr(zap_auth, "zap_call", fake)
    out = zap_auth.cmd_configure_verification({}, _verification_args())
    assert "setLoggedInIndicator" not in seen
    assert out["applied"] is False and "aborted" in out


def test_configure_verification_reports_settings_that_did_not_land(monkeypatch):
    """setAuthenticationMethod wipes the indicators; the readback must catch that shape."""
    seen = {}
    monkeypatch.setattr(zap_auth, "zap_call", _fake_zap(
        seen, {"checkingStrategy": "EACH_RESP", "loggedInPattern": ""}))

    out = zap_auth.cmd_configure_verification({}, _verification_args())
    assert out["applied"] is False
    assert out["mismatch"]["loggedInPattern"] == {"sent": "Sign out", "in_zap": ""}


def test_compare_verification_tolerates_string_typed_numbers():
    """ZAP echoes pollFrequency back as a string; that is not a mismatch."""
    assert zap_auth.compare_verification({"pollFrequency": 60}, {"pollFrequency": "60"}) == {}


def test_seed_url_adds_slash_only_to_a_bare_origin():
    """Include regexes require '/' after the host, so a bare origin is out of context."""
    assert zap_auth.seed_url("http://localhost:3000") == "http://localhost:3000/"
    assert zap_auth.seed_url("https://h") == "https://h/"
    # already canonical / has a path -> untouched
    assert zap_auth.seed_url("http://localhost:3000/") == "http://localhost:3000/"
    assert zap_auth.seed_url("http://localhost:3000/app") == "http://localhost:3000/app"
    # not a URL -> untouched (never invent scope)
    assert zap_auth.seed_url("") == ""
    assert zap_auth.seed_url("localhost:3000") == "localhost:3000"


def test_scan_as_user_seeds_a_canonical_url(monkeypatch):
    seen = {}
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda cfg, f, c, k, n, params=None: seen.update({n: params})
                        or {"ok": True})
    cfg = {"target": {"base_url": "http://localhost:3000"}}

    class Args:
        context_id = "1"
        user_id = "2"
        url = None
        context = "dast-run"
        user_name = "u"
        username = None
        policy = None
        gate_passed = True

    zap_auth.cmd_spider_as_user(cfg, Args())
    assert seen["scanAsUser"]["url"] == "http://localhost:3000/"
    zap_auth.cmd_active_scan_as_user(cfg, Args())
    assert seen["scanAsUser"]["url"] == "http://localhost:3000/"
    zap_auth.cmd_ajax_spider_as_user(cfg, Args())
    assert seen["scanAsUser"]["url"] == "http://localhost:3000/"


def test_parse_include_regexs_handles_both_shapes():
    """ZAP hands includeRegexs back as a JSON array or as a string holding one."""
    rgx = r"^https?://localhost(:\d+)?/.*$"
    assert zap_auth.parse_include_regexs([rgx]) == [rgx]
    assert zap_auth.parse_include_regexs(json.dumps([rgx])) == [rgx]
    assert zap_auth.parse_include_regexs("[]") == []
    assert zap_auth.parse_include_regexs(None) == []


def test_include_in_context_requires_a_regex():
    """An empty include list means ZAP applies no authentication at all, silently."""
    class Args:
        context = "dast-run"
        regex = []

    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.cmd_include_in_context({}, Args())


def test_include_in_context_confirms_the_scope_zap_holds(monkeypatch):
    seen = {}
    rgx = r"^https?://localhost(:\d+)?/.*$"

    def fake(cfg, fmt, comp, kind, name, params=None):
        seen.setdefault(name, []).append(params)
        if kind == "view":
            return {"ok": True, "data": {"context": {"includeRegexs": [rgx]}}}
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        regex = [rgx]

    out = zap_auth.cmd_include_in_context({}, Args())
    assert seen["includeInContext"][0] == {"contextName": "dast-run", "regex": rgx}
    assert out["applied"] is True and out["include_regexs"] == [rgx]


def test_include_in_context_reports_a_regex_that_did_not_land(monkeypatch):
    def fake(cfg, fmt, comp, kind, name, params=None):
        if kind == "view":
            return {"ok": True, "data": {"context": {"includeRegexs": []}}}
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        regex = ["^http://localhost/.*$"]

    assert zap_auth.cmd_include_in_context({}, Args())["applied"] is False


# --- ZAP's own verdict counters (the detection signal) ------------------------
# Shape verified on a live ZAP 2.17.0: nested LISTS, not the dict it looks like.
LIVE_ALLSITES = {"allSitesStats": [{"http://127.0.0.1:18500": [
    {"stats.auth.state.assumedin": 19, "stats.auth.state.loggedin": 2,
     "stats.auth.state.loggedout": 1, "stats.auth.success": 2}]}]}


def test_flatten_site_stats_reads_the_live_nested_shape():
    """Treating allSitesStats as a dict yields {} — which reads as 'no auth failures'."""
    flat = zap_auth.flatten_site_stats(LIVE_ALLSITES)
    assert flat["http://127.0.0.1:18500"]["stats.auth.state.loggedout"] == 1
    assert zap_auth.flatten_site_stats({}) == {}
    assert zap_auth.flatten_site_stats({"allSitesStats": {}}) == {}


def test_site_key_matches_target_base_url():
    sites = zap_auth.flatten_site_stats(LIVE_ALLSITES)
    assert zap_auth.site_key_for(sites, "http://127.0.0.1:18500") == "http://127.0.0.1:18500"
    assert zap_auth.site_key_for(sites, "http://127.0.0.1:18500/rest") is not None
    assert zap_auth.site_key_for(sites, "http://other:1") is None
    assert zap_auth.site_key_for(sites, "") is None


def test_storm_verdict_needs_a_minimum_sample():
    """A couple of logged-out responses must not condemn a run on its own."""
    tiny = zap_auth.summarize_auth_counters({"stats.auth.state.loggedout": 2})
    assert zap_auth.storm_verdict(tiny)["storm"] is False

    storming = zap_auth.summarize_auth_counters(
        {"stats.auth.state.loggedout": 10, "stats.auth.state.unknown": 11})
    v = zap_auth.storm_verdict(storming)
    assert v["storm"] is True and v["logged_out_ratio"] > zap_auth.LOGGED_OUT_RATIO_LIMIT

    healthy = zap_auth.summarize_auth_counters(
        {"stats.auth.state.unknown": 21, "stats.auth.state.loggedout": 1})
    assert zap_auth.storm_verdict(healthy)["storm"] is False


def _counters(**kw):
    return {f"stats.auth.{k.replace('_', '.')}": v for k, v in kw.items()}


def test_canary_flags_a_re_auth_storm():
    """Measured: a healthy config logs in exactly once; 11 logins over 10 URLs is a storm."""
    before = _counters(success=1)
    after = _counters(success=12, state_loggedout=10, state_unknown=11)
    v = zap_auth.canary_verdict(before, after, "EACH_RESP", driven=10)
    assert v["ok"] is False and v["logins"] == 11
    assert any("storm" in p for p in v["problems"])


def test_canary_flags_verification_that_never_ran():
    """POLL_URL with 0 polls: ZAP reports 'authenticated' forever and never re-checks."""
    before = _counters(success=0)
    after = _counters(success=1, state_unknown=11)
    v = zap_auth.canary_verdict(before, after, "POLL_URL", driven=3)
    assert v["ok"] is False
    assert any("never ran" in p for p in v["problems"])


def test_canary_accepts_a_healthy_poll_url_run():
    before = _counters(success=0)
    after = _counters(success=1, state_loggedin=1, state_assumedin=10)
    assert zap_auth.canary_verdict(before, after, "POLL_URL", driven=3)["ok"] is True


def test_canary_does_not_demand_polls_for_each_resp():
    """loggedin/assumedin are always 0 under EACH_* even when healthy — no false alarm."""
    before = _counters(success=0)
    after = _counters(success=1, state_unknown=11)
    assert zap_auth.canary_verdict(before, after, "EACH_RESP", driven=3)["ok"] is True


def test_canary_flags_responses_judged_without_any_indicator():
    before = _counters(success=0)
    after = _counters(success=1, state_noindicator=11)
    v = zap_auth.canary_verdict(before, after, "EACH_RESP", driven=3)
    assert v["ok"] is False and any("NO indicator" in p for p in v["problems"])


def test_verify_canary_refuses_a_single_response_shape():
    """One shape makes a storming config and a healthy one indistinguishable (measured)."""
    class Args:
        canary_url = ["http://t/a.json", "http://t/b.json"]
        context = "dast-run"

    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.cmd_verify_canary({}, Args())


def test_authenticated_scans_refuse_during_a_storm(monkeypatch):
    """The guard is the consumer's own read of ZAP's counters, not a caller flag."""
    storm = {"allSitesStats": [{"http://t:80": [
        {"stats.auth.state.loggedout": 10, "stats.auth.state.unknown": 11}]}]}
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda cfg, f, c, k, n, params=None: {"ok": True, "data": storm})
    cfg = {"target": {"base_url": "http://t:80"}}

    class Args:
        context_id = "1"
        user_id = "2"
        url = None
        context = "dast-run"
        user_name = "u"
        username = None
        policy = None
        gate_passed = True

    for fn in (zap_auth.cmd_spider_as_user, zap_auth.cmd_ajax_spider_as_user,
               zap_auth.cmd_active_scan_as_user):
        with pytest.raises(zap_auth.AuthUsageError, match="refused"):
            fn(cfg, Args())


def test_ajax_spider_uses_names(monkeypatch):
    seen = {}
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda cfg, f, c, k, n, params=None: seen.update({n: params}) or {"ok": True})

    class Args:
        context = "dast-run"
        user_name = "dast-user"
        username = None
        url = "http://localhost:3000"

    zap_auth.cmd_ajax_spider_as_user({}, Args())
    p = seen["scanAsUser"]
    assert p["contextName"] == "dast-run" and p["userName"] == "dast-user"
    assert "contextId" not in p and "userId" not in p


def test_ajax_spider_requires_names():
    class Args:
        context = None
        user_name = None
        username = None
        url = None

    with pytest.raises(zap_auth.AuthUsageError):
        zap_auth.cmd_ajax_spider_as_user({}, Args())


def test_user_id_list_collects_and_dedups():
    class Args:
        user_id = "3"
        user_ids = "3, 4 ,5"
    assert zap_auth._user_id_list(Args()) == ["3", "4", "5"]

    class Args2:
        user_id = None
        user_ids = "7,8"
    assert zap_auth._user_id_list(Args2()) == ["7", "8"]

    class Args3:
        user_id = "9"
        user_ids = None
    assert zap_auth._user_id_list(Args3()) == ["9"]


def test_clear_authentication_removes_all_users(monkeypatch):
    """Multi-account teardown must remove every user, then the context."""
    calls = []

    def fake(cfg, fmt, comp, kind, name, params=None):
        calls.append((name, params))
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        context_id = "1"
        user_id = "10"
        user_ids = "11,12"

    out = zap_auth.cmd_clear_authentication({}, Args())
    removed = [p["userId"] for (n, p) in calls if n == "removeUser"]
    assert removed == ["10", "11", "12"]
    # forced-user off happened before any removeUser
    assert calls[0][0] == "setForcedUserModeEnabled"
    assert any(n == "removeContext" for (n, _p) in calls)
    assert out["complete"] is True
    assert set(out["remove_users"]) == {"10", "11", "12"}


def test_clear_authentication_incomplete_when_a_user_removal_fails(monkeypatch):
    def fake(cfg, fmt, comp, kind, name, params=None):
        if name == "removeUser" and params.get("userId") == "12":
            return {"ok": False, "error": {"code": "result_fail", "message": "x"}}
        return {"ok": True}

    monkeypatch.setattr(zap_auth, "zap_call", fake)

    class Args:
        context = "dast-run"
        context_id = "1"
        user_id = None
        user_ids = "11,12"

    out = zap_auth.cmd_clear_authentication({}, Args())
    assert out["complete"] is False


@pytest.fixture
def local_app():
    """A real HTTP server on loopback. No ZAP involved — this pins the DIRECT read's own
    transport, which stubs at a higher level cannot see."""
    import http.server
    import socket
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/landed")
                self.send_header("Set-Cookie", "anon=1; Path=/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/landed":
                body = ("<p>cookie=%s</p>" % ("anon=1" in self.headers.get("Cookie", ""))).encode()
            elif self.path == "/utf8":
                body = "<p>ようこそ／ログアウト</p>".encode()      # no charset in the header
            else:
                body = b"<p>hello</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")     # deliberately no charset
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_direct_reader_does_not_follow_redirects_by_itself(local_app):
    """Following on this side only is defect 4. `follow_redirects` owns the walk, so both
    sides walk by the same rules — the transport must hand back the 3xx untouched."""
    resp = zap_auth.DirectReader().fetch(local_app + "/redirect")
    assert resp.ok is True
    assert resp.status == 302
    assert zap_auth.header_value(resp.header, "location") == "/landed"


def test_direct_reader_ignores_proxy_environment_variables(local_app, monkeypatch):
    """`HTTP_PROXY` on a DAST workstation frequently points AT ZAP — which would make the
    'unauthenticated' read authenticated — and a corporate proxy's block page would be
    accepted as the application's anonymous response."""
    for var in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")     # discard port: nothing listens
    resp = zap_auth.DirectReader().fetch(local_app + "/")
    assert resp.ok is True and resp.status == 200


def test_direct_reader_carries_its_cookies_across_hops(local_app):
    """A session app that bootstraps an anonymous session on the first hop must be followed
    the way ZAP follows it, not ping-ponged until the hop limit."""
    reader = zap_auth.DirectReader()
    out = zap_auth.follow_redirects(reader.fetch, local_app + "/redirect")
    assert out.status == 200
    assert "cookie=True" in out.body


def test_direct_reader_decodes_utf8_without_a_charset_header(local_app):
    """The live-measured false pass: `requests` applies ISO-8859-1 here, ZAP applies UTF-8,
    and the same anonymous page then looks different on the two sides."""
    resp = zap_auth.DirectReader().fetch(local_app + "/utf8")
    assert "ログアウト" in resp.body


def test_status_from_response_header():
    assert zap_auth.status_from_response_header("HTTP/1.1 200 OK\r\nX: y") == 200
    assert zap_auth.status_from_response_header("HTTP/1.1 302 Found") == 302
    assert zap_auth.status_from_response_header("") is None
    assert zap_auth.status_from_response_header("garbage") is None


def _message(url, status, body, extra_headers="", msg_id=1):
    return {"id": str(msg_id),
            "requestHeader": f"GET {url} HTTP/1.1\r\nhost: localhost:3000",
            "responseHeader": f"HTTP/1.1 {status} X{extra_headers}",
            "responseBody": body}


BASE = "http://localhost:3000"


def _stub_both_sides(monkeypatch, authed, unauth):
    """Stub the two TRANSPORTS, not the two reads.

    Each map is {url: (status, header_fields, body)}; a URL that is absent is a transport
    failure. Stubbing this low means `cmd_test_authentication` runs its real wiring —
    including the redirect walk on BOTH sides, which is the part that has no other cover.
    """
    calls = []

    def fake_zap_call(cfg, fmt, component, kind, name, params=None):
        calls.append(name)
        if name == "accessUrl":
            url = (params or {}).get("url")
            if url not in authed:
                return {"ok": False, "status": 400, "data": None}
            status, header, body = authed[url]
            return {"ok": True, "data": {"accessUrl": [{
                "id": "9", "requestHeader": f"GET {url} HTTP/1.1",
                "responseHeader": f"HTTP/1.1 {status} X" + (f"\r\n{header}" if header else ""),
                "responseBody": body}]}}
        return {"ok": True, "data": {}}

    def fake_get(_self, url):
        if url not in unauth:
            return False, None, "", ""
        status, header, body = unauth[url]
        return (True, status,
                f"HTTP/1.1 {status} X" + (f"\r\n{header}" if header else ""), body)

    monkeypatch.setattr(zap_auth, "zap_call", fake_zap_call)
    monkeypatch.setattr(zap_auth.DirectReader, "_get", fake_get)
    return calls


def _args(**kw):
    kw.setdefault("identity_markers", None)
    return type("Args", (), kw)


def test_test_authentication_reads_authed_via_zap(monkeypatch):
    """The authed read must come from ZAP (forced user applies), NOT a second direct
    fetch — otherwise both sides are identical and verification can never pass."""
    calls = _stub_both_sides(
        monkeypatch,
        authed={f"{BASE}/rest/user/whoami": (200, "", '{"user":{"email":"alice@juice-sh.op"}}')},
        unauth={f"{BASE}/rest/user/whoami": (401, "", '{"user":{}}')})

    ev = zap_auth.cmd_test_authentication({"target": {"base_url": BASE}}, _args(
        verification_url="/rest/user/whoami",
        logged_in_indicator="alice@juice-sh.op",
        identity_markers="alice@juice-sh.op"))

    assert "accessUrl" in calls                          # went through ZAP
    assert ev["status_authed"] == 200
    assert ev["status_unauth"] == 401
    assert ev["indicator_in_authed"] is True
    assert ev["indicator_in_unauth"] is False
    assert ev["indicator_is_differential"] is True
    assert ev["evidence_complete"] is True
    assert ev["identity_markers_in_authed"]["alice@juice-sh.op"] is True
    # Still no verdict — the caller decides.
    assert "authenticated" not in ev and "verdict" not in ev


def test_test_authentication_follows_redirects_on_BOTH_sides(monkeypatch):
    """The session-app shape, end to end through the command.

    Both sides redirect: the signed-in user to `/profile/` (trailing slash), everyone else
    to `/login`. Removing EITHER `follow_redirects` wrapper has to fail here — testing the
    walk in isolation left both removals silent.
    """
    _stub_both_sides(
        monkeypatch,
        authed={f"{BASE}/profile": (301, "Location: /profile/", ""),
                f"{BASE}/profile/": (200, "", "<p>alice@test.local</p>")},
        unauth={f"{BASE}/profile": (302, "Location: /login", ""),
                f"{BASE}/login": (200, "", "<h1>Sign in</h1>")})

    ev = zap_auth.cmd_test_authentication({"target": {"base_url": BASE}}, _args(
        verification_url="/profile", logged_in_indicator="alice"))

    assert ev["authed_read_url"] == f"{BASE}/profile/"     # authed side followed
    assert ev["unauth_read_url"] == f"{BASE}/login"        # unauth side followed
    assert [h["status"] for h in ev["authed_redirect_chain"]] == [301]
    assert [h["status"] for h in ev["unauth_redirect_chain"]] == [302]
    assert ev["indicator_is_differential"] is True
    assert ev["status_differs"] is False                  # both landed on 200
    assert ev["authed_chain_cut"] is None and ev["unauth_chain_cut"] is None


def test_test_authentication_stops_at_an_excluded_redirect_target(monkeypatch):
    """The exclude list has to reach the walk from the CONFIG, not just from an argument."""
    _stub_both_sides(
        monkeypatch,
        authed={f"{BASE}/account": (302, "Location: /api/reset", "")},
        unauth={f"{BASE}/account": (302, "Location: /api/reset", "")})

    cfg = {"target": {"base_url": BASE}, "exclude": {"paths": ["/api/reset"]}}
    ev = zap_auth.cmd_test_authentication(cfg, _args(
        verification_url="/account", logged_in_indicator="alice"))

    for side in ("authed", "unauth"):
        assert ev[f"{side}_redirect_chain"][-1]["followed"] is False
        assert "exclude.paths" in ev[f"{side}_chain_cut"]


def test_a_cut_chain_is_reported_at_the_top_level(monkeypatch):
    """A chain cut off-origin leaves a bodiless 3xx, which almost any indicator 'passes'
    against — so the caller must not have to dig through the chain to learn it."""
    _stub_both_sides(
        monkeypatch,
        authed={f"{BASE}/account": (200, "", "Signed in as alice")},
        unauth={f"{BASE}/account": (302, "Location: https://sso.example/authorize", "")})

    ev = zap_auth.cmd_test_authentication({"target": {"base_url": BASE}}, _args(
        verification_url="/account", logged_in_indicator="alice"))

    assert ev["unauth_chain_cut"] and "origin" in ev["unauth_chain_cut"]
    assert ev["authed_chain_cut"] is None
    # Still "differential" on the raw rule — which is exactly why the cut has to be visible.
    assert ev["indicator_is_differential"] is True


def test_test_authentication_refuses_without_an_indicator(monkeypatch):
    """No indicator meant every comparison came back null with exit 0 — indistinguishable
    from a verified differential to a caller that checks the exit status."""
    _stub_both_sides(monkeypatch, authed={f"{BASE}/": (200, "", "x")},
                     unauth={f"{BASE}/": (200, "", "x")})
    with pytest.raises(zap_auth.AuthUsageError, match="requires --logged-in-indicator"):
        zap_auth.cmd_test_authentication({"target": {"base_url": BASE}}, _args(
            verification_url="/", logged_in_indicator=None))


def test_verification_url_must_be_in_allowed_hosts(monkeypatch):
    """`--verification-url` may carry a full URL, and everything downstream (the same-origin
    rule) is anchored to it — so the scope boundary has to be checked here too."""
    _stub_both_sides(monkeypatch, authed={}, unauth={})
    cfg = {"target": {"base_url": BASE, "allowed_hosts": ["localhost", "127.0.0.1"]}}
    with pytest.raises(zap_auth.AuthUsageError, match="allowed_hosts"):
        zap_auth.cmd_test_authentication(cfg, _args(
            verification_url="http://evil.example/probe", logged_in_indicator="alice"))


def test_authed_read_never_returns_another_urls_response(monkeypatch):
    """ZAP's own login and poll traffic shares the history window with our request.

    Measured: one accessUrl call sits among `GET /login`, `POST /login`, poll requests and
    site-tree placeholder entries that carry no response at all. The old matcher tested
    whether the target's path appeared anywhere in the request line — for the DEFAULT
    verification URL that path is the empty string, which matches every entry — and took
    the newest match, so a login page could be reported as the authenticated response.
    """
    def fake_zap_call(cfg, fmt, component, kind, name, params=None):
        if name == "numberOfMessages":
            return {"ok": True, "data": {"numberOfMessages": "5"}}
        if name == "accessUrl":
            return {"ok": True, "data": {"accessUrl": "OK"}}   # older ZAP: no message back
        if name == "messages":
            # ids are 1-based, `start` is a 0-based offset — as measured on ZAP 2.17.
            history = [_message(f"{BASE}/older", 200, "", msg_id=i) for i in range(1, 5)] + [
                _message(f"{BASE}/", 200, "<html>stale anonymous read</html>", msg_id=5),
                _message(f"{BASE}/", 200, "<html>anonymous shell</html>", msg_id=6),  # ours
                _message(f"{BASE}/login", 200, "<html>Sign in</html>", msg_id=7),
                {"id": "8", "requestHeader": f"POST {BASE}/login HTTP/1.1",
                 "responseHeader": "HTTP/1.1 302 Found\r\nSet-Cookie: sessionid=x",
                 "responseBody": ""},
                # ZAP records site-tree nodes with no response at all, newest of all here.
                {"id": "9", "requestHeader": f"GET {BASE}/ HTTP/1.1",
                 "responseHeader": "HTTP/1.0 0", "responseBody": ""},
            ]
            # Measured on ZAP 2.17.0: `start` selects by ID, not by position.
            start = int((params or {}).get("start", 0))
            count = int((params or {}).get("count", len(history)))
            window = [m for m in history if int(m["id"]) >= start]
            return {"ok": True, "data": {"messages": window[:count]}}
        return {"ok": True, "data": {}}

    monkeypatch.setattr(zap_auth, "zap_call", fake_zap_call)
    out = zap_auth._fetch_through_zap({}, f"{BASE}/")
    assert out.ok is True
    assert out.status == 200
    assert "anonymous shell" in out.body      # ours...
    assert "Sign in" not in out.body          # ...not the login page that came after it
    assert "stale" not in out.body            # ...and not the one recorded before our call


def test_history_entries_are_dated_by_id_not_by_window_position(monkeypatch):
    """If a ZAP version treats `start` as an offset — or history has been pruned so ids and
    positions diverge — the window begins one message early, and that message is the last
    one from BEFORE our call."""
    stale = _message(f"{BASE}/api/me", 200, '{"user":"alice"}', msg_id=41)
    ours = _message(f"{BASE}/api/me", 401, '{"error":"anonymous"}', msg_id=42)

    def fake_zap_call(cfg, fmt, component, kind, name, params=None):
        if name == "messages":                       # offset-style: hands back one too many
            return {"ok": True, "data": {"messages": [stale, ours]}}
        return {"ok": True, "data": {}}

    monkeypatch.setattr(zap_auth, "zap_call", fake_zap_call)
    entries = zap_auth._history_entries_after({}, 41)
    assert [e["id"] for e in entries] == ["42"]


def test_authed_read_refuses_to_guess_when_the_history_cannot_be_dated(monkeypatch):
    """`numberOfMessages` failing used to become a 0 and open the WHOLE history to the
    fallback — where ZAP's own authenticated poll of the same URL is waiting."""
    def fake_zap_call(cfg, fmt, component, kind, name, params=None):
        if name == "numberOfMessages":
            return {"ok": False, "status": 400, "data": None}
        if name == "accessUrl":
            return {"ok": True, "data": {"accessUrl": "OK"}}
        if name == "messages":
            return {"ok": True, "data": {"messages": [
                _message(f"{BASE}/api/me", 200, '{"user":"alice"}', msg_id=1)]}}
        return {"ok": True, "data": {}}

    monkeypatch.setattr(zap_auth, "zap_call", fake_zap_call)
    out = zap_auth._fetch_through_zap({}, f"{BASE}/api/me")
    assert out.ok is False
    assert "dated" in out.via


def test_authed_read_is_not_ok_when_the_response_is_missing(monkeypatch):
    """No entry for the URL is 'we did not observe it', never an empty response."""
    def fake_zap_call(cfg, fmt, component, kind, name, params=None):
        if name == "numberOfMessages":
            return {"ok": True, "data": {"numberOfMessages": "0"}}
        if name == "accessUrl":
            return {"ok": True, "data": {"accessUrl": "OK"}}
        if name == "messages":
            return {"ok": True, "data": {"messages": [
                _message("http://localhost:3000/login", 200, "<html>Sign in</html>")]}}
        return {"ok": True, "data": {}}

    monkeypatch.setattr(zap_auth, "zap_call", fake_zap_call)
    assert zap_auth._fetch_through_zap({}, "http://localhost:3000/account").ok is False


def test_test_authentication_exits_nonzero_when_a_side_could_not_be_read(monkeypatch):
    """The CLI contract: unreadable evidence is not a pass, and not a silent one either."""
    _stub_both_sides(monkeypatch,
                     authed={f"{BASE}/guarded": (200, "", '{"user":"alice"}')},
                     unauth={})          # the anonymous read never completes
    rc = zap_auth.main(["test-authentication", "--config", EXAMPLE_CFG,
                        "--verification-url", f"{BASE}/guarded",
                        "--logged-in-indicator", "alice", "--json"])
    assert rc == 1


def test_evidence_non_differential_indicator():
    # An indicator present in BOTH responses is not differential (the classic false pass).
    ev = zap_auth.evidence_from_responses(
        _resp(200, "Logout"), _resp(200, "Logout"), logged_in_indicator="Logout",
    )
    assert ev["indicator_is_differential"] is False


def test_evidence_is_incomplete_when_a_read_failed():
    """A read that never happened must not read as 'the indicator was absent there'.

    Measured against a live target whose unauthenticated requests are dropped without a
    response: the old code answered indicator_is_differential=true with nothing on the
    other side at all — an absence of evidence promoted to the strongest possible pass.
    """
    ev = zap_auth.evidence_from_responses(
        _resp(200, '{"user":"alice"}'),
        zap_auth.Response(ok=False, url="http://h/probe"),
        logged_in_indicator="alice", identity_markers=["alice"],
    )
    assert ev["unauth_read_ok"] is False
    assert ev["evidence_complete"] is False           # -> exit code 1
    assert ev["indicator_is_differential"] is None    # not True, and not False either
    assert ev["indicator_in_unauth"] is None
    assert ev["identity_markers_in_unauth"]["alice"] is None
    assert ev["status_differs"] is None
    # The side that WAS read is still reported.
    assert ev["indicator_in_authed"] is True


def test_evidence_matches_response_headers_not_only_the_body():
    """ZAP matches its patterns on the response header too (measured), so evidence must.

    The session-app case: an SPA shell whose body is byte-identical either way, with the
    only difference in a response header. Body-only matching calls this non-differential
    and, under the stop-on-unverified rule, makes the target undiagnosable.
    """
    shell = "<html><body><div id='root'></div></body></html>"
    ev = zap_auth.evidence_from_responses(
        _resp(200, shell, header="HTTP/1.1 200 OK\r\nX-Authenticated-User: alice"),
        _resp(200, shell, header="HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=deadbeef"),
        logged_in_indicator="X-Authenticated-User", identity_markers=["alice"],
    )
    assert ev["indicator_is_differential"] is True
    assert ev["indicator_where_authed"] == "header"
    assert ev["indicator_where_unauth"] is None
    assert ev["identity_markers_in_authed"]["alice"] is True
    assert ev["identity_markers_in_unauth"]["alice"] is False


def test_indicator_in_the_UNAUTH_header_is_not_differential():
    """The other direction of the header fix. A session app that always emits the header —
    `alice` signed in, `anonymous` otherwise — must NOT read as differential; matching the
    header on the authed side only would call this verified."""
    shell = "<html><body><div id='root'></div></body></html>"
    ev = zap_auth.evidence_from_responses(
        _resp(200, shell, header="HTTP/1.1 200 OK\r\nX-Authenticated-User: alice"),
        _resp(200, shell, header="HTTP/1.1 200 OK\r\nX-Authenticated-User: anonymous"),
        logged_in_indicator="X-Authenticated-User",
    )
    assert ev["indicator_in_unauth"] is True
    assert ev["indicator_where_unauth"] == "header"
    assert ev["indicator_is_differential"] is False


def test_the_indicator_is_a_regex_the_way_zap_treats_it():
    """ZAP's parameter is `loggedInIndicatorRegex`, and measured behaviour agrees: with
    `Signed ?in as` it logs in once against "Signed in as alice", where a literal match
    would fail and make it storm. A literal matcher here reported 'absent' for a
    configuration ZAP was happy with — under the stop rule, that ends the run."""
    for pattern in ("Signed ?in as", "Signed in as|Logged in as", r"Signed in as \w+"):
        ev = zap_auth.evidence_from_responses(
            _resp(200, "<p>Signed in as alice</p>"), _resp(200, "<h1>Sign in</h1>"),
            logged_in_indicator=pattern)
        assert ev["indicator_is_differential"] is True, pattern
    # A pattern that cannot compile falls back to a literal search rather than exploding.
    ev = zap_auth.evidence_from_responses(
        _resp(200, "total is 100% [ok"), _resp(200, "no"), logged_in_indicator="100% [ok")
    assert ev["indicator_in_authed"] is True


def test_the_status_line_is_not_part_of_the_matched_surface():
    """`OK`/`200` as an indicator would otherwise match every 200 response's status line and
    turn the differential into "the statuses differed" — the first thing the fixed rule
    forbids."""
    body = "<html>identical either way</html>"
    ev = zap_auth.evidence_from_responses(
        _resp(200, body, header="HTTP/1.1 200 OK"),
        _resp(401, body, header="HTTP/1.1 401 Unauthorized"),
        logged_in_indicator="OK")
    assert ev["indicator_in_authed"] is False
    assert ev["indicator_is_differential"] is False


def test_an_indicator_in_a_followed_redirect_still_counts():
    """ZAP evaluates every response it sees, so a `Location`-based indicator matches for
    ZAP. Following redirects must not make exactly those indicators invisible here."""
    authed = zap_auth.Response(
        ok=True, status=200, header="HTTP/1.1 200 OK", body="<html>dashboard</html>",
        hop_headers=("HTTP/1.1 302 Found\r\nLocation: /dashboard",))
    unauth = zap_auth.Response(
        ok=True, status=200, header="HTTP/1.1 200 OK", body="<html>dashboard</html>",
        hop_headers=("HTTP/1.1 302 Found\r\nLocation: /login",))
    ev = zap_auth.evidence_from_responses(authed, unauth, logged_in_indicator="/dashboard")
    assert ev["indicator_where_authed"] == "redirect"
    assert ev["indicator_in_unauth"] is False
    assert ev["indicator_is_differential"] is True


def test_a_charsetless_utf8_page_decodes_the_same_on_both_sides():
    """Measured against a live ZAP: for `text/html` with no charset, ZAP decodes UTF-8 while
    `requests` applies the RFC default of ISO-8859-1. Two reads of the SAME anonymous page
    then produced a perfect differential built out of mojibake."""
    page = "<html><body><p>ようこそ／ログアウト</p></body></html>".encode()
    assert zap_auth.decode_body(page, "text/html") == page.decode()
    assert zap_auth.decode_body(page, "text/html; charset=utf-8") == page.decode()
    assert zap_auth.decode_body("<p>x</p>".encode("shift_jis"), "text/html; charset=shift_jis")
    # Undecodable bytes must not fail the read outright.
    assert zap_auth.decode_body(b"\xff\xfe\x00", "application/octet-stream")


def test_evidence_reports_where_the_indicator_matched():
    ev = zap_auth.evidence_from_responses(
        _resp(200, "Signed in as alice", header="HTTP/1.1 200 OK\r\nX-User: alice"),
        _resp(200, "Sign in"), logged_in_indicator="alice",
    )
    assert ev["indicator_where_authed"] == "both"


# --- redirect handling (the two sides must be read the same way) --------------
def test_redirects_are_followed_on_both_sides_with_the_same_rules():
    """A session app redirects BOTH sides — the authed request to /profile/ and the
    anonymous one to /login. Following one side only compares two different pages: measured
    301-with-an-empty-body against the login page, indicator on neither, run stopped."""
    pages = {
        "http://h/profile": zap_auth.Response(
            ok=True, status=301, header="HTTP/1.1 301 Moved\r\nLocation: /profile/"),
        "http://h/profile/": zap_auth.Response(
            ok=True, status=200, header="HTTP/1.1 200 OK", body="alice@test.local"),
    }
    out = zap_auth.follow_redirects(lambda u: pages[u], "http://h/profile")
    assert out.url == "http://h/profile/"
    assert out.status == 200 and "alice" in out.body
    assert out.chain[0]["status"] == 301 and out.chain[0]["followed"] is True


def test_redirect_following_stops_at_the_hop_limit_and_says_so():
    loop = zap_auth.Response(ok=True, status=302,
                             header="HTTP/1.1 302 Found\r\nLocation: /next")
    out = zap_auth.follow_redirects(lambda u: loop, "http://h/start", max_hops=2)
    assert len(out.chain) == 3                      # 2 followed + the one that stopped
    assert out.chain[-1]["followed"] is False
    assert "redirect limit" in out.chain[-1]["stopped"]


def test_redirect_off_origin_is_not_followed():
    """Leaving the target's origin is where the evidence stops being about the target."""
    resp = zap_auth.Response(
        ok=True, status=302, header="HTTP/1.1 302 Found\r\nLocation: https://sso.example/x")
    out = zap_auth.follow_redirects(lambda u: resp, "http://h/login")
    assert out.status == 302
    assert out.chain[-1]["followed"] is False
    assert "origin" in out.chain[-1]["stopped"]
    assert "sso.example" in out.chain[-1]["stopped"]


def test_redirect_into_an_excluded_path_is_not_followed():
    resp = zap_auth.Response(ok=True, status=302,
                             header="HTTP/1.1 302 Found\r\nLocation: /api/reset")
    out = zap_auth.follow_redirects(lambda u: resp, "http://h/account",
                                    exclude_paths=["/api/reset"])
    assert out.chain[-1]["followed"] is False
    assert "exclude.paths" in out.chain[-1]["stopped"]
    assert zap_auth.path_is_excluded("http://h/api/reset?x=1", ["/api/reset"]) == "/api/reset"
    assert zap_auth.path_is_excluded("http://h/api/reset/all", ["/api/reset"]) == "/api/reset"
    assert zap_auth.path_is_excluded("http://h/api/resettle", ["/api/reset"]) is None
    # A Location header is app-controlled, so spelling must not be a way around the guard.
    assert zap_auth.path_is_excluded("http://h/API/Reset", ["/api/reset"]) == "/api/reset"
    assert zap_auth.path_is_excluded("http://h/api/re%73et", ["/api/reset"]) == "/api/reset"
    # A malformed entry must not turn into "exclude everything" and stop every redirect.
    assert zap_auth.path_is_excluded("http://h/account", ["", "  ", "/"]) is None


def test_a_redirect_to_logout_is_never_followed_even_without_exclude_paths():
    """`exclude.paths` is optional and nothing requires `/logout` to be in it — but
    following a redirect into logout destroys the session being verified, as the forced
    user, leaving every later step to fail for a reason that is no longer visible."""
    resp = zap_auth.Response(ok=True, status=302,
                             header="HTTP/1.1 302 Found\r\nLocation: /accounts/logout/")
    out = zap_auth.follow_redirects(lambda u: resp, "http://h/account")   # no excludes
    assert out.chain[-1]["followed"] is False
    assert "ends the session" in out.chain[-1]["stopped"]

    for path in ("/logout", "/accounts/logout/", "/api/v1/logout", "/users/sign_out",
                 "/session/destroy", "/LogOff", "/log%6Fut"):
        assert zap_auth.is_session_ending("http://h" + path), path
    for path in ("/logout-report", "/account", "/logouts/history"):
        assert zap_auth.is_session_ending("http://h" + path) is None, path


def test_same_host_http_to_https_upgrade_is_followed():
    """Django SECURE_SSL_REDIRECT / Rails force_ssl / nginx `return 301 https://$host`:
    refusing this stops BOTH sides on an empty 301 and blames authentication for it."""
    pages = {
        "http://app.test/account": zap_auth.Response(
            ok=True, status=301, header="HTTP/1.1 301 Moved\r\nLocation: https://app.test/account"),
        "https://app.test/account": zap_auth.Response(
            ok=True, status=200, header="HTTP/1.1 200 OK", body="Signed in as alice"),
    }
    out = zap_auth.follow_redirects(lambda u: pages[u], "http://app.test/account")
    assert out.status == 200 and "alice" in out.body
    # ...but only upward, and only for the same host.
    assert zap_auth.is_safe_upgrade("https://other.test/x", "http://app.test/x") is False
    assert zap_auth.is_safe_upgrade("http://app.test/x", "https://app.test/x") is False


def test_origin_comparison_normalises_case_and_default_ports():
    assert zap_auth.same_origin("http://App.Test/x", "http://app.test:80/y") is True
    assert zap_auth.same_origin("https://app.test/x", "https://app.test:443/y") is True
    assert zap_auth.same_origin("http://app.test:8080/x", "http://app.test/y") is False


def test_recorded_urls_never_carry_a_query_string():
    """A redirect target is chosen by the application: on an OIDC flow its query holds the
    authorization code, state and nonce, and this output is copied into artifacts."""
    resp = zap_auth.Response(
        ok=True, status=302,
        header="HTTP/1.1 302 Found\r\n"
               "Location: https://sso.example/authorize?code=SplxlOBeZQ&state=af0ifj&nonce=abc")
    out = zap_auth.follow_redirects(lambda u: resp, "http://app.test/account?next=/x")
    blob = json.dumps({"chain": list(out.chain), "url": zap_auth.safe_url(out.url)})
    for secret in ("SplxlOBeZQ", "af0ifj", "abc", "next=/x"):
        assert secret not in blob, blob
    assert "<query omitted>" in blob
    assert "sso.example" in out.chain[-1]["stopped"]      # the origin is still named


def test_header_value_is_case_insensitive_and_skips_the_status_line():
    header = "HTTP/1.1 302 Found\r\nlocation: /login\r\nSet-Cookie: a=b"
    assert zap_auth.header_value(header, "Location") == "/login"
    assert zap_auth.header_value(header, "missing") is None


# --- CLI guards (reach the guard before any network call) --------------------
def test_configure_auth_refuses_auto_via_cli():
    rc = zap_auth.main([
        "configure-authentication", "--config", EXAMPLE_CFG,
        "--context-id", "1", "--method", "auto",
    ])
    assert rc == 2


def test_active_scan_requires_gate_via_cli():
    rc = zap_auth.main([
        "active-scan-as-user", "--config", EXAMPLE_CFG,
        "--context-id", "1", "--user-id", "0",
    ])
    assert rc == 2


class _Args:
    context_id = "1"
    user_id = "0"
    username_env = "DAST_USERNAME"
    password_env = "DAST_PASSWORD"
    cred_template = None


def test_set_credentials_missing_env_returns_not_ok(monkeypatch):
    monkeypatch.delenv("DAST_USERNAME", raising=False)
    monkeypatch.delenv("DAST_PASSWORD", raising=False)
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    out = zap_auth.cmd_set_credentials(cfg, _Args())
    assert out["ok"] is False
    assert set(out) <= {"ok", "reason"}


def test_set_credentials_does_not_echo_secret_values(monkeypatch):
    # Even on success, the credential VALUES must never appear in the return structure.
    monkeypatch.setenv("DAST_USERNAME", "alice")
    monkeypatch.setenv("DAST_PASSWORD", "sup3r-s3cr3t-value")
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda *a, **k: {"ok": True, "status": 200, "data": {"Result": "OK"}})
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    out = zap_auth.cmd_set_credentials(cfg, _Args())
    assert out["ok"] is True
    blob = str(out)
    assert "sup3r-s3cr3t-value" not in blob
    assert "alice" not in blob


# --- exit-code contract: a failed command must not report success ------------
def test_detect_capabilities_is_not_ok_when_zap_is_unreachable(monkeypatch):
    """authentication.md makes detect-capabilities the test for "ZAP's authentication
    features are unusable", which is a STOP condition. Without a top-level ok key main()
    would exit 0 and the caller would walk past it."""
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda *a, **k: {"ok": False, "status": None, "data": None})
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    out = zap_auth.cmd_detect_capabilities(cfg, _Args())
    assert out["ok"] is False
    assert out["reachable"] is False


def test_detect_capabilities_is_not_ok_when_zap_refuses_the_auth_view(monkeypatch):
    """ZAP is up, but the authentication view is rejected (missing add-on, bad key)."""
    def fake(cfg, fmt, component, kind, name, params=None):
        if component == "authentication":
            return {"ok": False, "status": 400,
                    "data": {"code": "no_implementor", "message": "no"}}
        return {"ok": True, "status": 200, "data": {"version": "2.17.0"}}

    monkeypatch.setattr(zap_auth, "zap_call", fake)
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    out = zap_auth.cmd_detect_capabilities(cfg, _Args())
    assert out["reachable"] is True
    assert out["ok"] is False


def test_set_forced_user_reports_a_failed_call(monkeypatch):
    """A silently failed setForcedUser makes test-authentication read the unauthenticated
    side twice, which looks like a target that cannot authenticate and stops the run."""
    monkeypatch.setattr(zap_auth, "zap_call", lambda *a, **k: {
        "ok": False, "status": 400, "data": {"code": "illegal_parameter", "message": "no"}})
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    args = _Args()
    args.state = "on"
    args.user_id = "3"
    args.context_id = "1"
    out = zap_auth.cmd_set_forced_user(cfg, args)
    assert out["ok"] is False


def test_set_forced_user_off_is_ok_when_the_call_succeeds(monkeypatch):
    monkeypatch.setattr(zap_auth, "zap_call",
                        lambda *a, **k: {"ok": True, "status": 200, "data": {"Result": "OK"}})
    cfg, _ = zap_auth._load_cfg(EXAMPLE_CFG)
    args = _Args()
    args.state = "off"
    out = zap_auth.cmd_set_forced_user(cfg, args)
    assert out["ok"] is True
    assert out["forced_user_enabled"] is False
