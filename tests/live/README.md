# Live authentication tests (opt-in)

The offline suite (`tests/test_*.py`) can only assert what `zap_auth.py` **sends**. These
tests assert what ZAP **does** with it, and what the wrapper reads back. Everything here was
found by measuring a running ZAP, not by reading the API documentation — and each one fails
*silently* in a real run, which is why they are worth the setup cost.

They are skipped unless `DAST_LIVE_ZAP` is set, so `pytest tests/` stays offline and fast.

## Running

```bash
ZAP_HOME=$(mktemp -d)
zap.sh -daemon -host 127.0.0.1 -port 8090 -dir "$ZAP_HOME" \
       -config api.disablekey=true -config insights.exitAuto=false &
# wait for http://127.0.0.1:8090/JSON/core/view/version/ to answer

DAST_LIVE_ZAP=http://127.0.0.1:8090 python -m pytest tests/live -v
```

`insights.exitAuto=false` is **required**. Several of these tests provoke a genuine
re-authentication storm, and the insights add-on answers a high auth-failure rate by shutting
the daemon down — measured here as `insight.auth.failure : 83`, which killed ZAP mid-suite and
made every later test fail with a bare connection error. The switch belongs in this harness
and nowhere else: in a real run that shutdown is a true signal, and disabling it would only
hide a scan that has stopped authenticating.

Use a throwaway `-dir`: the tests create contexts and users, and a ZAP home you care about is
not the place for that. They do clean up after themselves — contexts and users carry a unique
`dast-live-<pid>-<ms>` prefix and are removed in teardown even when a test fails — but a
scratch home makes the guarantee unnecessary.

## Two targets, because the defects differ by shape

Both are started by the tests on a free port; you do not run them yourself.

`target.py` is **token-shaped** (Juice Shop): a Bearer header, JSON bodies, an
authentication-only endpoint, an authenticated JSON API, an error route that is *not* about
authentication, and a plain HTML page. That mix matters — a canary driven over a single
response shape cannot tell a healthy configuration from a storming one.

`target_cookie.py` is **session-shaped** (Rails / Django / Laravel): a form login that sets a
session cookie, an anonymous request answered with a **redirect to `/login`** rather than a
401 with a body, a page whose authenticated version is *also* a redirect (`/profile` → 301
`/profile/`), an SPA shell whose body is **byte-identical** either way and differs only in the
`X-Authenticated-User` response header, a route that **drops anonymous connections** with no
response at all, a "session expired" route that **redirects into `/logout`**, and two accounts
for the mutual-identity check.

The second target exists because four defects in `test-authentication` were invisible against
the first one and fatal against the second: the unauthenticated read failing was reported as a
differential *pass*; only the body was matched while ZAP matches the header too; the
authenticated response was searched for in ZAP's history with a match loose enough for ZAP's
own login traffic to stand in for it; and redirects were followed on the unauthenticated side
only. The last three make a *correctly authenticated* session unverifiable — and since an
unverified run now stops rather than degrading to anonymous, that is not lost coverage but a
target that cannot be diagnosed at all.

`harness.py` (ZAP plumbing, target startup) and `conftest.py` (fixtures) are shared by both
suites so they cannot drift apart in how they configure ZAP.

## What each test pins

| Test | The behaviour, and why it bites |
| --- | --- |
| `test_poll_url_needs_all_five_parameters` | POLL_URL rejects the call unless all five poll parameters are present; `pollData`/`pollHeaders` accept empty strings. Dropping them for being falsy is what defeated verification and sent a run into AUTO_DETECT. |
| `test_authentication_is_inert_without_an_include_regex` | With an empty context include list ZAP applies no credentials at all — 0 logins, the request goes out anonymous, **no error**. `scanAsUser` is the only loud half. |
| `test_healthy_configuration_logs_in_exactly_once` | The baseline every other assertion is measured against. |
| `test_per_response_checking_without_logged_out_indicator_storms` | `loggedIn` set + `loggedOut` unset + `EACH_*` re-authenticates on every response that lacks the marker. |
| `test_canary_separates_a_healthy_config_from_a_storming_one` | `verify-canary` catches it before the spider, and the authenticated scanners refuse on their own reading of ZAP's counters. |
| `test_setting_the_auth_method_resets_the_verification_config` | `setAuthenticationMethod` resets verification to `EACH_RESP` with no indicators — which is why the method must be configured *before* verification, and why re-running step 2.5 discards it. |
| `test_zap_matches_its_indicator_against_the_response_header` | ZAP matches the logged-in pattern against the **response header** as well as the body: over an identical-body SPA shell, a header-only indicator gives 1 login and a never-matching body indicator gives 6. This is why the evidence must be gathered the same way. |
| `test_a_header_only_difference_is_visible_to_test_authentication` | Body-only matching answered "no difference" for a working session. |
| `test_both_sides_follow_redirects_so_a_session_page_can_be_verified` | Both sides redirect on a session app; following one side compared an empty 301 body against the login page. Note `status_differs` is *false* here — the chain is where the difference is. |
| `test_an_unreadable_unauthenticated_read_is_not_a_pass` | An unauthenticated read that never completes used to satisfy the differential rule by itself. Now `evidence_complete: false` (exit 1). |
| `test_the_authenticated_read_is_the_verification_url_not_zaps_own_traffic` | ZAP's login traffic shares the history window with our request; the old matcher's key for the default verification URL was the empty string. |
| `test_a_redirect_into_logout_is_not_followed_and_the_session_survives` | `/expired` redirects into `/logout` the way a session app does. The walk refuses session-ending targets with or without `exclude.paths`; following one would destroy the session being verified, as the forced user. |
| `test_a_session_page_verifies_and_reports_the_identity` | The healthy path on a session app, end to end. |
| `test_mutual_identity_differential_between_two_accounts` | Two accounts must read back as two identities; crossed sessions void every horizontal-IDOR conclusion built on them. |

## After a ZAP upgrade

Run these first. They are the cheapest way to find out whether the version changed any of the
behaviours above; the offline suite will stay green regardless, because it only knows what we
believe ZAP requires.
