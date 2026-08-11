# Live authentication tests (opt-in)

The offline suite (`tests/test_*.py`) can only assert what `zap_auth.py` **sends**. These
tests assert what ZAP **does** with it. Everything here was found by measuring a running ZAP,
not by reading the API documentation — and each one fails *silently* in a real run, which is
why they are worth the setup cost.

They are skipped unless `DAST_LIVE_ZAP` is set, so `pytest tests/` stays offline and fast.

## Running

```bash
ZAP_HOME=$(mktemp -d)
zap.sh -daemon -host 127.0.0.1 -port 8090 -dir "$ZAP_HOME" \
       -config api.disablekey=true -config insights.exitAuto=false &
# wait for http://127.0.0.1:8090/JSON/core/view/version/ to answer

DAST_LIVE_ZAP=http://127.0.0.1:8090 python -m pytest tests/live -v
```

`insights.exitAuto=false` is **required**. One of these tests provokes a genuine
re-authentication storm, and the insights add-on answers a high auth-failure rate by shutting
the daemon down — measured here as `insight.auth.failure : 83`, which killed ZAP mid-suite and
made every later test fail with a bare connection error. The switch belongs in this harness
and nowhere else: in a real run that shutdown is a true signal, and disabling it would only
hide a scan that has stopped authenticating.

Use a throwaway `-dir`: the tests create contexts and users, and a ZAP home you care about is
not the place for that. They do clean up after themselves — contexts and users carry a unique
`dast-live-<pid>-<ms>` prefix and are removed in teardown even when a test fails — but a
scratch home makes the guarantee unnecessary.

`target.py` is started by the tests on a free port; you do not run it yourself. It is a small
token-authenticating app shaped like Juice Shop: an authentication-only endpoint, an
authenticated JSON API, an error route that is *not* about authentication, and a plain HTML
page. That mix matters — a canary driven over a single response shape cannot tell a healthy
configuration from a storming one.

## What each test pins

| Test | The behaviour, and why it bites |
| --- | --- |
| `test_poll_url_needs_all_five_parameters` | POLL_URL rejects the call unless all five poll parameters are present; `pollData`/`pollHeaders` accept empty strings. Dropping them for being falsy is what defeated verification and sent a run into AUTO_DETECT. |
| `test_authentication_is_inert_without_an_include_regex` | With an empty context include list ZAP applies no credentials at all — 0 logins, the request goes out anonymous, **no error**. `scanAsUser` is the only loud half. |
| `test_healthy_configuration_logs_in_exactly_once` | The baseline every other assertion is measured against. |
| `test_per_response_checking_without_logged_out_indicator_storms` | `loggedIn` set + `loggedOut` unset + `EACH_*` re-authenticates on every response that lacks the marker. |
| `test_canary_separates_a_healthy_config_from_a_storming_one` | `verify-canary` catches it before the spider, and the authenticated scanners refuse on their own reading of ZAP's counters. |
| `test_setting_the_auth_method_resets_the_verification_config` | `setAuthenticationMethod` resets verification to `EACH_RESP` with no indicators — which is why the method must be configured *before* verification, and why re-running step 2.5 discards it. |

## After a ZAP upgrade

Run these first. They are the cheapest way to find out whether the version changed any of the
behaviours above; the offline suite will stay green regardless, because it only knows what we
believe ZAP requires.
