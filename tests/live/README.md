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

**A dedicated daemon, not one you are also using.** The scope suite changes state that is
global to the ZAP session rather than scoped to a context: `core/action/setMode`, the
`spider`/`ascan` exclusion lists, and the site tree itself. Each is restored or cleared in
teardown, and each test gets its own target port so the site nodes cannot collide — but
several of the behaviours being measured *depend on what is already in the tree*, so a daemon
someone else is driving will produce results that are not about the code. Running these
against a shared instance is how the site-tree order dependency below was first misread as
test contamination.

The tests never call `newSession`, on purpose: it would wipe the session of whoever owns the
daemon. The plugin does not call it either, which is exactly why the order dependency matters.

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
suites so they cannot drift apart in how they configure ZAP. `harness.include_regex()` returns
the include shape `references/zap-integration.md` recommends, so no suite hardcodes its own —
the scope tests that need a *different* shape build it locally, which is the point of them.

`test_live_scope.py` covers the scope layer rather than authentication: Protected mode, how the
Active Scan has to be seeded, and what an exclusion actually reaches.

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

### Scope, mode and exclusions (`test_live_scope.py`)

| Test | The behaviour, and why it bites |
| --- | --- |
| `test_a_new_context_is_in_scope_by_default` | `inScope` is already `true`, which is why no step calls `setContextInScope`. If the default flips, every scanner starts refusing for a reason no step accounts for. |
| `test_protect_mode_refuses_a_root_recursive_active_scan` | Protected mode (mandated) plus the recommended include (slash after the host) refuses `ascan` seeded at the root: recursion evaluates the *starting* node as the bare site node, which the regex deliberately does not match. This is why the Active Scan is launched against the context instead. |
| `test_recurse_false_scans_only_the_seed_node` | The trap waiting for whoever meets that refusal. `recurse=false` clears it, runs to 100%, and attacks nothing below the root — a completed Active Scan that tested one page. |
| `test_active_scan_needs_a_context_when_no_url_is_given` | Dropping the context as well is refused, so omitting `url` cannot silently widen into "scan the whole site tree". |
| `test_the_context_form_honours_context_exclusions` | Dropping the url must not drop `exclude.paths` with it: the excluded endpoint takes no attacks, its neighbour does. |
| `test_the_context_form_leaves_hosts_outside_the_context_alone` | A host in the site tree but outside the context stays untouched — the tree is the other half of the scope question. |
| `test_the_crawlers_are_not_subject_to_the_root_recursion_rule` | Only the Active Scan needs the context form. Measured separately because step 3 reaches the root first: if the crawlers were affected, the first visible failure would be a spider, not a scan. |
| `test_widening_the_include_after_the_tree_is_populated_is_not_recoverable` | Why the include regex was *not* widened instead. Widening works only before the target's site node exists; afterwards the refusal becomes `internal_error`, survives re-crawling and a fresh context, and clears only via `deleteSiteNode` — which needs the **bare** origin (a trailing slash answers OK and removes nothing). Both real shapes are covered: reusing a daemon for a second run, and `--from` re-entry. |
| `test_access_url_reaches_an_out_of_context_host_in_any_mode` | `core/action/accessUrl` is bound by neither the mode (protect *and* safe) nor the context, while the spider is refused in the same breath. That path is what `test-authentication`, `verify-canary` and the step-6 probes use, so its boundary is the wrapper's `allowed_hosts` check and prompt discipline — nothing else. |
| `test_an_excluded_url_gets_no_forced_user_credentials` | Excluding a URL also stops the forced user's credentials reaching it: 401, no `Authorization`, no login attempt, no error. Exclude the verification URL or a canary and the run ends in "cannot authenticate" with a perfectly correct configuration. |
| `test_scanner_exclusions_are_session_scoped_and_ignore_context_name` | `spider`/`ascan` exclusions belong to the session, outlive the context, and leak into the daemon owner's ZAP where they quietly drop part of every later scan. `contextName` does not scope them — ZAP answers OK and ignores it. |

## After a ZAP upgrade

Run these first. They are the cheapest way to find out whether the version changed any of the
behaviours above; the offline suite will stay green regardless, because it only knows what we
believe ZAP requires.
