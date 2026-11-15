# Browser acceptance harness

The harness uses the exact `playwright` 1.65.0 package and its `playwright/test`
runner. `package-lock.json` pins both Playwright packages and their integrity.
Node 22+ and a current native `openwarp-server` build are required. No global
Playwright install, personal browser profile, Chrome application path, CDP
attachment, or frontend build is used.

## Local commands

From the repository root, serially:

```sh
cargo build -p openwarp-server
npm --prefix tests/e2e ci --ignore-scripts
npm --prefix tests/e2e run browsers
npm --prefix tests/e2e run test:chromium
npm --prefix tests/e2e run test:critical
```

`npm --prefix tests/e2e test` runs all configured projects. Chromium runs every
case; Firefox and WebKit run only cases tagged `@critical`. The configuration
uses one worker, no parallel tests, and zero retries. Do not run this suite next
to another build or test suite. Browser installation may need system libraries
on Linux; the root CI job owns that setup.

The old entrypoints remain available from any directory:

```sh
node tests/e2e/console.mjs
node tests/e2e/step-up.mjs
OPENWARP_TEST_BROWSER=firefox node tests/e2e/step-up.mjs
```

They now select the corresponding portable runner specs. Browser selection
accepts `chromium`, `firefox`, or `webkit`; it never selects a machine browser.
Unlike the former CDP console script, the console spec clicks visible controls
and resumes a genuine cookie session instead of injecting `T` or calling
`enterApp()` directly. Screenshots previously produced by both entrypoints are
intentionally no longer produced. Root-owned visual acceptance is separate.

## Fixture and artifact boundaries

Each test owns a temporary directory, a private SQLite database, a loopback
HTTP mail sink, and a new server process. It does not inherit deployment,
provider, database, proxy, Redis, or master-key configuration. Startup checks
that the served embedded INDEX exactly matches current `ui.rs`; stale binaries
fail before browser actions. Fixture setup can use real APIs. The tested
behavior uses the visible browser UI, with no application API interception or
mocking. Browsers use Playwright's standard fresh headless launch and isolated
contexts. Fixture teardown closes the server and mail sink and removes the
database even after assertion failure.

By default no screenshots, videos, traces, storageState, downloads, request
bodies, recovery kits, tokens, or raw browser-console messages are retained.
For root-owned visual acceptance only,
`OPENWARP_TEST_BLANK_MODAL_SCREENSHOTS=1` captures cropped step-up dialogs after
asserting every factor field is blank and no kit/value editor exists. Captures
are limited to desktop Verify focus and narrow input focus, written under the
gitignored `.agents/state/browser-acceptance/blank-modals/` directory. The runner
disables Playwright's default failing-page accessible DOM capture and discards
runner output directories (`preserveOutput: 'never'`). The custom reporter
prints test names, status counts and assertion source locations, not raw
assertion values or DOM snapshots. Unexpected page errors, console errors,
failed responses and external requests fail the tests. HTTP 428 step-up
challenges are expected. Only auth specs opt into anonymous bootstrap HTTP 401:
exactly `GET /api/instance/edition` and `GET /api/me`, without Cookie or
Authorization, with expected load counts (3 for sign-in/out, 1 for signup).
Chromium/WebKit emit one native resource-console message per such response;
Firefox emits none. All other console errors and failed responses still fail. Do not override the
reporter with HTML/blob/JSON reporters for secret-bearing journeys. If a run is
hard-killed, check its private server process and temporary directory before
rerunning; normal failure and runner interruption use fixture teardown.

## Authored coverage and known gaps

These are authored scenarios, not a claim that the entire acceptance matrix has
passed. Executed results are recorded separately below.

| Spec | Browser behavior |
| --- | --- |
| `console.spec.mjs` | First four nav targets, app-scoped empty navigation, theme persistence/dark cycle, translated auth title and language persistence with user app name intact; keyboard app creation, native destructive cancellation with API read-back, narrow-screen navigation |
| `step-up.spec.mjs` | Original eight-check acceptance increment: current rebuilt console, Cancel/Escape/backdrop cancellation without verification or replay and restored focus, keyboard focus trap, narrow factor dialogs, emailed settings proof exactly once, Major recovery-code secret deployment exactly once, browser error/network checks |
| `auth.spec.mjs` | Real password UI sign-in/sign-out and fresh-context isolation; visible signup kit, local verification mail, sign-in, no kit/token localStorage key |
| `crypto.spec.mjs` | Client-supplied wrapped environment key; in-page encrypt/write/read; ciphertext API read-back and E2E request plaintext checks; reload locks then kit unlocks; member consent fixture, UI grant, member UI decrypt/read, UI revoke, owner rotation warning, removed member and outsider API denial |

The full S10 and S17 scenarios remain incomplete:

- Registration exposes a recovery-kit textarea and Copy kit, not a kit download.
  Core export likewise shows a textarea and Copy .env. No real core download
  control exists in the inspected UI. Firefox/WebKit download coverage is
  blocked rather than simulated; feature-gated PKI/SSH downloads are not in
  this core fixture.
- Removing a key grant is not automatic rekey. The test checks that the warning
  remains and stored ciphertext is unchanged. Manual `Rotate key now` exists
  but is not exercised here. Previously copied keys and plaintext cannot be
  revoked. Post-rotation denial is not claimed.
- Ciphertext is checked on the API boundary and outbound E2E requests, not by
  querying SQLite rows. This does not complete S10's database inspection.
- No step-up expiry/re-prompt, reused-factor denial, context-change race,
  browser MFA login, all-view/dialog matrix, slow-request navigation,
  integrations, delegated/server-generated mode UI, or full error-state matrix
  is claimed. API denial assertions for member/outsider are not browser denial
  journeys. Member browser errors are checked; its full network audit is not
  yet equivalent to the main page fixture.
- No visual acceptance or pixel/layout review is claimed. Narrow-dialog bounds
  and mobile navigation assertions do not replace root-owned visual judging.

## Executed evidence

Initial portable Chromium increment: 3 tests executed, 2 failed and 1 timed out
(exit 1). The failures exposed harness errors: the app-create API returns only
`id`/`mode`, not `name`, and awaiting a native-confirm click before dismissing
the dialog deadlocks. Fixture app names now come from the setup request and
native dialogs are handled concurrently without removing assertions.

Pinned dependency lock generation and `npm ci --ignore-scripts` both exited 0,
with 3 packages audited and 0 vulnerabilities. Browser installation exited 0.
A core `cargo build -p openwarp-server` exited 0.

Second Chromium increment: 6 tests executed, 4 passed and 2 failed (exit 1).
Navigation/theme/i18n, keyboard/mobile/destructive cancellation, E2E member
sharing/revocation, and step-up passed. Both auth journeys completed their UI
assertions but failed the strict console-error fixture gate. Two targeted auth
reproductions each executed 2 tests and failed both (exit 1). Numeric diagnostics
confirmed only native HTTP 401 resource messages from anonymous bootstrap:
`GET /api/instance/edition` and `GET /api/me`, 3 of each in the sign-in/out case
and 1 of each in the signup case. Both had 0 page exceptions and 0 external
requests. The coordinator classified those exact credential-free bootstrap
responses as expected. Auth specs now opt into bounded route/status/credential
and native-log-count expectations; the other specs retain zero-error gates.

Final full Chromium run: 6/6 passed (exit 0), one worker and zero retries.
Firefox critical initial run: 3 passed, 2 auth gate failures (exit 1), because
Firefox emits no native HTTP resource-console messages. After classification of
that observed engine difference, the affected auth specs passed 2/2 (exit 0).
This is coverage across two Firefox runs, not a clean single 5-test run.

WebKit critical initial run: 3 passed (auth and navigation), 1 crypto timeout,
1 step-up focus assertion failure (exit 1). Follow-up diagnostics established
an asynchronous workspace-picker fixture race and native WebKit Tab behavior
that skipped the modal's intermediate buttons. The fixture now waits for the
known member workspace row. The production Tab handler explicitly advances
focus through enabled, rendered, visible native tab stops, including links,
summaries and explicit tabindex controls. Independent source regressions were
frozen before repair; 118 UI/step-up/coverage tests passed afterward (exit 0).
The current server was rebuilt successfully (exit 0, 11.74 seconds).

A later WebKit cancellation assertion exposed a harness assumption: mouse
clicks need not focus buttons. Actual focus before the click and at modal open
was BODY, and cancellation correctly restored BODY. Focusing Save before a
mouse click still lost focus on WebKit. The restoration journey now explicitly
focuses Save and activates it with keyboard Enter, retaining all final focus,
write-count and cancellation assertions. Mouse-click focus restoration to Save
is not guaranteed or claimed.

Final validation after these repairs:

| Run | Exit | Result |
| --- | --- | --- |
| WebKit affected step-up | 0 | 1/1 passed |
| WebKit full critical project | 0 | 5/5 passed |
| Chromium affected crypto and step-up | 0 | 2/2 passed |
| Firefox affected crypto and step-up | 0 | 2/2 passed |

All runs used one worker and zero retries. Chromium's earlier full 6-test run
and Firefox's earlier split coverage are not represented as fresh full runs
after the modal repair. No full acceptance-matrix completion is asserted.
Blank-dialog desktop/mobile captures were refreshed during the final WebKit
critical run. Root-owned visual judging remains separate from these counts.

Evidence base: `f1c63c4f21767b9eff7c0b994b2ec2a5dc912264` plus the uncommitted
browser harness and existing server/UI changes in this worktree. Commands used
were the local Playwright binary with this config and `--project=chromium`,
`--project=firefox`, or `--project=webkit`; affected auth runs additionally
selected `auth.spec.mjs`. No automatic retries were enabled.
