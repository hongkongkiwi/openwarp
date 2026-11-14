# Testing rollout plan (2026-11-09)

Plan for building the test suite described in [../TESTING.md](../TESTING.md), the coverage ledger in [../testing/feature-matrix.md](../testing/feature-matrix.md) and the journeys in [../testing/scenarios.md](../testing/scenarios.md).

## Status update, 2026-11-14

The original plan and discovery findings below describe the 2026-11-09 baseline, not the current worktree. A1 through A3 have local acceptance. The historical pre-wallet A4 full core run passed 961 tests with 2 ignored across 133 suites. Full all-features collected 1,139: 1,135 passed, 0 failed and 4 ignored. The current post-wallet full core run collected 969: 967 passed, 0 failed and 2 ignored. Full all-features collected 1,148: 1,144 passed, 0 failed and 4 ignored. Both commands exited 0 and supersede the A4 full runs. The current runs used distinct owned PostgreSQL fixtures for leases (trust, port 54289) and static rotation (SCRAM, port 64529), plus owned Redis; all were stopped and the before and after inventories matched. The four all-features ignored cases cover receipt Redis, ESO, PostgreSQL replica and Worker SAML. Separately focused prior runs do not change the ignored count. The authored CI workflow has not run remotely. The [testing guide](../TESTING.md#local-status-2026-11-14) and [matrix update](../testing/feature-matrix.md#current-bounded-update-2026-11-14) distinguish individual local results from remaining work.

A4 has locally accepted client, CLI and browser increments. The browser harness and CI job exist, but the full browser matrix and S17 remain incomplete. The required-backend wrapper has 20 passing unit tests; its combined actual run passed 1 test on private PostgreSQL 17.12 and 2 on private MariaDB 11.4. The owned services and test databases were cleaned up. Redis and PostgreSQL replica tests each passed with a negative control; the replica fixture was private and cleaned up. SQLite passed with a recorded serialization deviation. These checks do not prove automatic HA.

The real ESO consumer test initially received 401 instead of the expected 404 after environment deletion; prior controls passed. The native fix stores deleted-environment receipts separately by token hash and caps static-token receipts at 30 days. Four valid findings from primary and advisory review were fixed. Afterward, 19 native cases passed: 15 original receipt cases, 1 ESO case, 2 custom-role cases and 1 owned Redis case. Workspace check and core and all-features Clippy also passed after the fixes. Fault injection, deterministic PostgreSQL clock and concurrency runtime coverage remain open. The post-fix Worker receipt smoke passed 6/6 checks against a freshly built core bundle and fresh Durable Object storage; it did not test a version 38 upgrade.

The actual worktree's migration 39 suite passed 15 cases, including 2 new receipt cases and all 3 live backend functions. Those results do not establish receipt HTTP behavior on PostgreSQL or MySQL. The final local CI-selected Node run passed 285 tests across 25 files, with 0 failed and 0 skipped; the earlier 378 count was incorrect. Final core and all-features Clippy, strict OpenAPI and Actionlint exited 0. OpenAPI reported 287 routes and 44 exclusions.

A5 wallet storage is implemented in the worktree. Six native wallet cases and three feature-gated regression cases passed after fixes. Primary adversarial and advisory reviews found a change-request promotion plaintext disclosure and a reveal path-policy defect; both were reproduced and fixed. The scoped P1 re-review accepted the fix without a new blocker. The Workers wallet storage smoke passed 7/7 groups on a fresh core bundle and fresh workerd storage using script SHA prefix `ecc71b`. It covered v2 registration, verification mail and sessions, VeryRisky email proof, masking, references and exports, path denial without consuming proof, and restart and audit behavior. TOTP and enterprise change-request flows were not tested. The current post-wallet full Rust results above include the six native wallet cases and three regression cases. Live backend wallet HTTP coverage remains open. Wallet signing, a dedicated wallet UI, OPAQUE and the other remaining A5 product contracts are not implemented; seven contracts remain pending. The completion criteria below remain goals, not a claim that they have been met.

## Context

OpenWarp has substantial existing coverage (private-database HTTP suites, module tests, Node console and crypto checks, provider and OIDC mocks, SDK real-server tests, backend services in CI, Terraform acceptance tests, Worker and container smoke tests) but no single map of what every feature requires. This plan sequences the work to close that gap without a broad harness refactor and without weakening product behavior to make checks pass.

Specification status: the three documents above are the deliverable authored on 2026-11-09 at commit 8425e29, branch `feat/comprehensive-clients`. Suite implementation is a separate, separately authorised phase.

## Discovery findings recorded during planning

- CI's Node invocation (`.github/workflows/ci.yml:49-55`) lists four suites; `product-ui.test.cjs` and `product-ui-races.test.cjs` also exist in `crates/server/tests/`. Decide their inclusion in the baseline pass.
- `sdk/go/client_test.go` exists; no CI step invokes it. Both client tree families (`sdk/` and `sdks/`) stay in scope unless explicitly retired.
- `action/` contains no test files; `crates/eso/src/main.rs` has 10 inline tests; `crates/cli/src/main.rs` has none and no CLI suite file exists.
- No dedicated historical-migration upgrade suite was found; backend fixtures exercise migrations implicitly at open.
- The OpenAPI work in flight (`openapi.json`, `openapi/`, `scripts/check-openapi.py`, `scripts/openapi-build.py`) belongs to another session: preserve it, do not treat unfinished generated contracts as authoritative, and keep using actual handlers as the cross-check.

## Phase A2: qualify the baseline

At a fixed revision, record for every suite: discovered, executed, skipped, failed, and which backend services were actually present. Run with `OPENWARP_TEST_POSTGRES_URL` and `OPENWARP_TEST_MYSQL_URL` set so backend suites do not silently skip, and report separately when they are unset.

1. Run the full gate commands from [../TESTING.md](../TESTING.md) serially; capture output.
2. Inspect the bodies of the suites named in each matrix row before declaring any case missing; a file's existence is not case coverage.
3. Resolve the two CI Node invocation questions and the `sdk/go` wiring question.
4. Record baseline failures and skips as-is. Never weaken assertions or change product behavior to obtain a clean baseline; product repairs go through their own review.

## Phase A3: implementation tranches

- P0 (identity, encryption, state machines): F01-F06, F12-F15, F18, F22, F27. Failing-first tests authored independently before any risky or shared-module repair; deterministic race orchestration for single-use redemption, CAS, revocation, approvals and job claims.
- P1 (domain and providers): remaining secret-domain features, per-provider contract rows, rotation and leases, transit, PKI, audit.
- P2 (surface and packaging): browser matrix (`tests/e2e/`, Playwright, Chromium full plus Firefox/WebKit for critical journeys), every consumer (CLI, four SDKs, Terraform, Action, ESO on ephemeral Kubernetes), deployment acceptance including replica and compose-topology cases.

Browser scaffolding may start during P1, but security invariants must not depend solely on UI tests. Each tranche finishes with executed positive and negative evidence; source-pattern checks alone do not count.

## Locations and reuse

- Unit cases beside their modules: `crates/server/src/`, `crates/crypto/src/lib.rs`, `crates/cli/src/main.rs`, `crates/eso/src/main.rs`.
- API and contract cases extend the matching `crates/server/tests/*.rs`; new focused suites only where nothing fits.
- Browser tooling and specs in `tests/e2e/` with pinned dependencies; no frontend build added to the application.
- Consumer cases stay with each client's existing runner; Workers coverage extends `scripts/worker-smoke.sh`, `scripts/worker-smoke.mjs`, `scripts/product-worker-smoke.mjs` and `scripts/tests/portable-runtime/`.
- CI changes in `.github/workflows/ci.yml`: add the browser lane, make the backend gate fail on missing required fixtures, add a scheduled full-matrix run, keep release acceptance (Terraform acceptance, ephemeral Kubernetes, backup and restore) separate from live-provider results.
- Reuse the mailbox fake (`postgres_backend.rs`), OIDC mock (`accounts.rs`) and provider captures (`sync_review_merge.rs`) before extracting new helpers. Any needed clock or transport seam is a small, separately reviewed change with unchanged default behavior.

## Verification

The commands in [../TESTING.md](../TESTING.md) are the gate set; SDK, Terraform, Workers and container commands come from `.github/workflows/ci.yml`. Before heavy local runs, check machine pressure, paging and disk; keep builds and suites serial; never run `cargo fmt`.

## Completion criteria

- Every ledger row has cases or an explicit exclusion, and no row claims passing without executed evidence at a recorded revision.
- Required lanes fail on missing services or zero selected tests rather than silently skipping.
- Browser assertions exercise real rendered behavior, with visual acceptance judged on rendered output.
- Live-provider checks are reported separately as vendor, date, operations and cleanup, or as blocked.
- No "every feature tested" or percentage claim precedes that evidence.
