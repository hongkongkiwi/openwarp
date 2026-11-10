# Testing rollout plan (2026-11-09)

Plan for building the test suite described in [../TESTING.md](../TESTING.md), the coverage ledger in [../testing/feature-matrix.md](../testing/feature-matrix.md) and the journeys in [../testing/scenarios.md](../testing/scenarios.md).

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
