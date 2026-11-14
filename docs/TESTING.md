# Testing

How OpenWarp is tested: the layers, the commands, the fixture rules, and the evidence a finished change must carry. The per-feature coverage ledger is [testing/feature-matrix.md](testing/feature-matrix.md), executable journeys are [testing/scenarios.md](testing/scenarios.md), and the rollout plan is [plans/2026-11-09-comprehensive-testing.md](plans/2026-11-09-comprehensive-testing.md).

Two rules frame everything here. HTTP suites start real server processes against private, disposable databases, so never point them at data you care about. A mock provider accepting a request is never evidence that the live provider accepts the same contract.

## Test layers

| Layer | Verifies | Boundary |
| --- | --- | --- |
| Unit | Validation, permission rules, transforms, state transitions, crypto primitives | Rust module tests, Node suites, SDK unit tests; no network |
| Contract and integration | Persistence, provider requests, identity protocols, failure handling | Disposable databases and local controllable fakes |
| API end to end | Full flows and authorisation through the real binary | Spawned `openwarp-server`, HTTP, private SQLite/PostgreSQL/MySQL |
| Browser end to end | Rendering, client-side crypto, keyboard, layout | Playwright against a rebuilt server; authored scenarios are a subset of the matrix |
| Consumer end to end | CLI, SDK, Terraform, GitHub Action, ESO against the server | Real client tools |
| Deployment acceptance | Container, Workers, proxies, restart, replicas | Packaged runtime and disposable infrastructure |
| Live sandbox | Actual third-party API acceptance | Separately authorised external test resources only |

The console stays embedded in the Rust binary; there is no frontend build. The Node suites check console source, not rendering, so UI changes still need a real browser check. The [browser harness](../tests/e2e/README.md) describes its fixtures, commands, results and gaps.

## Commands

Run serially, from the repository root. Never two builds or suites at once.

```bash
# core and all-features Rust gates
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=2
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --test-threads=2
python3 scripts/check-openapi.py --strict

# focused suites while iterating
cargo test -p openwarp-crypto
cargo test -p openwarp-server --test security -- --test-threads=2
cargo test -p openwarp-server --test authorization -- --test-threads=2
cargo test -p openwarp-server --test accounts -- --test-threads=2
```

SDK, Terraform, Workers and container commands are defined in [.github/workflows/ci.yml](../.github/workflows/ci.yml) and reuse the binary `cargo test` just built:

```bash
cargo build --bin openwarp-server
OPENWARP_BIN="$PWD/target/debug/openwarp-server" node --test sdk/contract/typescript/sdk.test.ts
OPENWARP_BIN="$PWD/target/debug/openwarp-server" python3 -m unittest discover -s sdk/contract/python -p 'test_*.py'
OPENWARP_BIN="$PWD/target/debug/openwarp-server" cargo test --manifest-path sdk/rust/Cargo.toml
```

The workflow also lists the Node, required-backend, browser, Workers, container, Action and provider commands. The Workers lane includes a wasm check, bundle, deployment gate and workerd smokes against MariaDB. The container lane builds and starts the image, polls `/health`, and runs the CLI and migration status commands. Workflow definitions are not evidence of a successful remote run.

### Node suites

| Suite | Covers | In CI today |
| --- | --- | --- |
| `ui.test.cjs` | Console source and behavior checks | Yes |
| `auth-v2.test.cjs` | Browser-side v2 authentication crypto | Yes |
| `e2e-libsodium.test.cjs` | E2E browser crypto against vendored libsodium | Yes |
| `vendor-integrity.test.cjs` | Vendored dependency integrity | Yes |
| `product-ui.test.cjs` | Product UI source checks | In the tree, not in the CI invocation |
| `product-ui-races.test.cjs` | Stale-response race guards | In the tree, not in the CI invocation |

The last two are a recorded discovery finding: decide in the rollout plan's baseline pass whether they belong in the CI invocation.

## Backend coverage

The PostgreSQL and MySQL suites run when their environment variables are set (`OPENWARP_TEST_POSTGRES_URL`, `OPENWARP_TEST_MYSQL_URL`). CI sets both; locally, unset variables mean those suites exit early. Any report must state which backends actually ran, and a lane that requires a backend must fail when its variable is missing rather than silently skip.

Native backends: SQLite (default, private per-suite databases), PostgreSQL, MySQL/MariaDB (aliases of one adapter). The Workers build runs the same routes on a SQLite Durable Object with `--no-default-features`, which excludes LDAP and the native PostgreSQL and Redis clients. Keep compile checks and runtime claims separate.

## Fixtures and isolation

Reuse the existing helpers before writing new ones: the mailbox fake that captures verification email (`crates/server/tests/postgres_backend.rs`), the local OIDC provider with signed tokens (`crates/server/tests/accounts.rs`), and the provider capture mocks (`crates/server/tests/sync_review_merge.rs`).

- Unique database names, loopback ports and resource names per suite; teardown on success, failure and interruption. Cleanup must refuse to touch resources it does not own.
- Never commit `*.db` files, recovery kits, tokens or exported secrets, and never print them in failure output.
- Deterministic time through existing clock seams where present; bounded polling instead of sleeps for asynchronous work.
- Provider fakes must be able to return malformed responses, pagination, denials, timeouts and partial success, because those paths are the point.
- Deterministic suites must not contact external hosts. `OPENWARP_ALLOW_PRIVATE_EGRESS=1` is an operator override; a fixture that uses it must confine it to its own disposable server process, and separate tests must prove the default egress guards reject private and loopback targets.
- Secret-bearing flows must not produce traces or screenshots with secrets in them.

## Browser end to end

The pinned Playwright harness in `tests/e2e/` runs authored console, step-up, authentication and crypto scenarios against private server processes. Chromium selects all authored cases; Firefox and WebKit select the critical subset. Fixture APIs may set up state; the behavior under test uses the UI. Rebuild the server before running: the fixture rejects a stale embedded console.

The 2026-11-14 local evidence is an earlier Chromium 6/6 run and Firefox 3 passing critical cases plus 2 passing auth cases after repair, followed by 2/2 affected Chromium and Firefox cases and 5/5 WebKit critical cases after the final modal repair. The earlier runs are not fresh full runs on that final state. Full S10 and S17, manual rekey, database-row inspection and core downloads remain unverified. The core UI exposes copy controls rather than a download for the recovery kit and export. See the [harness README](../tests/e2e/README.md) for details and failure history.

## Provider test tiers

1. Unit: config validation, naming and template transforms, capability tables.
2. Local contract: one controllable mock per protocol family, with per-adapter assertions on requests, auth, pagination, errors, managed state, mirror deletion and redaction. Unsupported capabilities (import, mirror, dry-run, connection test) are asserted explicitly where an adapter lacks them.
3. Live sandbox: separately authorised, dedicated non-production accounts, recorded as vendor, API version, date, operations exercised and cleanup outcome. Missing credentials mean blocked, never passing. A passing mock is reported as contract coverage, never live compatibility.

## CI lanes

The authored [ci.yml](../.github/workflows/ci.yml) has `rust`, `browser-authored-increment`, `worker`, `docker` and `sdks-and-provider` jobs. The Rust job explicitly selects the ignored ESO consumer and Redis receipt tests, using a separate disposable Redis service on port 6380 for the latter. Cargo discovers the six native wallet tests in the core run and the three feature-gated `wallet_regressions` tests in the all-features run. The Worker job runs the receipt and wallet storage smokes against the first bundle before the SAML build. The workflow also includes the required-backends wrapper, PostgreSQL replica test, Action and Go SDK tests, and browser projects. Its weekly and manual triggers are not a full matrix or release acceptance. Remote CI has not been run for this increment.

### Local status, 2026-11-14

A1 through A3 were accepted locally. The A4 full core run passed 961 tests with 2 ignored across 133 suites. The full all-features run collected 1,139 tests: 1,135 passed, 0 failed and 4 were ignored. The latter used distinct qualified PostgreSQL fixtures and an owned Redis fixture, all cleaned up. These full Rust runs predate the wallet changes and are not current wallet gates. The accepted A4 evidence includes 25 Python, 23 top-level Go, 56 CLI and 6 Action tests, CLI review acceptance, and 20 required-backend wrapper unit tests. The wrapper's combined actual run passed 3 tests: 1 on private PostgreSQL 17.12 and 2 on private MariaDB 11.4. The owned services and test databases were cleaned up. One Redis case and its negative control passed; one PostgreSQL two-process replica case and its negative control passed using a private fixture with cleanup. SQLite passed with a recorded serialization deviation. These results do not establish automatic high availability.

The real ESO consumer case initially received 401 after environment deletion where it expected 404; prior controls passed. A native fix now stores deleted-environment receipts separately by token hash and caps static-token receipts at 30 days. After four valid primary and advisory review findings were fixed, 19 native cases passed: 15 original receipt cases, 1 ESO case, 2 custom-role cases and 1 owned Redis case. Workspace check and core and all-features Clippy passed after the fixes. Fault injection, deterministic PostgreSQL clock and concurrency runtime coverage remain open.

The actual worktree's migration 39 suite passed 15 cases, including 2 new receipt cases and all 3 live backend functions. This covers migration and generic backend paths, not receipt HTTP behavior on PostgreSQL or MySQL. The post-fix Worker receipt smoke passed 6/6 checks against a freshly built core bundle and fresh Durable Object storage; it did not test an upgrade from version 38.

The final local serial checks passed: core and all-features Clippy, strict OpenAPI and Actionlint exited 0. The CI-selected Node run passed 285 tests across 25 files, with 0 failed and 0 skipped; the earlier reported 378 count was incorrect. Strict OpenAPI reported 287 routes and 44 exclusions. Remote CI has not run.

A5 wallet storage is implemented in the worktree. Six focused native wallet cases and three feature-gated regression cases passed after fixes. Independent primary adversarial and advisory reviews found a change-request promotion plaintext disclosure and a reveal path-policy defect. Both were reproduced and fixed; the scoped P1 re-review accepted the fix with no new blocking finding. The Workers wallet storage smoke passed 7/7 groups on a fresh core bundle and fresh workerd storage using script SHA prefix `ecc71b`. It exercised v2 registration, verification mail and sessions, VeryRisky email proof, masking, references and exports, path denial without consuming proof, and restart and audit behavior. It did not test TOTP or enterprise change-request flows. The current post-wallet full core run collected 969 tests: 967 passed, 0 failed and 2 were ignored. The full all-features run collected 1,148: 1,144 passed, 0 failed and 4 were ignored. Both commands exited 0. The runs used distinct owned PostgreSQL fixtures for leases (trust, port 54289) and static rotation (SCRAM, port 64529), plus owned Redis; all were stopped and the before and after inventories matched. The four all-features ignored cases cover receipt Redis, ESO, PostgreSQL replica and Worker SAML; separately focused prior runs do not change the ignored count. These results supersede the pre-wallet A4 full runs above. Live backend wallet HTTP behavior remains unverified. Wallet signing, a dedicated wallet UI, OPAQUE and the other remaining A5 product contracts are not implemented; seven contracts remain pending.

## Evidence rules

- Suite status vocabulary: unmapped, mapped-unverified, passing, failing, blocked, not applicable (with reason). A test's existence is not evidence that it passed.
- Reports carry discovered, executed and skipped counts. Zero selected tests or a missing required service fails the lane that claimed coverage.
- Preserve first-failure evidence. Do not mask flakiness with retries; track quarantines explicitly.
- Never weaken an assertion, skip a check or hardcode a value to manufacture green. Never run `cargo fmt`; the tree is not rustfmt-clean.
