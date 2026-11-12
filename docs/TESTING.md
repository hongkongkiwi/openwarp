# Testing

How OpenWarp is tested: the layers, the commands, the fixture rules, and the evidence a finished change must carry. The per-feature coverage ledger is [testing/feature-matrix.md](testing/feature-matrix.md), executable journeys are [testing/scenarios.md](testing/scenarios.md), and the rollout plan is [plans/2026-11-09-comprehensive-testing.md](plans/2026-11-09-comprehensive-testing.md).

Two rules frame everything here. HTTP suites start real server processes against private, disposable databases, so never point them at data you care about. A mock provider accepting a request is never evidence that the live provider accepts the same contract.

## Test layers

| Layer | Verifies | Boundary |
| --- | --- | --- |
| Unit | Validation, permission rules, transforms, state transitions, crypto primitives | Rust module tests, Node suites, SDK unit tests; no network |
| Contract and integration | Persistence, provider requests, identity protocols, failure handling | Disposable databases and local controllable fakes |
| API end to end | Full flows and authorisation through the real binary | Spawned `openwarp-server`, HTTP, private SQLite/PostgreSQL/MySQL |
| Browser end to end | Rendering, client-side crypto, keyboard, layout | Real browser against a rebuilt server (proposed, see below) |
| Consumer end to end | CLI, SDK, Terraform, GitHub Action, ESO against the server | Real client tools |
| Deployment acceptance | Container, Workers, proxies, restart, replicas | Packaged runtime and disposable infrastructure |
| Live sandbox | Actual third-party API acceptance | Separately authorised external test resources only |

Playwright is proposed tooling only. The console stays embedded in the Rust binary; there is no frontend build to add. The existing Node suites check console source, not rendering, so any UI change still needs a real browser check.

## Commands

Run serially, from the repository root. Never two builds or suites at once.

```bash
# full gate
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=2
node --test crates/server/tests/ui.test.cjs crates/server/tests/auth-v2.test.cjs \
  crates/server/tests/e2e-libsodium.test.cjs crates/server/tests/vendor-integrity.test.cjs
python3 scripts/check-openapi.py

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

The Workers lane typechecks `--target wasm32-unknown-unknown --no-default-features`, bundles with `worker-build`, runs `scripts/tests/portable-runtime/worker-deployment.test.cjs`, then the `scripts/worker-smoke.sh` smoke against MariaDB. The container lane builds the image, starts it with a generated master key, polls `/health` and runs `openwarp --help` inside the container.

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

## Browser end to end (proposed)

Not yet implemented; sequenced in the rollout plan.

- Location `tests/e2e/`, pinned Playwright dependencies, no application changes.
- Chromium for the full matrix; Firefox and WebKit for critical authentication, crypto, navigation and download journeys; mobile-width and keyboard coverage throughout.
- Separate browser contexts for owner, member and outsider. API calls may set up state, but the behavior under test must go through the UI.
- Semantic locators; stable test IDs only where the markup has none.
- Rebuild and restart the server before checking UI changes; a stale `target/debug` binary will not show the edit.

## Provider test tiers

1. Unit: config validation, naming and template transforms, capability tables.
2. Local contract: one controllable mock per protocol family, with per-adapter assertions on requests, auth, pagination, errors, managed state, mirror deletion and redaction. Unsupported capabilities (import, mirror, dry-run, connection test) are asserted explicitly where an adapter lacks them.
3. Live sandbox: separately authorised, dedicated non-production accounts, recorded as vendor, API version, date, operations exercised and cleanup outcome. Missing credentials mean blocked, never passing. A passing mock is reported as contract coverage, never live compatibility.

## CI lanes

Current jobs in [ci.yml](../.github/workflows/ci.yml): `rust` (Clippy, workspace tests with PostgreSQL 17 and MariaDB 11.4 services, four Node suites, OpenAPI check, TypeScript and Python SDKs), `worker` (wasm check, bundle, deployment gate, workerd smoke), `docker` (build plus startup smoke), `sdks-and-provider` (Rust SDK, TypeScript SDK, Terraform provider unit, live client and acceptance tests).

Planned additions, sequenced in the rollout plan: a browser lane, a hard-failing backend gate when required fixtures are absent, a scheduled full matrix (all browsers, clients, adapters, historical migrations, restart and replica cases), and release acceptance including ephemeral Kubernetes for ESO. Backend, security and Workers-sensitive changes should run their applicable gates before merge, not only nightly.

## Evidence rules

- Suite status vocabulary: unmapped, mapped-unverified, passing, failing, blocked, not applicable (with reason). A test's existence is not evidence that it passed.
- Reports carry discovered, executed and skipped counts. Zero selected tests or a missing required service fails the lane that claimed coverage.
- Preserve first-failure evidence. Do not mask flakiness with retries; track quarantines explicitly.
- Never weaken an assertion, skip a check or hardcode a value to manufacture green. Never run `cargo fmt`; the tree is not rustfmt-clean.
