# Development

Use this guide to build and validate changes to the server, CLI, crypto library, or embedded console. Read [architecture](ARCHITECTURE.md) for the source map.

## Prerequisites

- Stable Rust and Cargo with Clippy.
- Native compiler/linker tools for your operating system.
- Node.js with the built-in test runner for console checks.
- A container runtime only if you are validating the container build.

The local server and HTTP test suites can use SQLite. Redis and a separately running PostgreSQL server are not required for the basic local walkthrough.

## Run the server and CLI

```bash
DATABASE_URL=sqlite://openwarp.db ADDR=127.0.0.1:8080 \
  cargo run -p openwarp-server
```

Use a separate terminal for the CLI:

```bash
cargo run -p openwarp-cli -- --help
cargo run -p openwarp-cli -- login
```

The embedded console is part of the Rust binary, so rebuild/restart to serve source changes. Do not assume an old process or `target/debug` binary reflects the current working tree.

Use a disposable database and dummy credentials during development. Database files, recovery kits, tokens, and exported secrets must not enter commits or test artifacts shared publicly.

## Checks

Run checks serially, especially on machines with limited memory:

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=2
node --test crates/server/tests/ui.test.cjs
cargo build --workspace
```

The [CI workflow](../.github/workflows/ci.yml) runs Clippy, the workspace Rust tests with two test threads, the Node console test, and a separate container build/startup smoke test. `cargo check` and the final workspace build above are useful local checks, not additional claims about CI.

### Targeted checks

```bash
cargo test -p openwarp-crypto
cargo test -p openwarp-server --test security -- --test-threads=2
cargo test -p openwarp-server --test authorization -- --test-threads=2
cargo test -p openwarp-server --test accounts -- --test-threads=2
node --test crates/server/tests/ui.test.cjs
```

| Suite | Focus |
| --- | --- |
| Crypto crate | Encryption, key handling, and cryptographic behavior |
| `security.rs` | Tenant isolation, scopes, authentication, and protocol boundaries |
| `authorization.rs` | Roles, administrative gates, environment policy, and related regressions |
| `accounts.rs` | Account, invitation, signup, provider, and recovery behavior |
| `ui.test.cjs` | Embedded console source and behavior checks using Node |

The PostgreSQL recovery regression target is opt-in because it changes login roles in an external database. Use a disposable PostgreSQL database and a test administrator, never deployment credentials:

```bash
OPENWARP_TEST_STATIC_PG="$DISPOSABLE_POSTGRES_URL" \
  cargo test -p openwarp-server --features live-db-tests --test rotation_regressions -- --test-threads=1
OPENWARP_TEST_STATIC_PG="$DISPOSABLE_POSTGRES_URL" \
  cargo test -p openwarp-server --test static_rotation_live -- --test-threads=1
```

`rotation_regressions` is excluded from default workspace runs and fails if explicitly enabled without its database URL. `static_rotation_live` reports that live checks were not run when the URL is absent. A green default workspace run does not establish live PostgreSQL recovery coverage. Both live targets create uniquely named test roles and remove those roles after their cases.

HTTP suites start real server processes against private databases. The Node suite is not a substitute for rendering the console in a real browser. UI changes need an appropriate browser check for layout, keyboard interaction, and errors.

### Device certificate checks

Ordinary device enrollment and renewal need no TPM. Run the focused regression:

```bash
cargo test -p openwarp-server --test device_delivery default_device_lifecycle_does_not_require_a_tpm -- --test-threads=2
cargo test -p openwarp-server --test device_remaining -- --test-threads=2
cargo test -p openwarp-server --test tpm_interoperability -- --test-threads=2
```

`device_postgres` creates private databases when `OPENWARP_TEST_POSTGRES_URL`
points to a local test administrator database. It exercises transaction
cancellation, expiry after row-lock waits and concurrent policy changes. Without
that variable, the live database checks do not run. TPM interoperability uses
swtpm evidence, not a physical TPM; its public fixtures and generation recipe are
in `crates/server/tests/fixtures/tpm` and `scripts/tpm-fixture.sh`.

Device schema migrations append after canonical main's existing migrations.
The protocol discriminator `pki_cas.kind` remains `x509` or `ssh`; X.509 hierarchy
uses `ca_kind`. Additive convergence also covers the earlier device branch's
migration ledger without rewriting published statements.

## Container validation

CI builds the [`Dockerfile`](../Dockerfile), starts the resulting image, checks `/health`, and executes `openwarp --help` inside it. Building an image alone cannot catch every runtime library mismatch.

For local container validation, use your supported runtime and an isolated port/database. Do not start a second server against a working database just to test an image. Keep builds and test suites serial.

## Change guidelines

- Keep changes scoped and preserve unrelated work in shared checkouts.
- Add regression coverage for changed behavior, especially tenant, token, and environment boundaries.
- Exercise failure cases as well as successful requests. A mock provider accepting a request is not evidence that the live provider accepts the same API contract.
- Never weaken an assertion or expose a real credential to make a check pass.
- Keep comments focused on decisions, constraints, and security boundaries rather than narrating syntax.
- Update the relevant guide when changing flags, environment variables, routes, or provider configuration.

## Documentation maintenance

The root [README](../README.md) is the entry point. The [documentation index](README.md) organises task-oriented guides; detailed options belong in the references rather than duplicated in every page.

For documentation-only changes:

1. Check local Markdown links and heading anchors.
2. Compare commands and option placement against the CLI parser or `--help` from a current build.
3. Compare configuration defaults and API examples against source.
4. Check shell examples for syntax without executing destructive or remote operations.
5. State which examples were run and which were only inspected.

Do not publish fake screenshots, invented usage metrics, or unverified compatibility claims. Distinguish an implemented endpoint from a tested integration with a live provider.

[Architecture](ARCHITECTURE.md) · [API reference](API.md) · [Documentation index](README.md)
