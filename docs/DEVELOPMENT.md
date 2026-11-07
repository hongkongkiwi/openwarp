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
cargo test -p openwarp-server --test migrations -- --test-threads=1
node --test crates/server/tests/ui.test.cjs
```

| Suite | Focus |
| --- | --- |
| Crypto crate | Encryption, key handling, and cryptographic behavior |
| `security.rs` | Tenant isolation, scopes, authentication, and protocol boundaries |
| `authorization.rs` | Roles, administrative gates, environment policy, and related regressions |
| `accounts.rs` | Account, invitation, signup, provider, and recovery behavior |
| `migrations.rs` | Runner failure modes, legacy catch-up, and live PostgreSQL/MariaDB applies |
| `ui.test.cjs` | Embedded console source and behavior checks using Node |

HTTP suites start real server processes against private databases. The Node suite is not a substitute for rendering the console in a real browser. UI changes need an appropriate browser check for layout, keyboard interaction, and errors.

## Schema changes

Schema changes are append-only. Add a numbered file under `crates/server/migrations/` and the matching entry in `crates/server/src/migrate.rs`; never edit a migration that a released binary has applied, because the runner stores a checksum and refuses to boot when it no longer matches. The [schema migrations](MIGRATIONS.md) guide covers the ledger, the consolidated baseline, the MySQL DDL rules, and the repair commands.

`openwarp-migrate status`, `plan`, and `verify` inspect a database without changing it. `repair` modifies the migration ledger; follow the [repair guide](MIGRATIONS.md#operator-cli) before using it. Pass `OPENWARP_TEST_POSTGRES_URL` and `OPENWARP_TEST_MYSQL_URL` to the migration suite to apply the whole manifest against live engines. Run `WRANGLER=node_modules/.bin/wrangler scripts/d1-migrate-smoke.sh` to exercise the D1 driver against local workerd.

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

[Architecture](ARCHITECTURE.md) · [API reference](API.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Documentation index](README.md)
