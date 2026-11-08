# OpenWarp

Self-hosted secrets manager. A Rust workspace: the server also serves the browser console, so there is no separate frontend build. Workspaces (the API calls them orgs) contain applications, environments and secrets, with server-side or end-to-end encryption, scoped tokens, provider sync, and a CLI. An independent implementation inspired by Phase's public documentation; no Phase code, assets or branding.

Read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) before your first change, [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the source map, and [docs/SECURITY.md](docs/SECURITY.md) before touching auth, tenancy, tokens or crypto.

## Layout

| Path | What |
|---|---|
| `crates/server/src/main.rs` | Axum routes, identity and authorisation, secret operations, background work. ~2.3k lines, deliberately dense |
| `crates/server/src/db.rs` | SQLite/PostgreSQL/MariaDB adapter, statement execution, MySQL DDL rewriting |
| `crates/server/src/migrate.rs` | Migration runner: ledger, checksums, locking, squash baseline and repair |
| `crates/server/src/bin/migrate.rs` | `openwarp-migrate` operator CLI |
| `crates/server/migrations/` | Immutable numbered SQL migrations; `0001_baseline.sql` is the consolidated schema |
| `crates/server/src/ui.rs` | The entire browser console: HTML, CSS and JS in Rust string constants |
| `crates/server/src/e2e.js` | Browser-side end-to-end cryptography, served at `/e2e.js` |
| `crates/server/src/integrations.rs` | Provider sync (Instabox, Boat, Daytona, Trigger, …) |
| `crates/server/src/ssh_ca.rs` | OpenSSH user certificates: CA generation, principal patterns, signing, RevokedKeys |
| `crates/server/src/mailer.rs` | Transactional email providers and templates |
| `crates/server/tests/` | HTTP suites `security`, `authorization`, `accounts`; `ui.test.cjs` for console source |
| `crates/cli/src/main.rs` | The `openwarp` binary: login, inject, export, sync |
| `crates/eso/src/main.rs` | `openwarp-eso`, the External Secrets Operator webhook bridge |
| `crates/crypto/src/lib.rs` | Encryption, key wrapping, primitives |
| `sdk/`, `action/`, `terraform-provider-openwarp/` | Clients outside the Cargo workspace |

## Gates

Run from the repository root, serially. Never run two builds or suites at once. CI runs clippy and the Rust tests twice, once core-only and once with `--all-features`, then the console test, and a container build that polls `/health` and runs `openwarp --help` inside the image.

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=2
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --test-threads=2
node --test crates/server/tests/ui.test.cjs crates/server/tests/ui-contrast.test.cjs
```

The enterprise surfaces (SAML, SCIM, PKI, SSH certificates, transit, workload identity, change requests, LDAP) are Cargo features the default build compiles out; `enterprise` enables all of them. A compiled surface also needs a per-workspace grant before its routes answer, so a test that exercises one grants it first through `PUT /api/instance/features`. Changing a gated path without the all-features run leaves it unchecked.

Local-only: `cargo check --workspace`, `cargo build --workspace`.

Focused suites while iterating:

```bash
cargo test -p openwarp-crypto
cargo test -p openwarp-server --test security -- --test-threads=2
cargo test -p openwarp-server --test authorization -- --test-threads=2
cargo test -p openwarp-server --test accounts -- --test-threads=2
cargo test -p openwarp-server --test migrations -- --test-threads=1
```

Run the stack with `DATABASE_URL=sqlite://openwarp.db ADDR=127.0.0.1:8080 cargo run -p openwarp-server`; the CLI is `cargo run -p openwarp-cli -- --help` (binary name `openwarp`). The local walkthrough needs no Redis or PostgreSQL.

## Rules that bite

- **The console is not a frontend build.** Change `ui.rs` (or `e2e.js`), rebuild and restart the server; a stale `target/debug` binary will not show the edit. `node --test` checks source, not rendering, so any UI change also needs a real browser check for layout, keyboard interaction and console errors.
- **Do not run `cargo fmt`.** CI does not check rustfmt and the tree is not rustfmt-clean; formatting rewrites nearly every file. Match the local style, including one-line functions and compact markup.
- **Authentication is not authorisation.** `check_scope`, `role_perms`, `require_org` and `require_env` (`main.rs:171-223`) each narrow a request. OAuth scopes, token environment scope, custom roles, team grants, environment policy and IP allowlists all apply on top of the caller's identity.
- **SQL must run on every backend.** `db.rs` translates `?` placeholders for PostgreSQL and rewrites the canonical DDL for MySQL/MariaDB (keyed or indexed `TEXT` becomes `VARCHAR(255)`, defaults on `TEXT` become expressions, `CREATE INDEX IF NOT EXISTS` loses the guard, tables use a binary collation). Avoid SQLite-only syntax and MySQL reserved words (`key`) as bare identifiers.
- **Migrations are immutable and checked.** Add `crates/server/migrations/NNNN_name.sql` and the matching entry in `migrate.rs`; never edit a file that has shipped, because its SHA-256 is in `schema_migrations` and boot refuses on drift. Versions must be contiguous. A fresh database applies the consolidated baseline and records old versions as squashed; older databases replay frozen files tolerantly. Test with `cargo test -p openwarp-server --test migrations` and, when the containers are available, `OPENWARP_TEST_POSTGRES_URL` and `OPENWARP_TEST_MYSQL_URL`. `openwarp-migrate status|verify|repair` inspects or reconciles a database without starting the server.
- **E2E environments keep the key on the client.** The server stores ciphertext and per-user wrapped keys. Do not add a server-side plaintext path, and do not describe the compatibility creation path (which generates the key server-side) as server-blind.
- **Egress guards are deliberate.** `url_ok` / `egress_allowed` reject private and loopback targets for OIDC, webhooks and integrations. `OPENWARP_ALLOW_PRIVATE_EGRESS=1` is an operator override, not a way to make a test pass; dynamic database leases additionally require `OPENWARP_ALLOWED_DB_HOSTS`.
- **Provider sync is not transactional with local writes.** A local deploy can succeed while a remote write fails. Report per-integration results instead of assuming both landed, and keep provider-specific mirror-deletion behaviour intact.
- **Production needs `OPENWARP_MASTER_KEY`** (base64, exactly 32 bytes). Outside `OPENWARP_ENV=production` a missing key is generated and stored in the database. That is acceptable locally, never for a real deployment.
- **Keep the docs honest.** Changing a flag, environment variable, route or provider config means updating the matching page under `docs/`; state what you executed and what you only inspected.

## Tests and evidence

- `security.rs` locks tenant isolation, scopes, sessions and protocol boundaries; `authorization.rs` covers roles, grants, environment policy and approvals; `accounts.rs` covers signup, invitations, providers and recovery; `migrations.rs` covers ledger checks, a real v9 upgrade, and live PostgreSQL and MariaDB; `ui.test.cjs` checks console source.
- `scripts/d1-migrate-smoke.sh` runs the migration driver against a local workerd D1 database. It builds a test-only Worker feature, so never enable `d1-smoke` in a deployed bundle.
- The HTTP suites start real server processes against private databases. Never point them at data you care about, and never commit `*.db` files, recovery kits, tokens or exported secrets.
- Reproduce a bug with a failing test first. Tenant, token and environment boundaries need failure cases as well as success cases.
- Never weaken an assertion, skip a check or hardcode a value to manufacture green.

## Worktrees

Every git worktree lives inside this repository at `.worktrees/<name>`, which is gitignored. Never create one elsewhere under `~/Development`, in a checkout sibling, or in `/tmp`.

```bash
scripts/worktree.sh new <name> [branch] [base]   # base defaults to main
scripts/worktree.sh list
scripts/worktree.sh move <path> [name]           # relocate an outside worktree into .worktrees/
scripts/worktree.sh remove <name> [--force]      # refuses a dirty tree without --force
scripts/worktree.sh prune
```

Worktrees created before this rule may still live in `/Volumes/Storage/Development/.worktrees/hongkongkiwi/`. Relocate each with `move` once its lane is idle; never create a new one there.

- `git worktree list` shows every checkout; entries under `.worktrees/` are the only legitimate ones for this repo.
- One writer per worktree. Assume the main checkout is shared: stage explicit paths, never `git add -A`, and never commit another session's work in progress.
- Each worktree builds its own `target/`, several gigabytes each. Delete it while a lane is dormant; it rebuilds.
- Remove the worktree when its branch merges, and run `git worktree prune` after deleting a directory by hand.

## Commits

`main` history uses plain imperative subjects ("Add …", "Fix …", "Guard …"), with no Conventional Commit prefixes. Commit only the files the task touched, by path.

## Documentation

[docs/README.md](docs/README.md) is the index: [GETTING_STARTED](docs/GETTING_STARTED.md), [CONFIGURATION](docs/CONFIGURATION.md), [CLI](docs/CLI.md), [CONSOLE](docs/CONSOLE.md), [DEPLOY](docs/DEPLOY.md), [INTEGRATIONS](docs/INTEGRATIONS.md), [KUBERNETES](docs/KUBERNETES.md), [BACKUP](docs/BACKUP.md), [FEATURES](docs/FEATURES.md).
