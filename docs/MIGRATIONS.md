# Schema migrations

OpenWarp applies numbered, immutable SQL migrations on every boot. The runner is
[`crates/server/src/migrate.rs`](../crates/server/src/migrate.rs), the SQL files
live in [`crates/server/migrations/`](../crates/server/migrations), and
`openwarp-migrate` is the operator CLI for inspecting or repairing a database
without starting the server.

The same manifest runs on SQLite, PostgreSQL, MariaDB/MySQL, the Durable Object
SQLite handle used by the Workers build, and Cloudflare D1. Backend differences
(DDL rewriting, placeholders, transactions) stay in the storage adapter, not in
the migration files.

## Migrations are immutable

A migration is one SQL file named `NNNN_short_name.sql`, embedded at compile
time and listed in `MIGRATIONS`. Once a released binary has applied a version,
that file must not change: the runner stores its SHA-256 and refuses to boot when
the file no longer matches the ledger.

To change the schema, append a new file and a new manifest entry. Never rewrite
history to make a fresh database cleaner. A correction ships as the next
version.

Versions must run 1, 2, 3, and so on without holes. `validate` enforces that,
plus unique names, on every apply.

## What the baseline covers

- Version 1 is the migration-engine branch's consolidated schema. A database
  with no ledger applies this file and records versions 2 through 17 as
  `squashed`. The independently shipped main-branch version 17 added objects
  absent from this frozen baseline; version 19 reconciles those histories.
- Squashing only happens on a genuinely empty database. Before recording the
  baseline, the runner asks the backend's catalogue whether any tables exist
  outside `schema_migrations` and `schema_migration_lock`. If they do, the
  ledger was lost or never created and the run fails closed instead of
  certifying migrations the schema never received. SQLite, the Durable Object
  handle and D1 inspect `sqlite_master`; PostgreSQL and MySQL inspect
  `information_schema`. System tables, D1's `_cf_`/`d1_` bookkeeping and
  SQLite's `sqlite_` tables are excluded.
- Versions 2 through 16 are the frozen files that older binaries applied. They
  are kept so a database created by an older release can catch up. They are
  applied tolerantly, because the old boot path also added some of their columns
  eagerly and a duplicate object there is expected.
- Version 17 is the column-convergence migration for databases created before
  those eager `ALTER` statements existed. It is tolerant for the same reason.
- Version 18 is the guarded `env_restricted` backfill. It records a sentinel in
  `meta`, so a later deliberate change to an environment's allowlist survives.

- Version 19 restores the main branch's shipped version 17 objects:
  `envs.max_versions`, `leases.attempted_at`, the audit chain columns,
  `audit_heads`, `wrap_tokens`, and their indexes. It preserves existing values
  and leaves old audit rows unchained. Fresh databases and engine-branch version
  18 databases add these objects; main-branch version 17 databases retain them.
  This migration tolerates only duplicate errors for the named added columns
  and guarded MySQL indexes. Other errors leave it incomplete and stop boot.
  Legacy tolerance for versions 2 through 17 remains unchanged.

- Version 20 restores the main branch's shipped version 18 emergency lockdown
  columns. It also repeats the sentinel-guarded version 18 environment backfill:
  a legacy main version 18 row refers to lockdown, not to the engine backfill.
  Existing lockdown values and intentional changes made after the sentinel are
  retained.

- Version 21 adds `change_requests` and `change_request_envs`, matching the main
  branch's shipped version 19.
- Version 22 reconciles all objects from the main branch's shipped versions 17
  through 21. It repeats the engine's version 19 and 20 reconciliation SQL and
  adds change requests, workload trusts, workload replay protection,
  `tokens.trust_id`, and transit keys and versions. Repeating these guarded
  statements is necessary because a legacy main version 21 row occupies the
  engine's version 21 without proving that its SQL ran. Existing ciphertext,
  revocation state, key versions and lockdown values are retained. The
  environment backfill still respects its existing sentinel.
- Version 23 reconciles all objects from the main branch's shipped version 22:
  external-JWKS workload bindings and assertions, path policies, the
  compatibility Transit tables with their unique name index,
  `tokens.workload_revision`, the static rotation columns on
  `rotation_schedules` with their unique target index, and the
  `rotation_lifecycle` meta row that main's runner seeds alongside that version.
  A shipped main version 22 database already carries every object and keeps its
  data; a pre-merge engine database gains only what it lacks. The lifecycle
  seed is guarded so the shipped row survives unchanged.

- Version 24 reconciles the main branch's shipped device version 23: device
  identities and enrollment tokens with their indexes, and the device columns on
  `pki_certs`.
- Version 25 reconciles the main branch's shipped device version 24: the CA
  hierarchy columns (`parent_id`, revocation, hooks, attestation, `ca_kind`),
  device groups, and the device columns on `pki_devices` and `pki_enrollments`.
  The kind normalisation update is a no-op on engine databases, which already
  default `pki_cas.kind` to `x509`.
- Version 26 reconciles the main branch's shipped device version 25: renewal
  challenges, expiry deliveries and the TPM columns.
- Version 27 reconciles the main branch's shipped version 27, the device lookup
  and expiry indexes on `pki_certs`. Main's version 26 has no direct port: it
  replayed canonical and device DDL unguarded for device-branch databases, and
  its content is covered by version 28.
- Version 28 is the full convergence sweep for every shipped lineage: engine 23,
  main 23 through 27, and the device branch whose ledger rows 17 through 22 hold
  device-era DDL. It replays the guarded canonical set (change requests, workload
  trusts, transit, the audit chain, wrap tokens, emergency lockdown, and the
  main 22 objects), the complete device schema, and the lifecycle meta guard. A
  database that already carries an object keeps it and its data.
- Version 29 restores the workspace-policy schema PR7's former inline migration
  18 carried before the engine merge: the invitation management id and inviter
  columns on `invites`, the `idx_invites_id` unique index, and the guarded
  `workspace_policy_lock` and `workspace_creation_open` meta rows. It is
  tolerant: a database that already ran the inline original keeps its columns.
- Version 30 adds the assistant schema after the lineage convergence: `ai_settings`
  (BYOK endpoint and model policy plus the wrapped provider credential),
  `ai_plans`, `ai_finding_states`, `ai_finding_history`, `ai_usage` and
  `ai_activity`, the `folders` tree, and `integration_drafts`. Every create is
  guarded so a database that already carries the tables keeps them and their data.

New migrations start at version 31. SQL files 1 through 29 remain unchanged.
Legacy main version 17 through 27 ledger rows have no checksum and remain
unverified. A legacy main version 22 database applies versions 23 through 30; a
legacy main version 23 database applies versions 24 through 30; each later main
version applies the remaining tail, so a main version 27 database executes
versions 28 through 30. An engine version 20 database applies versions 21 through
30. The
runner records checksums only for the new reconciliation files it actually
executes, without relabelling occupied legacy versions.

## The ledger

`schema_migrations` records each applied version:

| Column | Meaning |
| --- | --- |
| `version` | Primary key, compared against the manifest |
| `applied_at` | Unix seconds when the run started |
| `name` | Manifest name, for readable operator output |
| `checksum` | SHA-256 of the embedded file |
| `success` | `0` while a migration is running, `1` when it completed |
| `execution_ms` | Wall-clock duration of the last successful run |

Two sentinel values are meaningful:

- `checksum = 'squashed'`: the version is covered by the consolidated baseline
  and was not replayed.
- `checksum = ''`: the row predates checksums. Versions 2 through 16 are
  backfilled from their frozen files on the first apply. Version 1 stays empty,
  because the consolidated baseline is not the file that original database
  applied.

Completion requires re-reading the version, name, checksum and success marker.
Strict PostgreSQL migrations commit their initial marker, DDL and completion
marker in one transaction. An unknown commit result is an error, not proof of
rollback, and the next owner must inspect the persisted ledger.

Native SQLite holds one `BEGIN IMMEDIATE` transaction on the same connection for
the entire apply or repair. Failure or process death rolls back the run, including
the ledger. PostgreSQL holds a session advisory lock on a client detached from its
pool before acquiring ownership. MySQL uses an unpooled connection and `GET_LOCK`.
All migration and ledger queries use that owning session. Dropping or cancelling
the operation discards the session instead of returning a locked connection to a
pool. Backend ownership ends only when the database ends the session or transaction,
not when a wall-clock deadline expires. MySQL and tolerant PostgreSQL failures can
still leave incomplete DDL; recovering ownership does not repair arbitrary data.

Durable Object migration operations run synchronously inside `transactionSync`;
an exception rolls back the whole operation. This does not depend on assuming
that asynchronous Durable Object events cannot interleave.

D1 and custom `Target` implementations have no proven session ownership protocol.
They use a persistent `schema_migration_lock` row that never expires. Only a
verified successful run releases its own row. An error or cancellation keeps it,
because submitted SQL may still be executing remotely. Its timestamp is diagnostic,
never permission for takeover. Both apply and repair obey the same ownership
protocol. Native backends also refuse an existing persistent row from an older or
custom runner until an operator resolves it.

Native operations reserve `schema_migration_lock` row 1 with owner
`native-session-v1` and timestamp 0. This permanent protocol marker is not an
active owner and does not mean that a migration is running. The native backend
lock remains the authority for each operation. Initialization competes atomically
with generic claims for the same primary key, before ledger creation or upgrades.
Generic apply and repair refuse a native-marked database, so a custom wrapper
cannot bypass a native session lock. A wrapper needing native access must
explicitly forward its `Target::apply` and `Target::repair` methods to the wrapped
`Db` operations. Read-only status, plan and verify remain available through either
path. Recovery cannot remove the native protocol marker.

Several replicas can boot at once against one database. Native ownership is
acquired before ledger creation or inspection. PostgreSQL and MySQL contenders
refuse an occupied session lock; SQLite waits up to its configured busy timeout
for the writer transaction. Let the winning instance finish before retrying.
The migration tests include two simultaneous PostgreSQL runners and assert a
clean final ledger when a live PostgreSQL test URL is configured.

## What boot refuses

The runner verifies the whole ledger before applying anything. Boot fails, with
the reason in the error, when:

- an applied file's checksum no longer matches the ledger;
- a migration has `success = 0`, meaning a previous attempt stopped part-way;
- the database has a version this binary does not contain, so the binary is
  older than the schema;
- a later version is applied while an earlier one is missing;
- the ledger has a version outside the manifest;
- application tables exist but the ledger has no rows, so the consolidated
  baseline cannot be recorded as squashed.

SQLite rolls back the whole failed run. A strict PostgreSQL transaction includes
its ledger marker, so a confirmed rollback leaves nothing to retry manually.
A lost commit response must be checked against persisted history. MySQL commits
DDL implicitly, so a failure there leaves `success = 0` and needs a decision.

## Operator CLI

```bash
# Inspect without changing anything
openwarp-migrate status
openwarp-migrate plan
openwarp-migrate verify

# Apply explicitly (the server also does this on boot)
openwarp-migrate apply
openwarp-migrate apply --to 18
openwarp-migrate apply --dry-run

# Reconcile a database by hand
openwarp-migrate repair --version 18 --set-applied
openwarp-migrate repair --version 18 --remove
openwarp-migrate repair --version 18 --accept-checksum
```

The URL comes from `DATABASE_URL` or `--database-url`. A missing scheme is a
SQLite path. Exit code 0 means clean, 1 means a problem was found, and 2 means
the arguments or the connection failed.

`status`, `plan`, and `verify` open SQLite with `query_only` and refuse a missing
file, so an inspection cannot create a database or change a ledger. `apply --dry-run`
is a preview too and opens read-only. A real `apply` may create a SQLite file.
`repair` requires an existing ledger. `status` does not print the database URL,
which may contain credentials. `--dry-run` is rejected on every command except
`apply`. A dry-run honors `--to` and identifies baseline-covered versions as
squashed rather than executed; the baseline still covers versions 2 through 17
on a fresh database even when the target is lower. The preview checks the current
ledger without acquiring migration ownership. A real apply checks it again under
ownership. If the ledger changes between those checks, an apply error exits 2.
Repair requires exactly one of the three action flags.

Use `--set-applied` after checking that an interrupted migration really did
finish its work. It only completes a row whose `success` marker is `0`, and it
verifies that the marker was written. Use `--remove` only for the latest
recorded version when that row is still interrupted; removing a completed
migration or an earlier version would leave a history gap and replay DDL that
already ran. A completed row is deliberately not removable through this
command. Use `--accept-checksum` only after reviewing why a frozen file
changed; it rewrites the stored hash, not the database. It refuses rows that
predate checksums and rows covered by the consolidated baseline, because
`checksum = ''` and `checksum = 'squashed'` are history markers, not drift.

### Recovering uncertain ownership

Stop all server instances, migration commands and workers that can submit SQL.
For a remote backend, confirm that previously submitted operations have finished
or been cancelled at the database; stopping the caller alone is not proof.
Inspect `SELECT owner, acquired_at FROM schema_migration_lock WHERE id=1` and
record the exact owner. Only after confirmed quiescence, native CLI users can run:

```bash
openwarp-migrate recover-lock --expected-owner 'mig_EXACT_RECORDED_OWNER' --quiesced
```

The deletion matches the expected owner, never every row. On D1, use the owning
Worker's `migrate::recover_lock(&d1, expected_owner)` after the same checks, or an
owner-qualified SQL deletion through the database operator tools. A different
owner must remain untouched. Then inspect `status`, reconcile partial DDL and use
an explicit repair if needed before restarting. Do not automate this fallback
based on age or heartbeat absence.

## Adding a migration

1. Add `crates/server/migrations/0031_your_change.sql`.
2. Add the matching entry to `MIGRATIONS` in `crates/server/src/migrate.rs` with
   the next version, a short name, and `tolerant: false`.
3. Write canonical SQL:
   - create objects with `IF NOT EXISTS`;
   - add columns with `ALTER TABLE ... ADD COLUMN`;
   - use `TEXT` and `BIGINT` as the schema already does;
   - do not open or close transactions; the runner owns the transaction;
   - MySQL-specific rewriting happens in `Db` (indexed `TEXT` becomes
     `VARCHAR(255)`, literal `TEXT` defaults become expression defaults), so the
     file must stay in the canonical form;
   - avoid `DELIMITER`. A `CREATE TRIGGER` body is kept together only when it
     ends with `END;`.
4. Apply it to all three native engines before merging:

   ```bash
   OPENWARP_TEST_POSTGRES_URL=postgres://user:pass@127.0.0.1:5432/postgres \
   OPENWARP_TEST_MYSQL_URL=mysql://root:pass@127.0.0.1:3306/mysql \
     cargo test -p openwarp-server --test migrations -- --test-threads=1
   ```

5. Run `openwarp-migrate verify` against a copy of a real database.

The runner splits statements using the target's SQL profile. SQLite, Durable
Object SQLite, and D1 recognise bracket-quoted identifiers; PostgreSQL and
MySQL do not, so brackets in PostgreSQL array expressions remain SQL syntax.
Existing custom `Target` implementations default to `SqlDialect::Legacy`, as do
`split_sql` and `all_statements`. Custom targets for other engines should
implement `sql_dialect` or use `split_sql_with_dialect` explicitly. SQLite and
ordinary PostgreSQL strings treat backslashes literally; PostgreSQL `E` strings
retain backslash escapes. This PostgreSQL profile assumes
`standard_conforming_strings=on`. MySQL and Legacy retain backslash escapes and
recognise `#` line comments; PostgreSQL and SQLite do not.

The splitter is not a full procedural SQL parser. It tracks `CREATE TRIGGER`
`BEGIN`/`END` bodies and nested `CASE` expressions, but does not support every
procedural dialect or MySQL `DELIMITER` directives. Use supported canonical SQL
and test migrations on each target engine.

Keep data migrations idempotent. The runner marks completion, but a crash
between a MySQL DDL statement and the ledger write can leave a schema that a
human has to reconcile.

## Testing the runner

`crates/server/tests/migrations.rs` covers the fresh path, checksum drift,
newer-database refusal, history gaps, interrupted migrations and repair, lock
contention and refusal of stale takeover, a legacy ledger catching up, and a full apply on
live PostgreSQL and MariaDB. It also builds the real version 9 schema from
`tests/fixtures/schema_v9.sql`, seeds rows, and upgrades it through versions 10
to 28 without losing data. The SQLite cases always run. The other two run when
their environment variables are set, as shown above; each test creates and drops
its own database. The embedded ledger test in `db.rs` pins the full manifest
explicitly: a fresh database records exactly 28 versions, 16 of them squashed.

The D1 driver runs against a local workerd D1 database:

```bash
npm install --no-save wrangler@4.151.1
WRANGLER=node_modules/.bin/wrangler scripts/d1-migrate-smoke.sh
```

The script builds the Worker with the test-only `d1-smoke` feature, which adds
an internal route that calls the same runner with the D1 binding. It applies the
manifest, checks version 28 and the 16 squashed rows, and verifies that a second
apply is a no-op. The production Worker build in `wrangler.toml` does not enable
the feature, so that route is absent from deployed bundles. CI runs this after
the Workerd smoke test.

A D1 deployment that owns migrations calls the same runner:

```rust
let d1 = env.d1("DB")?;
openwarp_server::migrate::apply(&d1, openwarp_server::migrate::MIGRATIONS, Default::default())
    .await
    .map_err(worker::Error::RustError)?;
```

[Back to the documentation index](README.md)
