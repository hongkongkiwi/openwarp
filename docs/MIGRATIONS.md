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

New migrations start at version 21. SQL files 1 through 19 remain unchanged.
Legacy main version 17 and 18 ledger rows have no checksum and remain unverified;
versions 19 and 20 record the reconciliations.

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

`schema_migration_lock` is a single row that serialises runners. A run takes it
before reading the ledger and deletes it when finished. A row older than 15
minutes is treated as abandoned and can be taken over. Long migrations are
unaffected: the timestamp is checked only when another runner cannot acquire the
lock.

Several replicas can boot at once against one database. Ledger creation is
idempotent and tolerates the PostgreSQL catalogue race; the loser of the lock
exits with `another instance is applying migrations` rather than waiting. Let the
winning instance finish and restart the other one. The migration tests include
two simultaneous PostgreSQL runners and assert a clean final ledger.

## What boot refuses

The runner verifies the whole ledger before applying anything. Boot fails, with
the reason in the error, when:

- an applied file's checksum no longer matches the ledger;
- a migration has `success = 0`, meaning a previous attempt stopped part-way;
- the database has a version this binary does not contain, so the binary is
  older than the schema;
- a later version is applied while an earlier one is missing;
- the ledger has a version outside the manifest.

A failed strict migration on SQLite or PostgreSQL is rolled back and its ledger
row is removed, so the next boot can simply try again. MySQL commits DDL
implicitly, so a failure there leaves `success = 0` and needs a decision.

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
file, so an inspection cannot create a database or change a ledger. `apply` may
create a SQLite file. `repair` requires an existing ledger.

Use `--set-applied` after checking that an interrupted migration really did
finish its work. Use `--remove` when the schema is unchanged and the migration
should run again from scratch. Use `--accept-checksum` only after reviewing why a
frozen file changed; it rewrites the stored hash, not the database.

## Adding a migration

1. Add `crates/server/migrations/0021_your_change.sql`.
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

Keep data migrations idempotent. The runner marks completion, but a crash
between a MySQL DDL statement and the ledger write can leave a schema that a
human has to reconcile.

## Testing the runner

`crates/server/tests/migrations.rs` covers the fresh path, checksum drift,
newer-database refusal, history gaps, interrupted migrations and repair, lock
contention and stale takeover, a legacy ledger catching up, and a full apply on
live PostgreSQL and MariaDB. It also builds the real version 9 schema from
`tests/fixtures/schema_v9.sql`, seeds rows, and upgrades it through versions 10
to 20 without losing data. The SQLite cases always run. The other two run when
their environment variables are set, as shown above; each test creates and drops
its own database.

The D1 driver runs against a local workerd D1 database:

```bash
npm install --no-save wrangler@4.151.1
WRANGLER=node_modules/.bin/wrangler scripts/d1-migrate-smoke.sh
```

The script builds the Worker with the test-only `d1-smoke` feature, which adds
an internal route that calls the same runner with the D1 binding. It applies the
manifest, checks version 20 and the 16 squashed rows, and verifies that a second
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
