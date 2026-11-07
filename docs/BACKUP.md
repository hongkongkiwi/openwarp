# Backup and restore

Back up the database, the matching master key, and deployment configuration. Users must also retain their recovery kits for end-to-end encrypted environments. A database and master key alone do not recover client-held E2E keys.

## What to preserve

| Item | Why it matters |
| --- | --- |
| SQLite database, PostgreSQL dump, or MySQL/MariaDB dump | Accounts, encrypted secrets, wrapped keys, policies, history, and integration state |
| Original `OPENWARP_MASTER_KEY` | Decrypts server-managed data for that database |
| User recovery kits | Preserve private keys needed for E2E access |
| Deployment configuration and secrets | Restore public URLs, database credentials, sign-in providers, mail relay, and network policy |
| Version or commit of the running server | Reproduce the schema and application behavior during recovery |

Store backups with restrictive permissions and encryption. In development, the generated master key is stored in the database, so that database backup includes the means to decrypt SSE secrets. Production backups and external master-key backups should have separate access controls.

Redis is an optional session cache, not the authoritative secret store. The Compose stack stores PostgreSQL data in the named `pgdata` volume, not the server's `./data` mount.

## SQLite backup

Use SQLite's backup operation for a consistent copy while the server is running. Create the backup directory first:

```bash
mkdir -p /backups
chmod 700 /backups
sqlite3 /data/openwarp.db ".backup '/backups/openwarp-$(date +%F).db'"
```

Adjust paths for your deployment. A local quick-start database is `./openwarp.db`, not `/data/openwarp.db`. Do not copy only a live `.db` file while ignoring its WAL state.

The included helper supports SQLite and PostgreSQL:

```bash
DATABASE_URL=sqlite:///data/openwarp.db \
BACKUP_DIR=/backups RETENTION_DAYS=14 \
  bash scripts/backup.sh
```

[`scripts/backup.sh`](../scripts/backup.sh) uses `sqlite3` or `pg_dump`, timestamps backup names, and deletes matching `openwarp-*.db` and `openwarp-*.dump` files older than the retention threshold. Give it a dedicated directory. Schedule it with your operating system or deployment scheduler; running the server does not schedule backups automatically.

## PostgreSQL backup

Use a `pg_dump` version compatible with the database server. Provision credentials without exposing them in shared shell history:

```bash
mkdir -p /backups
chmod 700 /backups
pg_dump --format=custom \
  --file="/backups/openwarp-$(date +%F).dump" \
  "$DATABASE_URL"
```

For the bundled Compose stack, run the client inside the database container:

```bash
docker compose exec -T db sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' \
  > "openwarp-$(date +%F).dump"
```

Check the exit status and protect the resulting file. A file's existence is not proof of a complete dump. Avoid `docker compose down -v`: it removes named volumes, including database storage.

## MySQL/MariaDB backup

Use `mariadb-dump` (or `mysqldump` for MySQL) with a user that can read every table:

```bash
mkdir -p /backups
chmod 700 /backups
mariadb-dump --single-transaction --routines \
  --result-file="/backups/openwarp-$(date +%F).sql" \
  openwarp
```

`--single-transaction` keeps InnoDB tables consistent while writes continue. Restore into an empty database with the server stopped, and keep the matching master key alongside the dump.

## Rehearse a restore

Restore to a new database first. Never point a recovery rehearsal at production. A restored server may contain integration credentials, scheduled rotations, and log destinations, so isolate its network before startup to prevent outbound writes or deliveries.

### SQLite rehearsal

1. Stop any process that could open the new restore target.
2. Copy the snapshot to a new path that does not contain an existing database.
3. Check the copy before starting OpenWarp:

```bash
sqlite3 /restore/openwarp.db 'PRAGMA integrity_check;'
```

The expected result is `ok`. Start the same server version with `DATABASE_URL=sqlite:///restore/openwarp.db`, the original master key, and a loopback listen address. Do not reuse stale `-wal` or `-shm` files from another database.

### PostgreSQL rehearsal

Create an empty scratch database using your database administration procedure, then restore into it:

```bash
pg_restore --exit-on-error --no-owner \
  --dbname="$RESTORE_DATABASE_URL" \
  /backups/openwarp-backup.dump
```

Replace the dump filename with an actual backup and ensure `RESTORE_DATABASE_URL` is the scratch target. The example deliberately omits `--clean`; it is not an instruction to destroy an existing database.

### Acceptance checks

- The server starts with the original key and database.
- `/health` succeeds.
- A test account can sign in and list its workspaces and environments.
- An authorised account can read a known SSE test secret.
- An E2E user can decrypt a known test secret with their original recovery kit.
- Membership, integration metadata, and representative audit history are present.

Record the backup timestamp, restored version, checks, and recovery time. Remove the rehearsal deployment through your normal controlled cleanup process after confirming it contains no unique data.

## Recovery pitfalls

| Symptom | Check |
| --- | --- |
| Accounts appear but SSE decryption fails | The master key must match the backed-up database |
| E2E secrets cannot be opened | The user needs their original private key and a matching grant |
| A restored instance sends unexpected traffic | Isolate egress before startup; stored automation configuration is part of the restore |
| Recent writes are missing | Confirm backup time and that the snapshot was consistent |
| Social login or reset links fail | Restore provider credentials, email relay settings, and the correct public URL |

Replacing a master key is not a migration or rotation procedure. Keep the original database and key intact while investigating a failed restore.

[Deployment](DEPLOY.md) · [Security model](SECURITY.md) · [Documentation index](README.md)

## Cloudflare Workers

Durable Object SQLite supports point-in-time recovery for the last 30 days
through the in-object PITR API: `getCurrentBookmark()`,
`getBookmarkForTime(timestamp)` and `onNextSessionRestoreBookmark(bookmark)`
followed by `ctx.abort()`. Cloudflare documents that this API does not work
under `wrangler dev`, so rehearse a restore on a non-production Worker first.

`OPENWARP_MASTER_KEY` is not stored in the object database; keep it as a
Worker secret and back it up separately, or recovered ciphertext cannot be read.
