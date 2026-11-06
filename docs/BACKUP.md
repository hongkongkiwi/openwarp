# Backup and restore

Everything that matters is in the database: users, wrapped private keys,
ciphertext, wrapped environment keys, audit history and integration configs.
The master key is the one thing that is not in the database when
`OPENWARP_MASTER_KEY` is set, so back it up separately.

## SQLite

```bash
# consistent copy while the server is running
sqlite3 /data/openwarp.db ".backup '/backups/openwarp-$(date +%F).db'"
```

`scripts/backup.sh` wraps this and prunes copies older than 14 days:

```bash
DATABASE_URL=sqlite:///data/openwarp.db BACKUP_DIR=/backups scripts/backup.sh
```

## Postgres

```bash
pg_dump --format=custom --file="/backups/openwarp-$(date +%F).dump" "$DATABASE_URL"
pg_restore --clean --if-exists --dbname="$DATABASE_URL" /backups/openwarp-2026-11-06.dump
```

## What a backup does not include

The `OPENWARP_MASTER_KEY` value and `OPENWARP_ALLOWED_DB_HOSTS` and the social
provider secrets live in the environment. Store the master key in a password
manager or secret store. Without it, every `value_enc` and `env_key_wrapped`
column is unrecoverable; with it and the database, everything is recoverable.

Test a restore into a scratch database before you need one. A backup you have
not restored is a guess.
