#!/usr/bin/env bash
# Back up an OpenWarp database. SQLite uses the online .backup command;
# Postgres shells out to pg_dump. Values come from the same env the server uses.
set -euo pipefail

DATABASE_URL="${DATABASE_URL:-sqlite:///data/openwarp.db}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
STAMP="$(date +%F-%H%M%S)"

mkdir -p "$BACKUP_DIR"

case "$DATABASE_URL" in
  sqlite:*)
    DB_PATH="${DATABASE_URL#sqlite://}"
    DB_PATH="${DB_PATH#sqlite:}"
    OUT="$BACKUP_DIR/openwarp-$STAMP.db"
    sqlite3 "$DB_PATH" ".backup '$OUT'"
    ;;
  postgres:*)
    OUT="$BACKUP_DIR/openwarp-$STAMP.dump"
    pg_dump --format=custom --file="$OUT" "$DATABASE_URL"
    ;;
  *)
    echo "unsupported DATABASE_URL: $DATABASE_URL" >&2
    exit 2
    ;;
esac

find "$BACKUP_DIR" -type f \( -name 'openwarp-*.db' -o -name 'openwarp-*.dump' \) \
  -mtime "+$RETENTION_DAYS" -print -delete

echo "backup written: $OUT"
