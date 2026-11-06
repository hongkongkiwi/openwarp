#!/usr/bin/env bash
# Exercise the Rust D1 migration driver against a local workerd D1 database.
#
# Requires worker-build on PATH and wrangler (set WRANGLER to its path, for
# example node_modules/.bin/wrangler after `npm install --no-save wrangler`).
# The Worker is built with the test-only `d1-smoke` feature; production builds
# do not include the internal route this script calls.
set -euo pipefail

# cargo-installed worker-build lives outside the non-interactive PATH on macOS.
case ":$PATH:" in
  *":$HOME/.cargo/bin:"*) ;;
  *) PATH="$HOME/.cargo/bin:$PATH" ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
wrangler="${WRANGLER:-wrangler}"
port="${D1_SMOKE_PORT:-8799}"
persist="$(mktemp -d "${TMPDIR:-/tmp}/openwarp-d1-smoke.XXXXXX")"
cd "$root"

cleanup() {
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$persist"
}
trap cleanup EXIT

"$wrangler" dev --local --config wrangler.d1-smoke.toml --port "$port" --persist-to "$persist" \
  --var "OPENWARP_MASTER_KEY:$(openssl rand -base64 32)" >"$persist/dev.log" 2>&1 &
pid=$!

ready=""
for _ in $(seq 1 600); do
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 1
done
if [ -z "$ready" ]; then
  echo "d1 smoke: worker did not become healthy" >&2
  tail -60 "$persist/dev.log" >&2
  exit 1
fi

first="$(curl -fsS "http://127.0.0.1:${port}/__internal/migrate-d1")"
second="$(curl -fsS "http://127.0.0.1:${port}/__internal/migrate-d1")"
echo "first:  $first"
echo "second: $second"
case "$first" in
  *"applied=[1, 18]"*|*"applied=[1,18]"*) ;;
  *) echo "d1 smoke: unexpected first apply result" >&2; exit 1 ;;
esac
case "$second" in
  *"applied=[]"*) ;;
  *) echo "d1 smoke: the second apply was not a no-op" >&2; exit 1 ;;
esac

query() {
  "$wrangler" d1 execute DB --local --config wrangler.d1-smoke.toml --persist-to "$persist" --json --command "$1"
}

tables="$(query "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table'")"
version="$(query "SELECT MAX(version) AS v FROM schema_migrations")"
squashed="$(query "SELECT COUNT(*) AS n FROM schema_migrations WHERE checksum='squashed'")"
echo "tables:   $tables"
echo "version:  $version"
echo "squashed: $squashed"
case "$version" in
  *'"v":18'*|*'"v": 18'*) ;;
  *) echo "d1 smoke: D1 did not reach version 18" >&2; exit 1 ;;
esac
case "$squashed" in
  *'"n":16'*|*'"n": 16'*) ;;
  *) echo "d1 smoke: D1 did not record 16 squashed versions" >&2; exit 1 ;;
esac
echo "d1 migration driver: ok"
