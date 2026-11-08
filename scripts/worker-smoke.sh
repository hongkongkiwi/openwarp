#!/usr/bin/env sh
# Boot the Workers deployment in workerd and exercise the shared API.
# Requires: worker-build, a Wrangler install, node 18+.
#   scripts/worker-smoke.sh            # uses npx wrangler
#   WRANGLER=/path/to/wrangler scripts/worker-smoke.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-8799}
ECHO_PORT=$((PORT + 1))
BASE="http://127.0.0.1:${PORT}"
WRANGLER=${WRANGLER:-npx --no-install wrangler}
# The OIDC check runs a loopback identity provider, so the local smoke allows
# private egress; production keeps the default refusal.
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/openwarp-worker-smoke.XXXXXX")
LOG="${STATE_DIR}/wrangler.log"

cleanup() {
  if [ -n "${DEV_PID:-}" ]; then kill "${DEV_PID}" 2>/dev/null || true; fi
  if [ -n "${ECHO_PID:-}" ]; then kill "${ECHO_PID}" 2>/dev/null || true; fi
  if [ "${SUCCESS:-0}" = 1 ]; then
    rm -rf "${STATE_DIR}"
  else
    echo "Smoke logs retained in ${STATE_DIR}" >&2
  fi
}
trap cleanup EXIT INT TERM

if [ ! -f "${ROOT}/crates/server/build/worker/shim.mjs" ]; then
  echo "worker bundle missing; run: (cd crates/server && worker-build --release --no-default-features)" >&2
  exit 2
fi

mkdir "${STATE_DIR}/config"
node "${ROOT}/scripts/worker-config-smoke.mjs" "${STATE_DIR}/config"
MASTER=$(head -c 32 /dev/urandom | base64)
PORT="${ECHO_PORT}" node "${ROOT}/scripts/smoke-echo.mjs" >"${LOG}.echo" 2>&1 &
ECHO_PID=$!
(cd "${ROOT}" && exec ${WRANGLER} dev --local --config "${STATE_DIR}/config/wrangler.toml" --port "${PORT}" --test-scheduled --persist-to "${STATE_DIR}/state" --var "OPENWARP_MASTER_KEY:${MASTER}" --var "OPENWARP_ENV:development" --var "OPENWARP_PUBLIC_URL:${BASE}" --var "OPENWARP_ALLOW_PRIVATE_EGRESS:1" --var "OPENWARP_ALLOWED_DB_HOSTS:127.0.0.1:5432,127.0.0.1:3306,127.0.0.1:3307" --var "OPENWARP_EMAIL_WEBHOOK:http://127.0.0.1:${ECHO_PORT}/mail" >"${LOG}" 2>&1) &
DEV_PID=$!

i=0
while [ "${i}" -lt 90 ]; do
  if curl -fsS "${BASE}/health" >/dev/null 2>&1; then break; fi
  if ! kill -0 "${DEV_PID}" 2>/dev/null; then
    echo "wrangler dev exited before becoming ready" >&2
    tail -n 60 "${LOG}" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
if ! curl -fsS "${BASE}/health" >/dev/null 2>&1; then
  echo "wrangler dev did not answer /health within 90s" >&2
  tail -n 60 "${LOG}" >&2
  exit 1
fi

OPENWARP_SMOKE_BASE="${BASE}" OPENWARP_SMOKE_ECHO="http://127.0.0.1:${ECHO_PORT}" node "${ROOT}/scripts/worker-smoke.mjs"
OPENWARP_SMOKE_BASE="${BASE}" OPENWARP_SMOKE_ECHO="http://127.0.0.1:${ECHO_PORT}" node "${ROOT}/scripts/product-worker-smoke.mjs"
SUCCESS=1
