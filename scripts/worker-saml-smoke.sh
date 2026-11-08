#!/usr/bin/env sh
# Real signed SAML through a prebuilt Worker and disposable local Durable Object state.
# Requires node, curl, Cargo and Wrangler. WRANGLER may name a local Wrangler executable.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-8899}
ECHO_PORT=$((PORT + 1))
BASE="http://127.0.0.1:${PORT}"
WRANGLER=${WRANGLER:-npx --no-install wrangler}
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/openwarp-worker-saml.XXXXXX")
LOG="${STATE_DIR}/wrangler.log"
umask 077
cleanup() {
  if [ -n "${DEV_PID:-}" ]; then kill "${DEV_PID}" 2>/dev/null || true; wait "${DEV_PID}" 2>/dev/null || true; fi
  if [ -n "${ECHO_PID:-}" ]; then kill "${ECHO_PID}" 2>/dev/null || true; wait "${ECHO_PID}" 2>/dev/null || true; fi
  if [ "${SUCCESS:-0}" = 1 ]; then rm -rf "${STATE_DIR}"; else printf 'SAML fixture logs retained in %s\n' "${STATE_DIR}" >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ ! -f "${ROOT}/crates/server/build/worker/shim.mjs" ]; then
  printf '%s\n' 'Worker bundle missing; build it with worker-build before running this test.' >&2
  exit 2
fi
# Refuse occupied fixture ports rather than accidentally testing another process.
node --input-type=module -e '
import net from "node:net";
for (const port of process.argv.slice(1)) {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(Number(port), "127.0.0.1", resolve); });
  await new Promise(resolve => server.close(resolve));
}' "${PORT}" "${ECHO_PORT}"
mkdir "${STATE_DIR}/config"
node "${ROOT}/scripts/worker-config-smoke.mjs" "${STATE_DIR}/config"
MASTER=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64"))')
PORT="${ECHO_PORT}" node "${ROOT}/scripts/smoke-echo.mjs" >"${STATE_DIR}/echo.log" 2>&1 &
ECHO_PID=$!
(cd "${ROOT}" && exec ${WRANGLER} dev --local --config "${STATE_DIR}/config/wrangler.toml" --port "${PORT}" --persist-to "${STATE_DIR}/state" --var "OPENWARP_MASTER_KEY:${MASTER}" --var "OPENWARP_ENV:development" --var "OPENWARP_PUBLIC_URL:${BASE}" --var "OPENWARP_ALLOW_PRIVATE_EGRESS:1" --var "OPENWARP_EMAIL_WEBHOOK:http://127.0.0.1:${ECHO_PORT}/mail" >"${LOG}" 2>&1) &
DEV_PID=$!
i=0
while [ "${i}" -lt 90 ]; do
  if ! kill -0 "${DEV_PID}" 2>/dev/null || ! kill -0 "${ECHO_PID}" 2>/dev/null; then
    printf 'SAML fixture exited before readiness; inspect %s\n' "${STATE_DIR}" >&2
    exit 1
  fi
  if curl -fsS "${BASE}/health" >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:${ECHO_PORT}/_requests" >/dev/null 2>&1; then break; fi
  i=$((i + 1))
  sleep 1
done
if [ "${i}" -eq 90 ]; then printf '%s\n' 'SAML Worker fixture did not become ready within 90s' >&2; exit 1; fi
cd "${ROOT}"
OPENWARP_TEST_WORKER_URL="${BASE}" OPENWARP_TEST_MAIL_URL="http://127.0.0.1:${ECHO_PORT}" cargo test -p openwarp-server --test worker_saml -- --ignored --test-threads=1
SUCCESS=1
