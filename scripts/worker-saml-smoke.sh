#!/usr/bin/env sh
# Real signed SAML through a prebuilt Worker and disposable local Durable Object state.
# Requires node, curl, Cargo and Wrangler. WRANGLER may name a local Wrangler executable.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-8899}
# Validate before shell arithmetic or starting either fixture process.
node --input-type=module -e '
const port = process.argv[1];
if (!/^[0-9]+$/.test(port) || Number(port) < 1024 || Number(port) > 65534 || String(Number(port)) !== port) {
  throw new Error("PORT must be a decimal integer from 1024 to 65534");
}' "${PORT}"
ECHO_PORT=$((PORT + 1))
BASE="http://127.0.0.1:${PORT}"
WRANGLER=${WRANGLER:-npx --no-install wrangler}
TEST_NAME=worker_saml_round_trip_validates_signatures_provisions_and_rejects_replay
umask 077
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/openwarp-worker-saml.XXXXXX")
LOG="${STATE_DIR}/wrangler.log"
cleanup() {
  if [ -n "${DEV_PID:-}" ]; then kill "${DEV_PID}" 2>/dev/null || true; wait "${DEV_PID}" 2>/dev/null || true; fi
  if [ -n "${ECHO_PID:-}" ]; then kill "${ECHO_PID}" 2>/dev/null || true; wait "${ECHO_PID}" 2>/dev/null || true; fi
  # Never retain account sessions or the fixture master key's persisted state.
  rm -rf "${STATE_DIR}/state" "${STATE_DIR}/config"
  if [ "${SUCCESS:-0}" = 1 ]; then rm -rf "${STATE_DIR}"; else printf 'SAML fixture logs retained in %s (disposable state removed)\n' "${STATE_DIR}" >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ ! -f "${ROOT}/crates/server/build/worker/shim.mjs" ]; then
  printf '%s\n' 'Worker bundle missing; build it with worker-build --release --no-default-features --features saml before running this test.' >&2
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
cd "${ROOT}"
# An explicitly requested but unselected ignored test is not runtime evidence.
if cargo test -p openwarp-server --test worker_saml --features saml "${TEST_NAME}" -- --ignored --exact --list >"${STATE_DIR}/selection.log" 2>&1; then :; else
  status=$?
  printf 'SAML test selection failed (exit %s); inspect %s\n' "${status}" "${STATE_DIR}/selection.log" >&2
  exit "${status}"
fi
node --input-type=module -e '
import fs from "node:fs";
const lines = fs.readFileSync(process.argv[1], "utf8").split(/\r?\n/);
const cases = lines.filter(line => line.endsWith(": test"));
if (cases.length !== 1 || cases[0] !== `${process.argv[2]}: test` || !lines.includes("1 test, 0 benchmarks")) {
  throw new Error("SAML runner must select exactly its one ignored runtime test; inspect selection.log");
}' "${STATE_DIR}/selection.log" "${TEST_NAME}"
mkdir "${STATE_DIR}/config"
node "${ROOT}/scripts/worker-config-smoke.mjs" "${STATE_DIR}/config"
MASTER=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64"))')
PORT="${ECHO_PORT}" node "${ROOT}/scripts/smoke-echo.mjs" >"${STATE_DIR}/echo.log" 2>&1 &
ECHO_PID=$!
# The license and private egress override belong only to this loopback fixture.
(exec ${WRANGLER} dev --local --config "${STATE_DIR}/config/wrangler.toml" --ip 127.0.0.1 --port "${PORT}" --persist-to "${STATE_DIR}/state" --var "OPENWARP_MASTER_KEY:${MASTER}" --var "OPENWARP_ENV:development" --var "OPENWARP_LICENSE:development" --var "OPENWARP_PUBLIC_URL:${BASE}" --var "OPENWARP_AUTH_PROVIDERS:password" --var "OPENWARP_ALLOW_PRIVATE_EGRESS:1" --var "OPENWARP_EMAIL_PROVIDER:webhook" --var "OPENWARP_EMAIL_WEBHOOK:http://127.0.0.1:${ECHO_PORT}/mail" >"${LOG}" 2>&1) &
DEV_PID=$!
i=0
while [ "${i}" -lt 90 ]; do
  if ! kill -0 "${DEV_PID}" 2>/dev/null || ! kill -0 "${ECHO_PID}" 2>/dev/null; then
    printf 'SAML fixture exited before readiness; inspect %s\n' "${STATE_DIR}" >&2
    exit 1
  fi
  if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "${BASE}/health" >"${STATE_DIR}/health.json" 2>/dev/null && curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${ECHO_PORT}/_requests" >/dev/null 2>&1; then break; fi
  i=$((i + 1))
  sleep 1
done
if [ "${i}" -eq 90 ]; then printf '%s\n' 'SAML Worker fixture did not become ready within 90 attempts' >&2; exit 1; fi
printf 'worker=%s\nmail=http://127.0.0.1:%s\nreadiness_attempt=%s\n' "${BASE}" "${ECHO_PORT}" "$((i + 1))" >"${STATE_DIR}/readiness.log"
if OPENWARP_TEST_WORKER_URL="${BASE}" OPENWARP_TEST_MAIL_URL="http://127.0.0.1:${ECHO_PORT}" cargo test -p openwarp-server --test worker_saml --features saml "${TEST_NAME}" -- --ignored --exact --test-threads=1 >"${STATE_DIR}/test.log" 2>&1; then :; else
  status=$?
  node -e 'process.stdout.write(require("node:fs").readFileSync(process.argv[1], "utf8"))' "${STATE_DIR}/test.log"
  exit "${status}"
fi
node --input-type=module -e '
import fs from "node:fs";
const log = fs.readFileSync(process.argv[1], "utf8");
process.stdout.write(log);
const lines = log.split(/\r?\n/);
if (!lines.includes("running 1 test") || !lines.includes(`test ${process.argv[2]} ... ok`) ||
    !lines.some(line => /^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in .+$/.test(line))) {
  throw new Error("SAML acceptance requires exactly 1 passed, 0 failed, 0 ignored and 0 filtered out");
}' "${STATE_DIR}/test.log" "${TEST_NAME}"
SUCCESS=1
