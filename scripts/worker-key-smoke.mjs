#!/usr/bin/env node
// Uses a prebuilt Worker bundle, an opaque mock KMS, and disposable Wrangler state.
// Run serially: WRANGLER=/path/to/wrangler node scripts/worker-key-smoke.mjs
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { writeWorkerConfig } from './worker-config-smoke.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicOrigin = 'https://key-smoke.test.invalid';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const pbkdf2 = promisify(crypto.pbkdf2);
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function call(base, route, { method = 'GET', cookie, json } = {}) {
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = {}; }
  return { status: response.status, headers: response.headers, data };
}
const ok = (response, label) => { ensure(response.status === 200, `${label} must return HTTP 200 (got ${response.status})`); return response; };

function seal(key, plain, aad = Buffer.alloc(0)) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('base64');
}
function unseal(key, wrapped, aad) {
  const bytes = Buffer.from(wrapped, 'base64');
  ensure(bytes.length >= 28, 'mock KMS envelope must contain nonce and tag');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
  decipher.setAAD(aad); decipher.setAuthTag(bytes.subarray(-16));
  return Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
}
export function totp(secret, counter) {
  let bits = 0, accumulator = 0;
  const bytes = [];
  for (const char of secret.toUpperCase().replace(/=+$/, '')) {
    const value = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    ensure(value >= 0, 'TOTP secret must be base32');
    accumulator = (accumulator << 5) | value; bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  const input = Buffer.alloc(8); input.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', Buffer.from(bytes)).update(input).digest();
  return String((digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}

async function main() {
  let temp, child, config, base, currentCheck = 'fixture setup', checks = 0;
  const sockets = new Set(), messages = [];
  const mockKey = crypto.randomBytes(32), kmsKeyId = 'key-smoke-primary';
  const kms = { failWrap: true, rejected: 0, rootWraps: 0, rootUnwraps: 0, envWraps: new Set(), envUnwraps: new Set() };
  const mock = http.createServer(async (request, response) => {
    const send = (status, data) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(data)); };
    try {
      let raw = ''; for await (const chunk of request) { raw += chunk; ensure(raw.length <= 65536, 'mock request must stay bounded'); }
      const body = JSON.parse(raw);
      if (request.url === '/mail') { messages.push(body); send(200, {}); return; }
      ensure(request.method === 'POST' && ['/kms/wrap', '/kms/unwrap'].includes(request.url), 'mock KMS route must be wrap or unwrap');
      ensure(body.key_id === kmsKeyId, 'mock KMS must receive the configured key id');
      ensure(body.context === 'master' || /^env:[A-Za-z0-9_-]+$/.test(body.context), 'mock KMS must receive a master or environment context');
      const aad = Buffer.from(JSON.stringify([body.key_id, body.context]));
      if (request.url === '/kms/wrap') {
        if (kms.failWrap) { kms.rejected++; send(503, { error: 'deliberate mock wrap outage' }); return; }
        ensure(typeof body.plaintext === 'string', 'mock wrap requires base64 plaintext');
        const plain = Buffer.from(body.plaintext, 'base64');
        ensure(plain.length === 32, 'root and environment keys must be 32 bytes');
        if (body.context === 'master') kms.rootWraps++; else kms.envWraps.add(body.context);
        send(200, { wrapped: seal(mockKey, plain, aad) });
      } else {
        ensure(typeof body.wrapped === 'string', 'mock unwrap requires an opaque envelope');
        const plain = unseal(mockKey, body.wrapped, aad);
        ensure(plain.length === 32, 'unwrapped root and environment keys must be 32 bytes');
        if (body.context === 'master') kms.rootUnwraps++; else kms.envUnwraps.add(body.context);
        send(200, { plaintext: plain.toString('base64') });
      }
    } catch { send(400, { error: 'invalid mock request or envelope' }); }
  });
  mock.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  async function check(name, run) { currentCheck = name; await run(); checks++; console.log(`PASS ${name}`); }
  async function stop() {
    const processToStop = child; child = undefined;
    if (!processToStop?.pid || processToStop.exitCode !== null || processToStop.signalCode !== null) return;
    try { process.kill(-processToStop.pid, 'SIGTERM'); } catch { processToStop.kill('SIGTERM'); }
    await Promise.race([once(processToStop, 'exit'), sleep(3000)]);
    if (processToStop.exitCode === null && processToStop.signalCode === null) {
      try { process.kill(-processToStop.pid, 'SIGKILL'); } catch { processToStop.kill('SIGKILL'); }
      await once(processToStop, 'exit');
    }
  }
  async function start(master) {
    ensure(!child, 'previous Wrangler process must stop before restart');
    const port = await freePort(); base = `http://127.0.0.1:${port}`;
    const vars = { OPENWARP_ENV: 'production', OPENWARP_MASTER_KEY: master, OPENWARP_PUBLIC_URL: publicOrigin,
      OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_ALLOW_PRIVATE_EGRESS: '1',
      OPENWARP_KMS_URL: `${mockUrl}/kms`, OPENWARP_KMS_KEY_ID: kmsKeyId, OPENWARP_EMAIL_WEBHOOK: `${mockUrl}/mail` };
    const args = [...(process.env.WRANGLER ? [] : ['--no-install', 'wrangler']), 'dev', '--local', '--config', config,
      '--port', String(port), '--persist-to', path.join(temp, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(process.env.WRANGLER || 'npx', args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.resume(); child.stderr.resume();
    let spawnError; child.on('error', error => { spawnError = error; });
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler must remain alive until listener readiness');
      const listening = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1'); socket.setTimeout(100);
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false)); socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (listening) return;
      await sleep(100);
    }
    throw new Error('WranglerListenerDeadline');
  }
  async function healthy() {
    for (let i = 0; i < 80; i++) {
      const response = await call(base, '/health');
      if (response.status === 200) return;
      ensure(response.status === 503, 'recovering initialization may return only HTTP 503 before HTTP 200');
      await sleep(100);
    }
    throw new Error('HealthRecoveryDeadline');
  }
  let mockUrl;
  const owner = { email: `keys-${crypto.randomUUID()}@test.invalid`, password: crypto.randomUUID(), lastCounter: -1 };
  async function login() {
    const challenge = ok(await call(base, '/api/auth/challenge', { method: 'POST', json: { email: owner.email } }), 'client-auth challenge').data;
    ensure(typeof challenge.challenge === 'string' && typeof challenge.challenge_id === 'string', 'client-auth challenge must be present');
    const proof = crypto.createHmac('sha256', owner.authKey).update(`${challenge.challenge}|${challenge.challenge_id}`).digest('hex');
    let response = ok(await call(base, '/api/auth/login-v2', { method: 'POST', json: { email: owner.email, challenge_id: challenge.challenge_id, proof } }), 'client-auth proof');
    if (owner.totp) {
      ensure(response.data.mfa_required === true && !!response.data.mfa_token && !response.data.token, 'TOTP owner must require a second factor');
      while (Math.floor(Date.now() / 30000) <= owner.lastCounter) await sleep(200);
      const counter = Math.floor(Date.now() / 30000);
      response = ok(await call(base, '/api/auth/mfa', { method: 'POST', json: { mfa_token: response.data.mfa_token, code: totp(owner.totp, counter) } }), 'TOTP login');
      owner.lastCounter = counter;
    }
    const cookie = (response.headers.get('set-cookie') || '').split(';')[0];
    ensure(!!response.data.token && /^ow_session=.+/.test(cookie), 'verified owner login must issue a real session');
    ensure(/;\s*Secure(?:;|$)/i.test(response.headers.get('set-cookie') || ''), 'production HTTPS session cookie must be Secure');
    owner.cookie = cookie;
  }
  const originalMaster = crypto.randomBytes(32).toString('base64'), newMaster = crypto.randomBytes(32).toString('base64');
  const candidateMaster = crypto.randomBytes(32).toString('base64');
  const secret = { key: 'KEY_SMOKE', value: crypto.randomBytes(24).toString('base64'), comment: 'key smoke fixture', path: '/' };
  let env;
  async function readSecret() {
    const response = ok(await call(base, `/api/envs/${env}/secrets`, { cookie: owner.cookie }), 'existing secret read');
    const rows = response.data.secrets;
    ensure(Array.isArray(rows) && rows.length === 1, 'the original environment must still contain exactly one secret');
    ensure(rows[0].key === secret.key && rows[0].value === secret.value && rows[0].comment === secret.comment && rows[0].path === secret.path,
      'existing secret name, value, comment and path must survive the key transition');
  }
  try {
    await fs.access(path.join(root, 'crates/server/build/worker/shim.mjs'));
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-key-smoke-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir); config = await writeWorkerConfig(configDir);
    mockUrl = `http://127.0.0.1:${await listen(mock)}`;
    await check('KMS initialization outage returns real HTTP 503, then recovers in the same Worker', async () => {
      await start(originalMaster);
      const pid = child.pid, rejected = kms.rejected;
      const first = await call(base, '/health');
      ensure(first.status === 503, `initial KMS wrap outage must return HTTP 503 (got ${first.status})`);
      ensure(kms.rejected > rejected, 'initial HTTP 503 must follow an actual rejected KMS wrap');
      ensure(!first.headers.has('set-cookie'), 'failed initialization must not issue a session');
      kms.failWrap = false; await healthy();
      ensure(child.pid === pid && kms.rootWraps === 1, 'recovery must initialize one root without restarting Wrangler');
    });
    await check('mail-verified client-auth owner creates KMS-wrapped environments and reads a secret', async () => {
      const kdf = ok(await call(base, `/api/auth/kdf?email=${encodeURIComponent(owner.email)}`), 'KDF discovery').data;
      ensure(kdf.version === 2 && kdf.algo === 'pbkdf2-sha256' && kdf.iterations === 600000, 'fixture must use documented client-auth KDF');
      const derived = await pbkdf2(owner.password, Buffer.from(kdf.salt, 'base64'), kdf.iterations, 64, 'sha256');
      owner.authKey = derived.subarray(0, 32);
      const pair = crypto.generateKeyPairSync('x25519');
      const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
      const registered = ok(await call(base, '/api/auth/register-v2', { method: 'POST', json: { email: owner.email, salt: kdf.salt,
        iterations: kdf.iterations, algo: kdf.algo, auth_key: owner.authKey.toString('base64'), public_key: publicKey.toString('base64'),
        wrapped_privkey: `owv2:${seal(derived.subarray(32), privateKey)}` } }), 'client-auth registration');
      ensure(registered.data.verification_required === true && !registered.data.token && !registered.headers.has('set-cookie'), 'signup must require actual mailbox verification');
      let link;
      for (let i = 0; i < 100 && !link; i++) {
        link = String(messages.find(message => message.to === owner.email)?.text || '').match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
        if (!link) await sleep(100);
      }
      ensure(!!link, 'verification mail must reach the isolated sink');
      const url = new URL(link); ensure(url.origin === publicOrigin, 'verification URL must use the production HTTPS origin');
      ensure([200, 302, 303].includes((await call(base, url.pathname + url.search)).status), 'mail verification must succeed');
      await login();
      ensure(ok(await call(base, '/api/instance', { cookie: owner.cookie }), 'instance owner check').data.instance_owner === true, 'the real verified account must be instance owner');
      const app = ok(await call(base, `/api/orgs/${registered.data.org_id}/apps`, { method: 'POST', cookie: owner.cookie, json: { name: 'key fixture' } }), 'app creation').data.id;
      const envs = ok(await call(base, `/api/apps/${app}/envs`, { cookie: owner.cookie }), 'environment listing').data;
      ensure(Array.isArray(envs) && envs.length > 0 && typeof envs[0].id === 'string', 'fixture app must create environments'); env = envs[0].id;
      ensure(kms.envWraps.has(`env:${env}`), 'environment creation must actually wrap its key through KMS');
      ok(await call(base, `/api/envs/${env}/secrets`, { method: 'PUT', cookie: owner.cookie, json: { secrets: [secret] } }), 'secret deploy');
      await readSecret(); ensure(kms.envUnwraps.has(`env:${env}`), 'secret access must actually unwrap the environment key through KMS');
      const setup = ok(await call(base, '/api/me/totp/setup', { method: 'POST', cookie: owner.cookie, json: {} }), 'TOTP setup');
      ensure(typeof setup.data.secret === 'string' && setup.data.secret.length > 0, 'TOTP setup must return a client-held secret'); owner.totp = setup.data.secret;
      ensure(ok(await call(base, '/api/me/totp/verify', { method: 'POST', cookie: owner.cookie, json: { code: totp(owner.totp, Math.floor(Date.now() / 30000)) } }), 'TOTP enrollment').data.enabled === true, 'TOTP enrollment must activate the factor');
    });
    await check('failed KMS wrap rejects rotation without corrupting existing ciphertext or client auth', async () => {
      const rejected = kms.rejected; kms.failWrap = true;
      try {
        const response = await call(base, '/api/instance/rotate-master', { method: 'POST', cookie: owner.cookie, json: { new_key: candidateMaster } });
        ensure(response.status === 400 && response.data.ok !== true, `KMS wrap failure must reject rotation with HTTP 400 (got ${response.status})`);
        ensure(kms.rejected === rejected + 1, 'rejected rotation must actually reach the failed KMS wrap');
      } finally { kms.failWrap = false; }
      // Failure occurs before the SQL batch; this is not a SQL rollback test.
      await readSecret(); await login(); await readSecret();
    });
    await check('owner master rotation completes and preserves a current-instance secret read', async () => {
      const pid = child.pid, rootWraps = kms.rootWraps;
      const response = ok(await call(base, '/api/instance/rotate-master', { method: 'POST', cookie: owner.cookie, json: { new_key: newMaster } }), 'master rotation');
      ensure(response.data.ok === true && response.data.rotated_records >= 2, 'rotation must include encrypted client auth and TOTP state');
      ensure(kms.rootWraps === rootWraps + 1 && child.pid === pid, 'rotation must wrap the replacement root without restarting Wrangler');
      await readSecret(); ok(await call(base, '/health'), 'current-instance health');
    });
    await check('same persisted state with stale binding rejects health and existing-data reads', async () => {
      await stop(); const unwraps = kms.rootUnwraps; await start(originalMaster);
      for (const route of ['/health', `/api/envs/${env}/secrets`]) {
        const response = await call(base, route, { cookie: owner.cookie });
        ensure(response.status === 503, `stale master binding must return HTTP 503 (got ${response.status})`);
        ensure(!response.headers.has('set-cookie') && !Array.isArray(response.data.secrets), 'stale binding must not issue sessions or return existing secrets');
      }
      ensure(kms.rootUnwraps > unwraps, 'stale restart must consult the persisted KMS root');
    });
    await check('same persisted state with rotated binding restores client auth, TOTP and original secret', async () => {
      await stop(); const unwraps = kms.rootUnwraps; await start(newMaster); await healthy();
      ensure(kms.rootUnwraps > unwraps, 'correct restart must unwrap the persisted rotated root');
      await login(); await readSecret();
      ensure(ok(await call(base, '/api/instance', { cookie: owner.cookie }), 'persisted owner check').data.instance_owner === true, 'owner identity must persist across restarts');
    });
    console.log(`${checks} key runtime checks, 0 failures`);
  } catch (error) {
    // Never print response payloads, tokens, key bindings, or Wrangler logs.
    const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
    console.error(`FAIL ${currentCheck}: ${reason}`);
    console.error(`${checks} key runtime checks passed; remaining checks unqualified`);
    process.exitCode = 1;
  } finally {
    await stop(); for (const socket of sockets) socket.destroy();
    if (mock.listening) await new Promise(resolve => mock.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
