#!/usr/bin/env node
// Uses a source-matched prebuilt Worker bundle and disposable Wrangler state.
// Run serially: WRANGLER=/absolute/path/to/wrangler node scripts/worker-rotation-inventory-smoke.mjs
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
import { totp } from './worker-key-smoke.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicOrigin = 'https://rotation-inventory.test.invalid';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const pbkdf2 = promisify(crypto.pbkdf2);
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function call(base, route, { method = 'GET', cookie, json } = {}) {
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  let data; try { data = JSON.parse(await response.text()); } catch { data = {}; }
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

async function main() {
  let temp, config, child, mockUrl, checks = 0, failures = 0, unqualified = 0;
  let phase = 'Worker rotation inventory setup';
  const sockets = new Set(), messages = [], hooks = [];
  const kmsKey = crypto.randomBytes(32), kmsId = 'rotation-inventory-fixture';
  const kms = { failWrap: false, rejected: 0, rootWraps: 0, rootUnwraps: 0, envWraps: new Set(), envUnwraps: new Set() };
  let mockFaults = 0;
  const mock = http.createServer(async (request, response) => {
    const send = (status, data) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(data)); };
    try {
      let raw = ''; for await (const chunk of request) { raw += chunk; ensure(raw.length <= 65536, 'mock request must stay bounded'); }
      ensure(request.method === 'POST', 'mock accepts POST requests only');
      const body = JSON.parse(raw);
      if (request.url === '/mail') { messages.push(body); send(200, {}); return; }
      if (request.url === '/hook') { hooks.push({ raw, body, headers: request.headers }); send(200, {}); return; }
      ensure(['/kms/wrap', '/kms/unwrap'].includes(request.url), 'mock KMS route must be wrap or unwrap');
      ensure(body.key_id === kmsId, 'mock KMS must receive the configured key id');
      ensure(body.context === 'master' || /^env:[A-Za-z0-9_-]+$/.test(body.context), 'mock KMS context must identify the root or an environment');
      const aad = Buffer.from(JSON.stringify([body.key_id, body.context]));
      if (request.url === '/kms/wrap') {
        if (kms.failWrap) { kms.rejected++; send(503, { error: 'deliberate fixture wrap outage' }); return; }
        ensure(typeof body.plaintext === 'string', 'mock wrap requires base64 plaintext');
        const plain = Buffer.from(body.plaintext, 'base64');
        ensure(plain.length === 32, 'root and environment keys must be 32 bytes');
        if (body.context === 'master') kms.rootWraps++; else kms.envWraps.add(body.context);
        send(200, { wrapped: seal(kmsKey, plain, aad) });
      } else {
        ensure(typeof body.wrapped === 'string', 'mock unwrap requires an opaque envelope');
        const plain = unseal(kmsKey, body.wrapped, aad);
        ensure(plain.length === 32, 'unwrapped root and environment keys must be 32 bytes');
        if (body.context === 'master') kms.rootUnwraps++; else kms.envUnwraps.add(body.context);
        send(200, { plaintext: plain.toString('base64') });
      }
    } catch { mockFaults++; send(400, { error: 'invalid isolated fixture request' }); }
  });
  mock.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  async function check(name, run) {
    phase = name; checks++;
    try { await run(); console.log(`PASS ${name}`); return true; }
    catch (error) {
      failures++;
      // Never print HTTP payloads, keys, cookies, bindings, or Wrangler logs.
      const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
      console.error(`FAIL ${name}: ${reason}`); return false;
    }
  }
  async function stop() {
    const previous = child; child = undefined;
    if (!previous?.pid || previous.exitCode !== null || previous.signalCode !== null) return;
    try { process.kill(-previous.pid, 'SIGTERM'); } catch { previous.kill('SIGTERM'); }
    await Promise.race([once(previous, 'exit'), sleep(3000)]);
    if (previous.exitCode === null && previous.signalCode === null) {
      try { process.kill(-previous.pid, 'SIGKILL'); } catch { previous.kill('SIGKILL'); }
      await once(previous, 'exit');
    }
  }
  async function start(label, master, withKms) {
    ensure(!child, 'previous Wrangler process must stop before restart');
    const port = await freePort(), base = `http://127.0.0.1:${port}`;
    const vars = { OPENWARP_ENV: 'production', OPENWARP_MASTER_KEY: master, OPENWARP_PUBLIC_URL: publicOrigin,
      OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_ALLOW_PRIVATE_EGRESS: '1', OPENWARP_EMAIL_WEBHOOK: `${mockUrl}/mail`,
      OPENWARP_KMS_URL: withKms ? `${mockUrl}/kms` : '', OPENWARP_KMS_KEY_ID: withKms ? kmsId : '' };
    const args = [...(process.env.WRANGLER ? [] : ['--no-install', 'wrangler']), 'dev', '--local', '--config', config,
      '--port', String(port), '--persist-to', path.join(temp, label)];
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
      if (listening) return base;
      await sleep(100);
    }
    throw new Error('WranglerListenerDeadline');
  }
  async function healthy(base) {
    for (let i = 0; i < 40; i++) {
      const response = await call(base, '/health');
      if (response.status === 200) return;
      ensure(response.status === 503, 'initialization may return only HTTP 503 before HTTP 200');
      await sleep(100);
    }
    assert.fail('matching root binding must recover HTTP 200 health from the persisted encrypted inventory');
  }
  async function fixture(withKms) {
    const label = withKms ? 'KMS root' : 'bound root';
    const original = crypto.randomBytes(32).toString('base64'), replacement = crypto.randomBytes(32).toString('base64');
    const owner = { email: `rotation-${crypto.randomUUID()}@test.invalid`, password: crypto.randomUUID(), lastCounter: -1 };
    const secret = { key: 'ROTATION_INVENTORY', value: crypto.randomBytes(24).toString('base64'), comment: 'inventory fixture', path: '/' };
    const hookKey = crypto.randomBytes(32).toString('base64');
    let base, org, env, transitRoute;
    const ciphertexts = [];
    const api = (route, options = {}) => call(base, route, { cookie: owner.cookie, ...options });
    async function login() {
      const challenge = ok(await api('/api/auth/challenge', { method: 'POST', json: { email: owner.email } }), 'client-auth challenge').data;
      ensure(typeof challenge.challenge === 'string' && typeof challenge.challenge_id === 'string', 'client-auth challenge must be present');
      const proof = crypto.createHmac('sha256', owner.authKey).update(`${challenge.challenge}|${challenge.challenge_id}`).digest('hex');
      let response = ok(await api('/api/auth/login-v2', { method: 'POST', json: { email: owner.email, challenge_id: challenge.challenge_id, proof } }), 'client-auth proof');
      if (owner.totp) {
        ensure(response.data.mfa_required === true && !!response.data.mfa_token && !response.data.token, 'TOTP owner must require a second factor');
        while (Math.floor(Date.now() / 30000) <= owner.lastCounter) await sleep(200);
        const counter = Math.floor(Date.now() / 30000);
        response = ok(await api('/api/auth/mfa', { method: 'POST', json: { mfa_token: response.data.mfa_token, code: totp(owner.totp, counter) } }), 'TOTP login');
        owner.lastCounter = counter;
      }
      const cookie = (response.headers.get('set-cookie') || '').split(';')[0];
      ensure(!!response.data.token && /^ow_session=.+/.test(cookie), 'verified login must issue a real session');
      owner.cookie = cookie;
    }
    async function readSecret() {
      const rows = ok(await api(`/api/envs/${env}/secrets`), 'existing environment read').data.secrets;
      ensure(Array.isArray(rows) && rows.length === 1, 'original environment must retain exactly one secret');
      ensure(rows[0].key === secret.key && rows[0].value === secret.value && rows[0].path === secret.path && rows[0].comment === secret.comment,
        'environment secret name, value, path and comment must survive the root transition');
      if (withKms) ensure(kms.envUnwraps.has(`env:${env}`), 'secret read must actually unwrap the environment key through KMS');
    }
    async function readTransit() {
      for (const item of ciphertexts) {
        const response = ok(await api(`${transitRoute}/decrypt`, { method: 'POST', json: { ciphertext: item.ciphertext, ...item.context } }), 'pre-rotation compat Transit ciphertext decrypt');
        ensure(response.data.plaintext === item.plaintext, 'every original compat Transit ciphertext must retain its exact plaintext');
      }
      const wrong = await api(`${transitRoute}/decrypt`, { method: 'POST', json: { ciphertext: ciphertexts[0].ciphertext, context: 'different-context' } });
      ensure(wrong.status === 400 && !wrong.data.plaintext, 'compat Transit must still reject a wrong context without plaintext');
      const rewrapped = ok(await api(`${transitRoute}/rewrap`, { method: 'POST', json: { ciphertext: ciphertexts[0].ciphertext, ...ciphertexts[0].context } }), 'compat Transit rewrap');
      ensure(rewrapped.data.key_version === 2 && /^owtransit:v1:2:/.test(rewrapped.data.ciphertext), 'rewrap must retain the latest compatibility version and wire format');
      const opened = ok(await api(`${transitRoute}/decrypt`, { method: 'POST', json: { ciphertext: rewrapped.data.ciphertext, ...ciphertexts[0].context } }), 'rewrapped compat Transit decrypt');
      ensure(opened.data.plaintext === ciphertexts[0].plaintext, 'rewrapped ciphertext must preserve the original plaintext');
    }
    async function fireHook() {
      const before = hooks.length;
      secret.value = crypto.randomBytes(24).toString('base64'); secret.comment = 'auto-rotation';
      const response = ok(await api(`/api/envs/${env}/rotate`, { method: 'POST', json: { key: secret.key, value: secret.value } }), 'secret rotation');
      ensure(response.data.rotation_hook_error === null, 'stored rotation-hook secret must remain usable after root rotation');
      ensure(Array.isArray(response.data.sync_errors) && response.data.sync_errors.length === 0, 'fixture must not hide integration sync errors');
      ensure(hooks.length === before + 1, 'secret rotation must deliver exactly one request to the isolated hook');
      const delivered = hooks[before], timestamp = delivered.headers['x-openwarp-timestamp'];
      ensure(typeof timestamp === 'string' && /^\d+$/.test(timestamp), 'rotation hook must include a signing timestamp');
      const expected = crypto.createHmac('sha256', hookKey).update(`${timestamp}.${delivered.raw}`).digest('hex');
      ensure(delivered.headers['x-openwarp-signature'] === `t=${timestamp},v1=${expected}`, 'rotation hook HMAC must verify under its original configured secret');
      ensure(delivered.body.event === 'secret.rotated' && delivered.body.org_id === org && delivered.body.env_id === env && delivered.body.key === secret.key && delivered.body.value === secret.value,
        'signed hook must carry the exact local secret rotation, not a substitute notification');
    }
    async function personalCredentials() {
      // These handlers decrypt before returning the intentional Worker transport refusal.
      const hibp = await api('/api/me/secret-health/email', { method: 'POST', json: { consent: true, email: owner.email } });
      ensure(hibp.status === 501, 'retained HIBP credential must decrypt before Worker transport refuses the email check');
      const enzoic = await api('/api/me/secret-health/enzoic/password', { method: 'POST', json: { consent: true, prefix: '0123456789' } });
      ensure(enzoic.status === 501, 'retained Enzoic credentials must decrypt before Worker transport refuses the password check');
    }
    try {
      phase = `${label}: establish real encrypted inventory`;
      base = await start(label, original, withKms); await healthy(base);
      const kdf = ok(await api(`/api/auth/kdf?email=${encodeURIComponent(owner.email)}`), 'KDF discovery').data;
      ensure(kdf.version === 2 && kdf.algo === 'pbkdf2-sha256' && kdf.iterations === 600000, 'fixture must use the documented client-auth KDF');
      const derived = await pbkdf2(owner.password, Buffer.from(kdf.salt, 'base64'), kdf.iterations, 64, 'sha256');
      owner.authKey = derived.subarray(0, 32);
      const pair = crypto.generateKeyPairSync('x25519');
      const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
      const registered = ok(await api('/api/auth/register-v2', { method: 'POST', json: { email: owner.email, salt: kdf.salt,
        iterations: kdf.iterations, algo: kdf.algo, auth_key: owner.authKey.toString('base64'), public_key: publicKey.toString('base64'),
        wrapped_privkey: `owv2:${seal(derived.subarray(32), privateKey)}` } }), 'client-auth registration');
      ensure(registered.data.verification_required === true && !registered.data.token && !registered.headers.has('set-cookie'), 'registration must require actual mailbox verification');
      let link;
      for (let i = 0; i < 100 && !link; i++) {
        link = String(messages.find(message => message.to === owner.email)?.text || '').match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
        if (!link) await sleep(100);
      }
      ensure(!!link, 'verification mail must reach the isolated sink');
      const url = new URL(link); ensure(url.origin === publicOrigin, 'verification mail must use the configured HTTPS origin');
      ensure([200, 302, 303].includes((await api(url.pathname + url.search)).status), 'mail verification must succeed');
      await login();
      ensure(ok(await api('/api/instance'), 'instance owner check').data.instance_owner === true, 'verified fixture account must be the instance owner');
      org = registered.data.org_id; ensure(typeof org === 'string' && !!org, 'registered owner must have a workspace');
      const app = ok(await api(`/api/orgs/${org}/apps`, { method: 'POST', json: { name: 'rotation inventory' } }), 'application creation').data.id;
      const envs = ok(await api(`/api/apps/${app}/envs`), 'environment listing').data;
      ensure(Array.isArray(envs) && typeof envs[0]?.id === 'string', 'application must create environments'); env = envs[0].id;
      if (withKms) ensure(kms.envWraps.has(`env:${env}`), 'KMS fixture must create externally wrapped environment keys');
      ok(await api(`/api/envs/${env}/secrets`, { method: 'PUT', json: { secrets: [secret] } }), 'initial secret deploy');
      transitRoute = `/api/orgs/${org}/transit-compat/keys`;
      const transit = ok(await api(transitRoute, { method: 'POST', json: { name: 'inventory-compat' } }), 'compat Transit key creation').data;
      ensure(typeof transit.id === 'string' && transit.key_version === 1, 'compat Transit must create its first key version'); transitRoute += `/${transit.id}`;
      for (const version of [1, 2]) {
        if (version === 2) ensure(ok(await api(`${transitRoute}/rotate`, { method: 'POST' }), 'compat Transit key rotation').data.key_version === 2, 'compat Transit fixture must retain two key versions');
        const plaintext = crypto.randomBytes(40).toString('base64'), context = version === 1 ? { context: 'inventory/context' } : {};
        const encrypted = ok(await api(`${transitRoute}/encrypt`, { method: 'POST', json: { plaintext, ...context } }), 'compat Transit encryption').data;
        ensure(encrypted.key_version === version && encrypted.ciphertext?.startsWith(`owtransit:v1:${version}:`), 'fixture must produce real versioned compatibility ciphertext');
        ciphertexts.push({ ciphertext: encrypted.ciphertext, plaintext, context });
      }
      ok(await api(`/api/orgs/${org}/rotation-hook`, { method: 'PUT', json: { url: `${mockUrl}/hook`, secret: hookKey } }), 'rotation hook configuration');
      ok(await api('/api/me/secret-health', { method: 'PUT', json: { api_key: crypto.randomBytes(16).toString('hex') } }), 'HIBP credential storage');
      ok(await api('/api/me/secret-health/enzoic', { method: 'PUT', json: { api_key: crypto.randomBytes(20).toString('hex'), api_secret: crypto.randomBytes(20).toString('hex') } }), 'Enzoic credential storage');
      // AI inference is native-only. Its persisted key participates in KMS cold-start verification.
      ensure(ok(await api(`/api/orgs/${org}/ai/settings`, { method: 'PUT', json: { api_key: crypto.randomBytes(24).toString('base64') } }), 'AI credential storage').data.has_api_key === true, 'fixture must persist an AI provider credential');
      const setup = ok(await api('/api/me/totp/setup', { method: 'POST', json: {} }), 'TOTP setup').data;
      ensure(typeof setup.secret === 'string' && setup.secret.length > 0, 'TOTP setup must return a client-held secret'); owner.totp = setup.secret;
      owner.lastCounter = Math.floor(Date.now() / 30000);
      ensure(ok(await api('/api/me/totp/verify', { method: 'POST', json: { code: totp(owner.totp, owner.lastCounter) } }), 'TOTP enrollment').data.enabled === true, 'TOTP factor must activate');
      await readSecret(); await readTransit(); await fireHook(); await personalCredentials();
      checks++; console.log(`PASS ${label}: establish real encrypted inventory`);
      const preflightGood = await check(`${label}: current-key rotation is refused without breaking existing records`, async () => {
        const response = await api('/api/instance/rotate-master', { method: 'POST', json: { new_key: original } });
        ensure(response.status === 400 && response.data.ok !== true, 'rotation to the current key must be refused');
        await readSecret(); await readTransit(); await fireHook(); await personalCredentials();
      });
      if (!preflightGood) { unqualified++; return; }
      if (withKms) {
        const rejected = await check(`${label}: failed replacement wrap leaves persisted old-root inventory usable`, async () => {
          const before = kms.rejected; kms.failWrap = true;
          try {
            const response = await api('/api/instance/rotate-master', { method: 'POST', json: { new_key: crypto.randomBytes(32).toString('base64') } });
            ensure(response.status === 400 && response.data.ok !== true, 'failed KMS wrap must reject root rotation with HTTP 400');
            ensure(kms.rejected === before + 1, 'failed rotation must make exactly one real KMS wrap attempt');
          } finally { kms.failWrap = false; }
          // This proves rejection before the batch, not rollback after a SQL fault.
          await stop(); base = await start(label, original, withKms); await healthy(base);
          await login(); await readSecret(); await readTransit(); await fireHook(); await personalCredentials();
        });
        if (!rejected) { unqualified++; return; }
      }
      const rotated = await check(`${label}: instance owner completes root rotation`, async () => {
        const wraps = kms.rootWraps;
        const response = ok(await api('/api/instance/rotate-master', { method: 'POST', json: { new_key: replacement } }), 'root rotation');
        ensure(response.data.ok === true, 'successful rotation must report completion');
        if (withKms) ensure(kms.rootWraps === wraps + 1, 'successful rotation must actually wrap one replacement root through KMS');
      });
      if (!rotated) { unqualified++; return; }
      await check(`${label}: original environment decrypts after root rotation`, readSecret);
      await check(`${label}: both original compat Transit versions survive root rotation`, readTransit);
      await check(`${label}: original rotation-hook secret still signs exact payloads`, fireHook);
      await check(`${label}: personal credentials remain decryptable with Worker transport refused`, personalCredentials);
      await check(`${label}: stale binding cannot initialize or read existing records`, async () => {
        await stop(); const unwraps = kms.rootUnwraps; base = await start(label, original, withKms);
        for (const route of ['/health', `/api/envs/${env}/secrets`, `${transitRoute}/decrypt`]) {
          const response = await api(route, route.endsWith('/decrypt') ? { method: 'POST', json: { ciphertext: ciphertexts[0].ciphertext, ...ciphertexts[0].context } } : {});
          ensure(response.status === 503, `stale root must refuse initialization and existing-data access with HTTP 503 (got ${response.status})`);
          ensure(!response.headers.has('set-cookie') && !response.data.plaintext && !response.data.secrets, 'stale root must not issue sessions or return protected data');
        }
        if (withKms) ensure(kms.rootUnwraps > unwraps, 'stale KMS restart must consult the persisted root');
      });
      const restarted = await check(`${label}: matching binding cold-starts the complete encrypted inventory`, async () => {
        await stop(); const unwraps = kms.rootUnwraps; base = await start(label, replacement, withKms); await healthy(base);
        if (withKms) ensure(kms.rootUnwraps > unwraps, 'matching KMS restart must unwrap the persisted replacement root');
      });
      if (!restarted) { unqualified += 4; return; }
      await check(`${label}: cold restart restores client auth, TOTP and original environment`, async () => { await login(); await readSecret(); });
      await check(`${label}: cold restart retains both compat Transit ciphertext versions`, readTransit);
      await check(`${label}: cold restart retains the original signed rotation hook`, fireHook);
      await check(`${label}: cold restart retains personal credentials without provider egress`, personalCredentials);
    } catch (error) {
      failures++; unqualified++;
      const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
      console.error(`FAIL ${phase}: ${reason}`);
    } finally { kms.failWrap = false; await stop(); }
  }
  try {
    await fs.access(path.join(root, 'crates/server/build/worker/shim.mjs'));
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-rotation-inventory-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir); config = await writeWorkerConfig(configDir);
    mockUrl = `http://127.0.0.1:${await listen(mock)}`;
    await fixture(false); await fixture(true);
    await check('isolated fixtures received only valid bounded requests', async () => { ensure(mockFaults === 0, 'mock fixture must not hide malformed requests or KMS envelope failures'); });
  } catch (error) {
    failures++; unqualified++;
    console.error(`FAIL ${phase}: ${error.code || error.name}`);
  } finally {
    await stop(); for (const socket of sockets) socket.destroy();
    if (mock.listening) await new Promise(resolve => mock.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
  console.log(`${checks} Worker rotation inventory checks attempted, ${failures} failures, ${unqualified} dependent check groups unqualified`);
  process.exitCode = failures || unqualified ? 1 : 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
