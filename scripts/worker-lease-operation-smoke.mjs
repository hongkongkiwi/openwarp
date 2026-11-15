#!/usr/bin/env node
// Requires a fresh prebuilt Worker and the pinned local Wrangler. Never builds or installs.
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
const wrangler = path.join(root, '.agents/tools/worker/node_modules/.bin/wrangler');
const publicOrigin = 'https://lease-operations.test.invalid';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const pbkdf2 = promisify(crypto.pbkdf2);
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function files(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return (await Promise.all(entries.map(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : [path.join(dir, entry.name)]))).flat();
}
async function requireFreshBundle() {
  await fs.access(wrangler);
  const build = path.join(root, 'crates/server/build');
  await fs.access(path.join(build, 'worker/shim.mjs'));
  const artifacts = (await files(build)).filter(file => /\.(wasm|mjs|js)$/.test(file));
  ensure(artifacts.some(file => file.endsWith('.wasm')), 'prebuilt Worker must contain an actual wasm artifact');
  const inputs = ['Cargo.toml', 'Cargo.lock', 'crates/server/Cargo.toml', 'crates/crypto/Cargo.toml', 'wrangler.toml'].map(file => path.join(root, file));
  for (const dir of ['crates/server/src', 'crates/server/migrations', 'crates/crypto/src']) inputs.push(...await files(path.join(root, dir)));
  const newestInput = Math.max(...await Promise.all(inputs.map(async file => (await fs.stat(file)).mtimeMs)));
  const oldestArtifact = Math.min(...await Promise.all(artifacts.map(async file => (await fs.stat(file)).mtimeMs)));
  ensure(oldestArtifact >= newestInput, 'stale Worker bundle is unqualified; rebuild the current sources before running this smoke');
}
async function call(base, route, { method = 'GET', cookie, json } = {}) {
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  let data; try { data = JSON.parse(await response.text()); } catch { data = {}; }
  return { status: response.status, headers: response.headers, data };
}
function ok(response, label) {
  const knownClockFailure = /no such function:\s*OW_NOW/i.test(String(response.data?.error || ''));
  ensure(response.status === 200, `${label} must return HTTP 200 (got ${response.status}${knownClockFailure ? '; no such function: OW_NOW' : ''})`);
  return response.data;
}
function wrappedPrivateKey(key, plain) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return `owv2:${Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('base64')}`;
}

async function main() {
  let temp, child, base, cookie, env, failures = 0, checks = 0, fixtureReady = false, clockFailure = false;
  let phase = 'fresh bundle and isolated workerd fixture';
  const messages = [], sockets = new Set();
  let mockFaults = 0;
  const mail = http.createServer(async (request, response) => {
    try {
      ensure(request.method === 'POST' && request.url === '/mail', 'mail fixture accepts only its local POST route');
      let raw = ''; for await (const chunk of request) { raw += chunk; ensure(raw.length <= 65536, 'mail fixture request must stay bounded'); }
      messages.push(JSON.parse(raw)); response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}');
    } catch { mockFaults++; response.writeHead(400); response.end('{}'); }
  });
  mail.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const api = (route, options = {}) => call(base, route, { cookie, ...options });
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
  async function check(name, run) {
    phase = name; checks++;
    try { await run(); console.log(`PASS ${name}`); }
    catch (error) {
      failures++;
      const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
      console.error(`FAIL ${name}: ${reason}`);
    }
  }
  async function issue(name) {
    const lease = ok(await api(`/api/envs/${env}/dynamic`, { method: 'POST', json: { name, type: 'generic', ttl_secs: 60 } }), 'generic lease issuance');
    ensure(typeof lease.id === 'string' && !!lease.id && typeof lease.value === 'string' && !!lease.value, 'issuance must return a real lease and credential');
    ensure(Number.isSafeInteger(lease.expires_at), 'issued lease must have an integer expiry');
    return lease;
  }
  async function lookup(id) { return ok(await api(`/api/leases/${id}`), 'lease metadata lookup'); }
  try {
    await requireFreshBundle();
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-worker-lease-operations-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir);
    const config = await writeWorkerConfig(configDir), port = await freePort(); base = `http://127.0.0.1:${port}`;
    const mailUrl = `http://127.0.0.1:${await listen(mail)}/mail`;
    const vars = { OPENWARP_ENV: 'test', OPENWARP_MASTER_KEY: crypto.randomBytes(32).toString('base64'), OPENWARP_PUBLIC_URL: publicOrigin,
      OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_EMAIL_PROVIDER: 'webhook', OPENWARP_EMAIL_WEBHOOK: mailUrl, OPENWARP_ALLOW_PRIVATE_EGRESS: '1' };
    const args = ['dev', '--local', '--config', config, '--port', String(port), '--persist-to', path.join(temp, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(wrangler, args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
    // Retain only the known SQL-clock diagnostic, never raw logs or request payloads.
    let logTail = '';
    const inspectLog = chunk => { logTail = (logTail + chunk.toString()).slice(-4096); if (/no such function:\s*OW_NOW/i.test(logTail)) clockFailure = true; };
    child.stdout.on('data', inspectLog); child.stderr.on('data', inspectLog);
    let spawnError; child.on('error', error => { spawnError = error; });
    let listening = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler must remain alive until listener readiness');
      listening = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1'); socket.setTimeout(100);
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false)); socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (listening) break; await sleep(100);
    }
    ensure(listening, 'local workerd listener must become ready within 60 seconds');
    let healthy = false;
    for (let i = 0; i < 40; i++) {
      const health = await api('/health'); if (health.status === 200) { healthy = true; break; }
      ensure(health.status === 503, 'initialization may return only HTTP 503 before healthy'); await sleep(100);
    }
    ensure(healthy, 'fresh Worker must initialize its private Durable Object database');
    const email = `lease-${crypto.randomUUID()}@test.invalid`, password = crypto.randomUUID();
    const kdf = ok(await api(`/api/auth/kdf?email=${encodeURIComponent(email)}`), 'KDF discovery');
    ensure(kdf.version === 2 && kdf.algo === 'pbkdf2-sha256' && kdf.iterations === 600000, 'fixture must use client-derived authentication');
    const derived = await pbkdf2(password, Buffer.from(kdf.salt, 'base64'), kdf.iterations, 64, 'sha256'), authKey = derived.subarray(0, 32);
    const pair = crypto.generateKeyPairSync('x25519');
    const registeredResponse = await api('/api/auth/register-v2', { method: 'POST', json: { email, salt: kdf.salt, iterations: kdf.iterations, algo: kdf.algo,
      auth_key: authKey.toString('base64'), public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
      wrapped_privkey: wrappedPrivateKey(derived.subarray(32), pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)) } });
    const registered = ok(registeredResponse, 'client-auth registration');
    ensure(registered.verification_required === true && !registered.token && !registeredResponse.headers.has('set-cookie'), 'registration must require actual mailbox verification');
    let link;
    for (let i = 0; i < 100 && !link; i++) {
      link = String(messages.find(message => message.to === email)?.text || '').match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
      if (!link) await sleep(100);
    }
    ensure(!!link, 'verification email must reach the isolated local sink');
    const verification = new URL(link); ensure(verification.origin === publicOrigin, 'verification mail must use the configured origin');
    ensure([200, 302, 303].includes((await api(verification.pathname + verification.search)).status), 'email verification must succeed');
    const challenge = ok(await api('/api/auth/challenge', { method: 'POST', json: { email } }), 'client-auth challenge');
    ensure(typeof challenge.challenge === 'string' && typeof challenge.challenge_id === 'string', 'login must receive a real challenge');
    const proof = crypto.createHmac('sha256', authKey).update(`${challenge.challenge}|${challenge.challenge_id}`).digest('hex');
    const login = await api('/api/auth/login-v2', { method: 'POST', json: { email, challenge_id: challenge.challenge_id, proof } });
    const session = ok(login, 'verified client-auth login'); cookie = (login.headers.get('set-cookie') || '').split(';')[0];
    ensure(!!session.token && !session.mfa_required && /^ow_session=.+/.test(cookie), 'verified owner without TOTP must receive a cookie session');
    const orgs = ok(await api('/api/orgs'), 'workspace listing'); ensure(Array.isArray(orgs) && typeof orgs[0]?.id === 'string', 'verified owner must have a workspace');
    const app = ok(await api(`/api/orgs/${orgs[0].id}/apps`, { method: 'POST', json: { name: 'Worker lease operation regressions' } }), 'application creation');
    ensure(typeof app.id === 'string', 'application creation must return an id');
    const envs = ok(await api(`/api/apps/${app.id}/envs`), 'environment listing');
    ensure(Array.isArray(envs) && typeof envs[0]?.id === 'string', 'application must create environments'); env = envs[0].id;
    const renewLease = await issue('renew-in-workerd'), revokeLease = await issue('revoke-in-workerd');
    fixtureReady = true; console.log('PASS isolated workerd, verified v2 cookie session, and two generic leases');
    const mailCount = messages.length;
    await check('Worker generic renewal commits exact expiry and retains its credential', async () => {
      const before = await lookup(renewLease.id);
      ensure(before.type === 'generic' && before.renewable === true && before.revoked === false, 'fresh generic lease must be active and renewable');
      const started = Math.floor(Date.now() / 1000);
      const renewed = ok(await api(`/api/leases/${renewLease.id}/renew`, { method: 'POST', json: { ttl_secs: 3600 } }), 'Worker audited generic renewal');
      const finished = Math.floor(Date.now() / 1000), after = await lookup(renewLease.id);
      ensure(renewed.id === renewLease.id && Number.isSafeInteger(renewed.expires_at), 'renewal must identify the existing lease and integer deadline');
      ensure(renewed.expires_at >= started + 3600 && renewed.expires_at <= finished + 3600, 'renewal expiry must equal a renewal-time second plus the requested TTL');
      ensure(after.expires_at === renewed.expires_at && after.expires_at > before.expires_at, 'lookup must retain exactly the committed extended expiry');
      ensure(after.renewable === true && after.revoked === false, 'completed renewal must release its claim and remain renewable');
      const rows = ok(await api(`/api/envs/${env}/dynamic`), 'renewed credential listing');
      ensure(Array.isArray(rows), 'lease list must be an array'); const row = rows.find(item => item.id === renewLease.id);
      ensure(row?.value === renewLease.value && row.expires_at === renewed.expires_at, 'renewal must retain the exact issued credential and committed expiry');
    });
    await check('Worker generic revocation commits revoked metadata and refuses renewal', async () => {
      const before = await lookup(revokeLease.id); ensure(before.revoked === false && before.renewable === true, 'independent revoke fixture must begin active');
      const revoked = ok(await api(`/api/leases/${revokeLease.id}`, { method: 'DELETE' }), 'Worker audited generic revocation');
      ensure(revoked.revoked === revokeLease.id, 'revocation response must identify the issued lease');
      const after = await lookup(revokeLease.id);
      ensure(after.revoked === true && after.renewable === false && after.expires_at === before.expires_at, 'revocation must commit metadata without rewriting expiry');
      const rejected = await api(`/api/leases/${revokeLease.id}/renew`, { method: 'POST', json: { ttl_secs: 3600 } });
      ensure([400, 404, 409, 410, 422, 501].includes(rejected.status) && typeof rejected.data.error === 'string', 'revoked Worker lease must reject renewal');
      const final = await lookup(revokeLease.id);
      ensure(final.revoked === true && final.renewable === false && final.expires_at === before.expires_at, 'rejected renewal must leave revoked metadata unchanged');
    });
    await check('ordinary lease actions without TOTP need no extra email proof', async () => {
      ensure(messages.length === mailCount && mockFaults === 0, 'Major lease actions without enrolled TOTP must not send additional email or hide malformed fixture traffic');
    });
  } catch (error) {
    failures++;
    const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
    console.error(`UNQUALIFIED ${phase}: ${reason}`);
  } finally {
    await stop(); for (const socket of sockets) socket.destroy();
    if (mail.listening) await new Promise(resolve => mail.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
  if (clockFailure) console.error('DIAGNOSTIC workerd observed no such function: OW_NOW');
  console.log(`${checks} Worker lease operation checks attempted, ${failures} failures, fixture ${fixtureReady ? 'qualified' : 'unqualified'}`);
  process.exitCode = failures || !fixtureReady ? 1 : 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
