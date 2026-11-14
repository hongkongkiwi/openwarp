#!/usr/bin/env node
// Requires a fresh core Worker and WRANGLER pointing to installed Wrangler 4.158.0. Never builds or installs.
// Exercises migration 39 on fresh Durable Object storage, not an upgrade from a preexisting database.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
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
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const pbkdf2 = promisify(crypto.pbkdf2);
const expectedChecks = 6;
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function files(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return (await Promise.all(entries.map(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : [path.join(dir, entry.name)]))).flat();
}
function localEnvironment() {
  return { ...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(OPENWARP_|CLOUDFLARE_|CF_)/.test(key) && !/^(DATABASE_URL|REDIS_URL|ADDR|https?_proxy|all_proxy|no_proxy)$/i.test(key))),
    WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' };
}
async function requireFreshBundle(wrangler) {
  ensure(typeof wrangler === 'string' && path.isAbsolute(wrangler), 'WRANGLER must explicitly name an installed absolute executable path');
  const { stdout } = await promisify(execFile)(wrangler, ['--version'], { cwd: root, timeout: 15000, maxBuffer: 65536, env: localEnvironment() });
  ensure(stdout.trim() === '4.158.0', 'receipt smoke requires exactly Wrangler 4.158.0');
  const build = path.join(root, 'crates/server/build');
  await fs.access(path.join(build, 'worker/shim.mjs'));
  const artifacts = (await files(build)).filter(file => /\.(wasm|mjs|js)$/.test(file));
  ensure(artifacts.some(file => file.endsWith('.wasm')), 'prebuilt Worker must contain an actual wasm artifact');
  const inputs = ['Cargo.toml', 'Cargo.lock', 'crates/server/Cargo.toml', 'crates/crypto/Cargo.toml', 'wrangler.toml'].map(file => path.join(root, file));
  for (const dir of ['crates/server/src', 'crates/server/migrations', 'crates/crypto/src', 'vendor']) inputs.push(...await files(path.join(root, dir)));
  const newestInput = Math.max(...await Promise.all(inputs.map(async file => (await fs.stat(file)).mtimeMs)));
  const oldestArtifact = Math.min(...await Promise.all(artifacts.map(async file => (await fs.stat(file)).mtimeMs)));
  ensure(oldestArtifact >= newestInput, 'stale Worker bundle is unqualified; rebuild current sources including migration 39 before running this smoke');
}
async function call(base, route, { method = 'GET', cookie, token, grant, json } = {}) {
  ensure(!(cookie && token), 'fixture requests must choose cookie or Bearer transport explicitly');
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie, origin: base } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(grant ? { 'x-openwarp-step-up': grant } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  let data; try { data = JSON.parse(await response.text()); } catch { data = null; }
  return { status: response.status, headers: response.headers, data };
}
function ok(response, label) {
  ensure(response.status === 200 && response.data !== null, `${label} must return HTTP 200 JSON (got ${response.status})`);
  return response.data;
}
function same(actual, expected, message) { ensure(JSON.stringify(actual) === JSON.stringify(expected), message); }
function wrappedPrivateKey(key, plain) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return `owv2:${Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('base64')}`;
}
function denied(response, status, label) {
  ensure(response.status === status && typeof response.data?.error === 'string', `${label} must return HTTP ${status} JSON (got ${response.status})`);
  ensure(response.data.code !== 'environment_deleted' && !response.headers.has('set-cookie'), `${label} must not signal deletion or issue a session`);
}

async function main() {
  let temp, child, config, port, base, cookie, org, app, env, otherEnv, token, snapshot;
  let phase = 'fresh bundle and isolated workerd fixture', checks = 0, passed = 0, failures = 0, fixtureReady = false;
  const wrangler = process.env.WRANGLER, messages = [], sockets = new Set();
  let mailFaults = 0;
  const mail = http.createServer(async (request, response) => {
    try {
      ensure(request.method === 'POST' && request.url === '/mail', 'mail sink accepts only its local POST route');
      let raw = ''; for await (const chunk of request) { raw += chunk; ensure(raw.length <= 65536, 'mail request must stay bounded'); }
      messages.push(JSON.parse(raw)); response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}');
    } catch { mailFaults++; response.writeHead(400); response.end('{}'); }
  });
  mail.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const master = crypto.randomBytes(32).toString('base64');
  let mailUrl;
  const api = (route, options = {}) => call(base, route, { cookie, ...options });
  const bearer = route => call(base, route, { token: token.token });
  const terminalRoutes = () => ['/api/me', `/api/envs/${env}/meta`, `/api/envs/${env}/export`, `/api/envs/${env}/export?base=1`];
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
  async function start() {
    ensure(!child, 'previous Wrangler must stop before restart');
    const vars = { OPENWARP_ENV: 'development', OPENWARP_LICENSE: 'development', OPENWARP_MASTER_KEY: master,
      OPENWARP_PUBLIC_URL: base, OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_ALLOW_PRIVATE_EGRESS: '1',
      OPENWARP_EMAIL_PROVIDER: 'webhook', OPENWARP_EMAIL_WEBHOOK: mailUrl };
    const args = ['dev', '--local', '--config', config, '--ip', '127.0.0.1', '--port', String(port), '--persist-to', path.join(temp, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(wrangler, args, { cwd: temp, detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: localEnvironment() });
    // Wrangler logs can contain credentials. Discard them without retaining diagnostic artifacts.
    child.stdout.resume(); child.stderr.resume();
    let spawnError; child.on('error', error => { spawnError = error; });
    let listening = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler must remain alive until readiness');
      listening = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1'); socket.setTimeout(100);
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false)); socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (listening) break; await sleep(100);
    }
    ensure(listening, 'local workerd listener must become ready within 60 seconds');
    for (let i = 0; i < 40; i++) {
      const health = await call(base, '/health'); if (health.status === 200) return;
      ensure(health.status === 503, `Worker initialization may return only HTTP 503 before healthy (got ${health.status})`); await sleep(100);
    }
    assert.fail('Worker must initialize its isolated Durable Object storage');
  }
  async function freshMail(before, email, needle) {
    for (let i = 0; i < 100; i++) {
      const text = messages.slice(before).filter(message => message.to === email).map(message => String(message.text || '')).find(text => text.includes(needle));
      if (text) return text;
      await sleep(100);
    }
    assert.fail('fresh owner email must reach the isolated local sink');
  }
  let email;
  async function owner(route, options = {}) {
    const response = await api(route, options);
    if (response.status !== 428) return response;
    ensure(response.data?.step_up_required === true && response.data.totp_required === false && typeof response.data.risk === 'string', 'owner mutation must require a real email proof without TOTP');
    const before = messages.length, risk = response.data.risk;
    const started = ok(await api('/api/auth/step-up/start', { method: 'POST', json: { risk } }), 'owner email step-up start');
    ensure(started.email_sent === true && typeof started.challenge === 'string', 'step-up must deliver a real local email');
    const code = (await freshMail(before, email, 'Your verification code is ')).match(/Your verification code is (\d{6})\b/)?.[1];
    ensure(!!code, 'owner step-up email must contain a six-digit code');
    const proved = ok(await api('/api/auth/step-up/verify', { method: 'POST', json: { challenge: started.challenge, email_code: code } }), 'owner email step-up verification');
    ensure(proved.risk === risk && typeof proved.token === 'string' && !!proved.token, 'step-up must issue a grant for the requested risk');
    return api(route, { ...options, grant: proved.token });
  }
  async function check(name, run) { phase = name; checks++; await run(); passed++; console.log(`PASS ${name}`); }
  async function receipt() {
    same(ok(await bearer('/api/me'), 'receipt own scope'), { env_scope: env }, 'receipt me must contain only its own environment scope');
    const meta = ok(await bearer(`/api/envs/${env}/meta`), 'receipt naming snapshot');
    ensure(Object.keys(meta).length === 4 && ['id', 'name', 'app', 'workspace'].every(key => meta[key] === snapshot[key]), 'receipt metadata must contain exactly the four original naming fields');
    for (const suffix of ['', '?base=1']) {
      const exported = await bearer(`/api/envs/${env}/export${suffix}`);
      ensure(exported.status === 404 && !exported.headers.has('set-cookie'), `receipt export must return terminal HTTP 404 without a session (got ${exported.status})`);
      ensure(Object.keys(exported.data || {}).length === 2 && exported.data.error === 'environment deleted' && exported.data.code === 'environment_deleted', 'receipt export must return only the documented coded deletion error');
    }
  }
  try {
    await requireFreshBundle(wrangler);
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-worker-deleted-env-receipts-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir); config = await writeWorkerConfig(configDir);
    port = await freePort(); base = `http://127.0.0.1:${port}`;
    mailUrl = `http://127.0.0.1:${await listen(mail)}/mail`;
    await start();
    email = `receipts-${crypto.randomUUID()}@test.invalid`;
    const kdf = ok(await api(`/api/auth/kdf?email=${encodeURIComponent(email)}`), 'KDF discovery');
    ensure(kdf.version === 2 && kdf.algo === 'pbkdf2-sha256' && kdf.iterations === 600000, 'fixture must use client-derived authentication');
    const derived = await pbkdf2(crypto.randomUUID(), Buffer.from(kdf.salt, 'base64'), kdf.iterations, 64, 'sha256'), authKey = derived.subarray(0, 32);
    const pair = crypto.generateKeyPairSync('x25519'), beforeRegistration = messages.length;
    const registeredResponse = await api('/api/auth/register-v2', { method: 'POST', json: { email, salt: kdf.salt, iterations: kdf.iterations, algo: kdf.algo,
      auth_key: authKey.toString('base64'), public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
      wrapped_privkey: wrappedPrivateKey(derived.subarray(32), pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)) } });
    const registered = ok(registeredResponse, 'client-auth registration');
    ensure(registered.verification_required === true && !registered.token && !registeredResponse.headers.has('set-cookie'), 'registration must require actual mailbox verification');
    const link = (await freshMail(beforeRegistration, email, '/api/auth/verify?token=')).match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
    ensure(!!link, 'owner registration email must contain a verification link');
    const verification = new URL(link); ensure(verification.origin === base, 'verification mail must target this loopback Worker');
    ensure([200, 302, 303].includes((await api(verification.pathname + verification.search)).status), 'owner email verification must succeed');
    const challenge = ok(await api('/api/auth/challenge', { method: 'POST', json: { email } }), 'client-auth challenge');
    ensure(typeof challenge.challenge === 'string' && typeof challenge.challenge_id === 'string', 'login must receive a real challenge');
    const proof = crypto.createHmac('sha256', authKey).update(`${challenge.challenge}|${challenge.challenge_id}`).digest('hex');
    const login = await api('/api/auth/login-v2', { method: 'POST', json: { email, challenge_id: challenge.challenge_id, proof } });
    const session = ok(login, 'verified client-auth login'); cookie = (login.headers.get('set-cookie') || '').split(';')[0];
    ensure(!!session.token && !session.mfa_required && /^ow_session=.+/.test(cookie), 'verified owner must receive a real cookie session');
    ensure(ok(await api('/api/instance'), 'instance owner check').instance_owner === true, 'verified account must own this isolated instance');
    const edition = ok(await api('/api/instance/edition'), 'development license check');
    ensure(edition.enterprise === true && edition.development === true, 'fixture must use only the dummy development license');
    org = registered.org_id; ensure(typeof org === 'string' && !!org, 'registered owner must have a workspace');
    app = ok(await owner(`/api/orgs/${org}/apps`, { method: 'POST', json: { name: 'Worker receipt boundary' } }), 'application creation').id;
    ensure(typeof app === 'string' && !!app, 'application creation must return an id');
    const envs = ok(await api(`/api/apps/${app}/envs`), 'environment listing');
    ensure(Array.isArray(envs), 'application must list its environments');
    env = envs.find(item => item.name === 'Development')?.id; otherEnv = envs.find(item => item.name === 'Staging')?.id;
    ensure(typeof env === 'string' && typeof otherEnv === 'string' && env !== otherEnv, 'fixture needs distinct live source and adjacent environments');
    const liveMeta = ok(await api(`/api/envs/${env}/meta`), 'source metadata');
    snapshot = Object.fromEntries(['id', 'name', 'app', 'workspace'].map(key => [key, liveMeta[key]]));
    ensure(Object.values(snapshot).every(value => typeof value === 'string' && !!value), 'live source must provide all four naming fields');
    const secret = { key: 'WORKER_RECEIPT_CONTROL', value: crypto.randomBytes(24).toString('base64') };
    ok(await owner(`/api/envs/${env}/secrets`, { method: 'PUT', json: { secrets: [secret] } }), 'live secret control deployment');
    token = ok(await owner(`/api/apps/${app}/tokens`, { method: 'POST', json: { name: 'receipt-reader', env_id: env, expires_in: 3600, scopes: 'secrets:read' } }), 'static human read token mint');
    ensure(typeof token.id === 'string' && !!token.id && typeof token.token === 'string' && !!token.token && token.scopes === 'secrets:read', 'fixture must retain the actual original static read credential and management id');
    await check('live original environment read token reaches real secrets before deletion', async () => {
      const me = ok(await bearer('/api/me'), 'live token identity'); ensure(me.id === session.user_id && me.env_scope === env, 'live static token must authenticate its human owner and exact environment ceiling');
      const secrets = ok(await bearer(`/api/envs/${env}/secrets`), 'live static token secret read').secrets;
      ensure(Array.isArray(secrets) && secrets.length === 1 && secrets[0].key === secret.key && secrets[0].value === secret.value, 'live read token must retrieve the actual deployed control secret');
      denied(await bearer(`/api/envs/${otherEnv}/meta`), 403, 'live token adjacent-environment control');
    });
    fixtureReady = true;
    await check('Worker deletion creates only minimal own receipt and coded export 404', async () => {
      const deleted = ok(await owner(`/api/envs/${env}`, { method: 'DELETE' }), 'real source environment deletion');
      ensure(deleted.ok === true, 'authenticated source deletion must report completion');
      ensure((await api(`/api/envs/${env}/meta`)).status === 404, 'ordinary owner lookup must confirm source deletion');
      const remaining = ok(await api(`/api/apps/${app}/envs`), 'post-deletion environment listing');
      ensure(Array.isArray(remaining) && !remaining.some(item => item.id === env) && remaining.some(item => item.id === otherEnv), 'source deletion must preserve the adjacent environment');
      await receipt();
    });
    await check('Worker receipt denies wrong environment, secrets, ordinary routes and cookie transport', async () => {
      for (const route of [`/api/envs/${otherEnv}/meta`, `/api/envs/${otherEnv}/export?base=1`, `/api/envs/${env}/secrets`, `/api/envs/${otherEnv}/secrets`, '/api/orgs', `/api/apps/${app}/tokens`]) {
        denied(await bearer(route), 403, 'receipt route boundary');
      }
      denied(await call(base, `/api/tokens/${token.id}`, { method: 'DELETE', token: token.token }), 403, 'receipt self-revocation boundary');
      for (const route of terminalRoutes()) denied(await call(base, route, { cookie: `ow_session=${token.token}` }), 401, 'receipt cookie boundary');
    });
    await check('Worker cold restart retains original receipt and surviving owner session', async () => {
      await stop(); await start();
      ensure(ok(await api('/api/instance'), 'persisted owner session').instance_owner === true, 'restart must recover the same owner session, not a fresh empty fixture');
      ensure((await api(`/api/envs/${env}/meta`)).status === 404, 'restart must not resurrect the deleted source');
      await receipt();
      denied(await bearer(`/api/envs/${env}/secrets`), 403, 'persisted receipt secret boundary');
    });
    await check('Worker owner lists and revokes retained receipt by original token id', async () => {
      const rows = ok(await api(`/api/apps/${app}/tokens`), 'owner receipt administration');
      ensure(Array.isArray(rows), 'owner token administration must return an array');
      const entries = rows.filter(row => row.id === token.id), entry = entries[0];
      ensure(entries.length === 1 && entry.kind === 'deleted_env_receipt' && entry.env_id === env, 'original id must name exactly one terminal receipt, never a live credential');
      ensure(['token', 'token_hash', 'email', 'pubkey', 'wrapped_privkey'].every(key => !(key in entry)), 'administration must omit credential material and account profile');
      const revoked = ok(await owner(`/api/tokens/${token.id}`, { method: 'DELETE' }), 'owner receipt revocation');
      ensure(revoked.revoked === token.id, 'owner must revoke the receipt by its original management id');
    });
    await check('revoked Worker receipt returns 401 on every terminal route', async () => {
      for (const route of terminalRoutes()) denied(await bearer(route), 401, 'revoked receipt');
      const rows = ok(await api(`/api/apps/${app}/tokens`), 'post-revocation token administration');
      ensure(Array.isArray(rows) && !rows.some(row => row.id === token.id), 'revocation must remove the original receipt from management');
      ensure(mailFaults === 0, 'mail fixture must receive only valid bounded requests');
    });
  } catch (error) {
    failures++;
    const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
    console.error(`${fixtureReady ? 'FAIL' : 'UNQUALIFIED'} ${phase}: ${reason}`);
  } finally {
    await stop(); for (const socket of sockets) socket.destroy();
    if (mail.listening) await new Promise(resolve => mail.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
  const qualified = fixtureReady && checks === expectedChecks && passed === expectedChecks && failures === 0;
  console.log(`${passed}/${expectedChecks} Worker deleted-environment receipt checks passed, ${checks} attempted, ${failures} failures, fixture ${qualified ? 'qualified' : 'unqualified'}`);
  process.exitCode = qualified ? 0 : 1;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
