#!/usr/bin/env node
// Requires a fresh prebuilt SAML Worker and pinned local Wrangler. Never builds or installs.
// Covers no-follow transport under development/private override, not production DNS rebinding.
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
const wrangler = process.env.WRANGLER || path.join(root, '.agents/tools/worker/node_modules/.bin/wrangler');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const pbkdf2 = promisify(crypto.pbkdf2);
const invalidXml = '<not-saml-metadata/>';
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function files(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return (await Promise.all(entries.map(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : [path.join(dir, entry.name)]))).flat();
}
async function requireFreshBundle() {
  const { stdout } = await promisify(execFile)(wrangler, ['--version'], { cwd: root, timeout: 15000, maxBuffer: 65536,
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' } });
  ensure(stdout.trim() === '4.158.0', 'metadata smoke requires exactly Wrangler 4.158.0; WRANGLER must name an installed executable');
  const build = path.join(root, 'crates/server/build');
  await fs.access(path.join(build, 'worker/shim.mjs'));
  const artifacts = (await files(build)).filter(file => /\.(wasm|mjs|js)$/.test(file));
  ensure(artifacts.some(file => file.endsWith('.wasm')), 'prebuilt Worker must contain an actual wasm artifact');
  const inputs = ['Cargo.toml', 'Cargo.lock', 'crates/server/Cargo.toml', 'crates/crypto/Cargo.toml', 'wrangler.toml'].map(file => path.join(root, file));
  for (const dir of ['crates/server/src', 'crates/server/migrations', 'crates/crypto/src']) inputs.push(...await files(path.join(root, dir)));
  const newestInput = Math.max(...await Promise.all(inputs.map(async file => (await fs.stat(file)).mtimeMs)));
  const oldestArtifact = Math.min(...await Promise.all(artifacts.map(async file => (await fs.stat(file)).mtimeMs)));
  ensure(oldestArtifact >= newestInput, 'stale Worker bundle is unqualified; rebuild the current sources with SAML before running this smoke');
}
async function call(base, route, { method = 'GET', cookie, json, grant } = {}) {
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie, origin: base } : {}), ...(grant ? { 'x-openwarp-step-up': grant } : {}),
      ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = null; }
  return { status: response.status, headers: response.headers, text, data };
}
function ok(response, label) {
  ensure(response.status === 200 && response.data !== null, `${label} must return HTTP 200 JSON (got ${response.status})`);
  return response.data;
}
function noPrivateKey(response) {
  ensure(!/PRIVATE KEY|\bsp_key_enc\b|\bsp_key_pem\b|\bsp_private_key\b/i.test(response.text), 'HTTP responses must not expose an SP private key or its encrypted storage field');
}
function wrappedPrivateKey(key, plain) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return `owv2:${Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('base64')}`;
}

async function main() {
  let temp, child, base, fixtureOrigin, cookie, org, grant, checks = 0, failures = 0, fixtureReady = false;
  let phase = 'fresh SAML bundle and isolated workerd fixture';
  const messages = [], sockets = new Set(), hits = new Map();
  let fixtureFaults = 0;
  const hitCount = route => hits.get(route) || 0;
  const fixture = http.createServer(async (request, response) => {
    try {
      const route = request.url;
      hits.set(route, hitCount(route) + 1);
      if (request.method === 'POST' && route === '/mail') {
        let raw = ''; for await (const chunk of request) { raw += chunk; ensure(raw.length <= 65536, 'mail request must stay bounded'); }
        messages.push(JSON.parse(raw)); response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}'); return;
      }
      ensure(request.method === 'GET' && ['/direct', '/redirect/307', '/redirect/308', '/destination/307', '/destination/308'].includes(route), 'fixture received an unexpected request');
      ensure(!request.headers.authorization && !request.headers.cookie && !request.headers['x-openwarp-step-up'], 'metadata GET must not forward owner credentials');
      if (route.startsWith('/redirect/')) {
        const status = Number(route.split('/').at(-1));
        response.writeHead(status, { location: `${fixtureOrigin}/destination/${status}` }); response.end(); return;
      }
      response.writeHead(200, { 'content-type': 'application/samlmetadata+xml' }); response.end(invalidXml);
    } catch {
      fixtureFaults++; response.writeHead(400); response.end('invalid isolated fixture request');
    }
  });
  fixture.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
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
    try { await run(); console.log(`PASS ${name}`); return true; }
    catch (error) {
      failures++;
      const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
      console.error(`FAIL ${name}: ${reason}`); return false;
    }
  }
  async function freshMail(before, email) {
    for (let i = 0; i < 100; i++) {
      const message = messages.slice(before).find(message => message.to === email);
      if (message) return String(message.text || '');
      await sleep(100);
    }
    assert.fail('fresh owner email must reach the isolated local sink');
  }
  async function configuration() {
    const response = await api(`/api/orgs/${org}/saml`), data = ok(response, 'enabled SAML configuration lookup');
    noPrivateKey(response);
    ensure(data.configured === false && data.idp_entity_id === '' && data.metadata_xml === '', 'rejected metadata must leave SAML unconfigured');
    return data;
  }
  async function rejectedState(response, before) {
    ensure(response.status >= 400 && response.status < 500 && typeof response.data?.error === 'string', `metadata must fail with an HTTP 4xx JSON error (got ${response.status})`);
    noPrivateKey(response);
    const after = await configuration();
    ensure(JSON.stringify(after) === JSON.stringify(before), 'failed metadata fetch must preserve the observable SAML configuration');
    const metadata = await api(`/api/auth/saml/${org}/metadata`);
    ensure(metadata.status === 404, `rejected configuration must not publish SP metadata (got ${metadata.status})`);
    noPrivateKey(metadata);
    ensure(fixtureFaults === 0, 'local fixture must receive only expected requests without owner credentials');
  }
  try {
    await requireFreshBundle();
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-worker-saml-metadata-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir);
    const config = await writeWorkerConfig(configDir), port = await freePort(); base = `http://127.0.0.1:${port}`;
    fixtureOrigin = `http://127.0.0.1:${await listen(fixture)}`;
    const vars = { OPENWARP_ENV: 'development', OPENWARP_LICENSE: 'development', OPENWARP_MASTER_KEY: crypto.randomBytes(32).toString('base64'),
      OPENWARP_PUBLIC_URL: base, OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_ALLOW_PRIVATE_EGRESS: '1',
      OPENWARP_EMAIL_PROVIDER: 'webhook', OPENWARP_EMAIL_WEBHOOK: `${fixtureOrigin}/mail` };
    const args = ['dev', '--local', '--config', config, '--ip', '127.0.0.1', '--port', String(port), '--persist-to', path.join(temp, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(wrangler, args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
    // Wrangler logs may contain secrets, so discard rather than print or retain them.
    child.stdout.resume(); child.stderr.resume();
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
    ensure(healthy, 'fresh Worker must initialize its isolated Durable Object database');
    const email = `saml-metadata-${crypto.randomUUID()}@test.invalid`, password = crypto.randomUUID();
    const kdf = ok(await api(`/api/auth/kdf?email=${encodeURIComponent(email)}`), 'KDF discovery');
    ensure(kdf.version === 2 && kdf.algo === 'pbkdf2-sha256' && kdf.iterations === 600000, 'fixture must use client-derived authentication');
    const derived = await pbkdf2(password, Buffer.from(kdf.salt, 'base64'), kdf.iterations, 64, 'sha256'), authKey = derived.subarray(0, 32);
    const pair = crypto.generateKeyPairSync('x25519'), beforeRegistration = messages.length;
    const registeredResponse = await api('/api/auth/register-v2', { method: 'POST', json: { email, salt: kdf.salt, iterations: kdf.iterations, algo: kdf.algo,
      auth_key: authKey.toString('base64'), public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
      wrapped_privkey: wrappedPrivateKey(derived.subarray(32), pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)) } });
    const registered = ok(registeredResponse, 'client-auth registration');
    ensure(registered.verification_required === true && !registered.token && !registeredResponse.headers.has('set-cookie'), 'registration must require real mailbox verification');
    const verificationText = await freshMail(beforeRegistration, email);
    const link = verificationText.match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
    ensure(!!link, 'registration email must contain a verification link');
    const verification = new URL(link); ensure(verification.origin === base, 'verification mail must target the isolated Worker');
    ensure([200, 302, 303].includes((await api(verification.pathname + verification.search)).status), 'email verification must succeed');
    const challenge = ok(await api('/api/auth/challenge', { method: 'POST', json: { email } }), 'client-auth challenge');
    ensure(typeof challenge.challenge === 'string' && typeof challenge.challenge_id === 'string', 'login must receive a real challenge');
    const proof = crypto.createHmac('sha256', authKey).update(`${challenge.challenge}|${challenge.challenge_id}`).digest('hex');
    const login = await api('/api/auth/login-v2', { method: 'POST', json: { email, challenge_id: challenge.challenge_id, proof } });
    const session = ok(login, 'verified client-auth login'); cookie = (login.headers.get('set-cookie') || '').split(';')[0];
    ensure(!!session.token && !session.mfa_required && /^ow_session=.+/.test(cookie), 'verified owner must receive a real cookie session');
    ensure(ok(await api('/api/instance'), 'instance owner check').instance_owner === true, 'verified fixture account must own the instance');
    org = registered.org_id; ensure(typeof org === 'string' && !!org, 'registered owner must have a workspace');
    const edition = ok(await api('/api/instance/edition'), 'local development license');
    ensure(edition.enterprise === true && edition.development === true, 'fixture must use the local development license, never deployment license credentials');
    const grants = ok(await api('/api/instance/features', { method: 'PUT', json: { org, features: ['saml'] } }), 'compiled SAML workspace grant');
    ensure(grants.org_id === org && Array.isArray(grants.features) && grants.features.includes('saml'), 'prebuilt bundle must compile SAML and retain its workspace grant');
    const probe = await api(`/api/orgs/${org}/saml`, { method: 'PUT', json: {} });
    ensure(probe.status === 400 && probe.data?.error === 'idp_entity_id is required', 'route probe must reach the enabled, licensed SAML handler');
    await configuration();
    const beforeStepUp = messages.length;
    const stepUp = ok(await api('/api/auth/step-up/start', { method: 'POST', json: { risk: 'very_risky' } }), 'owner email step-up start');
    ensure(stepUp.risk === 'very_risky' && JSON.stringify(stepUp.methods) === '["email"]' && stepUp.email_sent === true, 'owner must receive a real email-only step-up challenge');
    const code = (await freshMail(beforeStepUp, email)).split(/\D+/).find(word => word.length === 6);
    ensure(!!code && typeof stepUp.challenge === 'string', 'email step-up must provide a real six-digit code and challenge');
    const proved = ok(await api('/api/auth/step-up/verify', { method: 'POST', json: { challenge: stepUp.challenge, email_code: code } }), 'owner email step-up verification');
    ensure(proved.risk === 'very_risky' && typeof proved.token === 'string' && !!proved.token, 'metadata tests must carry an actual owner step-up grant'); grant = proved.token;
    const body = route => ({ idp_entity_id: 'urn:openwarp:test:metadata-redirect', metadata_url: `${fixtureOrigin}${route}`, allow_unsigned_metadata: true });
    const direct = await check('direct metadata GET reaches fixture and rejects invalid XML without saving', async () => {
      const before = await configuration(), count = hitCount('/direct');
      const response = await api(`/api/orgs/${org}/saml`, { method: 'PUT', grant, json: body('/direct') });
      ensure(hitCount('/direct') === count + 1, 'direct metadata URL must deliver exactly one GET to the fixture');
      ensure(response.status === 400 && /^invalid IdP metadata:/.test(response.data?.error || ''), `direct malformed XML must reach SAML validation (got HTTP ${response.status})`);
      await rejectedState(response, before);
    });
    ensure(direct, 'direct GET control failed; redirect reproduction is unqualified');
    fixtureReady = true; console.log('PASS fresh SAML workerd, development license, workspace grant, verified owner and email step-up');
    for (const status of [307, 308]) {
      await check(`Worker SAML metadata GET refuses HTTP ${status} redirects`, async () => {
        const before = await configuration(), source = `/redirect/${status}`, destination = `/destination/${status}`;
        const sourcesBefore = hitCount(source), destinationsBefore = hitCount(destination);
        const response = await api(`/api/orgs/${org}/saml`, { method: 'PUT', grant, json: body(source) });
        const sources = hitCount(source) - sourcesBefore, destinations = hitCount(destination) - destinationsBefore;
        console.log(`DIAGNOSTIC metadata redirect=${status} source_GETs=${sources} destination_GETs=${destinations} API_status=${response.status}`);
        ensure(destinations === 0, `HTTP ${status} metadata redirect must not contact destination (observed ${destinations} GETs; API HTTP ${response.status})`);
        ensure(sources === 1, `HTTP ${status} metadata URL must receive exactly one initial GET`);
        await rejectedState(response, before);
      });
    }
  } catch (error) {
    failures++;
    const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
    console.error(`UNQUALIFIED ${phase}: ${reason}`);
  } finally {
    await stop(); for (const socket of sockets) socket.destroy();
    if (fixture.listening) await new Promise(resolve => fixture.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
  console.log(`${checks} Worker SAML metadata checks attempted, ${failures} failures, fixture ${fixtureReady ? 'qualified' : 'unqualified'}`);
  process.exitCode = failures || !fixtureReady ? 1 : 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
