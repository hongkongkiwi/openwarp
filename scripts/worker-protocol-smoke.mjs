#!/usr/bin/env node
// Run against an existing bundle: node scripts/worker-protocol-smoke.mjs
// External fixture: OPENWARP_SMOKE_BASE, OPENWARP_SMOKE_TOKEN, OPENWARP_SMOKE_EMAIL,
// OPENWARP_SMOKE_PASSWORD, OPENWARP_SMOKE_ORIGIN and OPENWARP_SMOKE_RP_ID are required together.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeWorkerConfig } from './worker-config-smoke.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const b64 = value => Buffer.from(value).toString('base64url');
const sha = value => crypto.createHash('sha256').update(value).digest();

// Same none-attestation and ES256 COSE fixture shape as tests/auth_methods.rs.
export function cbor(value) {
  const header = (major, size) => {
    if (size < 24) return Buffer.from([(major << 5) | size]);
    if (size <= 255) return Buffer.from([(major << 5) | 24, size]);
    ensure(size <= 65535, 'CBOR fixture exceeds supported size');
    const out = Buffer.alloc(3); out[0] = (major << 5) | 25; out.writeUInt16BE(size, 1); return out;
  };
  if (Number.isSafeInteger(value)) return value >= 0 ? header(0, value) : header(1, -1 - value);
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([header(3, bytes.length), bytes]); }
  if (value instanceof Map) return Buffer.concat([header(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error('Unsupported CBOR fixture value');
}
export function authData(rpId, flags, counter, extra = Buffer.alloc(0)) {
  const count = Buffer.alloc(4); count.writeUInt32BE(counter);
  return Buffer.concat([sha(rpId), Buffer.from([flags]), count, extra]);
}
export function assertion(id, privateKey, rpId, origin, challenge, counter) {
  const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
  const auth = authData(rpId, 0x05, counter);
  const signature = crypto.sign('sha256', Buffer.concat([auth, sha(cd)]), privateKey);
  return { id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {},
    response: { clientDataJSON: b64(cd), authenticatorData: b64(auth), signature: b64(signature), userHandle: null } };
}
async function call(base, route, { method = 'GET', token, json, body, headers = {} } = {}) {
  const res = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    body: json === undefined ? body : JSON.stringify(json) });
  const bytes = Buffer.from(await res.arrayBuffer());
  let data; try { data = JSON.parse(bytes.toString()); } catch { data = {}; }
  return { status: res.status, headers: res.headers, data, bytes };
}
const ok = (r, label) => { ensure(r.status === 200, `${label} must return HTTP 200 (got ${r.status})`); return r; };
function noSession(r) { return !r.data.token && !/\bow_session=[^;\s]+/.test(r.headers.get('set-cookie') || ''); }
function openssl(args) {
  const result = spawnSync(process.env.OPENSSL || 'openssl', args, { encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 });
  ensure(!result.error && result.signal === null && Number.isInteger(result.status), 'OpenSSL command must execute without timeout');
  return { status: result.status, output: result.stdout + result.stderr };
}
function verified(result, label) { ensure(result.status === 0, `${label} must pass independent OpenSSL verification`); return result.output; }
function fresh(text, first, last, label) {
  const start = Date.parse(text.match(new RegExp(`${first}\\s*[:=]\\s*([^\\r\\n]+)`))?.[1] || '');
  const end = Date.parse(text.match(new RegExp(`${last}\\s*[:=]\\s*([^\\r\\n]+)`))?.[1] || '');
  const now = Date.now();
  ensure(Number.isFinite(start) && Number.isFinite(end) && start <= now + 300000 && start >= now - 300000 && end > now,
    `${label} must carry fresh wall-clock validity times`);
}
async function pki(f, dir) {
  const { base, token } = f;
  const org = ok(await call(base, '/api/orgs', { method: 'POST', token, json: { name: `protocol-${crypto.randomUUID()}` } }), 'workspace creation').data.id;
  ensure(typeof org === 'string' && !!org, 'workspace creation must return its id');
  const ca = ok(await call(base, `/api/orgs/${org}/pki/cas`, { method: 'POST', token, json: { name: 'protocol CA' } }), 'CA creation').data;
  ensure(typeof ca.id === 'string' && typeof ca.certificate === 'string', 'CA creation must return id and certificate');
  const issue = async cn => ok(await call(base, `/api/pki/cas/${ca.id}/issue`, { method: 'POST', token, json: { cn, sans: [cn], days: 2 } }), 'leaf issuance').data;
  const leaf = await issue('service.test.invalid'), other = await issue('other.test.invalid');
  ensure(typeof leaf.id === 'string' && typeof leaf.private_key === 'string', 'leaf issuance must return id and private key');
  const caFile = path.join(dir, 'ca.pem'), leafFile = path.join(dir, 'leaf.pem'), otherFile = path.join(dir, 'other.pem');
  const crlFile = path.join(dir, 'crl.pem'), requestFile = path.join(dir, 'request.der'), responseFile = path.join(dir, 'response.der');
  await fs.writeFile(caFile, ca.certificate, { mode: 0o600 });
  await fs.writeFile(leafFile, leaf.certificate, { mode: 0o600 });
  await fs.writeFile(otherFile, other.certificate, { mode: 0o600 });
  const parsed = new crypto.X509Certificate(leaf.certificate), issuer = new crypto.X509Certificate(ca.certificate);
  ensure(parsed.verify(issuer.publicKey), 'leaf signature must match the returned CA');
  ensure(parsed.checkHost('service.test.invalid') === 'service.test.invalid', 'issued SAN must match requested DNS name');
  ensure(parsed.publicKey.export({ type: 'spki', format: 'der' }).equals(crypto.createPublicKey(leaf.private_key).export({ type: 'spki', format: 'der' })), 'issued private key must match leaf public key');
  ensure(Date.parse(parsed.validFrom) <= Date.now() && Date.parse(parsed.validTo) > Date.now(), 'leaf must be valid at the current wall clock');
  verified(openssl(['verify', '-CAfile', caFile, leafFile, otherFile]), 'issued certificate chain');
  verified(openssl(['ocsp', '-issuer', caFile, '-cert', leafFile, '-no_nonce', '-reqout', requestFile]), 'OCSP request generation');
  async function ocsp(status) {
    const r = ok(await call(base, `/api/pki/cas/${ca.id}/ocsp`, { method: 'POST', body: await fs.readFile(requestFile), headers: { 'content-type': 'application/ocsp-request' } }), 'OCSP responder');
    ensure(r.headers.get('content-type')?.startsWith('application/ocsp-response'), 'OCSP content type must survive Worker conversion');
    await fs.writeFile(responseFile, r.bytes, { mode: 0o600 });
    const text = verified(openssl(['ocsp', '-respin', responseFile, '-issuer', caFile, '-cert', leafFile, '-CAfile', caFile, '-no_nonce', '-resp_text']), 'OCSP response');
    ensure(/Response verify OK/.test(text), 'OpenSSL must actually verify the OCSP signature');
    ensure(text.includes(`${leafFile}: ${status}`), `OCSP must report ${status} for the requested leaf`);
    fresh(text, 'This Update', 'Next Update', 'OCSP response');
  }
  async function crl() {
    const r = ok(await call(base, `/api/pki/cas/${ca.id}/crl`, { token }), 'CRL download');
    ensure(r.headers.get('content-type')?.startsWith('application/pkix-crl'), 'CRL content type must survive Worker conversion');
    await fs.writeFile(crlFile, r.bytes, { mode: 0o600 });
    const text = verified(openssl(['crl', '-in', crlFile, '-CAfile', caFile, '-verify', '-noout', '-lastupdate', '-nextupdate']), 'CRL signature');
    ensure(/verify OK/i.test(text), 'OpenSSL must actually verify the CRL signature');
    fresh(text, 'lastUpdate', 'nextUpdate', 'CRL');
  }
  await ocsp('good'); await crl();
  verified(openssl(['verify', '-CAfile', caFile, '-CRLfile', crlFile, '-crl_check', leafFile]), 'unrevoked leaf with empty CRL');
  ok(await call(base, `/api/pki/certs/${leaf.id}/revoke`, { method: 'POST', token, json: {} }), 'certificate revocation');
  await ocsp('revoked'); await crl();
  const revoked = openssl(['verify', '-CAfile', caFile, '-CRLfile', crlFile, '-crl_check', leafFile]);
  ensure(revoked.status !== 0 && /error 23 at[^\r\n]*certificate revoked/i.test(revoked.output), 'OpenSSL must reject the leaf specifically as revoked');
  verified(openssl(['verify', '-CAfile', caFile, '-CRLfile', crlFile, '-crl_check', otherFile]), 'unrelated leaf after revocation');
  console.log('PASS certificate chain, OCSP good/revoked, signed fresh CRL and unrelated-leaf guard');
}
async function passkey(f) {
  const { base, token, email, password, origin, rpId } = f;
  const start = ok(await call(base, '/api/me/passkeys/start', { method: 'POST', token, json: {} }), 'passkey registration start').data;
  const challenge = start.options?.publicKey?.challenge;
  ensure(typeof start.state_id === 'string' && typeof challenge === 'string' && !!challenge, 'registration must issue a real challenge and state');
  ensure(start.options.publicKey.rp.id === rpId, 'registration must advertise the configured RP id');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' }), id = crypto.randomBytes(32);
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  const length = Buffer.alloc(2); length.writeUInt16BE(id.length);
  const auth = authData(rpId, 0x45, 0, Buffer.concat([Buffer.alloc(16), length, id, cose]));
  const cd = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false }));
  const credential = { id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {}, response: {
    clientDataJSON: b64(cd), attestationObject: b64(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', auth]]))), transports: ['internal'] } };
  const enrolled = ok(await call(base, '/api/me/passkeys/finish', { method: 'POST', token, json: { state_id: start.state_id, name: 'protocol key', credential } }), 'passkey registration');
  ensure(enrolled.data.recovery_codes?.length === 8, 'first passkey must issue eight recovery codes');
  const factors = ok(await call(base, '/api/me/mfa', { token }), 'MFA status');
  ensure(factors.data.passkeys?.length === 1, 'registered passkey must persist');
  async function begin() {
    const login = ok(await call(base, '/api/auth/login', { method: 'POST', json: { email, password } }), 'password stage');
    ensure(login.data.mfa_required === true && login.data.methods?.includes('passkey') && noSession(login), 'password alone must not issue a session after passkey enrollment');
    const mfa_token = login.data.mfa_token;
    ensure(typeof mfa_token === 'string' && !!mfa_token, 'password stage must issue an MFA challenge');
    const started = ok(await call(base, '/api/auth/mfa/passkey/start', { method: 'POST', json: { mfa_token } }), 'passkey assertion start');
    const challenge = started.data.options?.publicKey?.challenge;
    ensure(typeof challenge === 'string' && !!challenge, 'assertion must use a server challenge');
    return { mfa_token, challenge };
  }
  const finish = (state, credential) => call(base, '/api/auth/mfa/passkey/finish', { method: 'POST', json: { mfa_token: state.mfa_token, credential } });
  async function reject(label, make) {
    const state = await begin(), credential = make(state.challenge);
    const r = await finish(state, credential);
    ensure([400, 401].includes(r.status) && noSession(r), `${label} must reject without issuing a session`);
  }
  await reject('wrong-origin signed assertion', challenge => assertion(id, privateKey, rpId, 'https://wrong.test.invalid', challenge, 1));
  await reject('invalid signature', challenge => {
    const value = assertion(id, privateKey, rpId, origin, challenge, 1);
    const signature = Buffer.from(value.response.signature, 'base64url'); signature[signature.length - 1] ^= 1;
    value.response.signature = b64(signature); return value;
  });
  const state = await begin(), signed = assertion(id, privateKey, rpId, origin, state.challenge, 1);
  const logged = ok(await finish(state, signed), 'valid signed passkey assertion');
  ensure(typeof logged.data.token === 'string' && !!logged.data.token && /\bow_session=/.test(logged.headers.get('set-cookie') || ''), 'successful passkey assertion must issue token and session cookie');
  ok(await call(base, '/api/me', { token: logged.data.token }), 'passkey-issued session');
  const replay = await finish(state, signed);
  ensure([400, 401].includes(replay.status) && noSession(replay), 'consumed passkey challenge must reject replay');
  await reject('nonadvancing signature counter', challenge => assertion(id, privateKey, rpId, origin, challenge, 1));
  console.log('PASS real ES256 passkey registration/assertion, origin, signature, replay and counter guards');
}
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function localFixture(dir, run) {
  const messages = [], sockets = new Set();
  const mail = http.createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    try { messages.push(JSON.parse(raw)); } catch { /* Missing mail proof fails signup below. */ }
    res.writeHead(200); res.end('{}');
  });
  mail.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  let child;
  try {
    await fs.access(path.join(root, 'crates/server/build/worker/shim.mjs'));
    const mailPort = await listen(mail), listener = net.createServer(), port = await listen(listener);
    await new Promise(resolve => listener.close(resolve));
    const origin = 'https://protocol.test.invalid', rpId = 'protocol.test.invalid';
    const vars = { OPENWARP_ENV: 'production', OPENWARP_MASTER_KEY: crypto.randomBytes(32).toString('base64'),
      OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_PUBLIC_URL: origin, OPENWARP_RP_ID: rpId, OPENWARP_RP_ORIGIN: origin,
      OPENWARP_ALLOW_PRIVATE_EGRESS: '1', OPENWARP_EMAIL_WEBHOOK: `http://127.0.0.1:${mailPort}/mail` };
    const configDir = path.join(dir, 'config');
    await fs.mkdir(configDir);
    const config = await writeWorkerConfig(configDir);
    const args = [...(process.env.WRANGLER ? [] : ['--no-install', 'wrangler']), 'dev', '--local', '--config', config, '--port', String(port), '--persist-to', path.join(dir, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(process.env.WRANGLER || 'npx', args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.resume(); child.stderr.resume();
    let spawnError; child.on('error', error => { spawnError = error; });
    const base = `http://127.0.0.1:${port}`;
    let ready = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler must remain alive until health succeeds');
      try { ready = (await fetch(base + '/health', { signal: AbortSignal.timeout(500) })).status === 200; } catch { /* Retry startup only. */ }
      if (ready) break;
      await sleep(100);
    }
    ensure(ready, 'existing Worker bundle must become healthy');
    const email = `protocol-${crypto.randomUUID()}@test.invalid`, password = crypto.randomUUID();
    const registered = ok(await call(base, '/api/auth/register', { method: 'POST', json: { email, password } }), 'fixture signup');
    ensure(registered.data.verification_required === true && noSession(registered), 'fixture signup must require verification');
    let link;
    for (let i = 0; i < 100 && !link; i++) {
      link = String(messages.find(m => m.to === email)?.text || '').match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
      if (!link) await sleep(100);
    }
    ensure(!!link, 'verification mail must reach the disposable sink');
    const url = new URL(link); ensure(url.origin === origin, 'mail must use pinned public origin');
    ok(await call(base, url.pathname + url.search), 'fixture verification');
    const login = ok(await call(base, '/api/auth/login', { method: 'POST', json: { email, password } }), 'fixture login');
    ensure(typeof login.data.token === 'string' && !!login.data.token, 'verified fixture must have a session');
    await run({ base, token: login.data.token, email, password, origin, rpId });
  } finally {
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
      await Promise.race([once(child, 'exit'), sleep(3000)]);
      if (child.exitCode === null && child.signalCode === null) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
        await once(child, 'exit');
      }
    }
    for (const socket of sockets) socket.destroy();
    if (mail.listening) await new Promise(resolve => mail.close(resolve));
  }
}
async function main() {
  let dir, failures = 0;
  try {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-protocol-smoke-'));
    verified(openssl(['version']), 'OpenSSL availability');
    const run = async fixture => {
      for (const [name, probe] of [['PKI', () => pki(fixture, dir)], ['passkey', () => passkey(fixture)]]) {
        try { await probe(); }
        catch (error) { failures++; console.error(`FAIL ${name}: ${error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.name}`); }
      }
    };
    if (process.env.OPENWARP_SMOKE_BASE) {
      const fixture = Object.fromEntries(Object.entries({ base: 'BASE', token: 'TOKEN', email: 'EMAIL', password: 'PASSWORD', origin: 'ORIGIN', rpId: 'RP_ID' }).map(([key, suffix]) => [key, process.env[`OPENWARP_SMOKE_${suffix}`]]));
      ensure(Object.values(fixture).every(value => typeof value === 'string' && !!value), 'external mode requires BASE, TOKEN, EMAIL, PASSWORD, ORIGIN and RP_ID');
      ensure(new URL(fixture.base).hostname === '127.0.0.1', 'external fixture must be a disposable loopback Worker');
      await run(fixture);
    } else await localFixture(dir, run);
  } catch (error) {
    failures++; console.error(`FAIL protocol harness: ${error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name}`);
  } finally { if (dir) await fs.rm(dir, { recursive: true, force: true }); }
  console.log(`${failures} protocol failures; SAML is not covered by this runner`);
  process.exitCode = failures ? 1 : 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
