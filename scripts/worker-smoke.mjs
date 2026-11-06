#!/usr/bin/env node
// End-to-end smoke test for the Workers deployment: real workerd, real Durable
// Object SQLite, the shared handlers. Run through scripts/worker-smoke.sh.
import fs from 'node:fs';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

const base = process.env.OPENWARP_SMOKE_BASE;
if (!base) { console.error('OPENWARP_SMOKE_BASE is required'); process.exit(2); }

// Reuse the RSA fixture the native OIDC tests sign with, so both runtimes verify
// the same token shape against the same public key.
const accountsSrc = fs.readFileSync(path.join(here, '..', 'crates', 'server', 'tests', 'accounts.rs'), 'utf8');
const TEST_PEM = accountsSrc.match(/const TEST_PEM: &str = r#"([\s\S]*?)"#;/)?.[1];
const TEST_N = accountsSrc.match(/const TEST_N: &str = "([^"]+)"/)?.[1];

function base64url(value) { return Buffer.from(value).toString('base64url'); }

let idpNonce = '';

function signIdToken(issuer, email) {
  const header = base64url(JSON.stringify({ alg: 'RS256', kid: 't1', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const claims = base64url(JSON.stringify({
    iss: issuer, aud: 'test-oidc', sub: 'worker-oidc-subject', email,
    email_verified: true, nonce: idpNonce, iat: now, exp: now + 300,
  }));
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${claims}`);
  return `${header}.${claims}.${signer.sign(TEST_PEM, 'base64url')}`;
}

// Loopback identity provider for the OIDC check. The Worker needs
// OPENWARP_ALLOW_PRIVATE_EGRESS=1 for it, which the shell script sets.
function startMockIdp() {
  const server = http.createServer((req, res) => {
    const issuer = `http://127.0.0.1:${server.address().port}`;
    let body = {};
    if (req.url.startsWith('/.well-known/openid-configuration')) {
      body = { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` };
    } else if (req.url.startsWith('/jwks')) {
      body = { keys: [{ kty: 'RSA', kid: 't1', use: 'sig', alg: 'RS256', n: TEST_N, e: 'AQAB' }] };
    } else if (req.url.startsWith('/token')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ access_token: 'x', id_token: signIdToken(issuer, 'oidc-user@test.invalid'), token_type: 'Bearer' }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

let failures = 0;
function check(name, condition, detail) {
  if (condition) { console.log(`PASS ${name}`); return; }
  failures += 1;
  console.error(`FAIL ${name}${detail ? `: ${detail}` : ''}`);
}

async function call(method, path, token, body) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = {}; }
  return { status: res.status, json, text };
}

const email = `smoke-${Date.now()}@test.invalid`;
const password = 'correct-horse-battery';

const health = await call('GET', '/health');
check('health responds 200', health.status === 200, health.text);

const registerStarted = Date.now();
const reg = await call('POST', '/api/auth/register', null, { email, password });
console.log(`INFO register round trip ${Date.now() - registerStarted}ms (includes one Argon2 wrap)`);
check('register creates a workspace', reg.status === 200 && !!reg.json.org_id, reg.text);
const org = reg.json.org_id;
let token = reg.json.token || '';

// Main requires the emailed verification link before a password session exists.
if (!token) {
  let link = '';
  for (let i = 0; i < 40 && !link; i += 1) {
    await new Promise(resolve => setTimeout(resolve, 250));
    const seen = await (await fetch(`${process.env.OPENWARP_SMOKE_ECHO}/_requests`)).json();
    for (const message of seen) {
      const match = String(message.body || '').match(/https?:\/\/[^\s"]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/);
      if (match) { link = match[0]; break; }
    }
  }
  check('verification link delivered to the email relay', !!link, 'no verify link in the relay inbox');
  if (!link) process.exit(1);
  const verified = await fetch(link, { redirect: 'manual' });
  check('verification link accepted', [200, 302, 303].includes(verified.status), String(verified.status));
  const login = await call('POST', '/api/auth/login', null, { email, password });
  check('verified account can sign in', login.status === 200 && !!login.json.token, `${login.status} ${login.text.slice(0, 160)}`);
  token = login.json.token || '';
  if (!token) process.exit(1);
}

const me = await call('GET', '/api/me', token);
check('authenticated request works', me.status === 200, me.text);

const app = await call('POST', `/api/orgs/${org}/apps`, token, { name: 'smoke' });
check('application created', app.status === 200 && app.json.id, app.text);

const envs = await call('GET', `/api/apps/${app.json.id}/envs`, token);
const env = (envs.json.envs || envs.json || []).find?.(e => e.name === 'Development') || (Array.isArray(envs.json) ? envs.json.find(e => e.name === 'Development') : null);
check('default environment listed', !!env && !!env.id, envs.text);
if (!env) process.exit(1);

const deployed = await call('PUT', `/api/envs/${env.id}/secrets`, token, { secrets: [{ key: 'SMOKE_KEY', value: 'smoke-value' }] });
check('secret deployed', deployed.status === 200, deployed.text);

const listed = await call('GET', `/api/envs/${env.id}/secrets`, token);
const found = (listed.json.secrets || []).find(s => s.key === 'SMOKE_KEY');
check('secret readable with its plaintext value', !!found && found.value === 'smoke-value', listed.text);

const history = await call('GET', `/api/envs/${env.id}/secrets`, token);
check('repeat read is stable', history.status === 200, history.text);

// A Durable Object statement must report its affected rows: SCIM deactivation
// branches on the DELETE count and would report "cannot remove the last owner"
// while already having removed the row.
const scim = await call('POST', `/scim/v2/Users?org_id=${org}`, token, { userName: `member-${Date.now()}@test.invalid` });
check('SCIM user created', scim.status === 200 && scim.json.id, scim.text);
const removed = await call('DELETE', `/scim/v2/Users/${scim.json.id}?org_id=${org}`, token);
check('SCIM deactivation reports success (affected-row count)', removed.status === 200, `${removed.status} ${removed.text}`);

// OIDC through the real Worker: discovery, JWKS, RS256 id_token verification
// (pure-Rust backend), user provisioning and session creation.
const idp = await startMockIdp();
const issuer = `http://127.0.0.1:${idp.address().port}`;
const settings = await call('PUT', `/api/orgs/${org}/settings`, token, {
  oidc_issuer: issuer, oidc_client_id: 'test-oidc', oidc_client_secret: 'secret',
  oidc_redirect_uri: `${base}/api/auth/oidc/callback`,
  oidc_auto_provision: true, oidc_allowed_domains: 'test.invalid',
});
check('OIDC settings saved', settings.status === 200, `${settings.status} ${settings.text}`);

const start = await fetch(`${base}/api/auth/oidc/${org}/start`, { redirect: 'manual' });
const location = start.headers.get('location') || '';
const authorize = new URL(location, base);
const state = authorize.searchParams.get('state');
idpNonce = authorize.searchParams.get('nonce') || '';
check('OIDC start redirects to the issuer with state', start.status >= 300 && start.status < 400 && !!state, `${start.status} ${location}`);

if (state) {
  const callback = await fetch(`${base}/api/auth/oidc/callback?code=abc&state=${encodeURIComponent(state)}`, { redirect: 'manual' });
  const target = callback.headers.get('location') || '';
  const callbackText = await callback.text();
  const ssoToken = target.includes('#token=') ? target.split('#token=')[1].split('&')[0] : '';
  check('OIDC callback verifies the RS256 id_token and issues a session', callback.status >= 300 && callback.status < 400 && !!ssoToken, `${callback.status} ${target} ${callbackText.slice(0, 200)}`);
  if (ssoToken) {
    const ssoMe = await call('GET', '/api/me', ssoToken);
    check('SSO session is authenticated', ssoMe.status === 200, `${ssoMe.status} ${ssoMe.text}`);
  }
}
idp.close();

// Certificate authority and leaf issuance through the RustCrypto stack.
const ca = await call('POST', `/api/orgs/${org}/pki/cas`, token, { name: 'smoke-ca' });
check('CA created on the Worker', ca.status === 200 && (ca.json.certificate || '').includes('BEGIN CERTIFICATE'), `${ca.status} ${ca.text.slice(0, 120)}`);
if (ca.json.id) {
  const leaf = await call('POST', `/api/pki/cas/${ca.json.id}/issue`, token, { cn: 'svc.test.invalid', sans: ['svc.test.invalid'], days: 30 });
  check('leaf certificate and key issued', leaf.status === 200 && (leaf.json.certificate || '').includes('BEGIN CERTIFICATE') && (leaf.json.private_key || '').includes('BEGIN PRIVATE KEY'), `${leaf.status} ${leaf.text.slice(0, 160)}`);
  const certs = await call('GET', `/api/pki/cas/${ca.json.id}/certs`, token);
  check('issued certificate is listed', certs.status === 200, `${certs.status} ${certs.text.slice(0, 120)}`);
}

// Optional: a live PostgreSQL lease through the Worker socket path.
if (process.env.OPENWARP_SMOKE_PG_URL) {
  const lease = await call('POST', `/api/envs/${env.id}/dynamic`, token, {
    name: 'pg', type: 'postgres', config: { connection: process.env.OPENWARP_SMOKE_PG_URL },
  });
  check('postgres lease created through the Worker socket', lease.status === 200 && !!lease.json.username, `${lease.status} ${lease.text}`);
  if (lease.json.id) {
    const revoked = await call('DELETE', `/api/leases/${lease.json.id}`, token);
    check('postgres lease revoked', revoked.status === 200, `${revoked.status} ${revoked.text}`);
  }
} else {
  console.log('SKIP postgres lease (set OPENWARP_SMOKE_PG_URL to exercise it)');
}

// Background and integration paths that only exist outside unit tests.
const echo = process.env.OPENWARP_SMOKE_ECHO;
if (echo) {
  const stream = await call('POST', `/api/orgs/${org}/log-streams`, token, { name: 'echo', url: `${echo}/log`, secret: 'stream-secret' });
  check('log stream created', stream.status === 200, `${stream.status} ${stream.text.slice(0, 120)}`);
  await call('GET', `/api/envs/${env.id}/secrets`, token);
  let delivered = false;
  let lastStatus = 'none';
  for (let i = 0; i < 40 && !delivered; i += 1) {
    await new Promise(resolve => setTimeout(resolve, 250));
    const list = await call('GET', `/api/orgs/${org}/log-streams/deliveries`, token);
    const rows = Array.isArray(list.json) ? list.json : (list.json.deliveries || []);
    const row = rows.find(entry => entry.status);
    lastStatus = row ? String(row.status) : 'none';
    delivered = rows.some(entry => String(entry.status) === 'delivered');
  }
  check('audit delivery reached the endpoint', delivered, lastStatus);
  const observed = await (await fetch(`${echo}/_requests`)).json();
  check('echo sink received a signed log event', observed.some(r => r.path === '/log' && String(r.headers['x-openwarp-signature'] || '').startsWith('t=')));

  const integ = await call('POST', `/api/envs/${env.id}/integrations`, token, { kind: 'webhook', name: 'echo', config: { url: `${echo}/hook` } });
  check('webhook integration created', integ.status === 200 && !!integ.json.id, `${integ.status} ${integ.text.slice(0, 120)}`);
  if (integ.json.id) {
    const sync = await call('POST', `/api/integrations/${integ.json.id}/sync`, token);
    check('webhook integration sync delivered', sync.status === 200, `${sync.status} ${sync.text.slice(0, 160)}`);
    const pushed = await (await fetch(`${echo}/_requests`)).json();
    check('echo sink received the pushed secrets', pushed.some(r => r.path === '/hook'));
  }

  await call('POST', '/api/auth/forgot', null, { email });
  const mail = await (await fetch(`${echo}/_requests`)).json();
  check('email relay received a reset message', mail.some(r => r.path === '/mail' && String(r.body).toLowerCase().includes('reset')));
}

const cron = await fetch(`${base}/__scheduled?cron=${encodeURIComponent('* * * * *')}`);
check('scheduled maintenance runs', cron.status === 200 || cron.status === 204, String(cron.status));

const out = await call('POST', '/api/auth/logout', token);
check('logout accepted', out.status === 200, out.text);
const after = await call('GET', '/api/me', token);
check('revoked session rejected immediately', after.status === 401, `${after.status} ${after.text}`);

// Five wrong passwords exhaust the per-address login budget in the database.
const target = `limit-${Date.now()}@test.invalid`;
await call('POST', '/api/auth/register', null, { email: target, password });
let last = 0;
for (let i = 0; i < 6; i += 1) {
  const r = await call('POST', '/api/auth/login', null, { email: target, password: 'wrong-password' });
  last = r.status;
}
check('login failures reach 429 (database-backed limit)', last === 429, String(last));

if (failures) { console.error(`${failures} check(s) failed`); process.exit(1); }
console.log('worker smoke: all checks passed');
