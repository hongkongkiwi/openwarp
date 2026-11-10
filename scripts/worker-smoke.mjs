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
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = {}; }
  return { status: res.status, json, text, headers: res.headers };
}

function totp(secret, counter = Math.floor(Date.now() / 30000)) {
  let bits = 0, value = 0;
  const bytes = [];
  for (const c of secret.toUpperCase().replace(/=+$/, '')) {
    const digit = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    if (digit < 0) throw new Error('invalid base32 TOTP secret');
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >>> bits) & 255); }
  }
  const count = Buffer.alloc(8);
  count.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', Buffer.from(bytes)).update(count).digest();
  const offset = digest[19] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

function noSession(response) {
  return !response.json.token && !/\bow_session=[^;\s]+/.test(response.headers.get('set-cookie') || '');
}

async function mfaSmoke(email, password, token, echo) {
  const detail = response => `HTTP ${response.status}`;
  const challenge = async label => {
    const login = await call('POST', '/api/auth/login', null, { email, password });
    const ok = login.status === 200 && login.json.mfa_required === true &&
      typeof login.json.mfa_token === 'string' && !!login.json.mfa_token && noSession(login);
    check(label, ok, detail(login));
    return ok ? login.json.mfa_token : '';
  };
  const factor = (mfa_token, code) => call('POST', '/api/auth/mfa', null, { mfa_token, code });
  const accepted = async (label, response) => {
    const ok = response.status === 200 && typeof response.json.token === 'string' && !!response.json.token;
    check(label, ok, detail(response));
    if (ok) {
      const me = await call('GET', '/api/me', response.json.token);
      check(`${label}: issued session authenticates`, me.status === 200 && me.json.email === email, detail(me));
    }
    return ok;
  };
  const rejected = (label, response) => check(label, response.status === 401 && noSession(response), detail(response));

  const setup = await call('POST', '/api/me/totp/setup', token, {});
  const ready = setup.status === 200 && /^[A-Z2-7]+$/.test(setup.json.secret || '') &&
    Array.isArray(setup.json.recovery_codes) && setup.json.recovery_codes.length > 0;
  check('TOTP setup returns a secret and recovery codes on Workers', ready, detail(setup));
  if (!ready) return;
  const secret = setup.json.secret;
  const recovery = setup.json.recovery_codes[0];
  const wrongSetup = await call('POST', '/api/me/totp/verify', token, { code: 'not-a-code' });
  rejected('invalid TOTP enrollment proof is rejected', wrongSetup);
  const verified = await call('POST', '/api/me/totp/verify', token, { code: totp(secret) });
  check('valid TOTP enrollment proof enables the factor', verified.status === 200 && verified.json.enabled === true, detail(verified));
  if (verified.status !== 200 || verified.json.enabled !== true) return;

  const pending = await challenge('TOTP password login returns a challenge without a session');
  if (!pending) return;
  rejected('an MFA challenge is not a bearer session', await call('GET', '/api/me', pending));
  rejected('wrong TOTP login code is rejected', await factor(pending, 'not-a-code'));
  // Stay away from a counter boundary so enrollment and login need no retries.
  if (Date.now() % 30000 > 25000) await new Promise(resolve => setTimeout(resolve, 30000 - Date.now() % 30000 + 100));
  const code = totp(secret);
  if (!await accepted('valid TOTP completes login', await factor(pending, code))) return;
  rejected('completed MFA challenge cannot be reused', await factor(pending, code));
  const replay = await challenge('another password login still requires TOTP');
  if (!replay) return;
  rejected('consumed TOTP code is rejected on a fresh challenge', await factor(replay, code));
  if (!await accepted('recovery code completes a fresh challenge', await factor(replay, recovery))) return;
  const recoveryReplay = await challenge('recovery does not disable the enrolled factor');
  if (!recoveryReplay) return;
  rejected('recovery code is single use across fresh challenges', await factor(recoveryReplay, recovery));

  const wrongPassword = await call('DELETE', '/api/me/totp', token, { password: 'wrong-password' });
  rejected('TOTP removal rejects a wrong current password', wrongPassword);
  const stillEnrolled = await call('GET', '/api/me/mfa', token);
  check('failed TOTP removal preserves enrollment', stillEnrolled.status === 200 && stillEnrolled.json.totp === true && stillEnrolled.json.required === true, detail(stillEnrolled));

  if (echo) {
    const inbox = async () => {
      const response = await fetch(`${echo}/_requests`, { signal: AbortSignal.timeout(2000) });
      if (!response.ok) throw new Error(`email inbox HTTP ${response.status}`);
      return response.json();
    };
    const emailedCode = async since => {
      for (let i = 0; i < 40; i++) {
        for (const request of (await inbox()).slice(since)) {
          if (request.path !== '/mail') continue;
          let message; try { message = JSON.parse(request.body); } catch { continue; }
          if (message.to !== email) continue;
          const match = String(message.text || '').match(/Your OpenWarp code is (\d{6})\./);
          if (match) return match[1];
        }
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      return '';
    };
    let since = (await inbox()).length;
    const enroll = await call('POST', '/api/me/mfa/email/start', token, { password });
    check('HTTP email MFA enrollment sends a code', enroll.status === 200 && enroll.json.sent === true, detail(enroll));
    const enrollmentCode = enroll.status === 200 ? await emailedCode(since) : '';
    check('HTTP email MFA enrollment code reaches this account', !!enrollmentCode);
    if (!enrollmentCode) return;
    rejected('wrong email enrollment code is rejected', await call('POST', '/api/me/mfa/email/verify', token, { code: 'not-a-code' }));
    const emailProof = await call('POST', '/api/me/mfa/email/verify', token, { code: enrollmentCode });
    check('HTTP email proof enables MFA', emailProof.status === 200 && emailProof.json.email === true, detail(emailProof));
    if (emailProof.status !== 200 || emailProof.json.email !== true) return;
    rejected('email enrollment code cannot be reused', await call('POST', '/api/me/mfa/email/verify', token, { code: enrollmentCode }));
    const disabled = await call('DELETE', '/api/me/totp', token, { password });
    check('TOTP can be removed with current password while email remains', disabled.status === 200 && disabled.json.totp === false, detail(disabled));
    const status = await call('GET', '/api/me/mfa', token);
    check('email-only account still requires MFA', status.status === 200 && status.json.email === true && status.json.totp === false && status.json.required === true, detail(status));
    const emailChallenge = await challenge('email-only password login returns no session');
    if (!emailChallenge) return;
    since = (await inbox()).length;
    const sent = await call('POST', '/api/auth/mfa/email/send', null, { mfa_token: emailChallenge });
    check('email login sends a code after password proof', sent.status === 200 && sent.json.sent === true, detail(sent));
    const loginCode = sent.status === 200 ? await emailedCode(since) : '';
    check('email login code reaches this account over HTTP', !!loginCode);
    if (!loginCode) return;
    rejected('wrong email login code is rejected', await factor(emailChallenge, 'not-a-code'));
    if (!await accepted('HTTP email code completes login', await factor(emailChallenge, loginCode))) return;
    const freshEmail = await challenge('email login still requires a fresh factor proof');
    if (!freshEmail) return;
    rejected('email login code is single use across challenges', await factor(freshEmail, loginCode));
    const emailDisabled = await call('DELETE', '/api/me/mfa/email', token, { password });
    check('email MFA can be removed with current password', emailDisabled.status === 200 && emailDisabled.json.email === false, detail(emailDisabled));
  } else {
    console.log('SKIP HTTP email MFA (set OPENWARP_SMOKE_ECHO to the configured email relay)');
    const disabled = await call('DELETE', '/api/me/totp', token, { password });
    check('TOTP cleanup accepts the current password', disabled.status === 200 && disabled.json.totp === false, detail(disabled));
  }
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

const batch = await call('PUT', `/api/envs/${env.id}/secrets`, token, { secrets: [
  { key: 'SMOKE_KEY', value: 'smoke-updated', expected_version: 1 },
  { key: 'SMOKE_BATCH', value: 'batch-value', expected_version: 0 },
] });
check('checked multi-secret write commits', batch.status === 200 && batch.json.deployed === 2, batch.text);
const committed = await call('GET', `/api/envs/${env.id}/secrets`, token);
check('checked update and insert are both readable', committed.status === 200
  && (committed.json.secrets || []).some(s => s.key === 'SMOKE_KEY' && s.value === 'smoke-updated' && s.version === 2)
  && (committed.json.secrets || []).some(s => s.key === 'SMOKE_BATCH' && s.value === 'batch-value' && s.version === 1), committed.text);

// A later invalid input or stale version must not persist the earlier valid write.
for (const [name, later, status] of [
  ['invalid later input', { key: 'INVALID KEY', value: 'invalid' }, 400],
  ['stale later CAS', { key: 'SMOKE_BATCH', value: 'stale', expected_version: 0 }, 409],
]) {
  const rejected = await call('PUT', `/api/envs/${env.id}/secrets`, token, { secrets: [
    { key: 'SMOKE_KEY', value: 'must-not-persist', expected_version: 2 }, later,
  ] });
  check(`${name} rejects the batch`, rejected.status === status, `${rejected.status} ${rejected.text}`);
  const unchanged = await call('GET', `/api/envs/${env.id}/secrets`, token);
  check(`${name} leaves both committed secrets unchanged`, unchanged.status === 200
    && (unchanged.json.secrets || []).some(s => s.key === 'SMOKE_KEY' && s.value === 'smoke-updated' && s.version === 2)
    && (unchanged.json.secrets || []).some(s => s.key === 'SMOKE_BATCH' && s.value === 'batch-value' && s.version === 1), unchanged.text);
}

// A Durable Object statement must report its affected rows: SCIM deactivation
// branches on the DELETE count and would report "cannot remove the last owner"
// while already having removed the row. SCIM is an enterprise cargo feature
// the deployment bundle omits, so an unlicensed build answers 404; a build
// that includes it must run the affected-row assertions instead.
const scim = await call('POST', `/scim/v2/Users?org_id=${org}`, token, { userName: `member-${Date.now()}@test.invalid` });
if (scim.status === 200) {
  check('SCIM user created', !!scim.json.id, scim.text);
  const removed = await call('DELETE', `/scim/v2/Users/${scim.json.id}?org_id=${org}`, token);
  check('SCIM deactivation reports success (affected-row count)', removed.status === 200, `${removed.status} ${removed.text}`);
} else {
  check('SCIM routes are gated off the deployment build', scim.status === 404, `${scim.status} ${scim.text.slice(0, 120)}`);
}

// Workspace settings writes work portably; workspace OIDC is an enterprise
// feature, so an unlicensed deployment answers with the stable 403 gate body
// instead of configuring the issuer.
const ungated = await call('PUT', `/api/orgs/${org}/settings`, token, { reuse_check: false });
check('Ungated workspace settings saved', ungated.status === 200, `${ungated.status} ${ungated.text}`);

const settings = await call('PUT', `/api/orgs/${org}/settings`, token, {
  oidc_issuer: 'https://issuer.test.invalid', oidc_client_id: 'test-oidc',
  oidc_redirect_uri: `${base}/api/auth/oidc/callback`,
});
check('Workspace OIDC answers the enterprise gate', settings.status === 403 &&
  settings.json.code === 'enterprise_feature' && settings.json.feature === 'org_oidc',
  `${settings.status} ${settings.text}`);

// Certificate authority and leaf issuance through the RustCrypto stack.
// The deployment bundle omits the enterprise pki feature, so the routes are
// absent; a licensed build that includes them must answer 200 instead.
const ca = await call('POST', `/api/orgs/${org}/pki/cas`, token, { name: 'smoke-ca' });
if (ca.status === 200) {
  check('CA created on the Worker', (ca.json.certificate || '').includes('BEGIN CERTIFICATE'), `${ca.status} ${ca.text.slice(0, 120)}`);
} else {
  check('PKI routes are gated off the deployment build', ca.status === 404, `${ca.status} ${ca.text.slice(0, 120)}`);
}
if (ca.json && ca.json.id) {
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

// Optional: a live MySQL/MariaDB lease through the Worker socket path, which
// runs the hand-written protocol client rather than a library.
if (process.env.OPENWARP_SMOKE_MYSQL_URL) {
  const database = new URL(process.env.OPENWARP_SMOKE_MYSQL_URL).pathname.replace(/^\//, '') || 'mysql';
  const lease = await call('POST', `/api/envs/${env.id}/dynamic`, token, {
    name: 'mysql', type: 'mysql',
    config: { connection: process.env.OPENWARP_SMOKE_MYSQL_URL, grants: [`SELECT ON ${database}.*`] },
  });
  check('mysql lease created through the Worker socket', lease.status === 200 && !!lease.json.username, `${lease.status} ${lease.text}`);
  if (lease.json.id) {
    const revoked = await call('DELETE', `/api/leases/${lease.json.id}`, token);
    check('mysql lease revoked', revoked.status === 200, `${revoked.status} ${revoked.text}`);
  }
} else {
  console.log('SKIP mysql lease (set OPENWARP_SMOKE_MYSQL_URL to exercise it)');
}

// Background and integration paths that only exist outside unit tests.
const echo = process.env.OPENWARP_SMOKE_ECHO;
if (echo) {
  const stream = await call('POST', `/api/orgs/${org}/log-streams`, token, { name: 'echo', url: `${echo}/log`, secret: 'stream-secret' });
  check('Audit streaming answers the enterprise gate', stream.status === 403 &&
    stream.json.code === 'enterprise_feature' && stream.json.feature === 'audit_streaming',
    `${stream.status} ${stream.text.slice(0, 160)}`);
  if (stream.status === 200) {
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
  }

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

// Factor enrollment runs after privileged operations and before the login-budget test.
await mfaSmoke(email, password, token, echo);

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
