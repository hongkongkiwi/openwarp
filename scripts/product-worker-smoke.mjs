#!/usr/bin/env node
// Run against a disposable local Worker started by the worker-smoke.sh setup.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

function localURL(value, name) {
  assert(value, `${name} is required`);
  const url = new URL(value);
  assert(['http:', 'https:'].includes(url.protocol), `${name} must use HTTP`);
  assert(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${name} must be loopback only`);
  assert(!url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, `${name} must be a bare loopback origin`);
  return url.origin;
}
const base = localURL(process.argv[2] || process.env.OPENWARP_SMOKE_BASE, 'BASEURL / OPENWARP_SMOKE_BASE');
const echo = process.env.OPENWARP_SMOKE_ECHO ? localURL(process.env.OPENWARP_SMOKE_ECHO, 'OPENWARP_SMOKE_ECHO') : null;
let checks = 0;
async function call(method, path, token, body) {
  assert(path.startsWith('/') && !path.startsWith('//'), 'API path must be local');
  const response = await fetch(base + path, {
    method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  return { status: response.status, json };
}
async function expect(method, path, token, body, status = 200) {
  const result = await call(method, path, token, body);
  assert.equal(result.status, status, `${method} ${path}: unexpected HTTP status`);
  assert(result.json && typeof result.json === 'object', `${method} ${path}: expected JSON API response`);
  if (status >= 400) assert.equal(typeof result.json.error, 'string', 'denial must be an API error');
  checks += 1;
  return result.json;
}
function id(value) { assert.equal(typeof value.id, 'string'); assert(value.id); return value.id; }
function pass(name) { console.log(`PASS ${name}`); }

await expect('GET', '/health');
const suffix = crypto.randomBytes(12).toString('hex');
const email = `product-${suffix}@test.invalid`;
const password = 'disposable-product-fixture-password';
const registration = await expect('POST', '/api/auth/register', null, { email, password });
let token = registration.token;
const org = registration.org_id;
assert.equal(typeof org, 'string');
if (!token) {
  assert(echo, 'OPENWARP_SMOKE_ECHO is required for verification on this server');
  let verificationPath;
  for (let attempt = 0; attempt < 80 && !verificationPath; attempt += 1) {
    const response = await fetch(`${echo}/_requests`, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200, 'local email relay request list');
    const messages = await response.json();
    assert(Array.isArray(messages), 'relay inbox is an array');
    for (const message of messages) {
      const body = typeof message.body === 'string' ? message.body : JSON.stringify(message.body);
      if (!body?.includes(email)) continue;
      const match = body.match(/https?:\/\/[^\s"]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/);
      if (match) {
        const url = new URL(match[0]);
        assert.equal(url.pathname, '/api/auth/verify');
        verificationPath = url.pathname + url.search;
        break;
      }
    }
    if (!verificationPath) await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert(verificationPath, 'verification email for this fixture was delivered');
  const verified = await call('GET', verificationPath);
  assert([200, 302, 303].includes(verified.status), 'verification accepted');
  token = (await expect('POST', '/api/auth/login', null, { email, password })).token;
}
assert.equal(typeof token, 'string');
const invited = await expect('POST', `/api/orgs/${org}/members`, token, { email: `reviewer-${suffix}@test.invalid`, role: 'admin' });
assert.equal(typeof invited.invite_token, 'string');
const reviewer = (await expect('POST', '/api/auth/accept-invite', null, { token: invited.invite_token, password })).token;
assert.equal(typeof reviewer, 'string');
const app = id(await expect('POST', `/api/orgs/${org}/apps`, token, { name: `product-${suffix}` }));
const envResponse = await expect('GET', `/api/apps/${app}/envs`, token);
const envs = Array.isArray(envResponse) ? envResponse : envResponse.envs;
assert(Array.isArray(envs) && envs.length >= 2, 'two default environments');
const [dev, prod] = envs.map(id);
async function put(env, secrets, status = 200) { return expect('PUT', `/api/envs/${env}/secrets`, token, { secrets }, status); }
async function secrets(env) { return (await expect('GET', `/api/envs/${env}/secrets`, token)).secrets; }
await put(dev, [{ key: 'TARGET', value: 'before-dev' }]);
await put(prod, [{ key: 'TARGET', value: 'before-prod' }]);

// Workload identity and transit are feature-gated per workspace; the smoke
// seeds its own grants (the fixture account is the instance owner).
const grants = await expect('PUT', '/api/instance/features', token, { org, features: ['workload-identity', 'transit', 'change-requests'] });
assert.equal(grants.org, org, 'feature grants seeded');
const identity = id(await expect('POST', `/api/orgs/${org}/identities`, token, { name: 'worker-product', role: 'developer' }));
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'product-test', alg: 'ES256', use: 'sig', key_ops: ['verify'] };
const trustPath = `/api/orgs/${org}/identities/${identity}/workload-trust`;
const trust = id(await expect('POST', trustPath, token, {
  issuer: 'https://issuer.test.invalid', audience: 'worker-product', subject: 'worker-product-job',
  env_id: dev, scopes: ['secrets:read'], ttl: 300, jwks: { keys: [jwk] },
}));
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = Math.floor(Date.now() / 1000);
const message = `${encode({ alg: 'ES256', kid: 'product-test', typ: 'JWT' })}.${encode({
  iss: 'https://issuer.test.invalid', aud: 'worker-product', sub: 'worker-product-job',
  iat: now, exp: now + 300, jti: crypto.randomUUID(),
})}`;
const signature = crypto.sign('sha256', Buffer.from(message), { key: privateKey, dsaEncoding: 'ieee-p1363' });
const proof = { trust_id: trust, jwt: `${message}.${signature.toString('base64url')}` };
const login = '/api/v1/machine/auth/workload/login';
const raced = await Promise.all([call('POST', login, null, proof), call('POST', login, null, proof)]);
assert.deepEqual(raced.map(r => r.status).sort((a, b) => a - b), [200, 401], 'one workload JWT exchange wins');
const workloadToken = raced.find(r => r.status === 200).json.accessToken;
assert.equal(typeof workloadToken, 'string');
assert.equal((await expect('GET', `/api/envs/${dev}/secrets`, workloadToken)).secrets[0].value, 'before-dev');
await expect('GET', `/api/envs/${prod}/secrets`, workloadToken, undefined, 403);
await expect('POST', login, null, proof, 401);
await expect('DELETE', `${trustPath}/${trust}`, token);
await expect('GET', `/api/envs/${dev}/secrets`, workloadToken, undefined, 401);
pass('Worker workload exchange, concurrent replay, environment scope and revocation');

const keysPath = `/api/orgs/${org}/transit/keys`;
const key = id(await expect('POST', keysPath, token, { name: `worker-${suffix}` }));
const plaintext = Buffer.from('Worker transit fixture\0binary').toString('base64');
const input = { plaintext, context: 'worker-product-context' };
const original = await expect('POST', `${keysPath}/${key}/encrypt`, token, input);
assert.equal(original.version, 1);
const ciphertext = { ciphertext: original.ciphertext, context: input.context };
assert.equal((await expect('POST', `${keysPath}/${key}/decrypt`, token, ciphertext)).plaintext, plaintext);
const rotations = await Promise.all([call('POST', `${keysPath}/${key}/rotate`, token, {}), call('POST', `${keysPath}/${key}/rotate`, token, {})]);
assert(rotations.every(r => [200, 409].includes(r.status)), 'rotation only succeeds or conflicts');
const versions = rotations.filter(r => r.status === 200).map(r => r.json.current_version).sort((a, b) => a - b);
assert(versions.length === 1 && versions[0] === 2 || versions.length === 2 && versions[0] === 2 && versions[1] === 3, 'no concurrent version clobber');
const latest = await expect('POST', `${keysPath}/${key}/encrypt`, token, input);
assert.equal(latest.version, versions.at(-1));
assert.equal((await expect('POST', `${keysPath}/${key}/decrypt`, token, ciphertext)).plaintext, plaintext);
await expect('POST', `${keysPath}/${key}/decrypt`, token, { ...ciphertext, context: 'wrong-context' }, 400);
const rewrapped = await expect('POST', `${keysPath}/${key}/rewrap`, token, ciphertext);
assert.equal(rewrapped.version, latest.version);
assert(!Object.hasOwn(rewrapped, 'plaintext'), 'rewrap does not disclose plaintext');
assert.equal((await expect('POST', `${keysPath}/${key}/decrypt`, token, { ciphertext: rewrapped.ciphertext, context: input.context })).plaintext, plaintext);
pass('Worker transit create, rotate, old-version decrypt, context binding and rewrap');

const changesPath = `/api/orgs/${org}/change-requests`;
const batch = { title: 'Worker portable batch', changes: [
  { env_id: dev, secrets: [{ key: 'TARGET', value: 'after-dev' }], deletes: [] },
  { env_id: prod, secrets: [{ key: 'TARGET', value: 'after-prod' }], deletes: [] },
] };
const change = id(await expect('POST', changesPath, token, batch));
const changePath = `/api/change-requests/${change}`;
await expect('POST', `${changePath}/approve`, token, { revision: 1 }, 403);
await expect('POST', `${changePath}/approve`, reviewer, { revision: 1 });
await put(prod, [{ key: 'TARGET', value: 'external-update' }]);
const beforeDev = await secrets(dev); const beforeProd = await secrets(prod);
await expect('POST', `${changePath}/apply`, reviewer, { revision: 1 }, 409);
assert.deepEqual(await secrets(dev), beforeDev, 'earlier environment does not partially apply');
assert.deepEqual(await secrets(prod), beforeProd, 'conflicting environment is unchanged');
assert.equal((await expect('GET', changePath, token)).status, 'approved');
assert.equal((await expect('PUT', changePath, token, { ...batch, revision: 1 })).revision, 2);
await expect('POST', `${changePath}/approve`, reviewer, { revision: 2 });
await expect('POST', `${changePath}/apply`, reviewer, { revision: 2 });
assert.equal((await secrets(dev))[0].value, 'after-dev');
assert.equal((await secrets(prod))[0].value, 'after-prod');
await expect('POST', `${changePath}/apply`, reviewer, { revision: 2 }, 409);
pass('Worker cross-environment stale batch rollback, revision rebase and successful apply');

const committed = await secrets(dev);
const current = committed.find(s => s.key === 'TARGET');
assert(current, 'checked batch target exists');
await put(dev, [
  { key: 'EARLIER_INSERT', value: 'must-roll-back', expected_version: 0 },
  { key: 'TARGET', value: 'must-not-persist', expected_version: current.version - 1 },
], 409);
assert.deepEqual(await secrets(dev), committed, 'later stale CAS rolls back earlier insert and history-visible version');
pass('Worker checked multi-secret CAS failure rolls back earlier valid write');
console.log(`PASS product Worker smoke (${checks} checked API responses; fixture workspace ${org})`);
