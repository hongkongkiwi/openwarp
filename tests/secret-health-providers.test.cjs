'use strict';

// Run with node --test tests/secret-health-providers.test.cjs. All networking and browser crypto are mocked.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

const modulePath = path.join(__dirname, '../crates/server/src/secret-health.js');
const email = '  Fixture.User@Example.Invalid  ';
const normalized = 'fixture.user@example.invalid';
const hash = createHash('sha256').update(normalized).digest('hex');
const reply = (body, code = 200) => new Response(JSON.stringify(body), {
  status: code, headers: { 'Content-Type': 'application/json' },
});

function client() {
  const network = [], digests = [];
  const context = vm.createContext({
    TextEncoder, TextDecoder, Response, Headers, ReadableStream, AbortController,
    setTimeout, clearTimeout, console,
    crypto: { subtle: { digest: async (algorithm, bytes) => {
      digests.push({ algorithm, value: new TextDecoder().decode(bytes) });
      const digest = Buffer.from(hash, 'hex');
      return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
    } } },
    fetch: async (...args) => { network.push(args); throw new Error('unexpected network access'); },
  });
  context.window = context;
  context.self = context;
  vm.runInContext(fs.readFileSync(modulePath, 'utf8'), context, { timeout: 1000 });
  assert.equal(typeof context.OpenWarpSecretHealth?.checkEmailExposure, 'function',
    'OpenWarpSecretHealth.checkEmailExposure must exist; the email exposure feature is not implemented');
  return { api: context.OpenWarpSecretHealth, network, digests };
}

function state(result, expected) {
  assert.equal(result?.status, expected);
  if (expected !== 'found') assert.equal(result.breaches?.length || 0, 0,
    'a non-found result must not carry positive breach sources');
}

test('checkEmailExposure is exported without hashing or fetching on module load', () => {
  const { network, digests } = client();
  assert.equal(network.length, 0);
  assert.equal(digests.length, 0);
});

test('email exposure checks require enabled === true and otherwise neither hash nor fetch', async () => {
  const { api, digests, network } = client();
  let calls = 0;
  const fetch = async () => { calls++; throw new Error('disabled checks must not fetch'); };
  for (const enabled of [undefined, false, null, 0, 1, 'true']) {
    state(await api.checkEmailExposure(email, { enabled, fetch }), 'disabled');
  }
  state(await api.checkEmailExposure(email), 'disabled');
  assert.equal(calls, 0);
  assert.equal(network.length, 0);
  assert.equal(digests.length, 0);
});

test('invalid and excessive email inputs are unavailable before hashing or egress', async () => {
  const { api, digests, network } = client();
  let calls = 0;
  const fetch = async () => { calls++; return reply({ status: 'not_found', breaches: [] }); };
  for (const value of ['', '   ', null, undefined, 42, {}, 'not-an-email', '@example.invalid',
    'user@', 'user name@example.invalid', 'a@b.invalid\r\nInjected: value', `${'x'.repeat(1024 * 1024)}@example.invalid`]) {
    state(await api.checkEmailExposure(value, { enabled: true, fetch }), 'unavailable');
  }
  assert.equal(calls, 0);
  assert.equal(network.length, 0);
  assert.equal(digests.length, 0);
});

test('explicit checking hashes the normalized email and sends only the 24-character prefix to the relay', async () => {
  const { api, digests, network } = client();
  const calls = [];
  const result = await api.checkEmailExposure(email, { enabled: true, fetch: async (url, options = {}) => {
    calls.push({ url, options });
    return reply({ status: 'found', breaches: ['Fixture Source'], email: normalized,
      password: 'fixture-exposed-value', records: [{ password: 'fixture-exposed-value' }] });
  } });
  assert.deepEqual(digests, [{ algorithm: 'SHA-256', value: normalized }]);
  assert.equal(calls.length, 1);
  assert.equal(network.length, 0, 'use the injected relay fetch, not an external provider request');
  const { url, options } = calls[0];
  assert.equal(String(url), '/api/me/secret-health/leakcheck');
  assert.equal(options.method, 'POST');
  assert.match(new Headers(options.headers).get('Content-Type') || '', /^application\/json(?:;|$)/i);
  assert.deepEqual(JSON.parse(options.body), { email_hash: hash.slice(0, 24), consent: true });
  assert.match(JSON.parse(options.body).email_hash, /^[a-f0-9]{24}$/);
  const wire = String(url) + JSON.stringify([...new Headers(options.headers)]) + options.body;
  for (const forbidden of [email, normalized, hash, 'fixture-exposed-value']) {
    assert.ok(!wire.includes(forbidden), 'the request must not disclose raw email, full hash or exposed values');
  }
  assert.deepEqual(JSON.parse(JSON.stringify(result)), { status: 'found', breaches: ['Fixture Source'] },
    'only validated source names leave the client boundary, not provider raw fields');
});

test('an explicit valid empty relay result is not_found', async () => {
  const { api } = client();
  const result = await api.checkEmailExposure(email, { enabled: true,
    fetch: async () => reply({ status: 'not_found', breaches: [] }) });
  state(result, 'not_found');
});

test('malformed or contradictory relay results are unavailable, never clean', async () => {
  const { api } = client();
  const malformed = [null, [], {}, { status: 'ok' }, { status: 'not_found' },
    { status: 'found', breaches: [] }, { status: 'found', breaches: 'Fixture Source' },
    { status: 'found', breaches: [null] }, { status: 'found', breaches: [123] },
    { status: 'found', breaches: [''] }, { status: 'found', breaches: ['   '] },
    { status: 'found', breaches: ['Source\r\nInjected: value'] },
    { status: 'found', breaches: [{ password: 'fixture-exposed-value' }] },
    { status: 'not_found', breaches: ['Fixture Source'] },
    { status: 'found', breaches: ['Valid Source', null] }];
  for (const body of malformed) {
    state(await api.checkEmailExposure(email, { enabled: true, fetch: async () => reply(body) }), 'unavailable');
  }
});

test('provider HTTP, transport, malformed JSON and response-reading failures are unavailable', async () => {
  const { api } = client();
  const failures = [
    ...[401, 403, 429, 500, 503].map(code => async () => reply({ status: 'not_found', breaches: [] }, code)),
    async () => { throw new Error('fixture transport failure'); },
    async () => new Response('<html>provider error</html>', { status: 200 }),
    async () => ({ ok: true, status: 200,
      json: async () => { throw new Error('fixture body failure'); },
      text: async () => { throw new Error('fixture body failure'); } }),
    async () => reply({ status: 'unavailable' }),
  ];
  for (const fetch of failures) {
    state(await api.checkEmailExposure(email, { enabled: true, fetch }), 'unavailable');
  }
});

test('excessive source names and source arrays are unavailable rather than forwarded or truncated clean', async () => {
  const { api } = client();
  for (const breaches of [['x'.repeat(1024 * 1024)], Array.from({ length: 10000 }, (_, i) => `Fixture Source ${i}`)]) {
    state(await api.checkEmailExposure(email, { enabled: true,
      fetch: async () => reply({ status: 'found', breaches }) }), 'unavailable');
  }
});
