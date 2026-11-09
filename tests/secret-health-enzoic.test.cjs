'use strict';

// Run with node --test tests/secret-health-enzoic.test.cjs. No provider is contacted.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

const modulePath = path.join(__dirname, '../crates/server/src/secret-health.js');
const password = '  FiXtUrE-e\u0301-\ud83d\udd10  ';
const hash = createHash('sha256').update(password, 'utf8').digest('hex');
const collision = hash.slice(0, 10) + (hash[10] === 'a' ? 'b' : 'a') + hash.slice(11);
const candidate = (sha256 = hash, revealedInExposure = true, exposureCount = 7) =>
  ({ sha256, revealedInExposure, exposureCount });
const reply = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
});

function client() {
  const network = [], digests = [];
  const context = vm.createContext({
    TextEncoder, TextDecoder, Response, Headers, ReadableStream, AbortController,
    setTimeout, clearTimeout, console,
    crypto: { subtle: { digest: async (algorithm, bytes) => {
      digests.push({ algorithm, bytes: Buffer.from(bytes).toString('hex') });
      const digest = Buffer.from(hash, 'hex');
      return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
    } } },
    fetch: async (...args) => { network.push(args); throw new Error('unexpected network access'); },
  });
  context.window = context;
  context.self = context;
  vm.runInContext(fs.readFileSync(modulePath, 'utf8'), context, { timeout: 1000 });
  assert.equal(typeof context.OpenWarpSecretHealth?.checkEnzoicPassword, 'function',
    'OpenWarpSecretHealth.checkEnzoicPassword must exist; the Enzoic password feature is not implemented');
  return { api: context.OpenWarpSecretHealth, network, digests };
}

function state(result, expected) {
  assert.equal(result?.status, expected);
  if (expected !== 'found') assert.ok(!result.count, 'non-found results cannot report positive exposure counts');
}

test('checkEnzoicPassword loads without hashing or initiating a lookup', () => {
  const { network, digests } = client();
  assert.equal(network.length, 0);
  assert.equal(digests.length, 0);
});

test('Enzoic password checks require enabled === true before hashing or fetching', async () => {
  const { api, network, digests } = client();
  let calls = 0;
  const fetch = async () => { calls++; throw new Error('disabled checks must not fetch'); };
  for (const enabled of [undefined, false, null, 0, 1, 'true']) {
    state(await api.checkEnzoicPassword(password, { enabled, fetch }), 'disabled');
  }
  state(await api.checkEnzoicPassword(password), 'disabled');
  assert.equal(calls, 0);
  assert.equal(network.length, 0);
  assert.equal(digests.length, 0);
});

test('invalid and excessive password inputs are unavailable without hashing or egress', async () => {
  const { api, network, digests } = client();
  let calls = 0;
  const fetch = async () => { calls++; return reply({ candidates: [] }); };
  for (const value of ['', null, undefined, 123, {}, [], 'x'.repeat(1024 * 1024)]) {
    state(await api.checkEnzoicPassword(value, { enabled: true, fetch }), 'unavailable');
  }
  assert.equal(calls, 0);
  assert.equal(network.length, 0);
  assert.equal(digests.length, 0);
});

test('an explicit check hashes exact UTF8 and relays only the lowercase ten-character prefix', async () => {
  const { api, network, digests } = client();
  const requests = [];
  const result = await api.checkEnzoicPassword(password, { enabled: true, fetch: async (url, options = {}) => {
    requests.push({ url, options });
    return reply({ candidates: [candidate()], password: 'fixture-exposed-value' });
  } });
  assert.deepEqual(digests, [{ algorithm: 'SHA-256', bytes: Buffer.from(password, 'utf8').toString('hex') }],
    'password whitespace, case and decomposed Unicode must remain unchanged');
  assert.equal(network.length, 0);
  assert.equal(requests.length, 1);
  const { url, options } = requests[0];
  assert.equal(String(url), '/api/me/secret-health/enzoic/password');
  assert.equal(options.method, 'POST');
  assert.match(new Headers(options.headers).get('Content-Type') || '', /^application\/json(?:;|$)/i);
  assert.deepEqual(JSON.parse(options.body), { prefix: hash.slice(0, 10), consent: true });
  assert.match(JSON.parse(options.body).prefix, /^[a-f0-9]{10}$/);
  const wire = String(url) + JSON.stringify([...new Headers(options.headers)]) + options.body;
  assert.ok(!wire.includes(password));
  assert.ok(!wire.toLowerCase().includes(hash), 'the full digest must remain local');
  state(result, 'found');
  if (result.count !== undefined) assert.equal(result.count, 7);
  assert.ok(Object.keys(result).every(key => ['status', 'count'].includes(key)),
    'do not forward candidate hashes, raw provider fields or exposed values');
});

test('only an exposed full-digest match is found, not merely a nonempty prefix bucket', async () => {
  const { api } = client();
  for (const candidates of [[], [candidate(collision)], [candidate(hash, false, 0)]]) {
    state(await api.checkEnzoicPassword(password, { enabled: true,
      fetch: async () => reply({ candidates }) }), 'not_found');
  }
  for (const candidates of [[candidate(collision), candidate()], [candidate(hash.toUpperCase())]]) {
    const result = await api.checkEnzoicPassword(password, { enabled: true,
      fetch: async () => reply({ candidates }) });
    state(result, 'found');
    if (result.count !== undefined) assert.equal(result.count, 7);
  }
});

test('malformed candidates invalidate the whole response even after an exposed match', async () => {
  const { api } = client();
  const malformed = [null, [], {}, candidate('a'.repeat(63)), candidate('g'.repeat(64)),
    candidate(` ${hash}`), candidate(hash, 'true'), candidate(hash, 1),
    { sha256: hash, exposureCount: 7 }, { sha256: hash, revealedInExposure: true },
    candidate(hash, true, -1), candidate(hash, true, 1.5), candidate(hash, true, '7'),
    candidate(hash, true, null), candidate(hash, true, Number.MAX_SAFE_INTEGER + 1)];
  for (const bad of malformed) {
    for (const candidates of [[bad], [candidate(), bad]]) {
      state(await api.checkEnzoicPassword(password, { enabled: true,
        fetch: async () => reply({ candidates }) }), 'unavailable');
    }
  }
  for (const body of [null, [], {}, { candidates: null }, { candidates: {} }, { candidates: 'none' }]) {
    state(await api.checkEnzoicPassword(password, { enabled: true,
      fetch: async () => reply(body) }), 'unavailable');
  }
});

test('HTTP, transport, JSON and response-reading failures never become not_found', async () => {
  const { api } = client();
  const failures = [
    ...[401, 403, 404, 429, 500, 503].map(code => async () => reply({ candidates: [] }, code)),
    async () => { throw new Error('fixture network failure'); },
    async () => new Response('<html>provider error</html>', { status: 200 }),
    async () => ({ ok: true, status: 200,
      json: async () => { throw new Error('fixture body failure'); },
      text: async () => { throw new Error('fixture body failure'); } }),
  ];
  for (const fetch of failures) {
    state(await api.checkEnzoicPassword(password, { enabled: true, fetch }), 'unavailable');
  }
});

test('oversized candidate hashes and candidate arrays are unavailable even after an early match', async () => {
  const { api } = client();
  for (const candidates of [[candidate(), candidate('a'.repeat(1024 * 1024))],
    [candidate(), ...Array.from({ length: 10000 }, () => candidate(collision))]]) {
    state(await api.checkEnzoicPassword(password, { enabled: true,
      fetch: async () => reply({ candidates }) }), 'unavailable');
  }
});
