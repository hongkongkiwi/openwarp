'use strict';

// Run with node --test tests/secret-health-enzoic-pairs.test.cjs. No provider is contacted.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { createHash, webcrypto } = require('node:crypto');

const modulePath = path.join(__dirname, '../crates/server/src/enzoic-pairs.js');
const email = '  FiXtUrE.User@Example.Invalid  ';
const lowerEmail = email.toLowerCase();
const password = '  FiXtUrE-e\u0301-\ud83d\udd10  ';
const salt = 'fixture-account-salt';
const legacySalt = 'fixture-legacy-salt';
const digest = (algorithm, value) => createHash(algorithm).update(value, 'utf8').digest('hex');
const derived = '0123456789abcdef0123456789abcdef01234567';
const collision = derived.slice(0, 10) + 'f' + derived.slice(11);
const account = (requirements = [{ hashType: 3, salt: legacySalt }]) =>
  ({ found: true, salt, passwordHashesRequired: requirements });
const reply = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
});

function client(commonJS = false) {
  assert.ok(fs.existsSync(modulePath),
    'Enzoic credential-pair feature missing: crates/server/src/enzoic-pairs.js must export checkCredentials');
  const network = [], digests = [];
  const context = vm.createContext({
    TextEncoder, TextDecoder, Response, Headers, ReadableStream, AbortController,
    setTimeout, clearTimeout, console,
    crypto: { subtle: { digest: async (algorithm, bytes) => {
      digests.push({ algorithm, value: new TextDecoder().decode(bytes) });
      return webcrypto.subtle.digest(algorithm, bytes);
    } } },
    fetch: async (...args) => { network.push(args); throw new Error('unexpected network access'); },
  });
  context.window = context;
  context.self = context;
  if (commonJS) {
    context.module = { exports: {} };
    context.exports = context.module.exports;
    context.require = createRequire(modulePath);
  }
  vm.runInContext(fs.readFileSync(modulePath, 'utf8'), context, { timeout: 1000 });
  const api = commonJS ? context.module.exports : context.OpenWarpEnzoicPairs;
  assert.equal(typeof api?.checkCredentials, 'function', 'checkCredentials must be a public export');
  return { api, network, digests };
}

function state(result, expected) {
  assert.equal(result?.status, expected);
  const output = JSON.stringify(result);
  for (const forbidden of [email, lowerEmail, password, derived]) {
    assert.ok(!output.includes(forbidden), 'results must not expose credentials or full candidate hashes');
  }
}

function primitives(output = derived) {
  const hashes = [], derivations = [];
  return {
    hashes, derivations,
    hashPassword: async (algorithm, value) => {
      hashes.push({ algorithm, value });
      return digest(algorithm, value);
    },
    argon2: async options => {
      derivations.push(JSON.parse(JSON.stringify(options)));
      return output;
    },
  };
}

function relay(bodies = [account(), { candidateHashes: [derived] }]) {
  const requests = [];
  return { requests, fetch: async (url, options = {}) => {
    requests.push({ url: String(url), options });
    assert.ok(requests.length <= bodies.length, 'no unexpected extra relay request');
    return reply(bodies[requests.length - 1]);
  } };
}

function requestBody(request, route) {
  assert.equal(request.url, `/api/me/secret-health/enzoic/${route}`);
  assert.equal(request.options.method, 'POST');
  assert.match(new Headers(request.options.headers).get('Content-Type') || '', /^application\/json(?:;|$)/i);
  return JSON.parse(request.options.body);
}

function assertNoDerivation(p, requests) {
  assert.equal(p.hashes.length, 0, 'reject before legacy password hashing');
  assert.equal(p.derivations.length, 0, 'reject before Argon2 work');
  assert.equal(requests.length, 1, 'reject before the credentials relay request');
}

test('credential-pair API exports in CommonJS and browser without hashing or networking', () => {
  for (const commonJS of [false, true]) {
    const { network, digests } = client(commonJS);
    assert.equal(network.length, 0);
    assert.equal(digests.length, 0);
  }
});

test('credential-pair checks require enabled === true before hashing or networking', async () => {
  const { api, network, digests } = client();
  const p = primitives(), r = relay();
  for (const enabled of [undefined, false, null, 0, 1, 'true', {}, []]) {
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled }), 'disabled');
  }
  state(await api.checkCredentials(email, password), 'disabled');
  assert.equal(p.hashes.length + p.derivations.length + r.requests.length + digests.length + network.length, 0);
});

test('invalid inputs and email/password bounds reject before hashing or networking', async () => {
  const { api, network, digests } = client();
  const p = primitives(), r = relay();
  for (const bad of ['', null, undefined, 42, {}, []]) {
    state(await api.checkCredentials(bad, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
    state(await api.checkCredentials(email, bad, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
  }
  for (const [user, pass] of [['x'.repeat(255), password], [email, 'x'.repeat(1025)]]) {
    state(await api.checkCredentials(user, pass, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
  }
  assert.equal(p.hashes.length + p.derivations.length + r.requests.length + digests.length + network.length, 0);
});

test('account lookup hashes lowercased exact email without trimming and stops on found:false', async () => {
  const { api, network } = client();
  const p = primitives(), r = relay([{ found: false }]);
  state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'not_found');
  assert.equal(r.requests.length, 1);
  assert.deepEqual(requestBody(r.requests[0], 'accounts'), {
    username_hash: digest('sha256', lowerEmail), consent: true,
  });
  assert.match(JSON.parse(r.requests[0].options.body).username_hash, /^[a-f0-9]{64}$/);
  assert.equal(p.derivations.length, 0);
  assert.equal(network.length, 0);
});

test('all named supported legacy formulas feed the exact bounded Argon2d options', async () => {
  const { api } = client();
  const vectors = [
    [1, 'md5', password], [2, 'sha1', password], [3, 'sha256', password],
    [13, 'md5', password + legacySalt], [14, 'sha512', password],
    [19, 'md5', legacySalt + password], [25, 'sha1', password + legacySalt],
    [27, 'md5', digest('md5', password)], [32, 'sha1', legacySalt + password],
    [35, 'sha384', password], [37, 'sha256', legacySalt + password],
    [40, 'sha512', password + ':' + legacySalt],
  ];
  for (const [hashType, algorithm, value] of vectors) {
    const p = primitives(), r = relay([account([{ hashType, salt: legacySalt }]), { candidateHashes: [derived] }]);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'found');
    assert.deepEqual(p.hashes, hashType === 27
      ? [{ algorithm: 'md5', value: password }, { algorithm, value }]
      : [{ algorithm, value }], `legacy formula ${hashType}`);
    assert.deepEqual(p.derivations, [{
      password: lowerEmail + '$' + digest(algorithm, value), salt,
      type: 'argon2d', iterations: 3, memorySize: 1024, parallelism: 2,
      hashLength: 20, outputType: 'hex',
    }], `Argon2d options for ${hashType}`);
    assert.deepEqual(requestBody(r.requests[1], 'credentials'), {
      partial_hashes: [derived.slice(0, 10)], consent: true,
    });
  }
  // Enzoic SDK c51cfc5 src/hashing.js:234-235 hashes the supplied salt, not the email.
  for (const suppliedSalt of ['Arbitrary-CaseSensitive-Salt', 'another-unrelated-salt']) {
    const p = primitives(), r = relay([account([{ hashType: 32, salt: suppliedSalt }]), { candidateHashes: [derived] }]);
    assert.notEqual(suppliedSalt, lowerEmail);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'found');
    assert.deepEqual(p.hashes, [{ algorithm: 'sha1', value: suppliedSalt + password }]);
    assert.equal(p.derivations[0].password, lowerEmail + '$' + digest('sha1', suppliedSalt + password));
    assert.deepEqual(requestBody(r.requests[1], 'credentials'), {
      partial_hashes: [derived.slice(0, 10)], consent: true,
    });
  }
});

test('only ten-character prefixes leave the client and full local equality determines found', async () => {
  const { api, network } = client();
  for (const [candidateHashes, expected] of [[[], 'not_found'], [[collision], 'not_found'],
    [[collision, derived], 'found']]) {
    const p = primitives(), r = relay([account(), { candidateHashes, password: 'fixture-provider-value' }]);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), expected);
    assert.equal(r.requests.length, 2);
    assert.deepEqual(requestBody(r.requests[0], 'accounts'), {
      username_hash: digest('sha256', lowerEmail), consent: true,
    });
    assert.deepEqual(requestBody(r.requests[1], 'credentials'), {
      partial_hashes: [derived.slice(0, 10)], consent: true,
    });
    const wire = r.requests.map(({ url, options }) => url + JSON.stringify([...new Headers(options.headers)]) + options.body).join('');
    for (const forbidden of [email, lowerEmail, password, digest('sha256', password), derived]) {
      assert.ok(!wire.includes(forbidden), 'relay must not receive plaintext or full password-derived hashes');
    }
  }
  assert.equal(network.length, 0);
});

test('unknown, ambiguous and expensive requirements invalidate the whole set before derivation', async () => {
  const { api } = client();
  for (const hashType of [0, 6, 41, 999, '3', null]) {
    for (const requirements of [[{ hashType, salt: legacySalt }],
      [{ hashType: 3, salt: legacySalt }, { hashType, salt: legacySalt }]]) {
      const p = primitives(), r = relay([account(requirements)]);
      state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
      assertNoDerivation(p, r.requests);
    }
  }
});

test('malformed account data, encoded salts and excessive salts reject before derivation', async () => {
  const { api } = client();
  const malformed = [null, [], {}, { found: null }, { found: 'false' }, { found: true },
    { ...account(), passwordHashesRequired: null }, { ...account(), passwordHashesRequired: {} },
    account([]), account([null]), account([{}]), account([{ hashType: 3, salt: {} }]),
    { ...account(), salt: null }, { ...account(), salt: {} },
    { ...account(), saltEncoding: 'base64' },
    account([{ hashType: 13, salt: legacySalt, saltEncoding: 'hex' }]),
    { ...account(), salt: 'x'.repeat(1025) },
    { ...account(), salt: '\u00e9'.repeat(513) },
    account([{ hashType: 13, salt: 'x'.repeat(1025) }]),
    account([{ hashType: 13, salt: '\u00e9'.repeat(513) }])];
  for (const encoded of ['$argon2d$v=19$m=1024,t=3,p=2$c2FsdA$ZmFrZQ', 'base64:c2FsdA==', 'hex:73616c74']) {
    malformed.push({ ...account(), salt: encoded });
    malformed.push(account([{ hashType: 13, salt: encoded }]));
  }
  for (const body of malformed) {
    const p = primitives(), r = relay([body]);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
    assertNoDerivation(p, r.requests);
  }
});

test('32 requirements and 1000 candidates are accepted while either next element is rejected', async () => {
  const { api } = client();
  const requirements = Array.from({ length: 32 }, (_, i) => ({ hashType: 13, salt: `fixture-salt-${i}` }));
  const candidates = [...Array(999).fill(collision), derived];
  let p = primitives(), r = relay([account(requirements), { candidateHashes: candidates }]);
  state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'found');
  assert.equal(p.derivations.length, 32, 'every required legacy hash must be derived, not skipped');
  for (const plainSalt of ['x'.repeat(1024), '\u00e9'.repeat(512), '73616c74']) {
    p = primitives(); r = relay([{ ...account([{ hashType: 13, salt: plainSalt, saltEncoding: 'plain' }]),
      salt: plainSalt, saltEncoding: 'plain' }, { candidateHashes: [derived] }]);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'found');
    assert.equal(p.derivations[0].salt, plainSalt);
  }
  p = primitives(); r = relay([account([...requirements, { hashType: 13, salt: legacySalt }])]);
  state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
  assertNoDerivation(p, r.requests);
  p = primitives(); r = relay([account(), { candidateHashes: [derived, ...Array(1000).fill(collision)] }]);
  state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
  const maxEmail = 'x'.repeat(242) + '@example.com';
  p = primitives(); r = relay([{ found: false }]);
  state(await api.checkCredentials(maxEmail, 'x'.repeat(1024), { ...p, fetch: r.fetch, enabled: true }), 'not_found');
});

test('malformed candidate sets are unavailable even when an earlier candidate matches', async () => {
  const { api } = client();
  const malformed = [null, [], {}, { candidateHashes: null }, { candidateHashes: {} }, { candidateHashes: 'none' }];
  for (const bad of [null, {}, [], 123, 'g'.repeat(40), 'a'.repeat(39), 'a'.repeat(41), ' ' + derived,
    'a'.repeat(1024 * 1024)]) {
    malformed.push({ candidateHashes: [bad] }, { candidateHashes: [derived, bad] });
  }
  for (const body of malformed) {
    const p = primitives(), r = relay([account(), body]);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
  }
});

test('HTTP, transport and JSON failures in either relay stage are unavailable', async () => {
  const { api } = client();
  const failures = [
    ...[401, 403, 429, 500, 503].map(code => async () => reply({ found: false, candidateHashes: [] }, code)),
    async () => { throw new Error('fixture transport failure'); },
    async () => new Response('<html>fixture error</html>', { status: 200 }),
    async () => ({ ok: true, status: 200,
      json: async () => { throw new Error('fixture response read failure'); },
      text: async () => { throw new Error('fixture response read failure'); } }),
  ];
  for (const fail of failures) {
    for (const stage of [1, 2]) {
      const p = primitives(); let calls = 0;
      state(await api.checkCredentials(email, password, { ...p, enabled: true, fetch: async () => {
        calls++;
        return calls === stage ? fail() : reply(account());
      } }), 'unavailable');
      assert.equal(calls, stage);
    }
  }
});

test('failed or invalid local primitives never send a credentials request', async () => {
  const { api } = client();
  for (const invalid of [null, {}, '', 'g'.repeat(40), 'a'.repeat(39), 'a'.repeat(41)]) {
    const p = primitives(invalid), r = relay([account()]);
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
    assert.equal(r.requests.length, 1);
  }
  for (const primitive of ['hashPassword', 'argon2']) {
    const p = primitives(), r = relay([account()]);
    p[primitive] = async () => { throw new Error('fixture primitive failure'); };
    state(await api.checkCredentials(email, password, { ...p, fetch: r.fetch, enabled: true }), 'unavailable');
    assert.equal(r.requests.length, 1);
  }
});
