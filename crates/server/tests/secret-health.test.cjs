'use strict';

// Run with node --test crates/server/tests/secret-health.test.cjs. No server or provider is contacted.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash, webcrypto } = require('node:crypto');

const originalFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error('real network access is prohibited in secret-health tests'); };
test.after(() => { globalThis.fetch = originalFetch; });

const src = path.join(__dirname, '../src');
const modulePath = path.join(src, 'secret-health.js');
const password = 'fixture-only-password-\u00e9-\ud83d\udd10';
const hash = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
const suffix = hash.slice(5);
const otherSuffix = (suffix[0] === 'A' ? 'B' : 'A') + suffix.slice(1);
const response = (body, status = 200) => new Response(body, { status });

function moduleSource() {
  assert.ok(fs.existsSync(modulePath), 'secret-health.js must exist; the secret-health feature is not implemented');
  return fs.readFileSync(modulePath, 'utf8');
}

function commonJS() {
  moduleSource();
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (...args) => { calls.push(args); throw new Error('unexpected automatic network request'); };
  let api;
  try {
    delete require.cache[require.resolve(modulePath)];
    api = require(modulePath);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.length, 0, 'loading the module must not initiate a lookup');
  assert.equal(typeof api.localStrength, 'function', 'CommonJS exports localStrength');
  assert.equal(typeof api.checkPassword, 'function', 'CommonJS exports checkPassword');
  return api;
}

function browser(zxcvbn) {
  const calls = [];
  const context = vm.createContext({
    crypto: webcrypto, TextEncoder, TextDecoder, Response, Headers, ReadableStream,
    AbortController, setTimeout, clearTimeout, console,
    fetch: async (...args) => { calls.push(args); throw new Error('unexpected automatic network request'); },
    ...(zxcvbn ? { zxcvbn } : {}),
  });
  context.window = context;
  context.self = context;
  vm.runInContext(moduleSource(), context, { timeout: 1000 });
  const api = context.OpenWarpSecretHealth;
  assert.ok(api, 'the browser global is OpenWarpSecretHealth');
  assert.equal(typeof api.localStrength, 'function');
  assert.equal(typeof api.checkPassword, 'function');
  assert.equal(calls.length, 0, 'loading the browser module must not initiate a lookup');
  return { api, calls };
}

function status(result, expected) {
  assert.equal(result?.status, expected);
  if (expected !== 'found') assert.ok(!result.count, 'a non-found result cannot report positive occurrences');
}

test('CommonJS and browser exports load without an automatic network lookup', () => {
  commonJS();
  browser();
});

test('localStrength uses browser zxcvbn offline and never starts a breach lookup', async () => {
  const seen = [];
  const { api, calls } = browser(value => {
    seen.push(value);
    return { score: 2, guesses: 12345, feedback: { warning: '', suggestions: [] } };
  });
  const result = await api.localStrength(password);
  assert.deepEqual(seen, [password], 'pass the exact value to the local estimator');
  assert.equal(result.score, 2, 'use the zxcvbn score rather than a length heuristic');
  assert.equal(calls.length, 0);
});

test('CommonJS localStrength works with the vendored estimator and ranks predictable values lower', async () => {
  const api = commonJS();
  const weak = await api.localStrength('password');
  const strong = await api.localStrength('q7!L2@v9#N4$w8%R6^t3&Y5');
  for (const result of [weak, strong]) {
    assert.ok(Number.isInteger(result.score) && result.score >= 0 && result.score <= 4);
  }
  assert.ok(weak.score < strong.score, 'the vendored zxcvbn estimator must distinguish these fixtures');
});

test('password checks are disabled by default and require explicit boolean opt-in', async () => {
  const api = commonJS();
  let calls = 0;
  const fetch = async () => { calls++; throw new Error('must not fetch while disabled'); };
  for (const enabled of [undefined, false, null, 0, 'true']) {
    status(await api.checkPassword(password, { enabled, fetch }), 'disabled');
  }
  status(await api.checkPassword(password), 'disabled');
  assert.equal(calls, 0);
});

test('an explicit password check sends only the uppercase five-character SHA1 prefix', async () => {
  const { api } = browser();
  const requests = [];
  const result = await api.checkPassword(password, {
    enabled: true,
    fetch: async (url, options = {}) => {
      requests.push({ url, options });
      return response(`${otherSuffix}:0\r\n${suffix}:42\r\n`);
    },
  });
  status(result, 'found');
  assert.equal(result.count, 42);
  assert.equal(requests.length, 1);
  const { url, options } = requests[0];
  assert.equal(String(url), `https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`);
  assert.equal((options.method || 'GET').toUpperCase(), 'GET');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(new Headers(options.headers).get('Add-Padding'), 'true');
  assert.ok(options.body == null, 'the range lookup has no request body');
  const transmitted = String(url) + JSON.stringify([...new Headers(options.headers)]) + String(options.body || '');
  assert.ok(!transmitted.includes(password), 'never transmit the plaintext value');
  assert.ok(!transmitted.toUpperCase().includes(hash), 'never transmit the full SHA1');
  assert.ok(!transmitted.toUpperCase().includes(suffix), 'never transmit the hash suffix');
});

test('valid absent and zero-count padding responses are not_found, not found', async () => {
  const api = commonJS();
  for (const body of [`${otherSuffix}:17\r\n`, `${suffix}:0\r\n${otherSuffix}:0\r\n`]) {
    status(await api.checkPassword(password, { enabled: true, fetch: async () => response(body) }), 'not_found');
  }
});

test('range parsing rejects malformed lines even after a matching suffix', async () => {
  const api = commonJS();
  const malformed = [
    '', '<html>provider error</html>', `${suffix.slice(1)}:12`, `${'Z'.repeat(35)}:12`,
    `${suffix}:-1`, `${suffix}:+1`, `${suffix}:1.5`, `${suffix}:1e3`, `${suffix}:12junk`,
    `${suffix}:`, `${suffix}:1:2`, `${suffix}:9007199254740992`,
    `${suffix}:7\r\nnot-a-range-line`,
  ];
  for (const body of malformed) {
    status(await api.checkPassword(password, { enabled: true, fetch: async () => response(body) }), 'unavailable');
  }
});

test('provider HTTP, transport and response-reading errors are unavailable, never clean', async () => {
  const api = commonJS();
  const failures = [
    ...[404, 429, 500, 503].map(code => async () => response(`${suffix}:9\r\n`, code)),
    async () => { throw new Error('fixture network failure'); },
    async () => ({ ok: true, status: 200, text: async () => { throw new Error('fixture body failure'); } }),
  ];
  for (const fetch of failures) status(await api.checkPassword(password, { enabled: true, fetch }), 'unavailable');
});

test('invalid or excessive password input is unavailable without a network request', async () => {
  const api = commonJS();
  let calls = 0;
  const fetch = async () => { calls++; return response(`${otherSuffix}:0\r\n`); };
  for (const value of ['', null, undefined, 123, {}, 'x'.repeat(1024 * 1024)]) {
    status(await api.checkPassword(value, { enabled: true, fetch }), 'unavailable');
  }
  assert.equal(calls, 0, 'reject invalid and excessive inputs before egress');
});

test('an excessive provider result is unavailable even if its first row matches', async () => {
  const api = commonJS();
  const body = `${suffix}:7\r\n` + `${otherSuffix}:0\r\n`.repeat(120000);
  assert.ok(Buffer.byteLength(body) > 4 * 1024 * 1024);
  status(await api.checkPassword(password, { enabled: true, fetch: async () => response(body) }), 'unavailable');
});

test('the console loads secret health and zxcvbn locally and the router serves both assets', () => {
  const ui = fs.readFileSync(path.join(src, 'ui.rs'), 'utf8');
  const app = fs.readFileSync(path.join(src, 'app.rs'), 'utf8');
  const scripts = [...ui.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)].map(match => match[1]);
  assert.ok(scripts.includes('/secret-health.js'), 'the console loads the local health module');
  const estimator = scripts.find(url => /^\/(?:vendor\/)?zxcvbn[^/]*\.js$/.test(url));
  assert.ok(estimator, 'the estimator is loaded locally, not from a CDN');
  for (const asset of ['/secret-health.js', estimator]) {
    assert.ok(app.includes(`"${asset}"`), `the router must serve ${asset}`);
  }
  assert.ok(/include_(?:str|bytes)!\("(?:vendor\/)?zxcvbn[^\"]*\.js"\)/.test(app),
    'the offline estimator must be vendored into the server');
});

test('settings and consented email checking have separate per-user API routes', () => {
  const app = fs.readFileSync(path.join(src, 'app.rs'), 'utf8');
  assert.ok(/\.route\("\/api\/me\/secret-health",\s*get\([^\n]+?\.put\(/.test(app),
    'GET status and PUT configuration share the per-user settings route');
  assert.ok(/\.route\("\/api\/me\/secret-health\/email",\s*post\(/.test(app),
    'email disclosure is an explicit POST, separate from password range checks');
});
