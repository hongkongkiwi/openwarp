'use strict';

// Run with node --test crates/server/tests/auth-v2.test.cjs. No server or browser.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, pbkdf2Sync } = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, '../src/auth-v2.js'), 'utf8');
const context = vm.createContext({
  crypto: webcrypto,
  atob,
  btoa,
  TextEncoder,
  TextDecoder,
  fetch: async () => ({ ok: true, json: async () => ({ version: 2 }) }),
  console,
});
vm.runInContext(source, context, { timeout: 1000 });
const AuthV2 = vm.runInContext('AuthV2', context);

test('PBKDF2 output is split into the auth and wrapping halves', async () => {
  const salt = Buffer.alloc(16, 7);
  const saltB64 = Buffer.from(salt).toString('base64');
  const expected = pbkdf2Sync('correct horse battery staple', salt, 600000, 64, 'sha256');
  const keys = await AuthV2.deriveKeys('correct horse battery staple', saltB64, 600000);
  assert.deepEqual(Buffer.from(keys.auth), expected.subarray(0, 32));
  assert.equal(keys.wrap.algorithm.name, 'AES-GCM');
  await assert.rejects(AuthV2.deriveKeys('pw', saltB64, 1000));
});

test('the private key wraps and unwraps with the wrapping key', async () => {
  const keys = await AuthV2.deriveKeys('pw', Buffer.alloc(16, 1).toString('base64'), 600000);
  const secret = webcrypto.getRandomValues(new Uint8Array(32));
  const wrapped = await AuthV2.wrapPrivate(keys.wrap, secret);
  assert.match(wrapped, /^owv2:/);
  const back = await AuthV2.unwrapPrivate(keys.wrap, wrapped);
  assert.deepEqual(Buffer.from(back), Buffer.from(secret));
  const other = await AuthV2.deriveKeys('other', Buffer.alloc(16, 1).toString('base64'), 600000);
  await assert.rejects(AuthV2.unwrapPrivate(other.wrap, wrapped));
});

test('the challenge proof is deterministic and bound to the challenge id', async () => {
  const keys = await AuthV2.deriveKeys('pw', Buffer.alloc(16, 2).toString('base64'), 600000);
  const one = await AuthV2.proof(keys.auth, 'challenge', 'id-1');
  const two = await AuthV2.proof(keys.auth, 'challenge', 'id-1');
  const other = await AuthV2.proof(keys.auth, 'challenge', 'id-2');
  assert.match(one, /^[0-9a-f]{64}$/);
  assert.equal(one, two);
  assert.notEqual(one, other);
});
