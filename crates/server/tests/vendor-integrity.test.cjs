'use strict';

// Pins the vendored libsodium browser bundles. Keep these hashes in sync with
// the SRI attributes in ui.rs and the notes in src/vendor/README.md.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const expected = {
  'libsodium.js': '9d9731995989ac2d7c73ba4fb6717e43cd2a4a4299c442b710c2d9e5065b14d1',
  'libsodium-wrappers.js': 'd015a93315140974698318d94274ff63c6d22530d8b0e3f3770d9bfeadc7eb60',
};
for (const [file, digest] of Object.entries(expected)) {
  test(`${file} matches the pinned SHA-256`, () => {
    const body = fs.readFileSync(path.join(__dirname, '../src/vendor', file));
    assert.equal(crypto.createHash('sha256').update(body).digest('hex'), digest);
  });
}
test('the libsodium licence is present', () => {
  assert.match(fs.readFileSync(path.join(__dirname, '../src/vendor/LICENSE.libsodium'), 'utf8'), /ISC|Permission to use/i);
});
test('the console policy permits the libsodium WebAssembly build', () => {
  const main = fs.readFileSync(path.join(__dirname, '../src/main.rs'), 'utf8');
  const start = main.indexOf('async fn index()');
  const end = main.indexOf('async fn security_headers');
  assert.ok(start > 0 && end > start, 'the index handler must be findable');
  assert.match(main.slice(start, end), /wasm-unsafe-eval/,
    'the console CSP must allow the WASM build, or the browser E2E editor cannot load libsodium');
});
