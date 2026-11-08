'use strict';

// Pins the vendored libsodium browser bundles. Keep these hashes in sync with
// the SRI attributes in ui.rs and the notes in src/vendor/README.md.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const expected = {
  'hash-wasm.js': 'b43a59e36eafcb2f744eb23badd590ca23c7dad54fb0395522cec6fb85a6582c',
  'LICENSE.hash-wasm': 'c14dea172f72f2714284a0ac2ab1b00b5352a01409d58255a46227ffc541debd',
  'zxcvbn.js': '6677fc15d245f397f52d5d0998f3a86f9aae752ae7b3ca4b3d9eaa91dffe174a',
  'LICENSE.zxcvbn': '8fd6c9ffe44291acd207a4d3cf7d6db5ac05f585ee1cf45db9fc6b153b08990f',
  'libsodium.js': '9d9731995989ac2d7c73ba4fb6717e43cd2a4a4299c442b710c2d9e5065b14d1',
  'libsodium-wrappers.js': 'd015a93315140974698318d94274ff63c6d22530d8b0e3f3770d9bfeadc7eb60',
};
for (const [file, digest] of Object.entries(expected)) {
  test(`${file} matches the pinned SHA-256`, () => {
    const body = fs.readFileSync(path.join(__dirname, '../src/vendor', file));
    assert.equal(crypto.createHash('sha256').update(body).digest('hex'), digest);
  });
}
test('the console pins the hash-wasm build with matching SRI', () => {
  const body = fs.readFileSync(path.join(__dirname, '../src/vendor/hash-wasm.js'));
  const sri = 'sha384-' + crypto.createHash('sha384').update(body).digest('base64');
  const ui = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
  assert.ok(ui.includes(`<script src="/hash-wasm.js" integrity="${sri}"></script>`));
  assert.ok(ui.indexOf('src="/hash-wasm.js"') < ui.indexOf('src="/enzoic-pairs.js"'));
});
test('the libsodium licence is present', () => {
  assert.match(fs.readFileSync(path.join(__dirname, '../src/vendor/LICENSE.libsodium'), 'utf8'), /ISC|Permission to use/i);
});
test('the console policy permits the libsodium WebAssembly build', () => {
  // The Workers refactor moved the handlers into the shared app module.
  const app = fs.readFileSync(path.join(__dirname, '../src/app.rs'), 'utf8');
  const start = app.indexOf('async fn index()');
  const end = app.indexOf('async fn security_headers');
  assert.ok(start > 0 && end > start, 'the index handler must be findable');
  assert.match(app.slice(start, end), /wasm-unsafe-eval/,
    'the console CSP must allow the WASM build, or the browser E2E editor cannot load libsodium');
});
