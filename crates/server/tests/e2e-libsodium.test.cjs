'use strict';

// Run with node --test crates/server/tests/e2e-libsodium.test.cjs. It loads the
// vendored libsodium bundles and the browser crypto file in a VM. The static
// vector was produced by openwarp-crypto, so it checks wire compatibility with
// the Rust server and CLI.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const context = vm.createContext({
  crypto: webcrypto, WebAssembly, TextEncoder, TextDecoder, atob, btoa,
  setTimeout, clearTimeout, console, Uint8Array, Uint32Array, ArrayBuffer, Promise,
});
context.window = context; context.self = context;
for (const file of ['vendor/libsodium.js', 'vendor/libsodium-wrappers.js', 'e2e.js']) {
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../src', file), 'utf8'), context, { timeout: 5000 });
}
const OW = vm.runInContext('OW', context);
const sodium = vm.runInContext('sodium', context);

// Produced by `cargo run -p openwarp-crypto --example vectors gen`.
const vector = {
  priv: 'YpLE+77VnoTImoPCzreys7ZX/JgkGv67wke/Vh9ePP0=',
  asym_ct: 'AYkSAxKVfqLfIZoFGq0Mhw/5GG4Gh4AO7VAgiK6STRH4jmsdgUjW1+eGdEg55kTOavMdoCQMv/yV/PHs10MYy0xNF0mvdxG/14k5fElf5+yFlefalZ4YBNE=',
  sym_key: 'hjUm0FHDkSJGL7E2Mg294Jh6NvTU6oxFs5FbthrBmjU=',
  sym_ct: 'GvRL2H1DGzFPeaLtg7eYGisp7yGIclI9Y1blJx5vF0xPmoo9ragrxFUn13NKx80dgfPFN69ajcHNAsg7r3A=',
};

test('the RFC 7748 public key matches', async () => {
  await sodium.ready;
  const secret = Uint8Array.from(Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex'));
  assert.equal(Buffer.from(await OW.x25519Pub(secret)).toString('hex'), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
});

test('libsodium decrypts Rust asymmetric and symmetric ciphertext', async () => {
  await sodium.ready;
  const asym = await OW.decryptAsymmetric(vector.priv, vector.asym_ct);
  assert.equal(new TextDecoder().decode(asym), 'hello e2e browser');
  const sym = await OW.decryptSymmetric(OW.b64dec(vector.sym_key), vector.sym_ct);
  assert.equal(new TextDecoder().decode(sym), 'symmetric secret value');
});

test('browser keypairs and both formats round-trip', async () => {
  await sodium.ready;
  const kp = await OW.generateKeypair();
  const message = new TextEncoder().encode('round trip');
  const ct = await OW.encryptAsymmetric(kp.public, message);
  assert.equal(new TextDecoder().decode(await OW.decryptAsymmetric(OW.b64enc(kp.secret), ct)), 'round trip');
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const sct = await OW.encryptSymmetric(key, message);
  assert.equal(new TextDecoder().decode(await OW.decryptSymmetric(key, sct)), 'round trip');
  const other = await OW.generateKeypair();
  await assert.rejects(OW.decryptAsymmetric(OW.b64enc(other.secret), ct));
});
