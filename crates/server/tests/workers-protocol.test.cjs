'use strict';

// Fixture checks only. Runtime proof requires scripts/worker-protocol-smoke.mjs.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const helpers = import(pathToFileURL(path.join(__dirname, '../../../scripts/worker-protocol-smoke.mjs')).href);

test('WebAuthn fixture CBOR matches fixed integer, byte-string and map vectors', async () => {
  const { cbor } = await helpers;
  for (const [input, hex] of [[0, '00'], [23, '17'], [24, '1818'], [256, '190100'], [-1, '20'], [-7, '26'],
    [Buffer.from('010203', 'hex'), '43010203'], ['none', '646e6f6e65'], [new Map(), 'a0'],
    [new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from('0102', 'hex')], [-3, Buffer.from('0304', 'hex')]]), 'a50102032620012142010222420304']]) {
    assert.equal(cbor(input).toString('hex'), hex);
  }
  assert.equal(cbor(Buffer.alloc(24)).subarray(0, 2).toString('hex'), '5818');
  assert.equal(cbor(Buffer.alloc(256)).subarray(0, 3).toString('hex'), '590100');
  assert.throws(() => cbor(null));
  assert.throws(() => cbor(65536));
});

test('authenticator data uses SHA-256 RP hash and big-endian counter', async () => {
  const { authData } = await helpers;
  assert.equal(authData('', 0x45, 0x01020304, Buffer.from('aabb', 'hex')).toString('hex'),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' + '4501020304aabb');
});

test('assertion fixture emits a real DER ES256 signature over authenticator data and client-data hash', async () => {
  const { assertion } = await helpers;
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const id = Buffer.from('credential'), challenge = 'server-challenge';
  const value = assertion(id, privateKey, 'example.com', 'https://example.com', challenge, 7);
  assert.equal(value.id, id.toString('base64url'));
  assert.equal(value.rawId, value.id);
  const cd = Buffer.from(value.response.clientDataJSON, 'base64url');
  assert.deepEqual(JSON.parse(cd), { type: 'webauthn.get', challenge, origin: 'https://example.com', crossOrigin: false });
  const auth = Buffer.from(value.response.authenticatorData, 'base64url');
  assert.equal(auth.length, 37);
  assert.equal(auth[32], 0x05);
  assert.equal(auth.readUInt32BE(33), 7);
  const message = Buffer.concat([auth, crypto.createHash('sha256').update(cd).digest()]);
  const signature = Buffer.from(value.response.signature, 'base64url');
  assert.equal(signature[0], 0x30);
  assert.equal(crypto.verify('sha256', message, publicKey, signature), true);
  message[0] ^= 1;
  assert.equal(crypto.verify('sha256', message, publicKey, signature), false);
});
