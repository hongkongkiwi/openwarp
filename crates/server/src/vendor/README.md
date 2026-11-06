# Vendored client crypto

`libsodium.js` and `libsodium-wrappers.js` are the browser builds from
`libsodium` and `libsodium-wrappers` 0.8.4, published by the libsodium.js
project under the ISC licence (see `LICENSE.libsodium`). They implement the
X25519 and XChaCha20-Poly1305 primitives used by `../e2e.js`; the wire format is
compatible with `openwarp-crypto`.

The console loads them with subresource integrity attributes in `../ui.rs`. The
Node test `../../tests/vendor-integrity.test.cjs` pins their SHA-256 hashes, and
CI runs it.

To update:

```bash
npm pack libsodium@0.8.4 libsodium-wrappers@0.8.4
tar -xzf libsodium-0.8.4.tgz
tar -xzf libsodium-wrappers-0.8.4.tgz
cp package/dist/modules/libsodium.js ../vendor/libsodium.js
cp package/dist/modules/libsodium-wrappers.js ../vendor/libsodium-wrappers.js
sha256sum ../vendor/libsodium*.js
openssl dgst -sha384 -binary ../vendor/libsodium.js | openssl base64 -A
openssl dgst -sha384 -binary ../vendor/libsodium-wrappers.js | openssl base64 -A
```

Then update the expected hashes in `../../tests/vendor-integrity.test.cjs` and
the integrity attributes in `../ui.rs`.

The browser API expects the core script first (it sets `libsodium`) and the
wrappers second (they set `sodium`). `e2e.js` awaits `sodium.ready` before using
any primitive.
