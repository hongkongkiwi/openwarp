# Vendored browser libraries

## zxcvbn 4.4.2

`zxcvbn.js` is the unchanged prebuilt `dist/zxcvbn.js` from
https://github.com/dropbox/zxcvbn, MIT licensed (`LICENSE.zxcvbn`).
Tag `v4.4.2` resolves to commit `f0735425180b130d6c57efbc044a47c0c8f1fd65`.
Downloaded on 2026-11-07 without executing package scripts:

- https://raw.githubusercontent.com/dropbox/zxcvbn/v4.4.2/dist/zxcvbn.js
- https://raw.githubusercontent.com/dropbox/zxcvbn/v4.4.2/LICENSE.txt

SHA-256:

- `zxcvbn.js`: `6677fc15d245f397f52d5d0998f3a86f9aae752ae7b3ca4b3d9eaa91dffe174a`
- `LICENSE.zxcvbn`: `8fd6c9ffe44291acd207a4d3cf7d6db5ac05f585ee1cf45db9fc6b153b08990f`

Updates must pin a new upstream commit, copy the published build and license
unchanged, and update these digests, the integrity test and console SRI.
No package install or frontend build is needed at runtime.

## hash-wasm 4.13.0

`hash-wasm.js` is the unchanged published `dist/index.umd.min.js`; its embedded
WebAssembly supplies MD5, SHA-1/SHA-2 and Argon2d for local Enzoic pair checks.
The console loads this same-origin UMD build with SHA-384 SRI. It does not use a
CDN or package installation. MIT license: `LICENSE.hash-wasm`.

Source: https://github.com/Daninet/hash-wasm/tree/867bb9764fbff6dc4808a54f40e3249f474678f9
(tag `v4.13.0`). Downloaded 2026-11-08 from
https://registry.npmjs.org/hash-wasm/-/hash-wasm-4.13.0.tgz into an isolated
empty directory, with only the build, license and reference text extracted.
No package scripts were executed. Package SHA-512 (base64), verified against
npm registry metadata:
`GrWl7wsV46fKIXQZB5ebskLZLAmKL6d9RS0fspCxDeQyjoNu1AfTJTMLPOJyfzaQm0ldFiwFN21/w+sE/kgEFQ==`.

SHA-256:

- `hash-wasm.js`: `b43a59e36eafcb2f744eb23badd590ca23c7dad54fb0395522cec6fb85a6582c`
- `LICENSE.hash-wasm`: `c14dea172f72f2714284a0ac2ab1b00b5352a01409d58255a46227ffc541debd`

Updates must preserve the published bytes and update the pins, SRI and real
primitive vectors. `argon2d(options)` accepts `iterations`, `memorySize` in KiB,
`parallelism`, `hashLength` in bytes and `outputType:'hex'`; the Enzoic protocol
uses 3, 1024, 2 and 20 respectively. The options' `type` field is for the test
injection contract; calling `argon2d`, rather than that field, selects the
real implementation. Salts are plain UTF-8, not encoded Argon2 configuration.

## Client crypto

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
