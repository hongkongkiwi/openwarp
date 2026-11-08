# OpenWarp patch to keystore-ocsp 1.0.0

Source: the published keystore-ocsp 1.0.0 crate, copied from the local Cargo
registry cache. Upstream: https://github.com/rodroidmods/keystore-rs.
The package declares MIT OR Apache-2.0 in Cargo.toml and Cargo.toml.orig;
those declarations and the upstream README are preserved. The published
crate contains no standalone license files.

`Responder::respond_at` previously constructed `BasicOcspResponseBuilder`
with `new()` before setting the supplied timestamp. That constructor reads
`SystemTime::now()`, which panics on wasm32-unknown-unknown even when the
caller supplied a Workers-compatible clock value.

This patch adds `BasicOcspResponseBuilder::new_at` and uses it in the shared
responder construction path. `new()` retains its current-time behavior.
Explicit-time construction only converts the supplied timestamp; it does
not read the platform clock. Signature generation and verification, request
validation, nonce handling, certificate status, and freshness calculations
are unchanged.

`response::openwarp_tests::explicit_time_builder_preserves_timestamp` checks
the supplied producedAt value. Native compilation alone cannot prove the
absence of a WebAssembly clock panic. The runtime regression check is
`scripts/worker-protocol-smoke.mjs` against a freshly built Worker bundle,
including OpenSSL verification of OCSP good/revoked responses and CRLs.
