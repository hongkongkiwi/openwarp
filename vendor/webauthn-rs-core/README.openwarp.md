# OpenWarp patch

Upstream: webauthn-rs-core 0.6.2, MPL-2.0 license as declared in Cargo.toml. The cached upstream package did not include a license file.

The local patch replaces the two production attestation wall-clock reads with a target-aware helper. Native builds retain the upstream clock; wasm builds use JavaScript Date. The patch does not change cryptographic or protocol verification logic.
