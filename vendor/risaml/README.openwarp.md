# OpenWarp patch

Upstream: risaml 0.7.0, MIT license (see LICENSE).

The local patch replaces production wall-clock reads with target-aware helpers. Native builds retain the upstream clock; wasm builds use JavaScript Date, including millisecond precision for SAML timestamps. The patch does not change cryptographic or protocol verification logic.
