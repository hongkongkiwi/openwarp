# risaml

[![crates.io](https://img.shields.io/crates/v/risaml.svg)](https://crates.io/crates/risaml)
[![docs.rs](https://img.shields.io/docsrs/risaml)](https://docs.rs/risaml)
[![MIT licensed](https://img.shields.io/crates/l/risaml)](https://github.com/Rhein-Industries/risaml/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

**Pure-Rust SAML 2.0** Service Provider and Identity Provider support. The
protocol layer uses Rust XML parsing and does not require `libxml2`, `xmlsec1`,
or an OpenSSL build chain. XML cryptography (XML-DSig, XML-Enc, C14N, detached
message signatures) is delegated to
[`ribergshamra`](https://github.com/Rhein-Industries/ribergshamra), using the
[`riptering`](https://github.com/Rhein-Industries/riptering) crypto providers.
The default `crypto-ribergshamra` feature selects RustCrypto and preserves the
historical optional algorithm and PKCS#11 capabilities.

```toml
[dependencies]
risaml = "0.7"

# Crypto-free protocol layer only:
# risaml = { version = "0.7", default-features = false }
```

The Rust import path is `risaml`.

## Upgrading

`risaml` is currently pre-1.0, so minor releases may contain breaking API or
behavior changes. Before updating across minor versions, review the
[migration guides](docs/migrations/README.md).

## Why risaml?

`risaml` is aimed at applications that need SAML SP/IdP flows without a C XML
security stack in their build and deployment environment.

| Area | risaml |
|------|---------|
| Native dependencies | No `libxml2`, `xmlsec1`, or OpenSSL build chain for the protocol layer |
| Roles | Service Provider and Identity Provider |
| Bindings | HTTP-POST, HTTP-Redirect, HTTP-POST-SimpleSign |
| Metadata | Parse and generate SP/IdP metadata; verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` / `LogoutResponse` |
| Crypto | XML-DSig, XML-Enc, detached signatures via `ribergshamra` |
| Hardening | Request correlation, audience/destination/issuer checks, XSW guards, bounded parsing |
| Unsafe code | `#![forbid(unsafe_code)]` |

Compared with [`samael`](https://crates.io/crates/samael), the main tradeoff is
deployment shape: `samael` is the established Rust SAML crate and commonly uses
the native `xmlsec` stack, while `risaml` keeps the SAML protocol path
Rust-only and delegates XML crypto to a Rust crate.

## What you can do

| Area | Highlights |
|------|------------|
| Web SSO | Signed `AuthnRequest` / `Response`, HTTP-POST, HTTP-Redirect, POST-SimpleSign |
| Metadata | Parse peer metadata, generate SP/IdP descriptors, verify signed aggregates |
| Single Logout | Create and parse logout request/response flows across all three bindings |
| Validation | Issuer, audience, destination/recipient, bearer confirmation, status, time windows, request correlation |
| Crypto | XML-DSig sign/verify, XML-Enc encrypt/decrypt, detached message signatures, metadata key pinning |
| Extraction | `quick-xml` DOM plus local-name field extraction |

### Unsupported SAML profiles

The high-level `Saml` API currently focuses on browser Web SSO, metadata-driven
SP/IdP setup, XML signature/encryption through `ribergshamra`, and Single Logout.
It does not yet implement Artifact resolution, SOAP/back-channel profiles,
ECP/PAOS, SAML query protocols, NameID management, or metadata federation. If
you need one of those profiles for a real interoperability target, please open
an issue with the profile, binding, IdP/SP product, and a minimal expected flow
so we can consider the implementation.

## Quick Start

The primary API is the typed `Saml` facade. Build local SP/IdP configuration
with `SpConfig::builder` and `IdpConfig::builder`, import peer metadata into
typed descriptors, and keep the returned `Pending<_>` value with your browser
session while the SAML round trip is in flight.

### Runnable typed SSO

A signed SP -> IdP -> SP round trip is available as an executable example:

```sh
cargo run -p risaml --example sso
```

Source: [`examples/sso.rs`](examples/sso.rs).

The repository also includes a typed Single Logout walkthrough in
[`examples/slo.rs`](examples/slo.rs) and a low-level compatibility walkthrough
in [`examples/raw_compat.rs`](examples/raw_compat.rs).

The [crate-root docs](https://docs.rs/risaml/latest/risaml/) contain
doctested fragments for the typed `Saml` facade, including
[`Saml<Sp>::start_sso`](https://docs.rs/risaml/latest/risaml/struct.Saml.html#method.start_sso),
[`Saml<Sp>::finish_sso`](https://docs.rs/risaml/latest/risaml/struct.Saml.html#method.finish_sso),
[`Saml<Idp>::receive_sso`](https://docs.rs/risaml/latest/risaml/struct.Saml.html#method.receive_sso),
and [`Saml<Sp>::finish_slo`](https://docs.rs/risaml/latest/risaml/struct.Saml.html#method.finish_slo).
Those rustdoc snippets are compiled by `cargo test --doc`; the README stays as
an entry point and links to the complete examples above.

### Service Provider SSO flow

1. Build local SP state with `SpConfig::builder` and `Saml::sp`.
2. Import peer IdP metadata into `IdpDescriptor`.
3. Start SSO with `sp.start_sso(...)` and store `started.pending` with the
   browser session.
4. In the ACS handler, pass the posted response fields and the matching pending
   value to `sp.finish_sso(...)`.

See [`examples/sso.rs`](examples/sso.rs) for a complete signed SP -> IdP -> SP
round trip and the [doctested crate-root SSO
fragment](https://docs.rs/risaml/latest/risaml/#sp-initiated-sso) for the
compact API shape.

Typed SSO and SP-initiated SLO pending requests expire after five minutes by
default. `StartSso::pending_lifetime` and `StartSlo::pending_lifetime` set a
named local correlation lifetime; IdP-initiated SLO defaults to its generated
wire expiration, which a local lifetime can shorten. Completion always checks
the stored expiry against the caller's validation clock. `RequireCache` also
atomically records a separate completed request ID until that expiry, rejecting
a second completion even when a peer issues a different valid response.
Persist the expiry when restoring snapshots. Replay-disabled compatibility
still requires the application to atomically consume browser-bound pending
state, and must not be used for assertions carrying `OneTimeUse`.

### Identity Provider - receive and respond

The IdP side mirrors the SP flow: import peer SP metadata into `SpDescriptor`,
parse an `AuthnRequest` with `idp.receive_sso(...)`, then produce a typed
browser response with `idp.respond_sso(...)`. The complete path is exercised in
[`examples/sso.rs`](examples/sso.rs), and the short rustdoc version is in the
[Identity Provider flows](https://docs.rs/risaml/latest/risaml/#identity-provider-flows)
crate-root section.

`IdpConfig::builder(...).issuance_lifetime(Duration)` controls the shared
issuance window for typed IdP output. One captured UTC `IssueInstant` derives both
SSO `Conditions@NotOnOrAfter` and bearer
`SubjectConfirmationData@NotOnOrAfter`. The default is exactly five minutes;
that duration is risaml policy, not an OASIS requirement.

### Single Logout

Typed Single Logout starts from `session.logout_subject()`, stores the
`PendingLogoutRequest`, and finishes only with the matching `LogoutResponse`.
Peer-initiated logout uses `Received<LogoutRequest>` rather than free-form
request ID strings. See [`examples/slo.rs`](examples/slo.rs) for the complete
typed walkthrough and the [doctested SLO
fragment](https://docs.rs/risaml/latest/risaml/#single-logout) for the compact
shape.

`Saml<Idp>::start_slo` models the local IdP as the SAML Session Authority and
always emits a UTC `LogoutRequest@NotOnOrAfter` derived from the same
`IdpConfig::issuance_lifetime` and captured `IssueInstant`. The exact values
are persisted in `PendingLogoutRequest`. Custom typed IdP LogoutRequest
templates must place `NotOnOrAfter="{NotOnOrAfter}"` as one unqualified root
attribute so the library can validate and sign the final value. Typed
`Saml<Sp>::start_slo` does not synthesize this role-specific attribute.

Inbound `LogoutRequest` messages require a UTC `IssueInstant`; risaml does not
invent a maximum age for it. Generic inbound `NotOnOrAfter` remains optional
under the protocol schema and is not rejected merely because a
Session-Authority producer rule would require it on a narrower outbound flow.
When present it must be UTC, and risaml rejects the request at its effective exclusive
deadline. That fail-closed rejection is a library policy permitted by SAML,
not an OASIS receiver `MUST`. `ClockSkew` controls the `NotOnOrAfter` tolerance,
and replay storage uses the same skew-adjusted deadline instead of generic
retention when the attribute is present.

### Metadata

Metadata trust is explicit. The rustdoc
[Metadata trust](https://docs.rs/risaml/latest/risaml/#metadata-trust)
section describes production-shaped signed metadata validation with pinned
certificates. `MetadataTrustPolicy::UnsignedForCompatibility` is available for
legacy interoperability, but it is a compatibility exception rather than a
production default.

Imports retain `validUntil` from the entity and selected SP/IdP role. Each
typed and raw browser-flow use checks that deadline; signature trust never
extends metadata validity. `Metadata::validate_at` supports manual consumers
and refresh managers. Aggregate `EntitiesDescriptor` imports remain unsupported
and fail closed so parent expiration cannot be discarded. Refresh scheduling
and `cacheDuration` are application concerns, distinct from hard validity.
Signing-only and encryption-only metadata keys keep their declared purpose,
including a sole key; keys without `use` serve both purposes. Role imports
never borrow another role's keys or endpoints.

Unknown assertion Conditions fail closed. `OneTimeUse` requires a replay
cache and immediate use of the assertion; retained assertion data must not be
reused for later decisions. `ProxyRestriction` is understood as a restriction
on subsequent assertion issuance, not an extra login audience restriction.
`SsoSession::proxy_restriction_xml` exposes it for applications implementing
proxy issuance; the built-in SSO consumer does not reissue session assertions.

The compact rustdoc flow snippets use
`ReplayPolicy::DisabledForCompatibility` only to keep examples dependency-free.
Production inbound validation should use `ReplayPolicy::RequireCache` with a
caller-owned replay cache and the retention guidance in
[`SamlValidationContext`](https://docs.rs/risaml/latest/risaml/struct.SamlValidationContext.html).

### Advanced/raw compatibility

The low-level compatibility API remains available under `risaml::raw` for
callers that need direct access to `ServiceProvider`, `IdentityProvider`,
`HttpRequest`, `BindingContext`, or protocol helper functions. New browser
SSO/SLO integrations should start with `Saml`, typed descriptors, and the
builder-backed config types shown above.
Public raw `create_logout_request*` helpers retain their compatibility output:
they do not synthesize `NotOnOrAfter`, and the public
`LOGOUT_REQUEST_TEMPLATE` remains unchanged.
Use visible docs.rs modules, crate-root re-exports, and `risaml::raw` before
reaching for hidden lower-level module paths.

## Features

```toml
[features]
default = ["crypto-ribergshamra"]
crypto-ribergshamra = [
    "crypto-rustcrypto",
    "crypto-legacy-algorithms",
    "crypto-post-quantum",
    "crypto-pkcs11",
]
crypto-bergshamra = ["crypto-ribergshamra"]  # compatibility alias
crypto-rustcrypto = ["dep:ribergshamra", "ribergshamra/rustcrypto"]
crypto-aws-lc = ["dep:ribergshamra", "ribergshamra/aws-lc"]
crypto-fips = ["dep:ribergshamra", "ribergshamra/fips"]
crypto-legacy-algorithms = ["ribergshamra?/legacy-algorithms"]
crypto-legacy-rsa-decryption = ["ribergshamra?/legacy-rsa-decryption"]
crypto-post-quantum = ["ribergshamra?/post-quantum"]
crypto-pkcs11 = ["ribergshamra?/pkcs11"]
```

`crypto-bergshamra` is a compatibility alias for `crypto-ribergshamra`, kept so
that feature selections written for the bergshamra-based releases keep
working. New configurations should name `crypto-ribergshamra` or select a
provider directly.

With `default-features = false`, the protocol layer still builds messages,
parses metadata, and runs extraction. Operations that need signing,
verification, or encryption return `SamlError::Unsupported`.

risaml requires Rust 1.88. Select at most one of `crypto-rustcrypto`,
`crypto-aws-lc`, and `crypto-fips`; provider combinations are rejected at
compile time. Disable default features before selecting AWS-LC or FIPS.

`crypto-legacy-algorithms`, `crypto-post-quantum`, and `crypto-pkcs11` forward
those ribergshamra capabilities without selecting a provider. The default
`crypto-ribergshamra` feature enables them with RustCrypto to preserve existing
behavior; direct provider selection starts with only that provider's baseline.
Without `crypto-legacy-algorithms`, and always with AWS-LC or FIPS, riptering
rejects RSA keys shorter than 2048 bits.

`crypto-legacy-rsa-decryption` is a separate, off-by-default compatibility
exception for the unresolved RustCrypto RSA private-decryption timing advisory.
Neither `crypto-legacy-algorithms` nor the default feature enables it. To retain
RustCrypto RSA-OAEP assertion decryption, explicitly select this Cargo feature
and the existing `XmlEncryptionPolicy` software-RSA risk option (or its raw
equivalent). The runtime option alone now propagates `SamlError::Crypto` from
the disabled backend; default runtime policy still returns `Unsupported`.
The exception does not fix RUSTSEC-2023-0071. RSA encryption, signing and
verification remain available, and the accepted compatibility wire format is
unchanged. Non-FIPS AWS-LC decryption is unaffected; FIPS approval restrictions
remain in force.

The dependency minimum is `ribergshamra` 0.11.0, which uses `riptering` 0.7
and exposes `legacy-rsa-decryption`. Refresh consumer lockfiles when upgrading;
applications that depend directly on these crates must use matching release
lines. CI validates the published registry graph with `--locked`.

ribergshamra supports AWS-LC and FIPS on Linux x86_64/aarch64. The `risaml`
provider matrix currently validates Linux x86_64; Linux aarch64 is an upstream
capability that this repository does not exercise in CI. `risaml` initializes
ribergshamra before its first crypto operation. Applications can fail early and
inspect the result during startup:

```rust
use risaml::{initialize_crypto_provider, CryptoFipsStatus};

let provider = initialize_crypto_provider()?;
assert_ne!(provider.fips_status(), CryptoFipsStatus::Uninitialized);
# Ok::<(), risaml::SamlError>(())
```

Initialization, attestation, unsupported-algorithm, and key-import failures are
fail-closed and map to `SamlError::Crypto`. `crypto-fips` means that the selected
AWS-LC provider actively attested FIPS mode; it does not claim that a consuming
binary or deployment is FIPS certified. FIPS policy rejects algorithms outside
its approved set, including the currently exposed SHA-1-based
`RSA_OAEP_MGF1P` XML-Enc key transport. ribergshamra's AWS-LC providers reject
signing with `RSA_SHA1`. The FIPS provider also rejects verifying `RSA_SHA1`;
non-FIPS AWS-LC still verifies inbound RSA-SHA1 Redirect and XML-DSig
signatures. AWS-LC has a narrower capability set than RustCrypto; consult
ribergshamra's
[provider-capability documentation](https://github.com/Rhein-Industries/ribergshamra/blob/main/docs/provider-capabilities.md)
before enabling custom algorithm URIs.

With `crypto-ribergshamra` enabled:

- XML signatures can be verified against metadata-declared keys.
- Signed-reference placement checks help mitigate XML Signature Wrapping (XSW).
- XML-Enc support is available. On the default RustCrypto provider, software
  RSA key-transport decryption is gated off by default and requires an
  explicit `crypto-legacy-rsa-decryption` feature and runtime opt-in through
  [`XmlEncryptionPolicy`](https://docs.rs/risaml/latest/risaml/struct.XmlEncryptionPolicy.html).
  AWS-LC decrypts RSA-OAEP with the default options.

## Security

Report security problems privately as described in [SECURITY.md](SECURITY.md);
do not open a public issue.

`risaml` is pre-1.0 and has not had an external security audit. Review the
crate, configuration, and peer metadata trust model before production use.

Security-sensitive defaults and checks include:

- `#![forbid(unsafe_code)]` on the crate root.
- DOCTYPE / XXE rejection and bounded XML parsing before authentication.
- XML escaping for generated templates, metadata endpoint locations, and SAML
  attribute values.
- Response validation for issuer, SAML status, assertion time window, audience,
  destination/recipient, bearer subject confirmation, and `InResponseTo`.
- Logout validation for issuer and request/response correlation.
- Signed metadata verification with root coverage requirements.
- AuthnRequest root-signature coverage when signed requests are required.
- Detached Redirect/SimpleSign signatures bound to the fields consumed by the
  flow parser.
- HTTP-Redirect raw DEFLATE output limits.
- XML-Enc software RSA key-transport decryption disabled by default on
  RustCrypto because that backend, reached through `ribergshamra` / `riptering`,
  is affected by RUSTSEC-2023-0071. AWS-LC and FIPS do not apply this gate.
  The separate compile-time exception and runtime risk policy are both required
  for RustCrypto decryption.

Schema validation is optional defense in depth via
`context::set_schema_validator`.

## Development

Report bugs and feature requests in
[GitHub Issues](https://github.com/Rhein-Industries/risaml/issues).

```sh
cargo fmt --all --check
cargo clippy -p risaml --all-targets -- -D warnings
cargo nextest run -p risaml
cargo test -p risaml --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p risaml --lib --no-deps
cargo test -p risaml --doc --no-default-features
cargo check -p risaml --no-default-features
cargo nextest run -p risaml --no-default-features --features crypto-rustcrypto
# AWS-LC/FIPS checks run on supported Linux runners; see .github/workflows/ci.yml.
```

## Compatibility and migration

Compatibility notes for applications moving from saml-rs 0.5.0.

- **Names.** The crate is `risaml` (`use risaml::...`, `cargo run -p risaml`).
  The compatibility re-export crates (`opensaml`, `samlify`,
  `rustsaml`, `samlet`) are not included. Public modules and
  all SAML protocol constants (URNs, namespaces, bindings, NameID formats,
  status codes) are unchanged.
- **XML security.** [ribergshamra](https://github.com/Rhein-Industries/ribergshamra)
  0.11 replaces bergshamra 0.8 and
  [riptering](https://github.com/Rhein-Industries/riptering) 0.7 replaces
  kryptering 0.5, so `Key`, `KeysManager` and the other re-exported XML
  security types come from ribergshamra. The default feature is now called
  `crypto-ribergshamra`; `crypto-bergshamra` remains as an alias for it, and
  the provider and capability features keep their names.
- **Software RSA key size.** The default RustCrypto software configuration
  retains historical RSA key sizes with `crypto-legacy-algorithms`. Without
  that feature, RustCrypto rejects RSA keys shorter than 2048 bits, as AWS-LC
  and FIPS already did. PKCS#11 has a separate key-admission policy described
  in the [migration guide](docs/migrations/0.6-to-0.7.md).
- **Project.** Package metadata points at
  <https://github.com/Rhein-Industries/risaml>; CI runs on GitHub-hosted
  runners and publishing is manual (the upstream release-plz automation is
  not used).

The full list is in the [changelog](CHANGELOG.md).

### Migrating from saml-rs

```toml
[dependencies]
risaml = "0.7"
# or keep the `saml_rs::` paths in your code:
# saml-rs = { package = "risaml", version = "0.7" }
```

With the plain `risaml` dependency, replace `saml_rs::` with `risaml::`.
Replace `crypto-bergshamra` with `crypto-ribergshamra` in feature lists (the
old name keeps working). Code that names bergshamra types next to risaml's
API, for example the `Key` returned by `load_private_key`, switches to
`ribergshamra::`. The [0.5 to 0.6 guide](docs/migrations/0.5-to-0.6.md) covers
the initial crate rename; then apply the
[0.6 to 0.7 guide](docs/migrations/0.6-to-0.7.md) for security policy changes.
Review the [XML processing limits](https://github.com/Rhein-Industries/ribergshamra/blob/v0.11.0/docs/security-limits.md)
when upgrading: the delegated XML backend applies fixed resource budgets and
corrected canonicalization and CRL policies.

## License

[MIT](LICENSE).[^history]

[^history]: Started from [saml-rs](https://github.com/salasebas/opensaml-rs) by [Sebastian Sala](https://github.com/salasebas), version 0.5.0 (tag `v0.5.0`, commit `9302371`).
