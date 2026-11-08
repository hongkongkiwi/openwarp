# Changelog

risaml is Rhein Industries' maintained fork of
[saml-rs](https://github.com/salasebas/opensaml-rs) by Sebastian Sala. Entries
from 0.6.0 on describe risaml. The history of saml-rs up to 0.5.0, the release
risaml was forked from, is kept unchanged below.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

## 0.7.0 — 2026-09-26

### Changed

- **Breaking:** require ribergshamra 0.11.0 on riptering 0.7 and ritsp-ltv 0.6.
  Consumers that name XML security types directly must update their matching
  dependencies. The MSRV remains Rust 1.88. The release intentionally tightens
  security acceptance and the software RSA decryption default; see the
  [0.6 to 0.7 migration guide](docs/migrations/0.6-to-0.7.md).

### Fixed

- Disable RustCrypto RSA key-transport decryption in the backend by default.
  Restoring it requires the separate `crypto-legacy-rsa-decryption` feature and
  the existing explicit runtime risk option; `crypto-legacy-algorithms` does
  not enable it. This is an exception for unresolved RUSTSEC-2023-0071, not a
  timing fix. Encryption/signatures, AWS-LC policy and wire formats are unchanged.
- Reject unsupported assertion Conditions instead of treating indeterminate
  conditions as valid. Recognize OneTimeUse and ProxyRestriction separately;
  typed OneTimeUse processing requires assertion replay storage.
- Retain entity and imported role metadata `validUntil`, and enforce it at
  inbound/outbound use after storage. Role-specific imports isolate SP/IdP
  certificates and endpoints, and honor each key's signing/encryption purpose.
- Bound typed pending SSO and SP-initiated SLO requests to five minutes by
  default, with named `pending_lifetime` options. IdP-initiated SLO retains its
  generated wire deadline unless explicitly shortened. Enforce pending expiry
  and cache completed request IDs with `RequireCache`; restored cached pending
  requests must carry an expiration.
- Keep qualified XML attributes distinct from unqualified consumed attributes,
  exclude namespace declarations from extraction, and reject SAML signature
  `ds:Object` elements before crypto-provider processing.
- Reject incomplete XML documents and raw-DEFLATE streams while retaining
  existing parser and inflated-output limits.
- Require content-preserving XML signature reference transforms and apply
  same-document reference preflight to nested XML-DSig signatures before
  handing the document to the crypto provider. Filtering and unknown reference
  transforms now fail closed; supported canonicalization transforms remain
  accepted.
- Reject XML-DSig signatures outside the signed message/metadata root or a
  direct Response assertion before signature detection or crypto-provider
  processing, including when no signature is present in an expected position.
- Return validation errors for malformed Unicode certificates and
  unrepresentable clock-skew bounds instead of panicking.
- Apply the existing CBC Response integrity policy to custom AES-192-CBC
  algorithms as well as the other supported CBC algorithms.

### Performance

- Reuse the most recent assertion shortcut DOM during field extraction,
  avoid normalization copies for compact base64 input, and clone only the
  requested first metadata certificate.
- Add a local fixture microbenchmark example for XML parsing and cloning,
  field extraction, binding encoding/decoding, and metadata certificate lookup.

### Validation and packaging

- Run complete default, explicit software RSA exception and crypto-free suites
  on Linux, Windows and macOS, plus Linux RustCrypto, AWS-LC and FIPS provider
  suites. CI and dependency-policy checks use the published, locked graph.
- Include the linked security policy, migration guidance and formatter/Clippy
  configuration in the crate, alongside the existing license and test fixtures.

## 0.6.0 — first risaml release — 2026-09-24

Changes relative to saml-rs 0.5.0 (upstream
tag `v0.5.0`, commit `9302371`):

### Changed

- **Breaking:** the crate is renamed `risaml` (`use risaml::...`,
  `cargo run -p risaml`). Existing code can keep its `saml_rs::` paths with
  `saml-rs = { package = "risaml", version = "0.6" }`. Public types, modules
  and SAML protocol constants (URNs, namespaces, bindings, NameID formats,
  status codes) are unchanged.
- **Breaking:** XML security moves from bergshamra 0.8 (on kryptering 0.5) to
  [ribergshamra](https://github.com/Rhein-Industries/ribergshamra) 0.10 (on
  [riptering](https://github.com/Rhein-Industries/riptering) 0.6 and
  [ritsp-ltv](https://github.com/Rhein-Industries/ritsp-ltv) 0.5), so `Key`,
  `KeysManager` and the other XML security types in risaml's API come from
  ribergshamra. ribergshamra is forked from bergshamra 0.9.1 and parses XML
  with uppsala 0.10; risaml's own XML handling still uses quick-xml.
- The default feature is renamed `crypto-ribergshamra`; `crypto-bergshamra`
  stays as a compatibility alias for it. The provider and capability features
  (`crypto-rustcrypto`, `crypto-aws-lc`, `crypto-fips`,
  `crypto-legacy-algorithms`, `crypto-post-quantum`, `crypto-pkcs11`) keep
  their names and map to ribergshamra's `rustcrypto`, `aws-lc`, `fips`,
  `legacy-algorithms`, `post-quantum` and `pkcs11`.
- With `crypto-rustcrypto` but without `crypto-legacy-algorithms`, riptering
  rejects RSA keys shorter than 2048 bits (AWS-LC and FIPS already did). The
  default features are unaffected.
- The compatibility re-export crates `opensaml`, `samlify`, `rustsaml` and
  `samlet` are not part of the fork.
- Package metadata points at <https://github.com/Rhein-Industries/risaml>;
  LICENSE keeps saml-rs's copyright line and adds Rhein Industries' line. The
  README opens with a fork notice; SECURITY.md and CONTRIBUTING.md describe
  Rhein Industries' reporting and contribution process.
- CI runs on GitHub-hosted runners without repository secrets. The release-plz
  workflow is removed and publishing is manual (see RELEASE.md). The
  cargo-semver-checks job is paused until risaml has a crates.io baseline.

## saml-rs history (upstream, up to 0.5.0)

Entries below are saml-rs's own changelog; they use the package names that
were current at the time.

### [0.5.0](https://github.com/salasebas/opensaml-rs/compare/v0.4.0...v0.5.0) - 2026-08-13

#### Added

- *(crypto)* expose selectable Bergshamra providers ([#110](https://github.com/salasebas/opensaml-rs/pull/110))

#### Other

- *(crypto)* [**breaking**] upgrade Bergshamra to 0.8 and MSRV to Rust 1.88 ([#108](https://github.com/salasebas/opensaml-rs/pull/108))

#### Fixed

- *(crypto)* apply the software RSA key-transport opt-in only to RustCrypto so
  AWS-LC decrypts RSA-OAEP with default options

### [0.4.0](https://github.com/salasebas/opensaml-rs/compare/v0.3.0...v0.4.0) - 2026-08-11

#### Added

- *(api)* [**breaking**] enforce standards-aware Response signature policy ([#81](https://github.com/salasebas/opensaml-rs/pull/81))

#### Fixed

- *(slo)* [**breaking**] emit session authority logout expiration ([#101](https://github.com/salasebas/opensaml-rs/pull/101))
- *(slo)* [**breaking**] validate LogoutRequest time bounds ([#73](https://github.com/salasebas/opensaml-rs/pull/73))
- *(slo)* [**breaking**] reject non-conformant custom LogoutResponse templates ([#91](https://github.com/salasebas/opensaml-rs/pull/91))
- *(sso)* [**breaking**] enforce UTC IssueInstant on responses and assertions ([#90](https://github.com/salasebas/opensaml-rs/pull/90))
- *(slo)* [**breaking**] validate logout response issue instant ([#80](https://github.com/salasebas/opensaml-rs/pull/80))
- *(protocol)* [**breaking**] validate AuthnRequest IssueInstant ([#74](https://github.com/salasebas/opensaml-rs/pull/74))

#### Other

- *(deps)* bump the cargo-maintenance group across 1 directory with 4 updates ([#104](https://github.com/salasebas/opensaml-rs/pull/104))
- *(slo)* add external HTTP-Redirect interoperability fixtures ([#99](https://github.com/salasebas/opensaml-rs/pull/99))
- *(migrations)* start 0.3 to 0.4 guide ([#84](https://github.com/salasebas/opensaml-rs/pull/84))
- *(deps)* bump uuid in the cargo-maintenance group ([#93](https://github.com/salasebas/opensaml-rs/pull/93))

#### Fixed

- *(slo)* [**breaking**] require UTC LogoutRequest `IssueInstant`, validate
  optional `NotOnOrAfter`, and derive replay expiry from its skew-adjusted
  deadline

### [0.3.0](https://github.com/salasebas/opensaml-rs/compare/v0.2.1...v0.3.0) - 2026-07-16

#### Fixed

- *(api)* [**breaking**] avoid exposing time crate types ([#72](https://github.com/salasebas/opensaml-rs/pull/72))

#### Other

- *(migrations)* add 0.2 to 0.3 guide ([#83](https://github.com/salasebas/opensaml-rs/pull/83))

### [0.2.1](https://github.com/salasebas/opensaml-rs/compare/v0.2.0...v0.2.1) - 2026-07-16

#### Added

- *(compat)* restore maintained crate aliases

#### Fixed

- enforce SAML 2.0 namespace and version profile ([#79](https://github.com/salasebas/opensaml-rs/pull/79))
- honor repeated AuthnStatement session bounds ([#71](https://github.com/salasebas/opensaml-rs/pull/71))
- *(security)* preserve SAML audience restriction groups ([#69](https://github.com/salasebas/opensaml-rs/pull/69))
- reject repeated SAML assertion conditions ([#67](https://github.com/salasebas/opensaml-rs/pull/67))
- *(security)* enforce SP assertion signature policy ([#70](https://github.com/salasebas/opensaml-rs/pull/70))
- *(xml)* reject multiple document elements ([#68](https://github.com/salasebas/opensaml-rs/pull/68))

#### Other

- add migration guide structure

#### Added

- *(api)* expose every `AuthnStatement` session tuple in XML order
- *(api)* add `RespondSso::sign_response()` for explicit top-level HTTP-POST Response signing
- *(api)* add an explicit compatibility opt-out for unsigned CBC-encrypted Responses

#### Changed

- *(api)* rename the SP message-signature policy and field to `ResponseSignaturePolicy`/`responses`
- *(sp)* require Response authentication for CBC-encrypted Assertions in strict typed flows
- *(idp)* sign CBC-encrypted Responses by default in typed flows

#### Fixed

- *(sp)* honor the earliest `SessionNotOnOrAfter` across repeated `AuthnStatement` values
- *(security)* enforce explicit required Response signatures against verified root coverage
- *(bindings)* reject authenticated Responses whose required `Destination` is missing
- *(docs)* apply Approved Errata 05 E26/E93 to Web SSO signature guidance

### [0.2.0](https://github.com/salasebas/opensaml-rs/compare/v0.1.4...v0.2.0) - 2026-07-14

#### Added

- *(api)* add typed Single Logout facade ([#59](https://github.com/salasebas/opensaml-rs/pull/59))
- *(api)* add typed Web SSO facade ([#58](https://github.com/salasebas/opensaml-rs/pull/58))
- *(api)* add typed SAML validation context
- *(api)* add typed config builders
- *(api)* refine typed SAML API contracts
- *(api)* add typed SAML browser and result models
- *(api)* add typed SAML binding subsets
- *(api)* add typed SAML configuration policies
- *(api)* add typed Saml facade contract
- *(opensaml)* support idp protocol assertion tag prefixes ([#28](https://github.com/salasebas/opensaml-rs/pull/28))
- *(opensaml)* add authn request options
- *(opensaml)* align IdP metadata ordering behavior
- *(opensaml)* support rsa pss sha256 signatures

#### Fixed

- *(crypto)* preflight SAML reference URIs ([#65](https://github.com/salasebas/opensaml-rs/pull/65))
- *(sp)* fail on missing response ACS metadata
- *(api)* repair typed browser model invariants
- *(deps)* update crypto-bigint to 0.7.5 ([#48](https://github.com/salasebas/opensaml-rs/pull/48))
- *(deps)* upgrade bergshamra to 0.6.3 ([#47](https://github.com/salasebas/opensaml-rs/pull/47))
- *(deps)* upgrade quick-xml to 0.41 ([#43](https://github.com/salasebas/opensaml-rs/pull/43))
- *(opensaml)* include SimpleSign fields in POST forms
- *(opensaml)* render login response attributes structurally
- fix login attribute metadata escaping ([#36](https://github.com/salasebas/opensaml-rs/pull/36))
- reject request-bound unsolicited SSO ([#35](https://github.com/salasebas/opensaml-rs/pull/35))
- fix metadata xml escaping ([#32](https://github.com/salasebas/opensaml-rs/pull/32))
- *(opensaml)* limit redirect base64 decode ([#30](https://github.com/salasebas/opensaml-rs/pull/30))
- *(opensaml)* render optional logout session index
- *(security)* bound XML parsing before authentication
- gate XML-Enc software RSA decryption
- *(opensaml)* escape SAML template values
- *(opensaml)* validate logout request issuer
- *(opensaml)* escape SAML attribute values
- *(opensaml)* validate SAML response destination
- *(opensaml)* require logout response correlation
- *(opensaml)* bind detached SAML signatures to consumed fields
- *(opensaml)* validate bearer subject confirmation
- *(opensaml)* require AuthnRequest root signature coverage
- *(opensaml)* validate AuthnRequest issuer
- *(opensaml)* [**breaking**] limit HTTP-Redirect DEFLATE output
- *(opensaml)* require explicit SAML response correlation
- *(opensaml)* require metadata signature root coverage
- *(security)* bind extracted SAML content to verified reference

#### Other

- *(deps)* bump bergshamra in the cargo-xml-crypto group ([#63](https://github.com/salasebas/opensaml-rs/pull/63))
- split large modules
- document docs.rs publication surface
- *(api)* document the typed Saml facade
- *(api)* verify builder typed user journeys
- [codex] Preserve signed metadata coverage in typed descriptors ([#57](https://github.com/salasebas/opensaml-rs/pull/57))
- *(error)* add semantic SAML validation errors
- [codex] Rebrand workspace as single saml-rs crate
- *(deps)* bump time in the cargo-maintenance group ([#46](https://github.com/salasebas/opensaml-rs/pull/46))
- [codex] split cargo dependency update lanes ([#44](https://github.com/salasebas/opensaml-rs/pull/44))
- *(opensaml)* pin crypto upgrade regressions ([#45](https://github.com/salasebas/opensaml-rs/pull/45))
- [codex] render default login responses structurally ([#42](https://github.com/salasebas/opensaml-rs/pull/42))
- [codex] validate crypto XML template inputs ([#41](https://github.com/salasebas/opensaml-rs/pull/41))
- *(opensaml)* render default logout messages structurally ([#39](https://github.com/salasebas/opensaml-rs/pull/39))
- *(opensaml)* render default authn requests structurally ([#40](https://github.com/salasebas/opensaml-rs/pull/40))
- *(readme)* clarify current SAML profile scope
- *(deps)* bump the github-actions group with 2 updates ([#34](https://github.com/salasebas/opensaml-rs/pull/34))
- *(deps)* bump the cargo-dependencies group with 2 updates ([#33](https://github.com/salasebas/opensaml-rs/pull/33))
- add validated POST binding form variant ([#31](https://github.com/salasebas/opensaml-rs/pull/31))
- update agent guidance ([#29](https://github.com/salasebas/opensaml-rs/pull/29))
- Merge pull request #27 from salasebas/advisor/002-authn-request-options
- remove tracked parity notes
- include agent files in worktrees
- refresh README and upstream samlify reference ([#22](https://github.com/salasebas/opensaml-rs/pull/22))
- fix release-plz push authentication
- add path-based PR labels
- add release-plz workflow

#### Changed

- Renamed the primary package from `opensaml` to `saml-rs`; Rust imports now use
  `saml_rs`.
- Moved implementation code from `crates/opensaml/src` to `src`.
- Renamed `OpenSamlError` to `SamlError`.
- Retired alias crates from active publication; do not yank existing healthy
  alias versions.
- Added typed config builders and direction-specific AuthnRequest policy names;
  builders use strict defaults while constructors/default policy values preserve
  compatibility, and final config validation now covers policy requirements.
- Hardened detailed metadata signature verification so signed metadata evidence
  is exposed through accessors, default-limit detailed wrappers are available,
  and unsafe metadata reference transforms such as XPath/XSLT fail closed before
  descriptor coverage is accepted.

### [0.1.4] - 2026-06-21

#### Changed

- Updated `quick-xml` from 0.37.5 to 0.40.1, `time` from 0.3.47 to
  0.3.49, and `uuid` from 1.23.2 to 1.23.3.
- Pinned GitHub Actions workflow dependencies to immutable commit SHAs and
  disabled checkout credential persistence.
- Added Dependabot cooldown windows for Cargo and GitHub Actions updates.

#### Fixed

- Adapted the internal XML DOM parser to `quick-xml` 0.40 text/reference
  events so predefined and numeric XML entities in element text are preserved.
- Removed the auto-label workflow that used `pull_request_target`, clearing the
  remaining high-severity `zizmor` trigger finding.

### [0.1.3] - 2026-06-20

#### Changed

- Updated `bergshamra` from 0.4.0 to 0.5.1.
- Re-audited the XML security trust-model comment against `bergshamra` 0.5.1
  secure `DsigContext::new()` defaults.
- XSW coverage includes duplicate SAML assertion IDs.

#### Fixed

- Reject duplicate SAML `ID`/`AssertionID` values before trusting an XML-DSig
  verification result.

### [0.1.2] - 2026-06-14

#### Changed

- Alias crate READMEs and crate descriptions simplified.
- Workspace version bump to 0.1.2 (packaging-only for alias crates).

### [0.1.1] - 2026-06-02

#### Added

- `create_logout_request_with_id` / `create_logout_response_with_id` — optional
  caller-provided `LogoutRequest` / `LogoutResponse` IDs.

#### Changed

- Root `README.md` rewrite: Rust-only positioning, opensaml vs samael
  comparison, and sectioned quick-start examples; `opensaml` on crates.io now
  uses that README.
- The published crate ships its `tests/` and `examples/` (packaging only; the
  consumed library is unchanged).

#### Fixed

- XML-escape `Location` attribute values in generated SP/IdP metadata.

### [0.1.0] - 2026-06-01

#### Added

- SAML 2.0 protocol layer to parity with npm `samlify` v2.10.2:
  - Constants (URNs, bindings, status codes, algorithms, NameID formats).
  - XML field extraction engine over `quick-xml` (`local-name()` XPath subset)
    with DOCTYPE hardening, plus the samlify field-sets.
  - Default message templates and tag substitution.
  - Service Provider and Identity Provider metadata parsing and generation.
  - HTTP-POST, HTTP-Redirect and HTTP-POST-SimpleSign message building.
  - `ServiceProvider`/`IdentityProvider` entities, login request/response
    creation and parsing, Single Logout, and the inbound `flow` orchestration
    (status, issuer and time validation).
- `crypto-bergshamra` feature delegating XML cryptography to
  `bergshamra` (**on by default**): key/certificate loading, XML-DSig signing
  and verification with anti-wrapping (XSW) protection, XML-Enc assertion
  encrypt/decrypt, and detached redirect/SimpleSign message signatures.
- `samlify` crate forwards the `crypto-bergshamra` feature.
- Customization to parity with samlify: a `User` subject with attributes wired
  into `IdentityProvider::create_login_response` (via `LoginResponseTemplate`),
  a `customTagReplacement` hook and custom message templates, `SignatureConfig`
  (signature prefix + placement), configurable `transformationAlgorithms`, a
  configurable encrypted-assertion tag prefix, and `SessionIndex` on logout.
- `Metadata::export_metadata` / `get_support_bindings` and `util::verify_fields`.
- Inline-certificate-vs-metadata mismatch is rejected with
  `OpenSamlError::UnmatchCertificate` (samlify rolling-cert safety).
- Conformance test suite ported 1:1 from samlify v2.10.2: all 131 active
  upstream cases (flow 64, index 47, issues 11, extractor 9) reproduced as 132
  Rust tests in `tests/{extractor,issues,index,flow}_conformance.rs`, with the
  upstream key/metadata fixtures. The crate runs 206 tests in total (89 without
  `crypto-bergshamra`); the whole suite passes.
- Security hardening: `<Audience>` restriction validation (`validate_audience`,
  on by default → `UnmatchAudience`), `InResponseTo` binding via
  `ServiceProvider::parse_login_response_with_request_id` (→ `InvalidInResponseTo`),
  metadata signature verification (`crypto::verify_metadata_signature` /
  `Metadata::verify_signature`), and XSW + robustness test suites
  (`tests/{xsw,hardening,robustness}.rs`). Schema validation remains pluggable
  via `context::set_schema_validator` on top of the always-on DOCTYPE rejection.
- Runnable end-to-end example: `cargo run -p opensaml --example sso`.
- Crypto-backend audit (bergshamra 0.4.0): documented the verification trust
  model in `crypto::verify` (signature, digest and XSW position checks always
  run; `insecure` only skips X.509 *chain* validation, irrelevant to the
  metadata key-pinning model; `trusted_keys_only` never imports inline key
  material). Hardening: signed `<Reference>` URIs must be same-document
  (`#id` or whole-document); external/remote/file references are rejected
  (`ERR_EXTERNAL_REFERENCE`).

#### Changed

- `crypto-bergshamra` is now enabled by default; disable with
  `default-features = false` for the crypto-free protocol layer (operations
  requiring signing, verification or encryption then fail closed with
  `OpenSamlError::Unsupported`).
- Reworked the crate from SP-only stubs to full SP + IdP.
- Signature verification tries each metadata-declared certificate individually,
  so signatures verify against any current key (rolling-certificate support).
- When encrypting, the IdP always signs the message *after* encryption (sound
  encrypt-then-sign); signing the message then encrypting a sub-element would
  invalidate the outer signature.

#### Fixed

- Decryption strips a leading XML declaration from the recovered assertion so
  it can be re-parsed in place during the inbound flow.
