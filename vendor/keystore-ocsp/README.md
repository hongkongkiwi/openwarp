<div align="center">

# 🔐 keystore-rs

**The Java keystore stack and the Bouncy Castle 1.85 surface — rewritten in pure Rust.**

<sub>No JVM · No OpenSSL · No C or assembly · No `unsafe`</sub>

<br>

<a href="https://github.com/rodroidmods/keystore-rs/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/rodroidmods/keystore-rs/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://crates.io/crates/keystore"><img alt="crates.io" src="https://img.shields.io/crates/v/keystore.svg"></a>
<a href="https://docs.rs/keystore"><img alt="docs.rs" src="https://docs.rs/keystore/badge.svg"></a>
<img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.89-blue.svg">
<img alt="unsafe forbidden" src="https://img.shields.io/badge/unsafe-forbidden-success.svg">
<img alt="tests" src="https://img.shields.io/badge/tests-1%2C379%20passing-brightgreen.svg">
<a href="#-license"><img alt="license" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg"></a>
<a href="https://t.me/+WmudnO0-xoNhMDQ8"><img alt="Telegram" src="https://img.shields.io/badge/Telegram-Join%20the%20channel-2CA5E0?logo=telegram&logoColor=white"></a>

<br>

[Install](#-install) · [Quick start](#-quick-start) · [Formats](#-supported-keystore-formats) · [Workspace](#-workspace) · [CLI](#-command-line) · [Coverage](docs/PORT_STATUS.md)

<br>

### Made by **Rodroid Mods**

[![Telegram](https://img.shields.io/badge/Join%20us%20on%20Telegram-%2BWmudnO0--xoNhMDQ8-2CA5E0?logo=telegram&logoColor=white)](https://t.me/+WmudnO0-xoNhMDQ8)

</div>

---

## ✨ What this is

A pure-Rust implementation of the Java keystore stack **and** the Bouncy Castle
1.85 feature surface built around it: X.509, CMS, OCSP, TSP, CMP, EST, CRMF,
standardized post-quantum crypto, HPKE/FPE/PAKE/BLS, TLS, OpenPGP and S/MIME.

The only platform dependency is the operating system random source. The goal is
behavioural parity, not a lookalike:

> keystores written here open in `keytool`, keystores written by `keytool` or
> Bouncy Castle open here, and the deterministic formats survive a load/store
> cycle **byte for byte**.

| | |
|---|---|
| 🗂️ **Formats** | JKS, CaseExactJKS, JCEKS, PKCS#12, BKS v1/v2, UBER, BCFKS, DKS |
| 🔏 **Algorithms** | RSA, ECDSA (P-256/384/521, secp256k1, brainpool), DSA, Ed25519, Ed448, X25519, X448 |
| 🧬 **Post-quantum** | ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS/HSS, HQC, Falcon/FN-DSA |
| 📜 **PKI** | X.509 v3 builders, PKCS#10, CRLs, RFC 5280 path validation, attribute certificates |
| 📨 **Protocols** | CMS/PKCS#7, OCSP, TSP, CMP/CRMF/CMC, EST, S/MIME |
| 🌐 **Ecosystem** | rustls identities and resolvers, Sequoia OpenPGP |
| 🖥️ **CLI** | `keytool`-compatible binary, including APK signing workflows |
| 🛡️ **Safety** | `#![forbid(unsafe_code)]` across the workspace |

## 📊 Status

| | |
|---|---|
| ✅ **Keystore formats** | Production-grade and byte-compatible where the format is deterministic, with JDK/Bouncy Castle corpus fixtures and Java oracles. |
| ✅ **Bouncy Castle surface** | Every class in the targeted surface is covered — 462,180 of the 836,820 classified Java lines (55.2% of all source, 75.8% of the useful non-plumbing surface). The last pending groups, SLH-DSA, `cert.selector` and `asn1.misc`, are ported. |
| ✅ **Verification** | 1,379 tests, 0 failures in the release workspace suite; the 10 ignored cases are doctest examples that need external fixtures. |
| ✅ **Gates** | Clippy and rustdoc run with `-D warnings`; MSRV 1.89; `cargo fmt` clean. |
| ⚠️ **Assurance** | Not an audited cryptographic product. Read the [security notes](#-security-notes) before using the newer layers in high-assurance systems. |

Full measurement, feature matrix and known gaps: [`docs/PORT_STATUS.md`](docs/PORT_STATUS.md).

## 📦 Install

```sh
cargo add keystore            # library, formats only by default
cargo install keystore-cli    # the `keystore` keytool-compatible binary
```

Rust edition 2024; Rust **1.89** or newer (the practical floor set by
`rasn-derive`'s `uuid` and the optional pure-Rust TLS provider).

`keystore` has a **lean default**: depending on it compiles only the format
crates (`keystore-core`, `keystore-jks`, `keystore-pkcs12`, `keystore-bc`) and
`AnyStore`. Everything else is opt-in:

```toml
[dependencies]
keystore = { version = "1.0", features = ["x509", "cms", "pqc"] }

# or everything
keystore = { version = "1.0", features = ["full"] }
```

<details>
<summary><b>Feature matrix</b> — click to expand</summary>

<br>

| Feature | Enables |
|---|---|
| `keystores` (default) | JKS, JCEKS, PKCS#12, BKS, UBER, BCFKS, DKS and `AnyStore` |
| `pki` | RSA/ECDSA/DSA/EdDSA keys, signatures, PKCS#10 and CRL handling |
| `x509` | X.500 names, v3 certificate/CSR/CRL builders, extensions, RFC 5280 validation |
| `cms` | CMS/PKCS#7, BER, S/MIME structures, AuthenticatedData, AuthEnvelopedData, KEMRI |
| `ocsp` | OCSP requests, responses, responder and verifier |
| `tsp` | RFC 3161 timestamps and ERS |
| `cmp` | CMP, CRMF and CMC |
| `est` | RFC 7030 EST transport and operations |
| `pqc` | ML-KEM, ML-DSA and XMSS |
| `lms` | LMS/HSS (RFC 8554 / SP 800-208 / RFC 9802) |
| `crypto` | Bouncy Castle breadth ciphers, hashes, MACs, modes and KDFs |
| `crypto-extra` | HPKE, FF1/FF3 FPE, SPAKE2, SRP-6a, J-PAKE, EC-JPAKE, OWL and BLS12-381 |
| `pqc-extra` | HQC KEM and Falcon/FN-DSA |
| `asn1-extra` | DVCS, EAC, ISISMt, ICAO, Netscape and vendor ASN.1 modules |
| `tls` | rustls bridge with bundled `webpki-roots` |
| `tls-rustcrypto` | `tls` plus the pure-Rust `oxitls-rustcrypto-provider` |
| `openpgp` | Sequoia OpenPGP with the RustCrypto backend |
| `mail` | MIME parsing and the S/MIME bridge |

</details>

The facade re-exports each crate under its feature name: `keystore::x509`,
`keystore::cms`, `keystore::ocsp`, `keystore::tsp`, `keystore::cmp`,
`keystore::est`, `keystore::pqc`, `keystore::crypto_extra`, and so on.
`keystore::tls_crypto_provider()` returns the pure-Rust rustls provider.

## 🚀 Quick start

```rust
use keystore::{AnyStore, Format, KeyStore, Password, Result};

fn main() -> Result<()> {
    let password = Password::new("changeit");

    // Read whatever the file is; the format is detected from the bytes.
    let store = AnyStore::open_file("store.jks", &password)?;

    // Semantic view: aliases, key material, chains, creation dates.
    let view: KeyStore = store.to_key_store();
    for alias in view.aliases() {
        println!("{alias}: {:?}", view.get(alias).map(|e| e.kind()));
    }

    // Convert, re-protecting every key with the new password.
    let p12 = store.convert_to(Format::Pkcs12, &password)?;
    p12.save_file("store.p12", &password)?;
    Ok(())
}
```

Each format crate is usable on its own when the lossless representation
matters — `Jks`, `Jceks`, `Pkcs12Store`, `BksStore`, `UberStore` and
`BcfksStore` all expose the stored entries, their timestamps and their protected
blobs, and `unlock` recovers a key sealed with a per-entry password.

<details>
<summary><b>Build a v3 certificate and write it into a PKCS#12 store</b> — click to expand</summary>

<br>

```rust
use std::str::FromStr;

use keystore::pki::{ext, generate_curve, Curve, SignatureAlgorithm};
use keystore::x509::builder::{CertificateBuilder, KeystoreSigner};
use keystore::x509::der::asn1::UtcTime;
use keystore::x509::der::{DateTime, Decode, Encode};
use keystore::x509::x509_cert::ext::Extension;
use keystore::x509::x509_cert::name::Name;
use keystore::x509::x509_cert::serial_number::SerialNumber;
use keystore::x509::x509_cert::spki::SubjectPublicKeyInfoOwned;
use keystore::x509::x509_cert::time::Time;
use keystore::{
    AnyStore, Certificate, Entry, Format, KeyStore, Password, PrivateKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = generate_curve(Curve::P256)?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&key.public_key_spki)?;
    let signer = KeystoreSigner::from_pkcs8(
        SignatureAlgorithm::Sha256WithEcdsa,
        &key.private_key_pkcs8,
    )?;
    let name = Name::from_str("CN=demo.example,O=Example")?;

    let mut specs = ext::Extensions::new();
    ext::parse_spec("BC=critical,ca:false", &mut specs)?;
    ext::parse_spec("SAN=dns:demo.example", &mut specs)?;
    let mut extensions = Vec::new();
    for spec in specs.iter() {
        extensions.push(Extension::from_der(&spec.der())?);
    }

    let utc = |year: u16| -> Result<Time, Box<dyn std::error::Error>> {
        let date = DateTime::new(year, 1, 1, 0, 0, 0)?;
        Ok(Time::UtcTime(UtcTime::from_date_time(date)?))
    };
    let cert = CertificateBuilder::new(
        name.clone(),
        SerialNumber::from(1u32),
        utc(2025)?,
        utc(2035)?,
        name,
        spki,
    )
    .add_extensions(extensions)?
    .build(&signer)?
    .to_der()?;

    let mut ks = KeyStore::new();
    ks.insert(
        "demo",
        Entry::PrivateKey {
            key: PrivateKey(key.private_key_pkcs8),
            chain: vec![Certificate(cert)],
        },
    );
    let password = Password::new("changeit");
    let store = AnyStore::from_key_store(Format::Pkcs12, &ks, &password)?;
    store.save_file("demo.p12", &password)?;
    Ok(())
}
```

</details>

All examples under `crates/keystore-rs/examples/` are compiled and run by CI.

## 🗂️ Supported keystore formats

| Format | Java type | Magic | Round-trip |
| --- | --- | --- | --- |
| JKS | `JavaKeyStore` | `FE ED FE ED` | byte-identical |
| CaseExactJKS | `JavaKeyStore.CaseExactJKS` | `FE ED FE ED` | byte-identical |
| JCEKS | `JceKeyStore` | `CE CE CE CE` | byte-identical |
| PKCS#12 | `PKCS12KeyStore` | DER `SEQUENCE` | interop (salts are random) |
| BKS v1 / v2 | `BcKeyStoreSpi` | `00 00 00 01` / `00 00 00 02` | byte-identical |
| UBER | `BcKeyStoreSpi.BouncyCastleStore` | `00 00 00 01` | byte-identical |
| BCFKS | `BcFKSKeyStoreSpi` | DER `SEQUENCE` | interop (salts are random) |
| DKS | `DomainKeyStore` | a directory of keystores | see below |

**Byte-identical** means a parsed store re-encodes to exactly the input bytes:
entry order, creation dates, certificate type strings, protected-key blobs and
sealed-key streams are all kept verbatim. **Interop** means the salt and nonce
are regenerated on every write, so the guarantee is that Java reads what we
write and we read what Java wrote.

Aliases follow each format's own Java implementation: `JavaKeyStore`,
`JceKeyStore` and `PKCS12KeyStore` lowercase every alias with
`Locale.ENGLISH`, so JKS, JCEKS and PKCS#12 aliases are case-insensitive and the
file only holds the folded spelling. Bouncy Castle's providers do no folding, so
BKS, UBER and BCFKS aliases stay case-sensitive.

<details>
<summary><b>Storing a passphrase as a secret key (`-importpass`)</b> — click to expand</summary>

<br>

A password can also be stored as a secret key, which is what `-importpass`
does: the passphrase is read from the terminal, or taken from `-keypass`.
SunJCE's `PBEKey.getEncoded()` is the password with each `char` truncated to one
byte, and the entry is a `PBEWithMD5AndDES` secret key.

JCEKS seals it like any other secret key; PKCS#12 writes the `SecretBag` whose
`secretType` is `pkcs8ShroudedKeyBag` that the JDK produces, down to the bare
PBE OID with no AlgorithmIdentifier parameters; BKS and UBER store the Java
algorithm name the way they store any secret key. JKS cannot hold one and fails
with keytool's `Cannot store non-PrivateKeys`, and BCFKS only takes the key
algorithms Bouncy Castle names (AES and DESede).

</details>

### 🖥️ Platform keystores

`Windows-MY`, `Windows-ROOT`, `KeychainStore` and `PKCS11` are **not file
formats**. They are the Windows certificate store, the macOS keychain and a
PKCS#11 module, each reached through an operating-system API, so there is no
portable Rust equivalent and no keystore file to parse. `-storetype` rejects
them with a message that says exactly that, instead of reporting an unknown type
or failing later while reading a file that does not exist.

## 🧩 Workspace

| Crate | Contents |
| --- | --- |
| `keystore-core` | `KeyStore` semantic view, `Entry`, `Password`, `Error`, `KeyStoreFormat`, PEM |
| `keystore-crypto` | keystore primitives plus the BC breadth layer (ciphers, hashes, MACs, modes, KDFs) |
| `keystore-jks` | JKS, CaseExactJKS and JCEKS |
| `keystore-pkcs12` | PKCS#12 with PBES1, PBES2, HmacPBES*, PBMAC1 and the Bouncy Castle presets |
| `keystore-bc` | BKS v1/v2, UBER, BCFKS (all eight provider names), signed BCFKS |
| `keystore-pki` | RSA/ECDSA/DSA/EdDSA keys, signatures, certificates, PKCS#10, CRLs |
| `keystore-x509` | X.500 names, v3 certificate/CSR/CRL builders, extensions, selectors, attribute certificates, path validation |
| `keystore-cms` | CMS/PKCS#7, BER, S/MIME ASN.1, AuthEnvelopedData, KEMRI |
| `keystore-ocsp` | OCSP requests, responses, responder and verifier |
| `keystore-tsp` | RFC 3161 TSP and ERS |
| `keystore-cmp` | CMP, CRMF and CMC |
| `keystore-est` | RFC 7030 EST |
| `keystore-pqc` | ML-KEM, ML-DSA, XMSS, LMS/HSS (`lms`) and SLH-DSA (`slhdsa`) |
| `keystore-crypto-extra` | HPKE, FF1/FF3 FPE, SPAKE2, SRP-6a, J-PAKE, EC-JPAKE, OWL and BLS12-381 |
| `keystore-pqc-extra` | HQC KEM and Falcon/FN-DSA |
| `keystore-asn1-extra` | DVCS, EAC, ISISMt, ICAO, Netscape and vendor ASN.1 |
| `keystore-tls` | rustls identities, resolvers, trust stores, OCSP stapling, CRL sets |
| `keystore-openpgp` | Sequoia OpenPGP bridge |
| `keystore-mail` | MIME and S/MIME bridge |
| `keystore` | facade: `AnyStore`, format detection, conversion, DKS, feature matrix |
| `keystore-cli` | a `keytool`-compatible command line |
| `keystore-conformance` | corpus fixtures and the Java oracle (test only) |

## ⌨️ Command line

`keystore` implements `keytool`'s commands with `keytool`'s single-dash options:

`-certreq` · `-changealias` · `-delete` · `-exportcert` · `-gencert` ·
`-genkeypair` · `-genseckey` · `-importcert` · `-importkeystore` ·
`-importpass` · `-keypasswd` · `-list` · `-printcert` · `-printcertreq` ·
`-printcrl` · `-printcms` · `-showinfo` · `-storepasswd` · `-version` ·
`-help`

`-genkeypair` generates the key pair **and** the self-signed certificate itself:

```sh
keystore -genkeypair -alias signer -keyalg EC -keysize 256 \
    -dname "CN=signer, O=example" -validity 365 \
    -keystore signer.p12 -storetype PKCS12 -storepass changeit
```

`-printcms` is backed by the `keystore-cms` crate, including BER multi-signer
files. The other new crates are library APIs rather than CLI commands: OCSP,
TSP, CMP, EST, PQC, TLS, OpenPGP and S/MIME need application context, so they
are exposed through the library and runnable examples instead of being forced
into keytool's option grammar. The CLI enables only the features it needs
(`keystores` + `cms`), so installing it does not pull the whole stack.

<details>
<summary><b>Everyday commands</b> — click to expand</summary>

<br>

```sh
# RSA, EC (P-256, P-384, P-521) or DSA (1024, 2048, 3072)
keystore -genkeypair -alias signer -keyalg DSA -keysize 2048 ...

# EdDSA, the same way keytool spells it
keystore -genkeypair -alias signer -keyalg Ed25519 ...

# Any named curve the RustCrypto crates implement, instead of -keysize
keystore -genkeypair -alias signer -keyalg EC -groupname secp256k1 ...

# Secret keys, for JCEKS, PKCS#12, BKS, UBER and BCFKS
keystore -genseckey -alias aes -keyalg AES -keysize 256 \
    -keystore secrets.jceks -storetype JCEKS -storepass changeit

# Store a passphrase as a PBE secret key, as keytool -importpass does;
# the passphrase itself is prompted for, or passed with -keypass
keystore -importpass -alias token -keystore secrets.p12 -storetype PKCS12 \
    -storepass changeit

# Change the store password, then one entry's key password
keystore -storepasswd -keystore signer.jks -storepass old -new new
keystore -keypasswd -alias signer -keystore signer.jks \
    -storepass new -keypass new -new key-only

# Certificate requests and issuance
keystore -certreq -alias signer -keystore signer.jks -storepass new -file signer.csr -rfc
keystore -gencert -alias ca -infile signer.csr -outfile signer.pem \
    -keystore ca.p12 -storepass changeit -validity 365
keystore -printcertreq -file signer.csr
keystore -printcrl -file revoked.crl -v
```

</details>

`-genkeypair`, `-certreq` and `-gencert` all take `-ext`, with keytool's syntax:
`name=value[,value...]`, where `critical` marks the extension critical.

```sh
keystore -genkeypair -alias ca -keyalg RSA -dname "CN=Example CA" \
    -ext BC=critical,ca:true -ext KU=critical,keyCertSign,cRLSign ...
```

The names are `BC` (basicConstraints), `KU` (keyUsage), `EKU`
(extendedKeyUsage), `SAN` (subjectAltName, with `dns:`, `ip:`, `email:` and
`uri:` prefixes), `SKI` and `AKI`. A subject key identifier is derived the way
the JDK derives it — SHA-1 over the public key bits — when `SKI=auto` is given,
and an authority key identifier is added to an issued certificate when the
issuer has one.

`-storepasswd` re-protects every key with the new password, which is what
`JavaKeyStore.engineStore` does; it fails with "Cannot recover key" if an entry
is protected with a password of its own. `-keypasswd` is the JKS/JCEKS-only
command that changes just one entry's key password.

## 🤖 Signing Android apps

A keystore it writes signs APKs with Google's `apksigner`, which loads the key
the same way any Java consumer would (`KeyStore.load`,
`getKey(alias, keyPassword)`, `getCertificateChain`):

```sh
keystore -genkeypair -alias signer -keyalg RSA -keysize 2048 \
    -dname "CN=signer, O=example" -validity 365 \
    -keystore signer.jks -storetype JKS \
    -storepass storepass -keypass keypass

apksigner sign --ks signer.jks --ks-type JKS \
    --ks-pass pass:storepass --ks-key-alias signer --key-pass pass:keypass \
    --out signed.apk app.apk

apksigner verify --verbose signed.apk
```

```text
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
```

The same holds for PKCS#12 stores and for EC keys.

## 🔐 PKCS#12 parameters

`Pkcs12Params` selects the key scheme, the certificate scheme and the MAC.
`Preset` mirrors the keystore types Bouncy Castle registers, so a store built
with a preset is the same flavour BC would write:

`PKCS12-DEF` · `PKCS12-3DES-40RC2` · `PKCS12-3DES-3DES` ·
`PKCS12-AES256-AES128` · `PKCS12-AES256-AES128-GCM` (PBES2 AES-GCM, no
MacData) · `PKCS12-PBMAC1` (RFC 9579)

## 🧾 Signed BCFKS

`BcFKSKeyStoreSpi` can be sealed with a `ContentSigner` instead of a
password-derived MAC. Such a store carries a `SignatureCheck` instead of a
`PbkdMacIntegrityCheck`, and the signature covers the encrypted store data.

`BcfksStore::parse_signed` verifies it against the certificate the store
carries, or against one supplied by the caller when it carries none.
`encode_signed` seals a store with a fresh signature, and an untouched signed
store re-encodes byte for byte because the signature is reused. Mutating one
invalidates it: `encode` then refuses, and `encode_signed` is the way to write it
back. RSA, ECDSA over every curve listed below, Ed25519, Ed448 and DSA are all
supported, for both verifying a store someone else signed and signing one of
ours.

## 🗃️ DKS

DKS is not an encoding: it is a directory of keystores presented as one,
described by a domain configuration file.

```text
domain app1 entryNameSeparator="/" {
    keystore app1-truststore keystoreURI="truststore.jks";
    keystore app1-keys keystoreType="PKCS12" keystoreURI="keystore.p12";
};
```

`keystore::dks::DksStore::load` parses the configuration, opens every keystore it
names and exposes the entries as `<keystore><separator><alias>`, folding aliases
to lower case the way `DomainKeyStore` does. `save` writes each sub-keystore
back with the password it opened with.

## 🌐 PKI and ecosystem layers

| Layer | Crate | What it covers |
|---|---|---|
| 📜 **X.509** | `keystore-x509` | BC-style X.500 names, v3 certificate/CSR/CRL builders, the full extension set, attribute certificates, issuer/subject unique IDs, RFC 5280 path validation over `pkix-chain` |
| 📨 **CMS** | `keystore-cms` | signed, enveloped, digested, compressed, authenticated and authEnveloped data; BER; S/MIME structures; KEM recipients |
| 🔍 **OCSP / TSP / CMP / EST** | `keystore-ocsp`, `keystore-tsp`, `keystore-cmp`, `keystore-est` | requests, responses, responders, verifiers, timestamp tokens, CRMF/CMC, and an RFC 7030 client with a caller-supplied transport |
| 🧬 **PQC** | `keystore-pqc`, `keystore-pqc-extra` | ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS/HSS, HQC and Falcon/FN-DSA, with SPKI/PKCS#8/OID glue where the algorithm defines it |
| 🔧 **Crypto extras** | `keystore-crypto-extra` | HPKE seal/open, FF1/FF3, SPAKE2, SRP-6a, J-PAKE, EC-JPAKE, OWL and BLS12-381 aggregation |
| 🌐 **TLS** | `keystore-tls` | rustls identities, SNI resolvers, trust stores, mTLS, OCSP stapling, CRL-set verification and bundled webpki-roots; an optional pure-Rust provider |
| ✉️ **OpenPGP / S/MIME** | `keystore-openpgp`, `keystore-mail` | Sequoia-backed OpenPGP and a MIME ↔ CMS bridge, with explicit trust rather than implicit web-of-trust |

## 🧪 Examples

`crates/keystore-rs/examples/` contains a self-contained example per crate. They
generate their own keys and certificates in memory; none reads a fixture or
touches the network.

| Example | Feature |
|---|---|
| `keystores` | none (formats only) |
| `x509`, `x509_keystore` | `x509` |
| `cms` | `cms` |
| `ocsp` | `ocsp` |
| `tsp` | `tsp` |
| `cmp` | `cmp` |
| `est` | `est` |
| `pqc` | `pqc` |
| `asn1_extra` | `asn1-extra` |
| `crypto_extra` | `crypto-extra` |
| `pqc_extra` | `pqc-extra` |
| `tls` | `tls-rustcrypto` + `x509` |
| `openpgp` | `openpgp` |
| `mail` | `mail` + `pki` |

```sh
cargo run -p keystore --example x509 --features x509
cargo run -p keystore --example x509_keystore --features x509
cargo run -p keystore --example crypto_extra --features crypto-extra
```

## ✅ Conformance and tests

- `corpus/` holds stores and PKI objects generated by JDK 25 and Bouncy Castle
  1.85 with a manifest; the suite checks parsing, byte-identical re-encoding and
  Java re-reads.
- `tools/verify` compiles Java oracles (`VerifyStore`, `ApkSignerProbe`,
  `SignBcfks`) that load what this workspace writes exactly as Java consumers
  do, including `getKey`/`getCertificateChain` and APK signing.
- `tools/bc-manifest` classifies all six published BC 1.85 source artifacts;
  `docs/PORT_STATUS.md` records the measured coverage and every known gap.
- `tools/fuzz` contains the fuzz targets; the workspace is `unsafe`-free.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test --release --workspace --no-fail-fast
cargo +1.89.0 check --workspace --all-targets
```

## 🚧 Remaining work

The measured coverage and every known gap are in
[`docs/PORT_STATUS.md`](docs/PORT_STATUS.md). Every Bouncy Castle 1.85 class
that is reachable from a keystore, certificate, CMS, OCSP, TSP, CMP or EST
workflow is now either ported here or delegated to a crate; the last wave closed
the three groups that were still pending — SLH-DSA, `cert.selector` and
`asn1.misc` — along with the documented variants of the covered families
(SRP-6a, EC-JPAKE/OWL on P-384 and P-521, FF3, HPKE AES-GCM and NIST-curve
suites, BLS uncompressed encodings).

What is deliberately left out is the part of Bouncy Castle with no Rust
consumer: the non-standard post-quantum families (SQIsign, HAWK, SDitH, FAEST,
AIMER, MAYO, MQOM and the other NIST round-two candidates), ETSI ITS, and the
Java/JCA provider plumbing that exists only to register algorithms with the JVM.

> **One asymmetry worth knowing:** PKCS#12 secret keys are written the way
> SunJCE writes them — a `SecretBag` whose `secretType` is
> `pkcs8ShroudedKeyBag` — and Bouncy Castle only reads that encoding when
> `org.bouncycastle.pkcs12.allow_sun_secret_keys` is set. Stores written here
> are JDK-compatible, and that is the compatibility the encoder targets.

## 🔒 Security notes

- Passwords use UTF-16 `char[]` semantics and are redacted from `Debug`, but are
  not zeroised on drop; decrypted key material lives in ordinary `Vec<u8>`.
- PKCS#12 and BCFKS draw salts/nonces from the OS CSPRNG; MAC and signature
  comparisons are constant time.
- The legacy algorithms (RC2, RC4, 3DES, SHA-1 MACs) exist for compatibility,
  not new designs; prefer AES/SHA-256 presets.
- The J-PAKE port uses `num-bigint` modular exponentiation, which is not constant
  time. Do not expose per-message timing.
- Several PQC crates are pre-1.0 (XMSS, HQC, FN-DSA); their key encodings may
  change before the corresponding standards are final.
- No third-party security review has been performed on the newer layers. The
  keystore formats have broad differential testing against Java; the rest is
  feature-complete and test-clean, not audited.

## 💬 Community

Questions, bug reports and feature requests are welcome in the Telegram
channel:

[![Join the Telegram channel](https://img.shields.io/badge/Telegram-%2BWmudnO0--xoNhMDQ8-2CA5E0?logo=telegram&logoColor=white&style=for-the-badge)](https://t.me/+WmudnO0-xoNhMDQ8)

## 📄 License

Dual licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

<div align="center">

---

**Made with ❤️ by [Rodroid Mods](https://t.me/+WmudnO0-xoNhMDQ8)**

<sub>If this project saved you a JVM, consider starring the repo ⭐</sub>

</div>
