//! Key, certificate and KeyInfo helpers backed by the selected `ribergshamra`
//! provider.

use crate::error::SamlError;
use crate::util::normalize_cert_string;
use ribergshamra::keys::keyinfo::build_x509_key_info;
use ribergshamra::keys::loader::{load_pem_auto, load_x509_cert_pem};
use ribergshamra::keys::Key;

fn crypto_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Crypto(err.to_string())
}

/// Load a private key from PEM (PKCS#1/PKCS#8, optionally passphrase-protected).
pub fn load_private_key(pem: &str, password: Option<&str>) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_pem_auto(pem.as_bytes(), password).map_err(crypto_err)
}

/// Wrap a bare base64 certificate (as found in metadata) into a PEM block.
fn to_cert_pem(cert: &str) -> String {
    if cert.contains("BEGIN CERTIFICATE") {
        return cert.to_string();
    }
    let b64 = normalize_cert_string(cert);
    let mut body = String::new();
    // Valid base64 is ASCII. Iterate characters so malformed non-ASCII certificate
    // text still reaches the key loader's ordinary error path without slicing
    // through a character boundary.
    for (index, character) in b64.chars().enumerate() {
        if index != 0 && index % 64 == 0 {
            body.push('\n');
        }
        body.push(character);
    }
    if !b64.is_empty() {
        body.push('\n');
    }
    format!("-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n")
}

/// Load an X.509 certificate (PEM or bare base64) as a verification key.
pub fn load_certificate(cert: &str) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_x509_cert_pem(to_cert_pem(cert).as_bytes()).map_err(crypto_err)
}

/// Build a `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` block from a
/// certificate.
pub fn build_key_info(cert: &str) -> String {
    let b64 = normalize_cert_string(cert);
    build_x509_key_info(&[b64.as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const SP_PRIVKEY_ENC: &str = include_str!("../../tests/fixtures/key/sp_privkey_enc.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_cert.cer");
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp_cert.cer");
    // SP signing passphrase from upstream test/key/keypass.txt
    const SP_PASS: &str = "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px";

    #[test]
    fn malformed_unicode_certificate_returns_error_without_panicking(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for ascii_prefix_length in [63, 127] {
            let malformed = format!("{}é{}", "A".repeat(ascii_prefix_length), "A".repeat(64));
            let error = load_certificate(&malformed)
                .err()
                .ok_or("malformed certificate must fail to load")?;
            assert!(matches!(error, SamlError::Crypto(_)));
        }
        Ok(())
    }

    #[test]
    fn loads_unencrypted_private_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        assert!(key.has_private_key());
        assert_eq!(key.algorithm_name(), "RSA");
        Ok(())
    }

    #[test]
    fn encrypted_private_key_passphrase_matches_provider_capability(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "crypto-rustcrypto")]
        {
            let key = load_private_key(SP_PRIVKEY_ENC, Some(SP_PASS))?;
            assert!(key.has_private_key());
        }
        // AWS-LC providers do not implement the encrypted PKCS#8 loader.
        #[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
        assert!(matches!(
            load_private_key(SP_PRIVKEY_ENC, Some(SP_PASS)),
            Err(SamlError::Crypto(message))
                if message.contains("encrypted PKCS#8 PEM is not available through the selected provider")
        ));
        Ok(())
    }

    #[test]
    fn loads_certificate_and_builds_key_info() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_certificate(IDP_CERT)?;
        assert_eq!(key.algorithm_name(), "RSA");
        assert!(key.to_spki_der().is_some());

        let key_info = build_key_info(SP_CERT);
        assert!(key_info.contains("<ds:X509Certificate>"));
        assert!(key_info.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""));
        Ok(())
    }
}
