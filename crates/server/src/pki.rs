//! Certificate authority and leaf issuance, shared by both deployments.
//!
//! Uses the RustCrypto stack (`x509-cert` + `p256`) instead of rcgen, whose only
//! backends are the C libraries ring and aws-lc-rs. Public keys are ECDSA P-256,
//! matching what the previous implementation issued.

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use p256::SecretKey;
use rand_core::{OsRng, RngCore};
use std::str::FromStr;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::certificate::Certificate;
use x509_cert::der::asn1::{GeneralizedTime, Ia5String, UtcTime};
use x509_cert::der::DateTime;
use x509_cert::der::{DecodePem, EncodePem};
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

pub struct Issued {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub serial_hex: String,
}

fn err(e: impl std::fmt::Display) -> String { e.to_string() }

/// Certificate timestamps from Unix seconds, choosing UTCTime inside the
/// 1970-2049 range and GeneralizedTime outside it.
fn time_at(unix: i64) -> Result<Time, String> {
    let (year, month, day, hour, minute, second) = crate::clock::utc_parts(unix);
    let datetime = DateTime::new(year as u16, month, day, hour, minute, second).map_err(err)?;
    if (1970..=2049).contains(&year) {
        Ok(Time::UtcTime(UtcTime::from_date_time(datetime).map_err(err)?))
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(datetime)))
    }
}

/// Root CAs keep the fixed window the previous implementation used.
fn ca_validity() -> Result<Validity, String> {
    let not_before = DateTime::new(2020, 1, 1, 0, 0, 0).map_err(err)?;
    let not_after = DateTime::new(2050, 1, 1, 0, 0, 0).map_err(err)?;
    Ok(Validity {
        not_before: Time::UtcTime(UtcTime::from_date_time(not_before).map_err(err)?),
        not_after: Time::GeneralTime(GeneralizedTime::from_date_time(not_after)),
    })
}

/// RFC 4514 escaping, so a comma or equals sign in a name cannot add an RDN.
fn escape_dn(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        let edge_space = c == ' ' && (i == 0 || i + 1 == value.chars().count());
        if edge_space || matches!(c, '\\' | '"' | '+' | ',' | ';' | '<' | '>' | '#' | '=') { out.push('\\'); }
        out.push(c);
    }
    out
}

fn subject(cn: &str) -> Result<Name, String> {
    Name::from_str(&format!("CN={}", escape_dn(cn))).map_err(|e| format!("invalid name {:?}: {}", cn, e))
}

fn serial() -> Result<(SerialNumber, String), String> {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes[0] == 0 { bytes[0] = 1; }
    let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    SerialNumber::new(&bytes).map(|s| (s, hex)).map_err(err)
}

fn public_key(key: &SecretKey) -> Result<SubjectPublicKeyInfoOwned, String> {
    let der = key.public_key().to_public_key_der().map_err(err)?;
    SubjectPublicKeyInfoOwned::try_from(der.as_bytes()).map_err(err)
}

pub fn create_ca(name: &str) -> Result<Issued, String> {
    let key = SecretKey::random(&mut OsRng);
    let signer = SigningKey::from(&key);
    let (serial, serial_hex) = serial()?;
    let builder = CertificateBuilder::new(Profile::Root, serial, ca_validity()?, subject(name)?, public_key(&key)?, &signer).map_err(err)?;
    let cert = builder.build::<DerSignature>().map_err(err)?;
    Ok(Issued {
        certificate_pem: cert.to_pem(LineEnding::LF).map_err(err)?,
        private_key_pem: key.to_pkcs8_pem(LineEnding::LF).map_err(err)?.to_string(),
        serial_hex,
    })
}

pub fn issue(ca_certificate_pem: &str, ca_private_key_pem: &str, cn: &str, sans: &[String], days: i64) -> Result<Issued, String> {
    let now = crate::clock::now();
    // A small backdate covers clock skew between issuer and consumer.
    let validity = Validity { not_before: time_at(now - 60)?, not_after: time_at(now + days.clamp(1, 3650) * 86_400)? };
    let ca = Certificate::from_pem(ca_certificate_pem).map_err(err)?;
    let ca_key = SecretKey::from_pkcs8_pem(ca_private_key_pem).map_err(err)?;
    let signer = SigningKey::from(&ca_key);
    let key = SecretKey::random(&mut OsRng);
    let (serial, serial_hex) = serial()?;
    let profile = Profile::Leaf { issuer: ca.tbs_certificate.subject.clone(), enable_key_agreement: false, enable_key_encipherment: false };
    let mut builder = CertificateBuilder::new(profile, serial, validity, subject(cn)?, public_key(&key)?, &signer).map_err(err)?;
    if !sans.is_empty() {
        let mut names = Vec::with_capacity(sans.len());
        for name in sans { names.push(GeneralName::DnsName(Ia5String::new(name.as_str()).map_err(|_| format!("invalid SAN {:?}: must be an ASCII DNS name", name))?)); }
        builder.add_extension(&SubjectAltName(names)).map_err(err)?;
    }
    let cert = builder.build::<DerSignature>().map_err(err)?;
    Ok(Issued {
        certificate_pem: cert.to_pem(LineEnding::LF).map_err(err)?,
        private_key_pem: key.to_pkcs8_pem(LineEnding::LF).map_err(err)?.to_string(),
        serial_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::GeneralName;

    #[test]
    fn creates_a_ca_and_issues_a_verifiable_leaf() {
        let ca = create_ca("OpenWarp Test CA").expect("create ca");
        let (_, ca_block) = x509_parser::pem::parse_x509_pem(ca.certificate_pem.as_bytes()).expect("parse ca pem");
        let parsed_ca = ca_block.parse_x509().expect("decode ca");
        assert!(parsed_ca.is_ca(), "the CA must have BasicConstraints CA:true");
        assert_eq!(parsed_ca.subject().to_string(), "CN=OpenWarp Test CA");

        let leaf = issue(&ca.certificate_pem, &ca.private_key_pem, "service.internal", &["service.internal".into(), "alt.internal".into()], 30).expect("issue");
        let (_, leaf_block) = x509_parser::pem::parse_x509_pem(leaf.certificate_pem.as_bytes()).expect("parse leaf pem");
        let parsed_leaf = leaf_block.parse_x509().expect("decode leaf");
        assert_eq!(parsed_leaf.subject().to_string(), "CN=service.internal");
        assert_eq!(parsed_leaf.issuer().to_string(), parsed_ca.subject().to_string(), "issuer name must match the CA");
        let san = parsed_leaf.subject_alternative_name().expect("san extension").expect("san present");
        let names: Vec<String> = san.value.general_names.iter().filter_map(|n| match n {
            GeneralName::DNSName(d) => Some((*d).to_string()),
            _ => None,
        }).collect();
        assert_eq!(names, vec!["service.internal".to_string(), "alt.internal".to_string()]);
        parsed_leaf.verify_signature(Some(parsed_ca.public_key())).expect("leaf signature must verify against the CA key");
        let days = (parsed_leaf.validity().not_after.timestamp() - crate::clock::now()) / 86_400;
        assert!((29..=30).contains(&days), "leaf validity must follow the requested days, got {}", days);
        assert!(leaf.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn a_comma_in_the_name_does_not_add_an_rdn() {
        let ca = create_ca("Foo, Inc").expect("create ca");
        let (_, block) = x509_parser::pem::parse_x509_pem(ca.certificate_pem.as_bytes()).expect("parse ca pem");
        let parsed = block.parse_x509().expect("decode ca");
        let common: Vec<&str> = parsed.subject().iter_common_name().filter_map(|cn| cn.as_str().ok()).collect();
        assert_eq!(common, vec!["Foo, Inc"], "the comma must stay inside one CN value");
    }
}
