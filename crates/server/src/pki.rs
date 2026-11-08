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

pub fn saml_signing_keypair(cn: &str) -> Result<(String, String), String> {
    let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(err)?;
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone());
    let public = key.to_public_key().to_public_key_der().map_err(err)?;
    let name = subject(cn)?;
    let profile = Profile::Leaf { issuer: name.clone(), enable_key_agreement: false, enable_key_encipherment: false };
    let builder = CertificateBuilder::new(profile, serial()?.0, ca_validity()?, name, SubjectPublicKeyInfoOwned::try_from(public.as_bytes()).map_err(err)?, &signer).map_err(err)?;
    let cert = builder.build::<rsa::pkcs1v15::Signature>().map_err(err)?;
    Ok((key.to_pkcs8_pem(LineEnding::LF).map_err(err)?.to_string(), cert.to_pem(LineEnding::LF).map_err(err)?.to_string()))
}

pub fn csr_public_key(pem: &str) -> Result<SubjectPublicKeyInfoOwned, String> {
    use x509_cert::der::Encode;
    let csr = x509_cert::request::CertReq::from_pem(pem).map_err(err)?;
    let der = csr.to_der().map_err(err)?;
    let request = keystore_pki::pkcs10::parse(&der).map_err(err)?;
    let key=keystore_pki::parse_public_key(&request.spki).map_err(err)?;
    match key {
        keystore_pki::PublicKey::Rsa(ref key) => { use rsa::traits::PublicKeyParts; if ![2048,3072,4096].contains(&key.n().bits()) { return Err("CSR RSA key must be 2048, 3072 or 4096 bits".into()); } }
        keystore_pki::PublicKey::EcP256(_) | keystore_pki::PublicKey::EcP384(_) | keystore_pki::PublicKey::Ed25519(_) => {}
        _ => return Err("unsupported CSR key algorithm".into()),
    }
    request.verify().map_err(err)?;
    Ok(csr.info.public_key)
}
pub fn certificate_live(pem: &str) -> bool {
    Certificate::from_pem(pem).map(|c| {
        let t = crate::clock::now().max(0) as u64;
        c.tbs_certificate.validity.not_before.to_unix_duration().as_secs() <= t && c.tbs_certificate.validity.not_after.to_unix_duration().as_secs() > t
    }).unwrap_or(false)
}
pub fn certificate_expiry(pem: &str) -> Result<i64,String> {
    let cert=Certificate::from_pem(pem).map_err(err)?;
    i64::try_from(cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs()).map_err(err)
}
pub fn create_intermediate(name: &str, parent_pem: &str, parent_key: &str) -> Result<Issued, String> {
    if !certificate_live(parent_pem) { return Err("parent CA is not live".into()); }
    let parent = Certificate::from_pem(parent_pem).map_err(err)?;
    let parent_key = SecretKey::from_pkcs8_pem(parent_key).map_err(err)?;
    let key = SecretKey::random(&mut OsRng); let signer = SigningKey::from(&parent_key);
    let (serial, serial_hex) = serial()?;
    let profile = Profile::SubCA { issuer: parent.tbs_certificate.subject.clone(), path_len_constraint: Some(0) };
    let builder = CertificateBuilder::new(profile, serial, parent.tbs_certificate.validity, subject(name)?, public_key(&key)?, &signer).map_err(err)?;
    let cert = builder.build::<DerSignature>().map_err(err)?;
    Ok(Issued { certificate_pem: cert.to_pem(LineEnding::LF).map_err(err)?, private_key_pem: key.to_pkcs8_pem(LineEnding::LF).map_err(err)?.to_string(), serial_hex })
}
/// Signs the verified CSR key using registry identity and policy, never CSR extensions.
pub fn issue_device(ca_pem: &str, ca_key: &str, cn: &str, sans: &[String], days: i64, csr: Option<&str>) -> Result<Issued, String> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
    if !certificate_live(ca_pem) { return Err("CA is not live".into()); }
    let ca = Certificate::from_pem(ca_pem).map_err(err)?;
    let ca_key = SecretKey::from_pkcs8_pem(ca_key).map_err(err)?; let signer = SigningKey::from(&ca_key);
    let key = if csr.is_none() { Some(SecretKey::random(&mut OsRng)) } else { None };
    let spki = match csr { Some(csr) => csr_public_key(csr)?, None => public_key(key.as_ref().ok_or("missing generated key")?)? };
    let (serial, serial_hex) = serial()?; let now = crate::clock::now();
    let expires=(now + days.clamp(1,365)*86400).min(certificate_expiry(ca_pem)?);
    if expires<=now { return Err("CA is not live".into()); }
    let validity = Validity { not_before: time_at(now - 60)?, not_after: time_at(expires)? };
    let profile = Profile::Leaf { issuer: ca.tbs_certificate.subject.clone(), enable_key_agreement: false, enable_key_encipherment: false };
    let mut builder = CertificateBuilder::new(profile, serial, validity, subject(cn)?, spki, &signer).map_err(err)?;
    builder.add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2")])).map_err(err)?;
    if !sans.is_empty() {
        let names = sans.iter().map(|name| match name.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => OctetString::new(ip.octets()).map(GeneralName::IpAddress).map_err(err),
            Ok(std::net::IpAddr::V6(ip)) => OctetString::new(ip.octets()).map(GeneralName::IpAddress).map_err(err),
            Err(_) => Ia5String::new(name.as_str()).map(GeneralName::DnsName).map_err(err),
        }).collect::<Result<Vec<_>,_>>()?;
        builder.add_extension(&SubjectAltName(names)).map_err(err)?;
    }
    let cert = builder.build::<DerSignature>().map_err(err)?;
    let private_key_pem = match key { Some(key) => key.to_pkcs8_pem(LineEnding::LF).map_err(err)?.to_string(), None => String::new() };
    Ok(Issued { certificate_pem: cert.to_pem(LineEnding::LF).map_err(err)?, private_key_pem, serial_hex })
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

    /// A root with a caller-chosen window, so tests can build short-lived and expired CAs.
    fn ca_with_validity(not_before: i64, not_after: i64) -> (String, String) {
        let key = SecretKey::random(&mut OsRng);
        let signer = SigningKey::from(&key);
        let (serial, _) = serial().expect("serial");
        let validity = Validity { not_before: time_at(not_before).expect("from"), not_after: time_at(not_after).expect("to") };
        let builder = CertificateBuilder::new(Profile::Root, serial, validity, subject("Window CA").expect("name"), public_key(&key).expect("key"), &signer).expect("builder");
        (builder.build::<DerSignature>().expect("build").to_pem(LineEnding::LF).expect("pem"), key.to_pkcs8_pem(LineEnding::LF).expect("key pem").to_string())
    }

    #[test]
    fn issuance_never_outlives_the_ca() {
        let now = crate::clock::now();
        let (ca_pem, ca_key) = ca_with_validity(now - 60, now + 600);
        let leaf = issue_device(&ca_pem, &ca_key, "device-1", &[], 30, None).expect("issue");
        assert_eq!(certificate_expiry(&leaf.certificate_pem).unwrap(), certificate_expiry(&ca_pem).unwrap(), "a 30-day request must stop at the CA expiry");
        assert!(certificate_live(&leaf.certificate_pem));
        // An intermediate is bounded by its parent and can then issue down the chain.
        let child = create_intermediate("Child CA", &ca_pem, &ca_key).expect("intermediate");
        let grandchild = issue_device(&child.certificate_pem, &child.private_key_pem, "device-2", &[], 30, None).expect("issue under child");
        assert_eq!(certificate_expiry(&grandchild.certificate_pem).unwrap(), certificate_expiry(&ca_pem).unwrap());
    }

    #[test]
    fn an_expired_parent_cannot_mint_an_intermediate_or_a_leaf() {
        let now = crate::clock::now();
        let (ca_pem, ca_key) = ca_with_validity(now - 7200, now - 3600);
        assert_eq!(create_intermediate("Child CA", &ca_pem, &ca_key).err().unwrap(), "parent CA is not live");
        assert_eq!(issue_device(&ca_pem, &ca_key, "device-1", &[], 30, None).err().unwrap(), "CA is not live");
    }
}
