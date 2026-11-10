//! OpenSSH user certificates for workers that dial the server.
//! The instance holds the CA. A worker key never leaves its host, and a
//! certificate only names that one worker, for ten minutes.

use rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};

const CERT_TTL: u64 = 600;

pub fn ensure_ca(existing: &str) -> Result<(PrivateKey, Option<String>), String> {
    if !existing.is_empty() {
        return PrivateKey::from_openssh(existing).map(|k| (k, None)).map_err(|e| e.to_string());
    }
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| e.to_string())?;
    let pem = key.to_openssh(ssh_key::LineEnding::LF).map_err(|e| e.to_string())?;
    Ok((key, Some(pem.to_string())))
}

pub fn public_openssh(private: &PrivateKey) -> Result<String, String> {
    private.public_key().to_openssh().map_err(|e| e.to_string())
}

/// Sign a user certificate whose only principal is `worker:<id>`.
/// No port forwarding, PTY, or agent forwarding is granted.
pub fn sign_worker(ca: &PrivateKey, subject: &PublicKey, worker_id: &str, serial: u64, now: u64) -> Result<String, String> {
    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        subject.key_data().clone(),
        now.saturating_sub(30),
        now.saturating_add(CERT_TTL),
    ).map_err(|e| e.to_string())?;
    builder.serial(serial).map_err(|e| e.to_string())?;
    builder.cert_type(ssh_key::certificate::CertType::User).map_err(|e| e.to_string())?;
    builder.key_id(format!("worker:{}", worker_id)).map_err(|e| e.to_string())?;
    builder.valid_principal(format!("worker:{}", worker_id)).map_err(|e| e.to_string())?;
    // OpenSSH refuses the certificate unless every critical option is understood.
    // force-command denies a shell. source-address is required so a stolen
    // certificate is not a bearer token for every network.
    builder.critical_option("force-command", "none").map_err(|e| e.to_string())?;
    builder.critical_option("source-address", "127.0.0.1/32,::1/128").map_err(|e| e.to_string())?;
    let cert = builder.sign(ca).map_err(|e| e.to_string())?;
    cert.to_openssh().map_err(|e| e.to_string())
}

pub fn parse_public(openssh: &str) -> Result<PublicKey, String> {
    let key = PublicKey::from_openssh(openssh).map_err(|e| e.to_string())?;
    if key.algorithm() != Algorithm::Ed25519 { return Err("worker key must be ed25519".into()); }
    Ok(key)
}

pub fn verify_worker(ca_public: &PublicKey, cert_openssh: &str, now: u64) -> Result<String, String> {
    let cert = Certificate::from_openssh(cert_openssh).map_err(|e| e.to_string())?;
    if cert.signature_key() != ca_public.key_data() { return Err("worker certificate was not signed by this instance".into()); }
    let fingerprint = ca_public.fingerprint(HashAlg::Sha256);
    cert.validate_at(now, std::iter::once(&fingerprint)).map_err(|e| format!("worker certificate rejected: {}", e))?;
    if cert.cert_type() != ssh_key::certificate::CertType::User { return Err("worker certificate is not a user certificate".into()); }
    let principals = cert.valid_principals();
    if principals.len() != 1 { return Err("certificate principal is not a single worker".into()); }
    let id = principals[0].strip_prefix("worker:").ok_or("certificate has no worker principal")?;
    if id.is_empty() { return Err("certificate has an empty worker principal".into()); }
    if cert.key_id() != principals[0] { return Err("certificate key id does not match its principal".into()); }
    let command = cert.critical_options().get("force-command").map(|s| s.as_str());
    if command != Some("none") { return Err("certificate does not pin a forced command".into()); }
    Ok(id.to_string())
}

pub fn fresh_serial() -> u64 { let mut b = [0u8; 8]; OsRng.fill_bytes(&mut b); u64::from_be_bytes(b) & 0x7fff_ffff_ffff_ffff }

#[cfg(test)]
pub fn generate_subject() -> Result<(PrivateKey, String), String> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| e.to_string())?;
    let public = key.public_key().to_openssh().map_err(|e| e.to_string())?;
    Ok((key, public))
}

#[cfg(test)]
pub fn subject_is_ed25519(key: &PrivateKey) -> bool { matches!(key.key_data(), ssh_key::private::KeypairData::Ed25519(_)) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_signed_certificate_names_only_its_worker() {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let (subject, public) = generate_subject().unwrap();
        assert!(subject_is_ed25519(&subject));
        let parsed = parse_public(&public).unwrap();
        let now = 1_700_000_000u64;
        let cert = sign_worker(&ca, &parsed, "w1", 7, now).unwrap();
        assert_eq!(verify_worker(ca.public_key(), &cert, now + 10).unwrap(), "w1");
        assert!(verify_worker(ca.public_key(), &cert, now + CERT_TTL + 60).is_err());
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(verify_worker(other.public_key(), &cert, now + 10).is_err());
    }
}
