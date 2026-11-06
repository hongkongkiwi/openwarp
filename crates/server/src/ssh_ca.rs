//! SSH certificate authority: mint short-lived OpenSSH user certificates.
//!
//! A host trusts one CA key through `TrustedUserCAKeys` and then accepts any
//! certificate that key signed while the certificate is inside its validity
//! window. The subject private key never reaches the server, so the useful
//! lifetime bound is the certificate itself: a stolen certificate stops working
//! when it expires, and the DSA key on the client is never transmitted.
//!
//! The security boundary is not the signature. It is the principal, which
//! decides which local account the certificate authenticates as. Principals are
//! matched against a per-CA role map and never taken from the caller unchecked.
use rand_core::{OsRng, RngCore};
use serde_json::json;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};

pub const DEFAULT_TTL: i64 = 900;
pub const MAX_TTL: i64 = 8 * 3600;
/// sshd logs this value on an accepted certificate login, so it is the join
/// between a server's auth log and a row in `ssh_certs`.
pub const KEY_ID_PREFIX: &str = "openwarp:";

const PERMIT_PTY: &str = "permit-pty";
const PERMIT_AGENT: &str = "permit-agent-forwarding";
const PERMIT_PORT: &str = "permit-port-forwarding";

/// An Ed25519 CA key, returned as (OpenSSH private key, OpenSSH public key).
/// Ed25519 is the only CA algorithm offered because OpenSSH 8.8 and later
/// disable RSA/SHA-1 certificate signatures by default, so an RSA CA would
/// appear to work until it met a current host.
pub fn generate_ca() -> Result<(String, String), String> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| format!("could not generate the SSH CA key: {}", e))?;
    let secret = key.to_openssh(LineEnding::LF).map_err(|e| format!("could not encode the SSH CA key: {}", e))?;
    let public = key.public_key().to_openssh().map_err(|e| format!("could not encode the SSH CA public key: {}", e))?;
    Ok((secret.to_string(), public))
}

/// The SHA256 fingerprint in the form `ssh-keygen -lf` prints, so an operator
/// can compare what we show with what the host has installed.
pub fn ca_fingerprint(public_key: &str) -> Result<String, String> {
    let key = PublicKey::from_openssh(public_key.trim()).map_err(|e| format!("not a usable OpenSSH public key: {}", e))?;
    Ok(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

pub fn valid_principal(principal: &str) -> bool {
    // A comma would split into two principals inside the certificate encoding,
    // and sshd splits the principals field on commas too.
    !principal.is_empty()
        && principal.len() <= 128
        && principal.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

/// A grant pattern is an exact name, `*`, or a prefix ending in one `*`.
/// Anything else is rejected rather than interpreted, so a pattern cannot
/// silently mean more than it says.
pub fn valid_pattern(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.len() > 128 || pattern.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let stars = pattern.chars().filter(|c| *c == '*').count();
    stars == 0 || (stars == 1 && pattern.ends_with('*'))
}

pub fn pattern_matches(pattern: &str, principal: &str) -> bool {
    if !valid_pattern(pattern) { return false; }
    match pattern.strip_suffix('*') {
        Some(prefix) => principal.starts_with(prefix),
        None => pattern == principal,
    }
}

pub fn principal_allowed(patterns: &[String], principal: &str) -> bool {
    patterns.iter().any(|p| pattern_matches(p, principal))
}

/// Effective lifetime: the caller may ask for less than their grant allows,
/// never more, and never more than the hard ceiling.
pub fn clamp_ttl(requested: Option<i64>, grant_max: i64) -> i64 {
    let ceiling = if grant_max > 0 { grant_max.min(MAX_TTL) } else { DEFAULT_TTL };
    requested.unwrap_or(DEFAULT_TTL).clamp(60, ceiling.max(60))
}

pub struct SignInput<'a> {
    pub public_key: &'a str,
    pub principal: &'a str,
    pub key_id: &'a str,
    pub ttl: i64,
}

pub struct Signed {
    pub certificate: String,
    pub serial: u64,
    pub valid_after: i64,
    pub valid_before: i64,
}

pub fn sign_user_cert(ca_key_openssh: &str, input: &SignInput<'_>, allow_forwarding: bool, now: i64) -> Result<Signed, String> {
    if !valid_principal(input.principal) {
        return Err(format!("{:?} is not a valid principal (letters, digits, . _ - @)", input.principal));
    }
    let ca = PrivateKey::from_openssh(ca_key_openssh)
        .map_err(|_| "the stored SSH CA key is not a usable OpenSSH private key; create a new CA".to_string())?;
    let subject = PublicKey::from_openssh(input.public_key.trim())
        .map_err(|e| format!("not a usable OpenSSH public key: {}", e))?;
    let mut raw = [0u8; 8];
    OsRng.fill_bytes(&mut raw);
    // Positive and non-zero: the serial is stored in a signed 64-bit column and
    // OpenSSH treats 0 as unset.
    let serial = (u64::from_le_bytes(raw) >> 1).max(1);
    // Sixty seconds of backdating absorbs clock skew between us and the host.
    let valid_after = now - 60;
    let valid_before = now.saturating_add(input.ttl);
    let mut b = Builder::new_with_random_nonce(&mut OsRng, subject.key_data().clone(), valid_after as u64, valid_before as u64)
        .map_err(|e| format!("could not start the certificate: {}", e))?;
    b.cert_type(CertType::User).map_err(|e| e.to_string())?;
    b.serial(serial).map_err(|e| e.to_string())?;
    b.key_id(input.key_id).map_err(|e| e.to_string())?;
    // Never all_principals_valid(): that is a certificate good for root
    // anywhere the CA is trusted.
    b.valid_principal(input.principal).map_err(|e| e.to_string())?;
    // Least privilege by default: a shell, nothing else.
    b.extension(PERMIT_PTY, "").map_err(|e| e.to_string())?;
    if allow_forwarding {
        b.extension(PERMIT_AGENT, "").map_err(|e| e.to_string())?;
        b.extension(PERMIT_PORT, "").map_err(|e| e.to_string())?;
    }
    let cert = b.sign(&ca).map_err(|e| format!("could not sign the certificate: {}", e))?;
    let certificate = cert.to_openssh().map_err(|e| format!("could not encode the certificate: {}", e))?;
    Ok(Signed { certificate, serial, valid_after, valid_before })
}

/// Read a minted certificate back the way a host would, so a caller can show
/// the user exactly what they are about to present instead of what we meant.
pub fn describe(certificate: &str) -> Result<serde_json::Value, String> {
    let cert = ssh_key::Certificate::from_openssh(certificate.trim())
        .map_err(|e| format!("not a usable OpenSSH certificate: {}", e))?;
    Ok(json!({
        "key_id": cert.key_id(),
        "principals": cert.valid_principals(),
        "valid_after": cert.valid_after(),
        "valid_before": cert.valid_before(),
        "serial": cert.serial(),
        "cert_type": format!("{:?}", cert.cert_type()).to_lowercase(),
    }))
}

/// sshd's `RevokedKeys` file: one public key or certificate per line. There is
/// no KRL writer here, so revocation is this file plus the certificate's own
/// short lifetime.
pub fn revoked_keys_file(certificates: &[String]) -> String {
    let mut out = String::new();
    for cert in certificates {
        let line = cert.trim();
        if !line.is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn sshd_snippet(public_key: &str) -> String {
    format!(
        "# On every host that should accept these certificates:\n\
         install -d -m 755 /etc/ssh/openwarp\n\
         printf '%s\\n' '{key}' > /etc/ssh/openwarp/ca.pub\n\
         printf '%s\\n' 'TrustedUserCAKeys /etc/ssh/openwarp/ca.pub' >> /etc/ssh/sshd_config\n\
         # reload sshd, then confirm the fingerprint matches {fp}\n\
         #\n\
         # A certificate principal only logs in when it names a local account.\n\
         # For a shared account, set AuthorizedPrincipalsFile and list the\n\
         # principals that account accepts.",
        key = public_key.trim(),
        fp = ca_fingerprint(public_key).unwrap_or_else(|_| "the value shown by ssh-keygen -lf".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_exact_or_prefix_only() {
        assert!(pattern_matches("deploy", "deploy"));
        assert!(!pattern_matches("deploy", "deploy2"));
        assert!(pattern_matches("web-*", "web-1"));
        assert!(pattern_matches("web-*", "web-"));
        assert!(!pattern_matches("web-*", "api-1"));
        assert!(pattern_matches("*", "root"));
        assert!(pattern_matches("*", "anything-at-all"));
    }

    #[test]
    fn patterns_that_could_mean_more_are_rejected() {
        for bad in ["", "web*prod", "*web", "web-*x", "a b", "web\n1", "*x*"] {
            assert!(!valid_pattern(bad), "{:?} must not be a pattern", bad);
            assert!(!pattern_matches(bad, "web-1"), "{:?} must not match anything", bad);
        }
        assert!(!principal_allowed(&["web*prod".into()], "web-1"));
        assert!(principal_allowed(&["web-*".into(), "db-1".into()], "db-1"));
    }

    #[test]
    fn principals_reject_commas_and_spaces() {
        assert!(valid_principal("alice"));
        assert!(valid_principal("deploy@prod-1"));
        assert!(!valid_principal("alice,bob"));
        assert!(!valid_principal("alice bob"));
        assert!(!valid_principal(""));
    }

    #[test]
    fn ttl_cannot_exceed_the_grant_or_the_ceiling() {
        assert_eq!(clamp_ttl(None, 900), 900);
        assert_eq!(clamp_ttl(Some(120), 900), 120);
        assert_eq!(clamp_ttl(Some(99_999), 900), 900);
        assert_eq!(clamp_ttl(Some(99_999), 99_999), MAX_TTL);
        assert_eq!(clamp_ttl(Some(1), 900), 60);
    }

    fn subject_key() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap().public_key().to_openssh().unwrap()
    }

    #[test]
    fn signed_certificate_parses_back_with_the_fields_we_set() {
        let (ca_secret, ca_public) = generate_ca().unwrap();
        let key = subject_key();
        let input = SignInput { public_key: &key, principal: "deploy", key_id: "openwarp:c1", ttl: 600 };
        let signed = sign_user_cert(&ca_secret, &input, false, 1_700_000_000).unwrap();
        assert!(signed.certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "), "{}", signed.certificate);
        assert_eq!(signed.valid_after, 1_700_000_000 - 60);
        assert_eq!(signed.valid_before, 1_700_000_600);
        let d = describe(&signed.certificate).unwrap();
        assert_eq!(d["key_id"], "openwarp:c1");
        assert_eq!(d["principals"], serde_json::json!(["deploy"]));
        assert_eq!(d["cert_type"], "user");
        assert_eq!(d["serial"], signed.serial);
        assert_eq!(signed.serial, describe(&signed.certificate).unwrap()["serial"]);
        assert!(!ca_public.is_empty());
        assert!(ca_fingerprint(&ca_public).unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn a_certificate_for_one_principal_does_not_claim_another() {
        let (ca_secret, _) = generate_ca().unwrap();
        let key = subject_key();
        let input = SignInput { public_key: &key, principal: "deploy", key_id: "openwarp:c2", ttl: 600 };
        let cert = sign_user_cert(&ca_secret, &input, true, 1_700_000_000).unwrap().certificate;
        let described = describe(&cert).unwrap();
        assert_eq!(described["principals"], serde_json::json!(["deploy"]));
        assert!(!described["principals"].as_array().unwrap().iter().any(|p| p == "root"));
    }

    #[test]
    fn revoked_keys_file_is_one_certificate_per_line() {
        let out = revoked_keys_file(&["  a cert  ".into(), String::new(), "b cert\n".into()]);
        assert_eq!(out, "a cert\nb cert\n");
        assert_eq!(revoked_keys_file(&[]), "");
    }

    #[test]
    fn sshd_snippet_names_the_installed_key() {
        let (_, public) = generate_ca().unwrap();
        let snippet = sshd_snippet(&public);
        assert!(snippet.contains(&public));
        assert!(snippet.contains("TrustedUserCAKeys /etc/ssh/openwarp/ca.pub"));
    }
}
