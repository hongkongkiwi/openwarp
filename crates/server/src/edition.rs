//! Edition resolution and the offline enterprise licence.
//!
//! OpenWarp ships two plans. A self-hosted installation needs no key and keeps
//! every core feature. An enterprise licence is a compact ES256 token signed by
//! the vendor key; verification is entirely offline and needs no activation
//! server, seat count or network access.
//!
//! The token is supplied through `OPENWARP_LICENSE` (inline) or
//! `OPENWARP_LICENSE_FILE` (path). `OPENWARP_LICENSE=none` forces the
//! self-hosted plan, and `development` is accepted only by debug builds outside
//! `OPENWARP_ENV=production`.

use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Vendor public key for the `ow-2026-01` signing key. Replace both this and
/// `KID` together when the signing key rotates.
#[cfg_attr(test, allow(dead_code))]
const ENTERPRISE_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaULDF3OOxDZ43w3ZX6AJNy8lqtAE
iYLvskdhsrb/1qCBYvgDe89K72F/1Fo65TCEl+MSnqFkWod6c5rizULuaA==
-----END PUBLIC KEY-----";
const KID: &str = "ow-2026-01";
const ISSUER: &str = "openwarp";
const SUBJECT: &str = "enterprise";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    SelfHosted,
    Enterprise,
}

/// Features that require the enterprise plan. Everything not listed here is
/// part of the self-hosted plan and never consults the licence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    OrgSso,
    OrgOidc,
    DirectorySync,
    AuditStreaming,
}

impl Feature {
    pub fn key(self) -> &'static str {
        match self {
            Feature::OrgSso => "org_sso",
            Feature::OrgOidc => "org_oidc",
            Feature::DirectorySync => "directory_sync",
            Feature::AuditStreaming => "audit_streaming",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Feature::OrgSso => "SAML single sign-on",
            Feature::OrgOidc => "workspace OIDC single sign-on",
            Feature::DirectorySync => "directory sign-in and SCIM provisioning",
            Feature::AuditStreaming => "audit log streaming",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LicenseState {
    tier: Tier,
    customer: String,
    expires_at: i64,
    development: bool,
    warning: String,
}

impl LicenseState {
    pub fn self_hosted() -> Self {
        Self { tier: Tier::SelfHosted, customer: String::new(), expires_at: 0, development: false, warning: String::new() }
    }

    fn with_warning(warning: String) -> Self {
        Self { warning, ..Self::self_hosted() }
    }

    fn enterprise(customer: String, expires_at: i64, development: bool) -> Self {
        Self { tier: Tier::Enterprise, customer, expires_at, development, warning: String::new() }
    }

    pub fn from_env() -> Self {
        let raw = crate::envcfg::var("OPENWARP_LICENSE").ok().filter(|v| !v.trim().is_empty())
            .or_else(|| crate::envcfg::var("OPENWARP_LICENSE_FILE").ok().filter(|v| !v.trim().is_empty())
                .and_then(|path| std::fs::read_to_string(path.trim()).ok()));
        let production = crate::envcfg::var("OPENWARP_ENV").map(|v| v.trim() == "production").unwrap_or(false);
        Self::resolve(raw.as_deref(), production, cfg!(debug_assertions))
    }

    /// Pure resolution used by tests. `raw` is the configured value, not the
    /// environment itself, so unit tests do not race on process state.
    pub fn resolve(raw: Option<&str>, production: bool, debug: bool) -> Self {
        let value = raw.map(str::trim).unwrap_or("");
        if value.is_empty() || value.eq_ignore_ascii_case("none") {
            return Self::self_hosted();
        }
        if value.eq_ignore_ascii_case("development") {
            if debug && !production {
                return Self::enterprise("development".into(), 0, true);
            }
            return Self::with_warning("the development licence is ignored by release and production builds".into());
        }
        match verify(value) {
            Ok(claims) => Self::enterprise(claims.customer, claims.exp, false),
            Err(e) => Self::with_warning(e),
        }
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn is_enterprise(&self) -> bool {
        self.tier == Tier::Enterprise
    }

    pub fn allows(&self, _feature: Feature) -> bool {
        self.is_enterprise()
    }

    pub fn status(&self) -> Value {
        json!({
            "tier": if self.is_enterprise() { "enterprise" } else { "self-hosted" },
            "enterprise": self.is_enterprise(),
            "customer": if self.customer.is_empty() { Value::Null } else { json!(self.customer) },
            "expires_at": if self.expires_at == 0 { Value::Null } else { json!(self.expires_at) },
            "development": self.development,
            "warning": if self.warning.is_empty() { Value::Null } else { json!(self.warning) },
        })
    }
}

/// The 403 body shared by every gated route. `code` and `feature` are stable
/// machine-readable fields; `error` is for humans and the console.
pub fn locked(feature: Feature) -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(json!({
        "error": format!("{} requires an OpenWarp enterprise license", feature.label()),
        "code": "enterprise_feature",
        "feature": feature.key(),
        "tier": "self-hosted",
    })))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub v: u8,
    pub iss: String,
    pub sub: String,
    pub customer: String,
    pub iat: i64,
    pub exp: i64,
}

fn public_key_pem() -> &'static str {
    #[cfg(test)]
    { TEST_PUBLIC_KEY_PEM }
    #[cfg(not(test))]
    { ENTERPRISE_PUBLIC_KEY_PEM }
}

pub fn verify(token: &str) -> Result<Claims, String> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    let key = DecodingKey::from_ec_pem(public_key_pem().as_bytes()).map_err(|e| format!("license public key is invalid: {}", e))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation.leeway = 120;
    let data = decode::<Claims>(token, &key, &validation).map_err(|e| format!("license rejected: {}", e))?;
    if data.header.kid.as_deref() != Some(KID) {
        return Err("license was signed by an unknown key".into());
    }
    let claims = data.claims;
    if claims.v != 1 {
        return Err(format!("license version {} is not supported", claims.v));
    }
    if claims.sub != SUBJECT {
        return Err("license is not an enterprise license".into());
    }
    if claims.customer.trim().is_empty() {
        return Err("license is missing the customer name".into());
    }
    let now = crate::clock::now();
    if claims.iat > now + 300 {
        return Err("license was issued in the future; check the system clock".into());
    }
    Ok(claims)
}

#[cfg(test)]
const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEixwaaLD58fyx/jJxqi6bCKTiNvAZ
dBybJHUCmbfRWE2nnDTJOUSNfVKETuYnx4t7rdu19sMf5rQZSHE/puSyTw==
-----END PUBLIC KEY-----";

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgldGjnxKZdsFy/ySh
1vMU0SPKg5zl7mAyMe0eQWpOf8yhRANCAASLHBposPnx/LH+MnGqLpsIpOI28Bl0
HJskdQKZt9FYTaecNMk5RI19UoRO5ifHi3ut27X2wx/mtBlIcT+m5LJP
-----END PRIVATE KEY-----";

    fn token(customer: &str, exp: i64) -> String {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KID.into());
        let claims = Claims { v: 1, iss: ISSUER.into(), sub: SUBJECT.into(), customer: customer.into(), iat: now, exp };
        encode(&header, &claims, &EncodingKey::from_ec_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn no_license_is_the_self_hosted_plan() {
        let state = LicenseState::resolve(None, false, false);
        assert_eq!(state.tier(), Tier::SelfHosted);
        for feature in [Feature::OrgSso, Feature::OrgOidc, Feature::DirectorySync, Feature::AuditStreaming] {
            assert!(!state.allows(feature), "{} must be locked without a license", feature.key());
        }
        assert!(LicenseState::resolve(Some("none"), false, true).tier() == Tier::SelfHosted);
    }

    #[test]
    fn a_signed_license_unlocks_every_enterprise_feature() {
        let state = LicenseState::resolve(Some(&token("Acme Ltd", 4102444800)), true, false);
        assert_eq!(state.tier(), Tier::Enterprise);
        assert_eq!(state.status()["customer"], json!("Acme Ltd"));
        assert!(state.allows(Feature::OrgSso));
        assert!(state.allows(Feature::AuditStreaming));
    }

    #[test]
    fn expired_tampered_and_misissued_tokens_are_rejected() {
        let expired = LicenseState::resolve(Some(&token("Acme Ltd", 1000)), false, false);
        assert_eq!(expired.tier(), Tier::SelfHosted, "expired licenses fall back to self-hosted");
        assert!(expired.status()["warning"].as_str().unwrap().contains("license"));

        let good = token("Acme Ltd", 4102444800);
        let mut parts: Vec<&str> = good.split('.').collect();
        let mut payload = String::from(parts[1]);
        payload.replace_range(0..1, if payload.starts_with('e') { "f" } else { "e" });
        parts[1] = &payload;
        let tampered = LicenseState::resolve(Some(&parts.join(".")), false, false);
        assert_eq!(tampered.tier(), Tier::SelfHosted);

        let wrong_alg = encode(&Header::new(Algorithm::HS256), &Claims { v: 1, iss: ISSUER.into(), sub: SUBJECT.into(), customer: "Acme Ltd".into(), iat: 0, exp: 4102444800 }, &EncodingKey::from_secret(b"secret")).unwrap();
        assert_eq!(LicenseState::resolve(Some(&wrong_alg), false, false).tier(), Tier::SelfHosted);
    }

    #[test]
    fn development_licenses_are_debug_only() {
        assert_eq!(LicenseState::resolve(Some("development"), false, true).tier(), Tier::Enterprise);
        assert_eq!(LicenseState::resolve(Some("development"), true, true).tier(), Tier::SelfHosted);
        assert_eq!(LicenseState::resolve(Some("development"), false, false).tier(), Tier::SelfHosted);
    }
}
