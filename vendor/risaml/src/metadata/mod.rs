//! SAML metadata parsing and shared SP/IdP metadata accessors.

pub mod generate;
pub mod idp;
mod policy;
pub mod sp;
mod write;

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use crate::crypto::MetadataSignatureVerification;
pub use generate::{
    generate_idp_metadata, generate_sp_metadata, try_generate_idp_metadata, Endpoint,
    IdpMetadataConfig, SpMetadataConfig,
};
pub use idp::IdpMetadata;
pub use sp::SpMetadata;

use crate::constants::{Binding, CertUse};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{dom, extract_with_limits, ExtractorField, LocalPath, XmlLimits};
use std::time::SystemTime;
use time::OffsetDateTime;

fn base_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("entityID", &["EntityDescriptor"]).attrs(&["entityID"]),
        ExtractorField::new(
            "sharedCertificate",
            &[
                "EntityDescriptor",
                "~SSODescriptor",
                "KeyDescriptor",
                "KeyInfo",
                "X509Data",
                "X509Certificate",
            ],
        ),
        ExtractorField::new(
            "certificate",
            &["EntityDescriptor", "~SSODescriptor", "KeyDescriptor"],
        )
        .aggregate(&["use"], &["KeyInfo", "X509Data", "X509Certificate"]),
        ExtractorField::new(
            "singleLogoutService",
            &["EntityDescriptor", "~SSODescriptor", "SingleLogoutService"],
        )
        .attrs(&["Binding", "Location"]),
        ExtractorField::new(
            "nameIDFormat",
            &["EntityDescriptor", "~SSODescriptor", "NameIDFormat"],
        ),
    ]
}

/// Normalise a "single object or array of objects" value into a node list.
pub(crate) fn as_object_list(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

fn location_for_binding(value: Option<&Value>, binding: Binding) -> Option<String> {
    let value = value?;
    for obj in as_object_list(value) {
        if obj.get_str("binding") == Some(binding.urn()) {
            return obj.get_str("location").map(str::to_string);
        }
    }
    None
}

/// Parsed entity metadata (the base shared by SP and IdP).
#[derive(Debug, Clone)]
pub struct Metadata {
    xml: String,
    pub(crate) meta: Value,
    valid_until: Option<OffsetDateTime>,
}

impl Metadata {
    /// Parse `xml`, adding the role-specific `extra` extractor fields.
    ///
    /// Rejects documents carrying more than one top-level `<EntityDescriptor>`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits,
    /// extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse(xml: &str, extra: Vec<ExtractorField>) -> Result<Self, SamlError> {
        Self::parse_with_limits(xml, extra, XmlLimits::default())
    }

    /// Parse `xml` with explicit XML parser resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits,
    /// extraction, or the single-`EntityDescriptor` check fails.
    pub fn parse_with_limits(
        xml: &str,
        extra: Vec<ExtractorField>,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        Self::parse_for_role_with_limits(xml, extra, limits, None)
    }

    pub(crate) fn parse_for_role_with_limits(
        xml: &str,
        extra: Vec<ExtractorField>,
        limits: XmlLimits,
        role: Option<&str>,
    ) -> Result<Self, SamlError> {
        let roots = dom::parse_roots_with_limits(xml, limits)?;
        if roots
            .iter()
            .filter(|n| n.local_name == "EntityDescriptor")
            .count()
            > 1
        {
            return Err(SamlError::Xml(
                "ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR".into(),
            ));
        }

        let root = roots.first().filter(|root| roots.len() == 1 && root.local_name == "EntityDescriptor")
            .ok_or_else(|| SamlError::Unsupported("metadata import requires a standalone EntityDescriptor; aggregate parent validity cannot be discarded".into()))?;
        policy::validate_metadata_namespaces(xml)?;
        let roles: Vec<_> = root
            .children
            .iter()
            .filter(|child| {
                role.map_or_else(
                    || {
                        matches!(
                            child.local_name.as_str(),
                            "SPSSODescriptor" | "IDPSSODescriptor"
                        )
                    },
                    |role| child.local_name == role,
                )
            })
            .collect();
        if role.is_some() && roles.is_empty() {
            return Err(SamlError::MissingMetadata(role.unwrap_or_default().into()));
        }
        let valid_until = policy::effective_expiration(root, &roles)?;

        let mut fields = base_fields();
        fields.extend(extra);
        if let Some(role) = role {
            for field in &mut fields {
                if let LocalPath::Single(path) = &mut field.local_path {
                    for element in path {
                        if element == "~SSODescriptor" {
                            *element = role.to_string();
                        }
                    }
                }
            }
        }
        let mut meta = extract_with_limits(xml, &fields, limits)?;

        meta.insert("certificate", policy::certificates_for_roles(&roles)?);

        Ok(Self {
            xml: xml.to_string(),
            meta,
            valid_until,
        })
    }

    /// The original metadata XML.
    pub fn get_metadata(&self) -> &str {
        &self.xml
    }

    /// `entityID`.
    pub fn get_entity_id(&self) -> Option<&str> {
        self.meta.get_str("entityID")
    }

    /// Earliest declared validity deadline across the entity and imported SSO
    /// role descriptors. Missing validity is distinct from cache staleness.
    pub fn valid_until(&self) -> Option<OffsetDateTime> {
        self.valid_until
    }

    /// Enforce metadata validity at its use instant, including after storage.
    /// Approved Errata 05 E94 adds Metadata 4.3.2: expired metadata MUST NOT
    /// be used. No clock skew extends this metadata deadline.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::TimeWindowInvalid`] at or after `validUntil`, or
    /// when the supplied clock cannot be represented.
    pub fn validate_at(&self, now: SystemTime) -> Result<(), SamlError> {
        let now = crate::validator::offset_datetime_from_system_time(now)?;
        if self.valid_until.is_some_and(|deadline| now >= deadline) {
            return Err(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::MetadataValidUntil,
            });
        }
        Ok(())
    }

    /// Declared `<NameIDFormat>` values.
    pub fn get_name_id_format(&self) -> Vec<String> {
        match self.meta.get("nameIDFormat") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(Value::Str(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    /// All X.509 certificates declared for `use` (raw, as written in metadata).
    pub fn x509_certificates(&self, use_: CertUse) -> Vec<String> {
        match self
            .meta
            .get("certificate")
            .and_then(|c| c.get_key(use_.as_str()))
        {
            Some(Value::Str(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// First X.509 certificate declared for `use`.
    pub fn get_x509_certificate(&self, use_: CertUse) -> Option<String> {
        match self
            .meta
            .get("certificate")
            .and_then(|certificates| certificates.get_key(use_.as_str()))
        {
            Some(Value::Str(certificate)) => Some(certificate.clone()),
            Some(Value::Array(certificates)) => certificates
                .iter()
                .find_map(Value::as_str)
                .map(str::to_string),
            Some(Value::Null | Value::Object(_)) | None => None,
        }
    }

    /// `SingleLogoutService` location for `binding`.
    pub fn get_single_logout_service(&self, binding: Binding) -> Option<String> {
        location_for_binding(self.meta.get("singleLogoutService"), binding)
    }

    /// Write the metadata XML to `path`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the filesystem write fails.
    pub fn export_metadata(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::write(path, &self.xml)
    }

    /// Bindings for which a `SingleLogoutService` endpoint is declared.
    pub fn get_support_bindings(&self) -> Vec<Binding> {
        [Binding::Redirect, Binding::Post, Binding::SimpleSign]
            .into_iter()
            .filter(|b| self.get_single_logout_service(*b).is_some())
            .collect()
    }

    /// Verify this metadata document's enveloped signature against trusted
    /// certificate(s) (federation trust anchor). Requires a crypto provider.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, or signed `<EntityDescriptor>` coverage
    /// checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature(&self, trusted_certificates: &[String]) -> Result<bool, SamlError> {
        self.verify_signature_with_limits(trusted_certificates, XmlLimits::default())
    }

    /// Verify this metadata document's signature with explicit XML parser limits.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, or signed `<EntityDescriptor>` coverage
    /// checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature_with_limits(
        &self,
        trusted_certificates: &[String],
        limits: XmlLimits,
    ) -> Result<bool, SamlError> {
        crate::crypto::verify_metadata_signature_with_limits(
            &self.xml,
            trusted_certificates,
            limits,
        )
    }

    /// Verify this metadata document's signature and preserve signed
    /// `<EntityDescriptor>` coverage evidence using default XML parser limits.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, transform policy, or signed
    /// `<EntityDescriptor>` coverage checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature_detailed(
        &self,
        trusted_certificates: &[String],
    ) -> Result<crate::crypto::MetadataSignatureVerification, SamlError> {
        crate::crypto::verify_metadata_signature_detailed(&self.xml, trusted_certificates)
    }

    /// Verify this metadata document's signature and preserve signed
    /// `<EntityDescriptor>` coverage evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, certificate loading,
    /// cryptographic verification, transform policy, or signed
    /// `<EntityDescriptor>` coverage checks fail.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    pub fn verify_signature_detailed_with_limits(
        &self,
        trusted_certificates: &[String],
        limits: XmlLimits,
    ) -> Result<MetadataSignatureVerification, SamlError> {
        crate::crypto::verify_metadata_signature_detailed_with_limits(
            &self.xml,
            trusted_certificates,
            limits,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDPMETA: &str = include_str!("../../tests/fixtures/idpmeta.xml");
    const SPMETA: &str = include_str!("../../tests/fixtures/spmeta.xml");
    const MULTIPLE: &str = include_str!("../../tests/fixtures/multiple_entitydescriptor.xml");

    #[test]
    fn rejects_multiple_entity_descriptors() {
        assert!(Metadata::parse(MULTIPLE, Vec::new()).is_err());
    }

    #[test]
    fn first_certificate_lookup_preserves_rolling_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let metadata = IdpMetadata::from_xml(include_str!(
            "../../tests/fixtures/misc/idpmeta_rollingcert.xml"
        ))?;
        let certificates = metadata.x509_certificates(CertUse::Signing);
        assert_eq!(certificates.len(), 2);
        assert_eq!(
            metadata.get_x509_certificate(CertUse::Signing).as_ref(),
            certificates.first()
        );
        Ok(())
    }

    #[test]
    fn parses_idp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdpMetadata::from_xml(IDPMETA)?;
        assert_eq!(
            idp.get_entity_id(),
            Some("https://idp.example.com/metadata")
        );
        assert!(idp.is_want_authn_requests_signed());
        assert_eq!(
            idp.get_single_sign_on_service(Binding::Redirect).as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        assert!(idp.get_x509_certificate(CertUse::Signing).is_some());
        assert!(idp
            .get_name_id_format()
            .iter()
            .any(|f| f.contains("persistent")));
        Ok(())
    }

    #[test]
    fn parses_sp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert_eq!(sp.get_entity_id(), Some("https://sp.example.org/metadata"));
        assert!(sp.is_want_assertions_signed());
        assert!(sp.is_authn_request_signed());
        assert_eq!(
            sp.get_assertion_consumer_service(Binding::Post).as_deref(),
            Some("https://sp.example.org/sp/sso")
        );
        assert_eq!(
            sp.get_single_logout_service(Binding::Redirect).as_deref(),
            Some("https://sp.example.org/sp/slo")
        );
        assert!(sp.get_x509_certificate(CertUse::Encryption).is_some());
        Ok(())
    }

    #[test]
    fn support_bindings_and_export() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert!(sp.get_support_bindings().contains(&Binding::Redirect));
        let mut path = std::env::temp_dir();
        path.push(format!("risaml_md_{}.xml", std::process::id()));
        sp.export_metadata(&path)?;
        assert_eq!(std::fs::read_to_string(&path)?, sp.get_metadata());
        std::fs::remove_file(&path)?;
        Ok(())
    }
}
