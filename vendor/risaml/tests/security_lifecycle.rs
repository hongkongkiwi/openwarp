use std::time::SystemTime;

use risaml::binding::base64_encode;
use risaml::constants::{Binding, CertUse, ParserType};
use risaml::error::TimeWindowField;
use risaml::flow::{flow, FlowOptions, HttpRequest};
use risaml::metadata::{IdpMetadata, SpMetadata};
use risaml::{
    AcsEndpoint, BrowserInput, EntityId, IdpDescriptor, MetadataTrustPolicy, PendingAuthnRequest,
    RelayStateParam, ReplayPolicy, Saml, SamlError, SamlInstant, SamlValidationContext, SpConfig,
    SpValidationPolicy, SsoResponse, SsoResponseBinding, StartSso,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const RESPONSE: &str = include_str!("fixtures/response.xml");

fn instant(value: &str) -> Result<SystemTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339).map(SystemTime::from)
}

fn parse_condition(condition: &str) -> Result<risaml::flow::FlowResult, SamlError> {
    let xml = RESPONSE.replace(
        "</saml:Conditions>",
        &format!("{condition}</saml:Conditions>"),
    );
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.now = Some(
        instant("2023-01-01T00:00:00Z").map_err(|error| SamlError::Invalid(error.to_string()))?,
    );
    flow(
        &options,
        &HttpRequest::post(vec![("SAMLResponse".into(), base64_encode(xml.as_bytes()))]),
    )
}

#[test]
fn indeterminate_conditions_are_rejected() {
    for condition in [
        r#"<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="custom:Unknown"/>"#,
        r#"<custom:Condition xmlns:custom="urn:custom"/>"#,
        r#"<custom:OneTimeUse xmlns:custom="urn:custom"/>"#,
        r#"<saml:ProxyRestriction Count="-1"/>"#,
        r#"<saml:OneTimeUse><custom:Unknown xmlns:custom="urn:custom"/></saml:OneTimeUse>"#,
        r#"<saml:ProxyRestriction><saml:OneTimeUse/></saml:ProxyRestriction>"#,
        r#"<saml:ProxyRestriction Count="0"/><saml:ProxyRestriction/>"#,
        r#"<saml:OneTimeUse/><saml:OneTimeUse/>"#,
    ] {
        assert!(
            matches!(
                parse_condition(condition),
                Err(SamlError::ProtocolProfile(_))
            ),
            "{condition}"
        );
    }
    let xml = RESPONSE.replace("<saml:Conditions ", "<saml:Conditions extra=\"unknown\" ");
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    assert!(matches!(
        flow(
            &options,
            &HttpRequest::post(vec![("SAMLResponse".into(), base64_encode(xml.as_bytes()))])
        ),
        Err(SamlError::ProtocolProfile(_))
    ));
}

#[test]
fn standard_use_conditions_are_understood_without_wrong_audience_semantics(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = parse_condition(
        r#"<saml:OneTimeUse/><saml:ProxyRestriction Count="0"><saml:Audience>https://another.example.com/proxy</saml:Audience></saml:ProxyRestriction>"#,
    )?;
    let session = risaml::SsoSession::try_from(flow)?;
    assert!(session.one_time_use());
    assert!(session
        .proxy_restriction_xml()
        .is_some_and(|xml| xml.contains("Count=\"0\"")));
    let mut validation = SamlValidationContext::new(
        instant("2023-01-01T00:00:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    );
    assert!(matches!(
        session.check_and_store_replay(&mut validation),
        Err(SamlError::ProtocolProfile(_))
    ));
    parse_condition(r#"<saml:ProxyRestriction Count="+999999999999999999999999999999999"/>"#)?;
    parse_condition(r#"<saml:ProxyRestriction Count="-0"/>"#)?;
    Ok(())
}

#[test]
fn one_time_use_is_accepted_once_with_replay_storage() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Default)]
    struct Cache(std::collections::HashSet<String>);
    impl risaml::ReplayCache for Cache {
        fn check_and_store(
            &mut self,
            key: risaml::ReplayKey,
            _expires_at: SystemTime,
        ) -> Result<(), SamlError> {
            let key = key.cache_key();
            if self.0.insert(key.clone()) {
                Ok(())
            } else {
                Err(SamlError::ReplayDetected { key })
            }
        }
    }
    let session = risaml::SsoSession::try_from(parse_condition("<saml:OneTimeUse/>")?)?;
    let mut cache = Cache::default();
    let mut validation = SamlValidationContext::new(
        instant("2023-01-01T00:00:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );
    session.check_and_store_replay(&mut validation)?;
    assert!(matches!(
        session.check_and_store_replay(&mut validation),
        Err(SamlError::ReplayDetected { .. })
    ));
    Ok(())
}

fn metadata(roles: &str, expiry: &str) -> String {
    format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://peer.example.com/metadata"{expiry}>{roles}</EntityDescriptor>"#
    )
}

fn key(use_: &str, certificate: &str) -> String {
    format!(
        r#"<KeyDescriptor{use_}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"#
    )
}

#[test]
fn role_and_key_purpose_are_preserved_including_single_key_and_rollover(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = metadata(
        &format!(
            r#"<SPSSODescriptor>{sp}</SPSSODescriptor><IDPSSODescriptor>{enc}{sig1}{shared}{sig2}</IDPSSODescriptor>"#,
            sp = key(r#" use="signing""#, "sp-signing"),
            enc = key(r#" use="encryption""#, "idp-encryption"),
            sig1 = key(r#" use="signing""#, "idp-current"),
            shared = key("", "idp-shared"),
            sig2 = key(r#" use="signing""#, "idp-next")
        ),
        "",
    );
    let idp = IdpMetadata::from_xml(&xml)?;
    assert_eq!(
        idp.x509_certificates(CertUse::Signing),
        ["idp-current", "idp-shared", "idp-next"]
    );
    assert_eq!(
        idp.x509_certificates(CertUse::Encryption),
        ["idp-encryption", "idp-shared"]
    );
    let sp = SpMetadata::from_xml(&xml)?;
    assert_eq!(sp.x509_certificates(CertUse::Signing), ["sp-signing"]);
    assert!(sp.x509_certificates(CertUse::Encryption).is_empty());
    assert!(IdpMetadata::from_xml(&metadata(
        &format!(
            "<IDPSSODescriptor>{}</IDPSSODescriptor>",
            key(r#" use="unknown""#, "bad")
        ),
        ""
    ))
    .is_err());
    Ok(())
}

#[test]
fn metadata_expiration_is_retained_and_checked_at_each_use(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = metadata(
        r#"<SPSSODescriptor validUntil="2020-01-01T00:00:00Z"/><IDPSSODescriptor validUntil="2026-01-01T00:00:00Z"/>"#,
        r#" validUntil="2027-01-01T00:00:00Z""#,
    );
    let idp = IdpMetadata::from_xml(&xml)?;
    idp.validate_at(instant("2025-12-31T23:59:59Z")?)?;
    assert!(matches!(
        idp.validate_at(instant("2026-01-01T00:00:00Z")?),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::MetadataValidUntil
        })
    ));
    let xml = metadata(
        r#"<IDPSSODescriptor validUntil="2028-01-01T00:00:00Z"/>"#,
        r#" validUntil="2026-01-01T00:00:00Z""#,
    );
    assert_eq!(
        IdpMetadata::from_xml(&xml)?.valid_until(),
        Some(OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339)?)
    );
    assert!(IdpMetadata::from_xml(&metadata(
        "<IDPSSODescriptor/>",
        r#" validUntil="not-a-date""#
    ))
    .is_err());
    assert!(IdpMetadata::from_xml(&format!(
        "<EntitiesDescriptor validUntil=\"2020-01-01T00:00:00Z\">{xml}</EntitiesDescriptor>"
    ))
    .is_err());
    Ok(())
}

fn sp() -> Result<Saml<risaml::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )
}

#[test]
fn typed_start_rejects_expired_metadata_and_invalid_pending_lifetimes(
) -> Result<(), Box<dyn std::error::Error>> {
    let roles = r#"<IDPSSODescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/sso"/></IDPSSODescriptor>"#;
    let expired = IdpDescriptor::from_metadata_xml(
        &metadata(roles, r#" validUntil="2020-01-01T00:00:00Z""#),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert!(matches!(
        sp()?.start_sso(&expired, StartSso::post()),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::MetadataValidUntil
        })
    ));
    let current = IdpDescriptor::from_metadata_xml(
        &metadata(roles, ""),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let sp = sp()?;
    for lifetime in [std::time::Duration::ZERO, std::time::Duration::MAX] {
        assert!(matches!(
            sp.start_sso(&current, StartSso::post().pending_lifetime(lifetime)),
            Err(SamlError::TimeWindowInvalid {
                field: TimeWindowField::PendingRequestExpiration
            })
        ));
    }
    let started = sp.start_sso(&current, StartSso::post())?;
    assert!(started.pending.issued_at().is_some());
    assert!(started.pending.expires_at().is_some());
    Ok(())
}

#[test]
fn expired_pending_request_is_rejected_before_response_processing(
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = IdpDescriptor::from_metadata_xml(
        &metadata("<IDPSSODescriptor/>", ""),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let pending = PendingAuthnRequest::try_new(
        risaml::MessageId::try_new("_request")?,
        RelayStateParam::absent(),
        AcsEndpoint::post("https://sp.example.com/acs")?,
        SsoResponseBinding::Post,
        peer.entity_id().clone(),
    )?
    .with_issue_instant(SamlInstant::try_new("2026-01-01T00:00:00Z")?)
    .with_expiration(SamlInstant::try_new("2026-01-01T00:05:00Z")?);
    assert!(matches!(
        sp()?.finish_sso(
            &peer,
            &pending,
            BrowserInput::<SsoResponse>::post(Vec::new()),
            SamlValidationContext::new(
                instant("2026-01-01T00:05:00Z")?,
                ReplayPolicy::DisabledForCompatibility
            )
        ),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::PendingRequestExpiration
        })
    ));
    Ok(())
}

#[test]
fn consumed_attributes_cannot_be_shadowed_by_xmlns_or_qualified_aliases(
) -> Result<(), Box<dyn std::error::Error>> {
    let doc = risaml::xml::dom::parse(
        r#"<root xmlns:ID="urn:alias" xmlns:x="urn:extension" x:ID="other" ID="real"/>"#,
    )?;
    assert_eq!(doc.root.attr("ID"), Some("real"));
    assert_eq!(doc.root.attr("x:ID"), Some("other"));
    let aliased = metadata(
        "<IDPSSODescriptor/>",
        r#" xmlns:x="urn:extension" x:validUntil="2020-01-01T00:00:00Z""#,
    );
    assert!(IdpMetadata::from_xml(&aliased).is_err());
    Ok(())
}
