use crate::constants::namespace;
use crate::error::{SamlError, TimeWindowField};
use crate::util::Value;
use crate::xml::{dom::Node, parse_saml_utc_date_time};
use quick_xml::events::{attributes::Attribute, Event};
use quick_xml::name::{QName, ResolveResult};
use quick_xml::{NsReader, XmlVersion};
use std::borrow::Cow;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

// Metadata 2.3.2/2.4.1 and approved Errata E94: entity validity applies to
// contained roles; an earlier role deadline cannot be extended by its parent.
pub(super) fn effective_expiration(
    root: &Node,
    roles: &[&Node],
) -> Result<Option<OffsetDateTime>, SamlError> {
    let mut earliest = None;
    for node in std::iter::once(root).chain(roles.iter().copied()) {
        if let Some(value) = node.attr("validUntil") {
            let value = parse_saml_utc_date_time(value).ok_or(SamlError::TimeWindowInvalid {
                field: TimeWindowField::MetadataValidUntil,
            })?;
            let deadline = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                SamlError::TimeWindowInvalid {
                    field: TimeWindowField::MetadataValidUntil,
                }
            })?;
            earliest =
                Some(earliest.map_or(deadline, |current: OffsetDateTime| current.min(deadline)));
        }
    }
    Ok(earliest)
}

// Metadata 2.4.1.1: an explicit use restricts key purpose. Absence means the
// key is available for both purposes, independently of how many keys exist.
pub(super) fn certificates_for_roles(roles: &[&Node]) -> Result<Value, SamlError> {
    let mut signing = Vec::new();
    let mut encryption = Vec::new();
    for role in roles {
        for descriptor in role
            .children
            .iter()
            .filter(|child| child.local_name == "KeyDescriptor")
        {
            let purpose = descriptor.attr("use");
            if !matches!(purpose, None | Some("signing" | "encryption")) {
                return Err(SamlError::ProtocolProfile(
                    "invalid metadata KeyDescriptor use".into(),
                ));
            }
            for info in descriptor
                .children
                .iter()
                .filter(|child| child.local_name == "KeyInfo")
            {
                for data in info
                    .children
                    .iter()
                    .filter(|child| child.local_name == "X509Data")
                {
                    for certificate in data
                        .children
                        .iter()
                        .filter(|child| child.local_name == "X509Certificate")
                    {
                        if purpose != Some("encryption") {
                            signing.push(Value::Str(certificate.text.clone()));
                        }
                        if purpose != Some("signing") {
                            encryption.push(Value::Str(certificate.text.clone()));
                        }
                    }
                }
            }
        }
    }
    Ok(Value::Object(vec![
        ("signing".into(), Value::Array(signing)),
        ("encryption".into(), Value::Array(encryption)),
    ]))
}

pub(super) fn validate_metadata_namespaces(xml: &str) -> Result<(), SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    loop {
        let decoder = reader.decoder();
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let resolved = match resolved {
            ResolveResult::Bound(value) => Some(
                Attribute {
                    key: QName(b"xmlns"),
                    value: Cow::Borrowed(value.as_ref()),
                }
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
                .map_err(|error| SamlError::Xml(error.to_string()))?
                .into_owned(),
            ),
            ResolveResult::Unbound => None,
            ResolveResult::Unknown(_) => Some(String::new()),
        };
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let local = element.local_name().as_ref().to_vec();
                let parent = stack.last().map(Vec::as_slice);
                let expected = match (parent, local.as_slice()) {
                    (None, b"EntityDescriptor")
                    | (Some(b"EntityDescriptor"), b"SPSSODescriptor" | b"IDPSSODescriptor")
                    | (
                        Some(b"SPSSODescriptor" | b"IDPSSODescriptor"),
                        b"KeyDescriptor"
                        | b"SingleLogoutService"
                        | b"NameIDFormat"
                        | b"SingleSignOnService"
                        | b"AssertionConsumerService",
                    ) => Some(namespace::METADATA),
                    _ => None,
                };
                if let Some(expected) = expected {
                    // Preserve the raw API's unqualified metadata compatibility;
                    // qualified names must identify the consumed vocabulary.
                    if resolved.as_deref().is_some_and(|actual| actual != expected) {
                        return Err(SamlError::ProtocolProfile(
                            "metadata element has an invalid namespace".into(),
                        ));
                    }
                    let consumed: &[&[u8]] = &[
                        b"entityID",
                        b"validUntil",
                        b"use",
                        b"Binding",
                        b"Location",
                        b"index",
                        b"isDefault",
                        b"WantAuthnRequestsSigned",
                        b"WantAssertionsSigned",
                        b"AuthnRequestsSigned",
                    ];
                    for attribute in element.attributes() {
                        let attribute =
                            attribute.map_err(|error| SamlError::Xml(error.to_string()))?;
                        if attribute.key.as_namespace_binding().is_none()
                            && attribute.key.as_ref().contains(&b':')
                            && consumed.contains(&attribute.key.local_name().as_ref())
                        {
                            return Err(SamlError::ProtocolProfile(
                                "consumed metadata attributes must be unqualified".into(),
                            ));
                        }
                    }
                }
                if !empty {
                    stack.push(local);
                }
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => return Ok(()),
            _ => {}
        }
    }
}
