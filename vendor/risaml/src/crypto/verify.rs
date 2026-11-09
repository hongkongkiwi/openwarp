//! XML-DSig verification and anti-wrapping checks, delegating cryptography to
//! the selected `ribergshamra` provider.
//!
//! Security model:
//! - `trusted_keys_only`: the signature is verified against the certificate(s)
//!   declared in IdP metadata, never an attacker-supplied inline cert.
//! - `strict_verification`: ribergshamra enforces that each signed reference
//!   targets the document element, an ancestor, or a sibling of the Signature.
//! - Explicit XSW guard: reject any `Assertion`/`Signature` nested under
//!   `SubjectConfirmationData`.
//! - XML-DSig signatures outside message-level or direct assertion-level
//!   positions are rejected before backend processing.
//! - Every backend-visible XML-DSig signature is checked for same-document
//!   references and content-preserving transforms before backend processing.
//! - Only content covered by a verified reference is returned for extraction.

use super::keys::load_certificate;
use crate::constants::transform_algorithm;
use crate::error::{ReferenceResolutionReason, SamlError, SignatureVerificationReason};
use crate::util::normalize_cert_string;
use crate::xml::dom::{self, Node, XmlLimits};
use quick_xml::encoding::Decoder;
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{QName, ResolveResult};
use quick_xml::{NsReader, XmlVersion};
use ribergshamra::{verify, verify_all, DsigContext, KeysManager, VerifiedReference, VerifyResult};
use std::borrow::Cow;
use std::collections::HashSet;

fn children_named<'a>(node: &'a Node, name: &str) -> Vec<&'a Node> {
    node.children
        .iter()
        .filter(|c| c.local_name == name)
        .collect()
}

fn has_child(node: &Node, name: &str) -> bool {
    node.children.iter().any(|c| c.local_name == name)
}

fn saml_signature_candidates(root: &Node) -> Vec<&Node> {
    let mut signatures = children_named(root, "Signature");
    for assertion in children_named(root, "Assertion") {
        signatures.extend(children_named(assertion, "Signature"));
    }
    signatures
}

fn has_descendant(node: &Node, names: &[&str]) -> bool {
    node.children
        .iter()
        .any(|c| names.contains(&c.local_name.as_str()) || has_descendant(c, names))
}

/// XSW guard: `Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData//(Assertion|Signature)`.
fn wrapping_detected(root: &Node) -> bool {
    for assertion in children_named(root, "Assertion") {
        for subject in children_named(assertion, "Subject") {
            for sc in children_named(subject, "SubjectConfirmation") {
                for scd in children_named(sc, "SubjectConfirmationData") {
                    if has_descendant(scd, &["Assertion", "Signature"]) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn saml_id_attr(name: &str) -> bool {
    matches!(name, "ID" | "AssertionID")
}

fn duplicate_saml_id(node: &Node, seen: &mut HashSet<String>) -> Option<String> {
    for (name, value) in &node.attrs {
        // The provider can inspect aliases by local name. Keep the duplicate-ID
        // guard conservative even though consumed SAML attributes are exact.
        let local_name = name.rsplit(':').next().unwrap_or(name);
        if saml_id_attr(local_name) && !value.is_empty() && !seen.insert(value.clone()) {
            return Some(value.clone());
        }
    }
    node.children
        .iter()
        .find_map(|child| duplicate_saml_id(child, seen))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifiedTarget {
    WholeDocument,
    Id(String),
}

fn reference_resolution(reason: ReferenceResolutionReason) -> SamlError {
    SamlError::ReferenceResolution { reason }
}

fn verified_target_from_uri(uri: &str) -> Result<VerifiedTarget, SamlError> {
    if uri.is_empty() || uri == "#xpointer(/)" {
        return Ok(VerifiedTarget::WholeDocument);
    }

    let fragment = uri
        .strip_prefix('#')
        .ok_or_else(|| reference_resolution(ReferenceResolutionReason::ExternalReference))?;
    if fragment.is_empty() {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    if let Some(id) = fragment
        .strip_prefix("xpointer(id('")
        .and_then(|rest| rest.strip_suffix("'))"))
    {
        if id.is_empty() {
            return Err(reference_resolution(
                ReferenceResolutionReason::UnsupportedReferenceUri,
            ));
        }
        return Ok(VerifiedTarget::Id(id.to_string()));
    }
    if fragment.starts_with("xpointer(") {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    Ok(VerifiedTarget::Id(fragment.to_string()))
}

fn verified_targets(references: &[VerifiedReference]) -> Result<Vec<VerifiedTarget>, SamlError> {
    if references.is_empty() {
        return Err(reference_resolution(
            ReferenceResolutionReason::MissingSignatureReference,
        ));
    }

    let mut targets = Vec::with_capacity(references.len());
    for reference in references {
        if is_external_reference(&reference.uri) {
            return Err(reference_resolution(
                ReferenceResolutionReason::ExternalReference,
            ));
        }
        if !reference.digest_verified {
            return Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::ReferenceDigest,
            });
        }
        let target = verified_target_from_uri(&reference.uri)?;
        if matches!(target, VerifiedTarget::Id(_)) && reference.resolved_node.is_none() {
            return Err(reference_resolution(
                ReferenceResolutionReason::UnresolvedReference,
            ));
        }
        targets.push(target);
    }
    Ok(targets)
}

fn node_saml_id(node: &Node) -> Option<&str> {
    node.attr("ID").or_else(|| node.attr("AssertionID"))
}

fn target_matches_node(targets: &[VerifiedTarget], node: &Node) -> bool {
    targets.iter().any(|target| match target {
        VerifiedTarget::WholeDocument => true,
        VerifiedTarget::Id(id) => node_saml_id(node).is_some_and(|node_id| node_id == id),
    })
}

fn id_target_matches_node(targets: &[VerifiedTarget], node: &Node) -> bool {
    targets.iter().any(|target| match target {
        VerifiedTarget::WholeDocument => false,
        VerifiedTarget::Id(id) => node_saml_id(node).is_some_and(|node_id| node_id == id),
    })
}

fn response_is_covered(targets: &[VerifiedTarget], root: &Node) -> bool {
    target_matches_node(targets, root)
}

fn verified_content_not_covered() -> SamlError {
    SamlError::SignedReferenceMismatch
}

const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const XML_C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XML_C14N_10_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const XML_C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const XML_C14N_11_WITH_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

fn signature_transform_preserves_content(algorithm: &str) -> bool {
    matches!(
        algorithm,
        transform_algorithm::ENVELOPED_SIGNATURE
            | transform_algorithm::EXC_C14N
            | EXC_C14N_WITH_COMMENTS
            | XML_C14N_10
            | XML_C14N_10_WITH_COMMENTS
            | XML_C14N_11
            | XML_C14N_11_WITH_COMMENTS
    )
}

fn ensure_reference_transforms_preserve_content(reference: &Node) -> Result<(), SamlError> {
    for transforms in children_named(reference, "Transforms") {
        for transform in children_named(transforms, "Transform") {
            if transform
                .attr("Algorithm")
                .is_some_and(signature_transform_preserves_content)
            {
                continue;
            }
            return Err(verified_content_not_covered());
        }
    }
    Ok(())
}

// SAML Core 5.4.4 (OASIS Standard 2005, unchanged by Approved Errata 05)
// permits verifiers to reject other reference transforms. If
// accepted, they must ensure that no SAML content is excluded. An ID match alone
// cannot establish that guarantee for XPath, XSLT, or other filtering transforms.
// Keep the existing metadata-supported canonicalization methods: they preserve
// message content, as does removal of the enveloped Signature itself.
fn ensure_signature_transforms_preserve_content(signatures: &[&Node]) -> Result<(), SamlError> {
    for signature in signatures {
        for signed_info in children_named(signature, "SignedInfo") {
            for reference in children_named(signed_info, "Reference") {
                ensure_reference_transforms_preserve_content(reference)?;
            }
        }
    }
    Ok(())
}

fn ensure_metadata_signature_transforms_preserve_descriptor(root: &Node) -> Result<(), SamlError> {
    if root.local_name != "EntityDescriptor" {
        return Ok(());
    }

    ensure_signature_transforms_preserve_content(&children_named(root, "Signature"))
}

fn verified_root_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
) -> Result<String, SamlError> {
    if target_matches_node(targets, root) {
        return Ok(xml[root.start..root.end].to_string());
    }
    Err(verified_content_not_covered())
}

/// Return the source of the content covered by a verified reference: the lone
/// `<Assertion>`, a consumed root element, or the whole `<Response>` when
/// assertions are encrypted.
fn verified_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
) -> Result<Option<String>, SamlError> {
    if root.local_name == "Assertion" {
        return verified_root_content(root, xml, targets).map(Some);
    }
    if root.local_name.contains("Response") {
        let assertions = children_named(root, "Assertion");
        if assertions.len() > 1 {
            return Err(SamlError::PotentialWrappingAttack);
        }
        if assertions.len() == 1 {
            let a = assertions[0];
            if id_target_matches_node(targets, a) || response_is_covered(targets, root) {
                return Ok(Some(xml[a.start..a.end].to_string()));
            }
            return Err(verified_content_not_covered());
        }
        if has_child(root, "EncryptedAssertion") {
            if response_is_covered(targets, root) {
                return Ok(Some(xml[root.start..root.end].to_string()));
            }
            return Err(verified_content_not_covered());
        }
    }
    if root.local_name == "EntityDescriptor" {
        if target_matches_node(targets, root) {
            return Ok(Some(xml[root.start..root.end].to_string()));
        }
        return Err(verified_content_not_covered());
    }
    if matches!(
        root.local_name.as_str(),
        "AuthnRequest" | "LogoutRequest" | "LogoutResponse"
    ) {
        return verified_root_content(root, xml, targets).map(Some);
    }
    Ok(None)
}

fn assertion_is_directly_covered(root: &Node, targets: &[VerifiedTarget]) -> bool {
    if root.local_name == "Assertion" {
        return target_matches_node(targets, root);
    }
    if root.local_name.contains("Response") {
        let assertions = children_named(root, "Assertion");
        return assertions.len() == 1 && id_target_matches_node(targets, assertions[0]);
    }
    false
}

/// True for a signed `<Reference>` URI that is not same-document (i.e. not a
/// `#id` fragment or the whole document). Such references can pull external or
/// local-file content into the verified set and are rejected for SAML.
fn is_external_reference(uri: &str) -> bool {
    !uri.is_empty() && !uri.starts_with('#')
}

fn has_saml_xml_signature(root: &Node) -> bool {
    !saml_signature_candidates(root).is_empty()
}

fn preflight_saml_reference_uris(signatures: &[&Node]) -> Result<(), SamlError> {
    for signature in signatures {
        for signed_info in children_named(signature, "SignedInfo") {
            for reference in children_named(signed_info, "Reference") {
                verified_target_from_uri(reference.attr("URI").unwrap_or_default())?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SignatureScope {
    Other,
    Signature,
    SignedInfo,
    Reference,
    Transforms,
}

#[derive(Clone, Copy)]
enum SignaturePosition {
    Message,
    Response,
    DirectAssertion,
    Other,
}

impl SignaturePosition {
    fn permits_signature(self) -> bool {
        matches!(self, Self::Message | Self::Response | Self::DirectAssertion)
    }
}

#[derive(Clone, Copy)]
struct SignatureFrame {
    scope: SignatureScope,
    position: SignaturePosition,
}

fn signature_position(
    element: &BytesStart<'_>,
    namespace: Option<&str>,
    ancestors: &[SignatureFrame],
) -> SignaturePosition {
    // Retain the raw API's unqualified message compatibility. A foreign
    // namespace never acquires SAML signature positions through its name.
    let in_namespace = |expected: &str| namespace.is_none_or(|namespace| namespace == expected);
    let local_name = element.local_name();
    let name = local_name.as_ref();
    if ancestors.is_empty() {
        if name == b"Assertion" && in_namespace(crate::constants::namespace::ASSERTION) {
            return SignaturePosition::Message;
        }
        if matches!(name, b"EntityDescriptor" | b"EntitiesDescriptor")
            && in_namespace(crate::constants::namespace::METADATA)
        {
            return SignaturePosition::Message;
        }
        if in_namespace(crate::constants::namespace::PROTOCOL) {
            return match name {
                b"Response" => SignaturePosition::Response,
                b"AuthnRequest"
                | b"LogoutRequest"
                | b"LogoutResponse"
                | b"ArtifactResolve"
                | b"ArtifactResponse"
                | b"AssertionIDRequest"
                | b"SubjectQuery"
                | b"AuthnQuery"
                | b"AttributeQuery"
                | b"AuthzDecisionQuery"
                | b"ManageNameIDRequest"
                | b"ManageNameIDResponse"
                | b"NameIDMappingRequest"
                | b"NameIDMappingResponse" => SignaturePosition::Message,
                _ => SignaturePosition::Other,
            };
        }
    } else if ancestors.len() == 1
        && matches!(ancestors[0].position, SignaturePosition::Response)
        && name == b"Assertion"
        && in_namespace(crate::constants::namespace::ASSERTION)
    {
        return SignaturePosition::DirectAssertion;
    }
    SignaturePosition::Other
}

fn signature_namespace<'a>(
    namespace: &'a ResolveResult<'_>,
    decoder: Decoder,
) -> Result<Option<Cow<'a, str>>, SamlError> {
    match namespace {
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Bound(namespace) => {
            // NsReader exposes raw xmlns attribute bytes. Apply the same XML
            // attribute normalization as the backend before comparing URIs.
            Attribute {
                key: QName(b"xmlns"),
                value: Cow::Borrowed(namespace.as_ref()),
            }
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map(Some)
            .map_err(|error| SamlError::Xml(error.to_string()))
        }
        // An unresolved prefix receives no recognized signature positions.
        // Keep unsigned raw templates compatible instead of adding general
        // namespace validation to this verification boundary.
        ResolveResult::Unknown(_) => Ok(Some(Cow::Borrowed(""))),
    }
}

fn signature_attribute(
    element: &BytesStart<'_>,
    name: &[u8],
    decoder: Decoder,
) -> Result<Option<String>, SamlError> {
    let mut value = None;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| SamlError::Xml(error.to_string()))?;
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        if attribute.key.local_name().as_ref() == name {
            // The backend looks up these attributes by local name. Reject a
            // qualified alias so its selected value cannot differ from ours.
            if attribute.key.as_ref() != name {
                return Err(SamlError::Xml(
                    "qualified XML signature reference attribute".into(),
                ));
            }
            value = Some(
                attribute
                    .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
                    .map_err(|error| SamlError::Xml(error.to_string()))?
                    .into_owned(),
            );
        }
    }
    Ok(value)
}

fn preflight_signature_element(
    element: &BytesStart<'_>,
    is_dsig: bool,
    parent: SignatureScope,
    decoder: Decoder,
) -> Result<SignatureScope, SamlError> {
    if !is_dsig {
        return Ok(SignatureScope::Other);
    }
    let scope = match (element.local_name().as_ref(), parent) {
        (b"Signature", _) => SignatureScope::Signature,
        (b"SignedInfo", SignatureScope::Signature) => SignatureScope::SignedInfo,
        (b"Reference", SignatureScope::SignedInfo) => {
            let uri = signature_attribute(element, b"URI", decoder)?.unwrap_or_default();
            verified_target_from_uri(&uri)?;
            SignatureScope::Reference
        }
        (b"Transforms", SignatureScope::Reference) => SignatureScope::Transforms,
        (b"Transform", SignatureScope::Transforms) => {
            let algorithm = signature_attribute(element, b"Algorithm", decoder)?;
            if !algorithm
                .as_deref()
                .is_some_and(signature_transform_preserves_content)
            {
                return Err(verified_content_not_covered());
            }
            SignatureScope::Other
        }
        _ => SignatureScope::Other,
    };
    Ok(scope)
}

// OASIS SAML Core 2.3.3, 3.2.1, and 3.2.2 and Metadata 2.3.1/2.3.2 place an
// enveloped Signature directly under its signed assertion/message/descriptor.
// This verifier consumes the root and direct Response assertions only. Reject
// signatures elsewhere as a library processing boundary, including signatures
// that another extension or nested-assertion profile could legitimately define.
// The backend discovers every XML-DSig Signature descendant; restricting only
// candidate selection would leave that larger set available to the backend.
fn preflight_backend_signatures(xml: &str) -> Result<(), SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut scopes: Vec<SignatureFrame> = Vec::new();
    loop {
        let decoder = reader.decoder();
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let namespace = signature_namespace(&namespace, decoder)?;
        let is_dsig = namespace.as_deref() == Some(crate::constants::namespace::DSIG);
        let parent = scopes.last().copied();
        let parent_scope = parent.map_or(SignatureScope::Other, |frame| frame.scope);
        let empty_element = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                // Approved SAML Errata 05 E91 adds Core 5.4.5 and Metadata
                // 3.1.5: verifiers SHOULD reject signatures containing Object.
                if is_dsig
                    && element.local_name().as_ref() == b"Object"
                    && scopes
                        .iter()
                        .any(|frame| matches!(frame.scope, SignatureScope::Signature))
                {
                    return Err(SamlError::PotentialWrappingAttack);
                }
                if is_dsig
                    && element.local_name().as_ref() == b"Signature"
                    && !parent.is_some_and(|frame| frame.position.permits_signature())
                {
                    return Err(SamlError::PotentialWrappingAttack);
                }
                let frame = SignatureFrame {
                    scope: preflight_signature_element(&element, is_dsig, parent_scope, decoder)?,
                    position: signature_position(&element, namespace.as_deref(), &scopes),
                };
                if !empty_element {
                    scopes.push(frame);
                }
            }
            Event::End(_) => {
                scopes.pop();
            }
            Event::Eof => return Ok(()),
            _ => {}
        }
    }
}

pub(crate) fn has_xml_signature_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    preflight_backend_signatures(xml)?;
    Ok(has_saml_xml_signature(&doc.root))
}

/// First `<X509Certificate>` text found inside a candidate `<Signature>` (the
/// cert the sender embedded in the message), if any.
fn inline_signature_cert(signatures: &[&Node]) -> Option<String> {
    fn descendant_cert(node: &Node) -> Option<String> {
        if node.local_name == "X509Certificate" && !node.text.is_empty() {
            return Some(node.text.clone());
        }
        node.children.iter().find_map(descendant_cert)
    }

    signatures
        .iter()
        .find_map(|signature| descendant_cert(signature))
}

/// Verify the XML-DSig signature(s) of `xml` against `metadata_certs`.
///
/// Returns `(verified, signed_content)`:
/// - `(false, None)` when there is no signature or it does not verify;
/// - `(true, Some(xml))` with the signed assertion/response on success;
/// - `Err(PotentialWrappingAttack)` on a detected XSW attempt.
///
/// References must be same-document. Only enveloped-signature and supported
/// canonicalization transforms are accepted; filtering transforms cannot prove
/// that the returned SAML content is fully covered.
/// XML-DSig signatures outside the signed root or a direct Response assertion
/// are rejected before backend processing, including signatures in extensions.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, transform policy, or signed-content coverage checks fail.
pub fn verify_signature(
    xml: &str,
    metadata_certs: &[String],
) -> Result<(bool, Option<String>), SamlError> {
    verify_signature_with_limits(xml, metadata_certs, XmlLimits::default())
}

/// Verify the XML-DSig signature(s) of `xml` with explicit XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, transform policy, or signed-content coverage checks fail.
pub fn verify_signature_with_limits(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
) -> Result<(bool, Option<String>), SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    let root = &doc.root;

    if root.local_name.contains("Response") && wrapping_detected(root) {
        return Err(SamlError::PotentialWrappingAttack);
    }

    let mut seen_ids = HashSet::new();
    if duplicate_saml_id(root, &mut seen_ids).is_some() {
        return Err(SamlError::PotentialWrappingAttack);
    }

    // Candidate signatures: message-level (root > Signature) or assertion-level.
    preflight_backend_signatures(xml)?;
    let signature_candidates = saml_signature_candidates(root);
    if signature_candidates.is_empty() {
        return Ok((false, None));
    }
    preflight_saml_reference_uris(&signature_candidates)?;
    ensure_signature_transforms_preserve_content(&signature_candidates)?;

    // If the message embeds a certificate, it must be one declared in metadata
    // (rolling-cert safety). Verification itself still uses only the metadata
    // certs.
    if let Some(inline) = inline_signature_cert(&signature_candidates) {
        let inline = normalize_cert_string(&inline);
        if !metadata_certs.is_empty()
            && !metadata_certs
                .iter()
                .any(|c| normalize_cert_string(c) == inline)
        {
            return Err(SamlError::CertificateMismatch);
        }
    }

    super::provider::ensure_crypto_provider_initialized()?;

    // Try each metadata certificate individually (rolling-cert support): the
    // signature verifies if any one of the declared keys matches.
    let mut have_key = false;
    let mut key_load_error = None;
    let mut tried_invalid = false;
    let mut last_err: Option<SamlError> = None;
    for cert in metadata_certs {
        let key = match load_certificate(cert) {
            Ok(key) => key,
            Err(error) => {
                key_load_error.get_or_insert(error);
                continue;
            }
        };
        have_key = true;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        // Trust model (audited against bergshamra 0.8.0; the `DsigContext`
        // fields, defaults and builders are unchanged in ribergshamra 0.10.0):
        // - Metadata certificates are pinned key material, not a public CA
        //   chain. Verification uses only the metadata-pinned key; inline
        //   KeyInfo (X509Certificate/KeyValue) is never imported as key
        //   material.
        // - Set `trusted_keys_only`, `strict_verification`,
        //   `require_reference_digests`, and `hmac_min_out_len` explicitly
        //   instead of relying on upstream defaults.
        // - `strict_verification`: same-document references must target the
        //   document element, an ancestor, or a sibling of the Signature (XSW
        //   guard); the surrounding preflight and result checks reject
        //   external or unresolved SAML references.
        // - `with_insecure(true)`: intentionally skips ribergshamra's X.509
        //   certificate validation (chain/trust/time), which is irrelevant to
        //   our leaf-key pinning model. `trusted_keys_only` still confines
        //   verification to metadata-pinned keys, and this setting does not
        //   skip signature, digest, reference, duplicate-ID, or XSW checks.
        // - Inbound SAML verification must never use
        //   `DsigContext::new_permissive()`.
        let ctx = DsigContext::new(manager)
            .with_trusted_keys_only(true)
            .with_strict_verification(true)
            .with_require_reference_digests(true)
            .with_hmac_min_out_len(160)
            .with_insecure(true);
        match verify(&ctx, xml) {
            Ok(VerifyResult::Valid {
                signature_node: _,
                references,
                ..
            }) => {
                let targets = verified_targets(&references)?;
                return Ok((true, verified_content(root, xml, &targets)?));
            }
            Ok(VerifyResult::Invalid { .. }) => tried_invalid = true,
            Err(e) => last_err = Some(SamlError::Crypto(e.to_string())),
        }
    }
    if !have_key {
        return Err(key_load_error.unwrap_or(SamlError::NoTrustedCertificate));
    }
    // A leftover unloadable cert must not poison a rolling-cert verdict.
    // A clean "invalid" (key mismatch / tampered) is a non-error false; only
    // surface a structural error when no loaded certificate produced a verdict.
    match last_err {
        Some(err) if !tried_invalid => Err(err),
        _ => Ok((false, None)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignatureVerification {
    verified: bool,
    signed_content: Option<String>,
    assertion_directly_covered: bool,
    response_covered: bool,
}

impl SignatureVerification {
    pub(crate) fn verified(&self) -> bool {
        self.verified
    }

    pub(crate) fn assertion_directly_covered(&self) -> bool {
        self.assertion_directly_covered
    }

    pub(crate) fn response_covered(&self) -> bool {
        self.response_covered
    }

    pub(crate) fn into_signed_content(self) -> Option<String> {
        self.signed_content
    }
}

pub(crate) fn verify_signatures_detailed_with_limits(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
) -> Result<SignatureVerification, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    let root = &doc.root;

    if root.local_name.contains("Response") && wrapping_detected(root) {
        return Err(SamlError::PotentialWrappingAttack);
    }

    let mut seen_ids = HashSet::new();
    if duplicate_saml_id(root, &mut seen_ids).is_some() {
        return Err(SamlError::PotentialWrappingAttack);
    }

    preflight_backend_signatures(xml)?;
    let signature_candidates = saml_signature_candidates(root);
    if signature_candidates.is_empty() {
        return Ok(SignatureVerification {
            verified: false,
            signed_content: None,
            assertion_directly_covered: false,
            response_covered: false,
        });
    }
    preflight_saml_reference_uris(&signature_candidates)?;
    ensure_signature_transforms_preserve_content(&signature_candidates)?;

    if let Some(inline) = inline_signature_cert(&signature_candidates) {
        let inline = normalize_cert_string(&inline);
        if !metadata_certs.is_empty()
            && !metadata_certs
                .iter()
                .any(|c| normalize_cert_string(c) == inline)
        {
            return Err(SamlError::CertificateMismatch);
        }
    }

    super::provider::ensure_crypto_provider_initialized()?;

    let mut have_key = false;
    let mut key_load_error = None;
    let mut tried_invalid = false;
    let mut last_err: Option<SamlError> = None;
    let mut first_signature_verified = false;
    let mut targets = Vec::new();
    for cert in metadata_certs {
        let key = match load_certificate(cert) {
            Ok(key) => key,
            Err(error) => {
                key_load_error.get_or_insert(error);
                continue;
            }
        };
        have_key = true;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let ctx = DsigContext::new(manager)
            .with_trusted_keys_only(true)
            .with_strict_verification(true)
            .with_require_reference_digests(true)
            .with_hmac_min_out_len(160)
            .with_insecure(true);
        match verify_all(&ctx, xml) {
            Ok(results) => {
                first_signature_verified |=
                    matches!(results.first(), Some(VerifyResult::Valid { .. }));
                for result in results {
                    match result {
                        VerifyResult::Valid {
                            signature_node: _,
                            references,
                            ..
                        } => targets.extend(verified_targets(&references)?),
                        VerifyResult::Invalid { .. } => tried_invalid = true,
                    }
                }
            }
            Err(error) => last_err = Some(SamlError::Crypto(error.to_string())),
        }
    }
    if !have_key {
        return Err(key_load_error.unwrap_or(SamlError::NoTrustedCertificate));
    }
    if first_signature_verified && !targets.is_empty() {
        let assertion_directly_covered = assertion_is_directly_covered(root, &targets);
        let response_covered =
            root.local_name.contains("Response") && response_is_covered(&targets, root);
        return Ok(SignatureVerification {
            verified: true,
            signed_content: verified_content(root, xml, &targets)?,
            assertion_directly_covered,
            response_covered,
        });
    }
    match last_err {
        Some(error) if !tried_invalid => Err(error),
        _ => Ok(SignatureVerification {
            verified: false,
            signed_content: None,
            assertion_directly_covered: false,
            response_covered: false,
        }),
    }
}

/// Detailed metadata signature verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSignatureVerification {
    verified: bool,
    signed_entity_descriptor_xml: Option<String>,
}

impl MetadataSignatureVerification {
    pub(crate) fn from_signed_descriptor(signed_entity_descriptor_xml: String) -> Self {
        Self {
            verified: true,
            signed_entity_descriptor_xml: Some(signed_entity_descriptor_xml),
        }
    }

    pub(crate) fn unverified() -> Self {
        Self {
            verified: false,
            signed_entity_descriptor_xml: None,
        }
    }

    /// Whether a metadata signature verified against the pinned certificates.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// The signed `<EntityDescriptor>` XML when verification succeeds.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        self.signed_entity_descriptor_xml.as_deref()
    }

    pub(crate) fn into_signed_entity_descriptor_xml(self) -> Option<String> {
        self.signed_entity_descriptor_xml
    }
}

/// Verify the enveloped XML-DSig signature on a metadata document against
/// trusted certificate(s); returns whether it is valid and covers the consumed
/// `<EntityDescriptor>` document.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed `<EntityDescriptor>` coverage checks fail.
pub fn verify_metadata_signature(
    xml: &str,
    trusted_certificates: &[String],
) -> Result<bool, SamlError> {
    verify_metadata_signature_with_limits(xml, trusted_certificates, XmlLimits::default())
}

/// Verify a metadata XML-DSig signature with explicit XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed `<EntityDescriptor>` coverage checks fail.
pub fn verify_metadata_signature_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    Ok(
        verify_metadata_signature_detailed_with_limits(xml, trusted_certificates, limits)?
            .verified(),
    )
}

/// Verify a metadata XML-DSig signature and preserve signed descriptor coverage
/// using default XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, transform policy, or signed `<EntityDescriptor>` coverage
/// checks fail.
pub fn verify_metadata_signature_detailed(
    xml: &str,
    trusted_certificates: &[String],
) -> Result<MetadataSignatureVerification, SamlError> {
    verify_metadata_signature_detailed_with_limits(xml, trusted_certificates, XmlLimits::default())
}

/// Verify a metadata XML-DSig signature and preserve signed descriptor coverage.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, transform policy, or signed `<EntityDescriptor>` coverage
/// checks fail.
pub fn verify_metadata_signature_detailed_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<MetadataSignatureVerification, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    ensure_metadata_signature_transforms_preserve_descriptor(&doc.root)?;

    let (verified, signed_entity_descriptor_xml) =
        verify_signature_with_limits(xml, trusted_certificates, limits)?;
    if !verified {
        return Ok(MetadataSignatureVerification::unverified());
    }
    signed_entity_descriptor_xml
        .map(MetadataSignatureVerification::from_signed_descriptor)
        .ok_or_else(verified_content_not_covered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::constants::{digest_for_signature, namespace, transform_algorithm};
    use crate::crypto::construct_saml_signature;
    use crate::crypto::keys::load_private_key;
    use crate::util::normalize_cert_string;
    use crate::xml::{extract, ExtractorField};
    use ribergshamra::sign;

    #[test]
    fn external_reference_detection() {
        assert!(!is_external_reference("")); // whole document
        assert!(!is_external_reference("#_assertion123")); // same-document
        assert!(is_external_reference("https://evil.example.com/x"));
        assert!(is_external_reference("/etc/passwd"));
        assert!(is_external_reference("file:///etc/passwd"));
        assert!(is_external_reference("cid:attachment"));
    }

    #[test]
    fn signature_transform_allowlist_preserves_canonicalization_interoperability() {
        const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        const XSLT_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
        const UNKNOWN_TRANSFORM: &str = "urn:example:unknown-transform";

        for algorithm in [
            transform_algorithm::ENVELOPED_SIGNATURE,
            transform_algorithm::EXC_C14N,
            EXC_C14N_WITH_COMMENTS,
            XML_C14N_10,
            XML_C14N_10_WITH_COMMENTS,
            XML_C14N_11,
            XML_C14N_11_WITH_COMMENTS,
        ] {
            assert!(
                signature_transform_preserves_content(algorithm),
                "{algorithm}"
            );
        }

        for algorithm in [XPATH_TRANSFORM, XSLT_TRANSFORM, UNKNOWN_TRANSFORM] {
            assert!(
                !signature_transform_preserves_content(algorithm),
                "{algorithm}"
            );
        }
    }

    #[test]
    fn saml_verification_rejects_filtering_reference_transforms_before_crypto(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for message in [
            "Assertion",
            "Response",
            "AuthnRequest",
            "LogoutRequest",
            "LogoutResponse",
        ] {
            for algorithm in [
                "http://www.w3.org/TR/1999/REC-xpath-19991116",
                "http://www.w3.org/2002/06/xmldsig-filter2",
                "http://www.w3.org/TR/1999/REC-xslt-19991116",
                "http://www.w3.org/2000/09/xmldsig#base64",
                "urn:example:unknown-transform",
            ] {
                // A deliberately unsigned template proves rejection before key
                // loading or transform execution without constructing a filtered
                // signature. Full message coverage cannot be inferred from URI.
                let xml = format!(
                    r##"<{message} ID="_message" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><ds:SignedInfo><ds:Reference URI="#_message"><ds:Transforms><ds:Transform Algorithm="{algorithm}"/></ds:Transforms><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></{message}>"##,
                );
                assert!(matches!(
                    verify_signature(&xml, &[]),
                    Err(SamlError::SignedReferenceMismatch)
                ));
                assert!(matches!(
                    verify_signatures_detailed_with_limits(&xml, &[], XmlLimits::default()),
                    Err(SamlError::SignedReferenceMismatch)
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn assertion_level_filtering_transform_and_missing_algorithm_are_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for transform in [
            r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>"#,
            "<ds:Transform/>",
        ] {
            let xml = format!(
                r##"<Response ID="_response" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Assertion ID="_assertion"><ds:Signature><ds:SignedInfo><ds:Reference URI="#_assertion"><ds:Transforms>{transform}</ds:Transforms></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></Assertion></Response>"##,
            );
            assert!(matches!(
                verify_signature(&xml, &[]),
                Err(SamlError::SignedReferenceMismatch)
            ));
            assert!(matches!(
                verify_signatures_detailed_with_limits(&xml, &[], XmlLimits::default()),
                Err(SamlError::SignedReferenceMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn unexpected_signature_positions_are_rejected_even_without_a_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
        for body in [
            "<Extensions><ds:Signature/></Extensions>",
            "<Assertion><Advice><ds:Signature/></Advice></Assertion>",
            "<Assertion><Subject><ds:Signature/></Subject></Assertion>",
            "<Assertion><Assertion><ds:Signature/></Assertion></Assertion>",
            "<ds:Signature><ds:Object><ds:Signature/></ds:Object></ds:Signature>",
            "<foreign:Assertion xmlns:foreign=\"urn:example:extension\"><ds:Signature/></foreign:Assertion>",
        ] {
            let xml = format!(r#"<Response xmlns:ds="{DSIG}">{body}</Response>"#);
            assert!(matches!(
                verify_signature(&xml, &[]),
                Err(SamlError::PotentialWrappingAttack)
            ));
            assert!(matches!(
                verify_signatures_detailed_with_limits(&xml, &[], XmlLimits::default()),
                Err(SamlError::PotentialWrappingAttack)
            ));
            assert!(matches!(
                has_xml_signature_with_limits(&xml, XmlLimits::default()),
                Err(SamlError::PotentialWrappingAttack)
            ));
        }
        for xml in [
            format!(r#"<ds:Signature xmlns:ds="{DSIG}"/>"#),
            format!(r#"<Wrapper xmlns:ds="{DSIG}"><ds:Signature/></Wrapper>"#),
            format!(
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{DSIG}"><md:Extensions><ds:Signature/></md:Extensions></md:EntityDescriptor>"#
            ),
        ] {
            assert!(matches!(
                verify_metadata_signature_detailed(&xml, &[]),
                Err(SamlError::PotentialWrappingAttack)
            ));
        }
        Ok(())
    }

    #[test]
    fn signature_objects_are_rejected_before_backend_processing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for root in ["Response", "EntityDescriptor"] {
            for object in ["<ds:Object/>", "<ds:KeyInfo><ds:Object/></ds:KeyInfo>"] {
                let xml = format!(
                    r#"<{root} xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature>{object}</ds:Signature></{root}>"#
                );
                assert!(matches!(
                    preflight_backend_signatures(&xml),
                    Err(SamlError::PotentialWrappingAttack)
                ));
            }
        }
        preflight_backend_signatures(
            r#"<Response xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:x="urn:extension"><ds:Signature><x:Object/></ds:Signature></Response>"#,
        )?;
        Ok(())
    }

    #[test]
    fn qualified_aliases_still_participate_in_duplicate_saml_id_guard(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<Response ID="_id" xmlns:x="urn:extension"><Assertion x:ID="_id"/></Response>"#,
        )?;
        assert_eq!(
            duplicate_saml_id(&doc.root, &mut HashSet::new()),
            Some("_id".into())
        );
        assert_eq!(node_saml_id(&doc.root.children[0]), None);
        Ok(())
    }

    #[test]
    fn expected_signature_positions_preserve_namespace_and_empty_element_handling(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for xml in [
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><saml:Issuer/><ds:Signature/><samlp:Status/><saml:Assertion><saml:Issuer/><ds:Signature/></saml:Assertion></samlp:Response>"#,
            r#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Issuer/><ds:Signature/></Assertion>"#,
            r#"<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></AuthnRequest>"#,
            r#"<LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></LogoutRequest>"#,
            r#"<LogoutResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></LogoutResponse>"#,
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></EntityDescriptor>"#,
            r#"<Response xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/><Assertion><ds:Signature/></Assertion></Response>"#,
        ] {
            preflight_backend_signatures(xml)?;
            assert!(has_xml_signature_with_limits(xml, XmlLimits::default())?);
            assert!(matches!(
                verify_signature(xml, &[]),
                Err(SamlError::NoTrustedCertificate)
            ));
        }
        Ok(())
    }

    #[test]
    fn signature_positions_use_normalized_namespace_uris() -> Result<(), Box<dyn std::error::Error>>
    {
        // Ordinary character references are legal XML namespace syntax.
        let expected = r#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protoco&#108;" xmlns:ds="http://www.w3.org/2000/09/xmldsig&#35;"><ds:Signature/><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertio&#110;"><ds:Signature/></Assertion></Response>"#;
        preflight_backend_signatures(expected)?;
        assert!(has_xml_signature_with_limits(
            expected,
            XmlLimits::default()
        )?);

        let misplaced = r#"<Response xmlns:ds="http://www.w3.org/2000/09/xmldsig&#35;"><Extensions><ds:Signature/></Extensions></Response>"#;
        assert!(matches!(
            verify_signature(misplaced, &[]),
            Err(SamlError::PotentialWrappingAttack)
        ));
        assert!(matches!(
            has_xml_signature_with_limits(misplaced, XmlLimits::default()),
            Err(SamlError::PotentialWrappingAttack)
        ));
        Ok(())
    }

    #[test]
    fn misplaced_dsig_signatures_are_rejected_before_reference_preflight(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for reference in [
            r#"<Reference URI="urn:example:external"/>"#,
            r##"<Reference URI="#_response"><Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/></Transforms></Reference>"##,
        ] {
            // Placement is checked before any key, reference, or transform is
            // handed to the backend; unsigned templates are sufficient here.
            let xml = format!(
                r##"<Response ID="_response" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><ds:SignedInfo><ds:Reference URI="#_response"/></ds:SignedInfo></ds:Signature><Extensions><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>{reference}</SignedInfo></Signature></Extensions></Response>"##,
            );
            assert!(matches!(
                verify_signature(&xml, &[]),
                Err(SamlError::PotentialWrappingAttack)
            ));
            assert!(matches!(
                verify_signatures_detailed_with_limits(&xml, &[], XmlLimits::default()),
                Err(SamlError::PotentialWrappingAttack)
            ));
        }
        Ok(())
    }

    #[test]
    fn signature_preflight_rejects_qualified_attribute_aliases(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for reference in [
            r##"<Reference alias:URI="#_response"/>"##,
            r##"<Reference alias:URI="#_response" URI="#_response"/>"##,
            r##"<Reference URI="#_response" alias:URI="#_response"/>"##,
            r##"<Reference URI="#_response"><Transforms><Transform alias:Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms></Reference>"##,
            r##"<Reference URI="#_response"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" alias:Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms></Reference>"##,
        ] {
            let xml = format!(
                r##"<Response ID="_response"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:alias="urn:example:attributes"><SignedInfo>{reference}</SignedInfo></Signature></Response>"##,
            );
            assert!(matches!(
                verify_signature(&xml, &[]),
                Err(SamlError::Xml(_))
            ));
            assert!(matches!(
                verify_signatures_detailed_with_limits(&xml, &[], XmlLimits::default()),
                Err(SamlError::Xml(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn signature_scanner_ignores_namespace_declaration_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = r##"<Response ID="_response"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><Reference xmlns:URI="urn:example:unused" URI="#_response"/></SignedInfo></Signature></Response>"##;
        preflight_backend_signatures(xml)?;
        assert!(has_xml_signature_with_limits(xml, XmlLimits::default())?);
        Ok(())
    }

    #[test]
    fn foreign_signature_extension_is_outside_backend_reference_preflight(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = r##"<Response ID="_response" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><ds:SignedInfo><ds:Reference URI="#_response"/></ds:SignedInfo></ds:Signature><Extensions><Signature xmlns="urn:example:extension"><SignedInfo><Reference URI="urn:example:external"><Transforms><Transform Algorithm="urn:example:extension-transform"/></Transforms></Reference></SignedInfo></Signature></Extensions></Response>"##;
        assert!(matches!(
            verify_signature(xml, &[]),
            Err(SamlError::NoTrustedCertificate)
        ));
        assert!(matches!(
            verify_signatures_detailed_with_limits(xml, &[], XmlLimits::default()),
            Err(SamlError::NoTrustedCertificate)
        ));
        Ok(())
    }

    #[test]
    fn same_document_reference_target_parsing() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(verified_target_from_uri("")?, VerifiedTarget::WholeDocument);
        assert_eq!(
            verified_target_from_uri("#_assertion123")?,
            VerifiedTarget::Id("_assertion123".to_string())
        );
        assert_eq!(
            verified_target_from_uri("#xpointer(/)")?,
            VerifiedTarget::WholeDocument
        );
        assert_eq!(
            verified_target_from_uri("#xpointer(id('_assertion123'))")?,
            VerifiedTarget::Id("_assertion123".to_string())
        );
        Ok(())
    }

    #[test]
    fn unsupported_reference_target_parsing_fails() {
        assert!(matches!(
            verified_target_from_uri("#"),
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::UnsupportedReferenceUri
            })
        ));
        assert!(matches!(
            verified_target_from_uri("#xpointer(//saml:Assertion)"),
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::UnsupportedReferenceUri
            })
        ));
    }

    #[test]
    fn duplicate_saml_id_allows_unique_ids() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_returns_repeated_value() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(
            duplicate_saml_id(&doc.root, &mut seen),
            Some("_same".to_string())
        );
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_ignores_empty_values() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID=""><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID=""/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
        Ok(())
    }

    const RESPONSE_SIGNED: &str = include_str!("../../tests/fixtures/response_signed.xml");
    const SIGNED_REQUEST: &str = include_str!("../../tests/fixtures/signed_request_sha256.xml");
    const ATTACK: &str = include_str!("../../tests/fixtures/attack_response_signed.xml");
    const FALSE_SIGNED: &str = include_str!("../../tests/fixtures/false_signed_request_sha256.xml");
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");
    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    // IdP signing cert (matches the response_signed.xml signer / idpmeta).
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp_cert.cer");
    const IDP_PROVIDER_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
    const IDP_PROVIDER_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
    // SP signing cert (matches signed_request_sha256.xml signer).
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_cert.cer");
    const SP_SIGNING_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");

    fn sha256_signed_assertion() -> Result<String, Box<dyn std::error::Error>> {
        let key = load_private_key(IDP_PROVIDER_PRIVKEY, None)?;
        Ok(construct_saml_signature(
            RESPONSE,
            false,
            &key,
            IDP_PROVIDER_CERT,
            RSA_SHA256,
            &[],
            None,
        )?)
    }

    fn metadata_signed_response() -> Result<(String, &'static str), Box<dyn std::error::Error>> {
        // Preserve the historical SHA-1 verification case outside FIPS. FIPS
        // positive coverage uses the same assertion shape with RSA-SHA256.
        #[cfg(not(feature = "crypto-fips"))]
        {
            Ok((RESPONSE_SIGNED.to_string(), IDP_CERT))
        }
        #[cfg(feature = "crypto-fips")]
        {
            Ok((sha256_signed_assertion()?, IDP_PROVIDER_CERT))
        }
    }

    fn signed_response_with_foreign_extension_certificate(
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = RESPONSE.replacen(
            "<samlp:Status>",
            r#"<samlp:Extensions><x:Signature xmlns:x="urn:example:extension"><x:X509Certificate>attacker</x:X509Certificate></x:Signature></samlp:Extensions><samlp:Status>"#,
            1,
        );
        let key = load_private_key(SP_PRIVKEY, None)?;
        Ok(construct_saml_signature(
            &response,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?)
    }

    fn response_with_first_invalid_signature() -> Result<String, Box<dyn std::error::Error>> {
        let cert = normalize_cert_string(IDP_CERT);
        let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
        let invalid_signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"><ds:Transforms><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>invalid</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            sig_alg = RSA_SHA256,
        );
        Ok(RESPONSE_SIGNED.replacen(
            "<samlp:Status>",
            &format!("{invalid_signature}<samlp:Status>"),
            1,
        ))
    }

    fn cid_reference_response() -> Result<String, Box<dyn std::error::Error>> {
        let cert = normalize_cert_string(SP_SIGNING_CERT);
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"cid:attachment-1@example.com\"><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            sig_alg = RSA_SHA256,
            digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?,
        );
        let template =
            RESPONSE.replacen("<samlp:Status>", &format!("{signature}<samlp:Status>"), 1);
        let key = load_private_key(SP_PRIVKEY, None)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let ctx = DsigContext::new(manager).with_insecure(true);
        Ok(sign(&ctx, &template)?)
    }

    fn assert_reference_resolution(
        result: Result<(bool, Option<String>), SamlError>,
        expected: ReferenceResolutionReason,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match result {
            Err(SamlError::ReferenceResolution { reason }) if reason == expected => Ok(()),
            other => Err(format!("expected reference resolution {expected}, got {other:?}").into()),
        }
    }

    #[test]
    fn dsig_context_secure_defaults_survive_insecure_builder() {
        let ctx = DsigContext::new(KeysManager::new());
        assert!(ctx.trusted_keys_only);
        assert!(ctx.strict_verification);
        assert!(ctx.require_reference_digests);
        assert_eq!(ctx.hmac_min_out_len, 160);
        assert!(!ctx.insecure);

        let insecure = ctx.with_insecure(true);
        assert!(insecure.insecure);
        assert!(insecure.trusted_keys_only);
        assert!(insecure.strict_verification);
        assert!(insecure.require_reference_digests);
        assert_eq!(insecure.hmac_min_out_len, 160);
    }

    #[test]
    fn verifies_signed_response_with_metadata_cert() -> Result<(), Box<dyn std::error::Error>> {
        let (signed, certificate) = metadata_signed_response()?;
        let (verified, content) = verify_signature(&signed, &[certificate.to_string()])?;
        assert!(verified, "signed assertion should verify with the IdP cert");
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn verifies_generated_same_document_signature() -> Result<(), Box<dyn std::error::Error>> {
        let signed = sha256_signed_assertion()?;
        let (verified, content) = verify_signature(&signed, &[IDP_PROVIDER_CERT.to_string()])?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[cfg(feature = "crypto-fips")]
    #[test]
    fn fips_rejects_historical_sha1_assertion() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            verify_signature(RESPONSE_SIGNED, &[IDP_CERT.to_string()]),
            Err(SamlError::Crypto(message))
                if message.contains("does not support Digest(Sha1)")
        ));
        // verify_all converts per-signature policy errors into Invalid; the
        // detailed SAML result must therefore carry no verified coverage.
        let detailed = verify_signatures_detailed_with_limits(
            RESPONSE_SIGNED,
            &[IDP_CERT.to_string()],
            XmlLimits::default(),
        )?;
        assert!(
            !detailed.verified()
                && !detailed.assertion_directly_covered()
                && !detailed.response_covered()
        );
        Ok(())
    }

    #[test]
    fn foreign_extension_certificate_is_not_treated_as_signature_key_info(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = signed_response_with_foreign_extension_certificate()?;
        let (verified, content) = verify_signature(&signed, &[SP_SIGNING_CERT.to_string()])?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn detailed_verification_ignores_foreign_extension_certificate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = signed_response_with_foreign_extension_certificate()?;
        let result = verify_signatures_detailed_with_limits(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
        )?;
        assert!(result.verified() && result.assertion_directly_covered());
        Ok(())
    }

    #[test]
    fn inline_certificate_is_not_used_without_metadata_pin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        match verify_signature(RESPONSE_SIGNED, &[]) {
            Err(SamlError::NoTrustedCertificate) => Ok(()),
            other => Err(format!("expected missing pinned certificate, got {other:?}").into()),
        }
    }

    #[test]
    fn first_invalid_signature_prevents_later_valid_signature_from_authorizing_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = verify_signature(
            &response_with_first_invalid_signature()?,
            &[IDP_CERT.to_string()],
        )?;
        assert_eq!(result, (false, None));
        Ok(())
    }

    #[test]
    fn detailed_verification_rejects_invalid_first_signature_before_later_assertion_coverage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = verify_signatures_detailed_with_limits(
            &response_with_first_invalid_signature()?,
            &[IDP_CERT.to_string()],
            XmlLimits::default(),
        )?;
        assert!(!result.verified() && !result.response_covered());
        Ok(())
    }

    #[test]
    fn detailed_verification_aggregates_rolling_cert_coverage_after_first_signature_verifies(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signed_assertion, assertion_certificate) = metadata_signed_response()?;
        let response_key = load_private_key(SP_PRIVKEY, None)?;
        let signed_response_and_assertion = construct_saml_signature(
            &signed_assertion,
            true,
            &response_key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        let result = verify_signatures_detailed_with_limits(
            &signed_response_and_assertion,
            &[
                SP_SIGNING_CERT.to_string(),
                assertion_certificate.to_string(),
            ],
            XmlLimits::default(),
        )?;
        assert!(
            result.verified() && result.assertion_directly_covered() && result.response_covered()
        );
        Ok(())
    }

    #[test]
    fn signed_cid_reference_is_rejected_before_content_extraction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_reference_resolution(
            verify_signature(&cid_reference_response()?, &[SP_SIGNING_CERT.to_string()]),
            ReferenceResolutionReason::ExternalReference,
        )
    }

    #[test]
    fn rejects_signed_request_without_root_coverage() -> Result<(), Box<dyn std::error::Error>> {
        match verify_signature(SIGNED_REQUEST, &[SP_CERT.to_string()]) {
            Err(SamlError::SignedReferenceMismatch) => Ok(()),
            other => {
                Err(format!("expected uncovered AuthnRequest rejection, got {other:?}").into())
            }
        }
    }

    #[test]
    fn rejects_wrong_certificate() -> Result<(), Box<dyn std::error::Error>> {
        // RESPONSE_SIGNED embeds the IdP cert; verifying against the SP cert
        // trips the inline-vs-metadata mismatch guard.
        match verify_signature(RESPONSE_SIGNED, &[SP_CERT.to_string()]) {
            Err(SamlError::CertificateMismatch) => Ok(()),
            other => Err(format!("expected CertificateMismatch, got {other:?}").into()),
        }
    }

    #[test]
    fn rejects_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
        // false_signed_request_sha256.xml: signature present but content tampered
        let (verified, _) = verify_signature(FALSE_SIGNED, &[SP_CERT.to_string()])?;
        assert!(!verified, "tampered message must not verify");
        Ok(())
    }

    #[test]
    fn rolling_cert_unloadable_peer_keeps_invalid_verdict() -> Result<(), Box<dyn std::error::Error>>
    {
        let garbage = "not a certificate".to_string();
        let signer = SP_CERT.to_string();
        for certs in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
            assert_eq!(
                verify_signature(FALSE_SIGNED, &certs)?,
                (false, None),
                "unloadable leftover must not replace Invalid with Crypto"
            );
        }
        Ok(())
    }

    #[test]
    fn detailed_rolling_cert_unloadable_peer_keeps_invalid_verdict(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let garbage = "not a certificate".to_string();
        let signer = SP_CERT.to_string();
        for certs in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
            let result =
                verify_signatures_detailed_with_limits(FALSE_SIGNED, &certs, XmlLimits::default())?;
            assert!(
                !result.verified()
                    && !result.assertion_directly_covered()
                    && !result.response_covered(),
                "unloadable leftover must not replace Invalid with Crypto"
            );
        }
        Ok(())
    }

    #[test]
    fn rolling_cert_unloadable_peer_does_not_block_valid_signature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // response_signed.xml is SHA-1; FIPS rejects that digest.
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed = construct_saml_signature(
            RESPONSE,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        let (verified, content) = verify_signature(
            &signed,
            &["not a certificate".to_string(), SP_SIGNING_CERT.to_string()],
        )?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn rejects_multi_root_wrapping_attack_before_signature_verification(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // attack_response_signed.xml places a forged NameID before the signed
        // response. Reject the multi-root document before signature processing.
        match verify_signature(ATTACK, &[IDP_CERT.to_string()]) {
            Err(SamlError::Xml(message)) if message == "multiple document elements" => Ok(()),
            other => Err(format!("expected multi-root XML rejection, got {other:?}").into()),
        }
    }

    #[test]
    fn no_signature_returns_false() -> Result<(), Box<dyn std::error::Error>> {
        // a document without any Signature element verifies to (false, None)
        let (verified, content) = verify_signature("<samlp:Response>x</samlp:Response>", &[])?;
        assert!(!verified);
        assert!(content.is_none());
        // keep the extractor import exercised
        let _ = extract("<a/>", &[ExtractorField::new("x", &["a"])])?;
        Ok(())
    }
}
