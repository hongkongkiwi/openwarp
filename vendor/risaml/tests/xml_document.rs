use risaml::binding::{base64_encode, deflate_raw_encode};
use risaml::constants::{Binding, ParserType};
use risaml::flow::{flow, FlowOptions, HttpRequest};
use risaml::SamlError;

const AUTHN_REQUEST: &str = concat!(
    "<samlp:AuthnRequest ",
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
    "ID=\"_request\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\">",
    "<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>",
    "</samlp:AuthnRequest>",
);

#[test]
fn namespace_declarations_do_not_shadow_consumed_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = AUTHN_REQUEST.replace("ID=\"_request\"", "xmlns:ID=\"urn:prefix\" ID=\"_request\"");
    let result = flow(&options(Binding::Post), &post_request(&xml))?;
    assert_eq!(result.extract.get_str("request.id"), Some("_request"));
    Ok(())
}

fn options(binding: Binding) -> FlowOptions<'static> {
    let mut options = FlowOptions::default();
    options.binding = Some(binding);
    options.parser_type = Some(ParserType::SamlRequest);
    options
}

fn post_request(xml: &str) -> HttpRequest {
    HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        base64_encode(xml.as_bytes()),
    )])
}

fn redirect_request(xml: &str) -> Result<HttpRequest, SamlError> {
    let compressed = deflate_raw_encode(xml.as_bytes())?;
    Ok(HttpRequest::redirect(vec![(
        "SAMLRequest".to_string(),
        base64_encode(&compressed),
    )]))
}

fn assert_multiple_document_elements(error: SamlError) {
    assert!(matches!(
        error,
        SamlError::Xml(message) if message == "multiple document elements"
    ));
}

#[test]
fn post_flow_rejects_multiple_document_elements() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("{AUTHN_REQUEST}<garbage/>");
    let error = flow(&options(Binding::Post), &post_request(&xml))
        .err()
        .ok_or("POST flow unexpectedly accepted multiple document elements")?;

    assert_multiple_document_elements(error);
    Ok(())
}

#[test]
fn redirect_flow_rejects_multiple_document_elements() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("{AUTHN_REQUEST}<garbage/>");
    let error = flow(&options(Binding::Redirect), &redirect_request(&xml)?)
        .err()
        .ok_or("Redirect flow unexpectedly accepted multiple document elements")?;

    assert_multiple_document_elements(error);
    Ok(())
}

#[test]
fn post_flow_accepts_xml_misc_around_document_element() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<!-- before --><?before allowed?>{AUTHN_REQUEST}<?after allowed?><!-- after -->"
    );

    flow(&options(Binding::Post), &post_request(&xml))?;
    Ok(())
}

#[test]
fn document_parser_rejects_unclosed_elements() {
    for xml in ["<Root>", "<Root><Child/>", "<Root/><Unclosed>"] {
        assert!(matches!(
            risaml::xml::dom::parse(xml),
            Err(SamlError::Xml(_))
        ));
        assert!(matches!(
            risaml::xml::dom::parse_roots(xml),
            Err(SamlError::Xml(_))
        ));
    }
}

#[test]
fn post_flow_rejects_unclosed_trailing_element() -> Result<(), Box<dyn std::error::Error>> {
    let unclosed = AUTHN_REQUEST
        .strip_suffix("</samlp:AuthnRequest>")
        .ok_or("missing closing test element")?;
    let xml = format!("{AUTHN_REQUEST}{unclosed}");
    let error = flow(&options(Binding::Post), &post_request(&xml))
        .err()
        .ok_or("POST flow unexpectedly accepted an unclosed trailing element")?;

    assert!(matches!(error, SamlError::Xml(_)));
    Ok(())
}

#[test]
fn redirect_flow_rejects_unclosed_trailing_element() -> Result<(), Box<dyn std::error::Error>> {
    let unclosed = AUTHN_REQUEST
        .strip_suffix("</samlp:AuthnRequest>")
        .ok_or("missing closing test element")?;
    let xml = format!("{AUTHN_REQUEST}{unclosed}");
    let error = flow(&options(Binding::Redirect), &redirect_request(&xml)?)
        .err()
        .ok_or("Redirect flow unexpectedly accepted an unclosed trailing element")?;

    assert!(matches!(error, SamlError::Xml(_)));
    Ok(())
}
