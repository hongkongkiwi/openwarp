use risaml::util::Value;
use risaml::xml::{extract, extract_with_limits, ExtractorField, XmlLimits};
use risaml::SamlError;

#[test]
fn repeated_shortcuts_keep_source_context_and_field_order() -> Result<(), Box<dyn std::error::Error>>
{
    let first = "<Assertion ID=\"first\"><Subject>one &amp; two</Subject></Assertion>";
    let second = "<Assertion ID=\"second\"><Subject><![CDATA[three]]></Subject></Assertion>";
    let fields = [
        ExtractorField::new("firstId", &["Assertion"])
            .attrs(&["ID"])
            .with_shortcut(first),
        ExtractorField::new("root", &["Response"]).attrs(&["ID"]),
        ExtractorField::new("firstSubject", &["Assertion", "Subject"]).with_shortcut(first),
        ExtractorField::new("firstContext", &["Assertion", "Subject"])
            .with_context()
            .with_shortcut(first),
        ExtractorField::new("secondId", &["Assertion"])
            .attrs(&["ID"])
            .with_shortcut(second),
        ExtractorField::new("secondContext", &["Assertion", "Subject"])
            .with_context()
            .with_shortcut(second),
        ExtractorField::new("firstAgain", &["Assertion"])
            .attrs(&["ID"])
            .with_shortcut(first),
    ];

    let extracted = extract("<Response ID=\"root\"/>", &fields)?;

    assert_eq!(
        extracted,
        Value::Object(vec![
            ("firstId".into(), Value::Str("first".into())),
            ("root".into(), Value::Str("root".into())),
            ("firstSubject".into(), Value::Str("one & two".into())),
            (
                "firstContext".into(),
                Value::Str("<Subject>one &amp; two</Subject>".into())
            ),
            ("secondId".into(), Value::Str("second".into())),
            (
                "secondContext".into(),
                Value::Str("<Subject><![CDATA[three]]></Subject>".into())
            ),
            ("firstAgain".into(), Value::Str("first".into())),
        ])
    );
    Ok(())
}

#[test]
fn changed_shortcut_still_enforces_xml_limits() {
    let limits = XmlLimits {
        max_depth: 2,
        ..XmlLimits::default()
    };
    let fields = [
        ExtractorField::new("first", &["Assertion"]).with_shortcut("<Assertion/>"),
        ExtractorField::new("second", &["Assertion"]).with_shortcut("<Assertion/>"),
        ExtractorField::new("tooDeep", &["Assertion"])
            .with_shortcut("<Assertion><Subject><NameID/></Subject></Assertion>"),
    ];

    assert!(matches!(
        extract_with_limits("<Response/>", &fields, limits),
        Err(SamlError::Invalid(message)) if message.contains("ERR_XML_LIMIT_EXCEEDED")
    ));
}

#[test]
fn shortcuts_do_not_bypass_root_document_validation() {
    let fields = [ExtractorField::new("id", &["Assertion"])
        .attrs(&["ID"])
        .with_shortcut("<Assertion ID=\"valid\"/>")];

    assert!(matches!(
        extract("<Response/><Unclosed>", &fields),
        Err(SamlError::Xml(_))
    ));
}
