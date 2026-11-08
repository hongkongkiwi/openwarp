//! GeneralName and distinguished-name comparison.
//!
//! Names are kept as their DER because OCSP never needs to edit them. Comparing
//! them byte-for-byte is not enough: a certificate and a ResponderID can encode
//! the same X.500 name with different string types or RDN ordering, so the
//! comparison falls back to parsing the attributes.

use keystore_pki::der::{self, Reader};

use crate::error::{OcspError, Result};

/// The GeneralName choices OCSP requests and AIA records use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneralName {
    /// `[0]` otherName, kept raw.
    OtherName(Vec<u8>),
    /// `[1]` rfc822Name.
    Rfc822Name(String),
    /// `[2]` dNSName.
    DnsName(String),
    /// `[3]` x400Address, kept raw.
    X400Address(Vec<u8>),
    /// `[4]` directoryName, the complete DER of a Name.
    DirectoryName(Vec<u8>),
    /// `[5]` ediPartyName, kept raw.
    EdiPartyName(Vec<u8>),
    /// `[6]` uniformResourceIdentifier.
    Uri(String),
    /// `[7]` iPAddress.
    IpAddress(Vec<u8>),
    /// `[8]` registeredID.
    RegisteredId(String),
    /// A tag this crate does not model, preserved so it round-trips.
    Unknown { tag: u8, value: Vec<u8> },
}

impl GeneralName {
    pub fn to_der(&self) -> Vec<u8> {
        match self {
            GeneralName::OtherName(value) => der::tlv(0xa0, value),
            GeneralName::Rfc822Name(name) => der::tlv(0x81, name.as_bytes()),
            GeneralName::DnsName(name) => der::tlv(0x82, name.as_bytes()),
            GeneralName::X400Address(value) => der::tlv(0xa3, value),
            GeneralName::DirectoryName(name) => der::tlv(0xa4, name),
            GeneralName::EdiPartyName(value) => der::tlv(0xa5, value),
            GeneralName::Uri(uri) => der::tlv(0x86, uri.as_bytes()),
            GeneralName::IpAddress(address) => der::tlv(0x87, address),
            GeneralName::RegisteredId(oid) => der::tlv(0x88, &oid_content(oid)),
            GeneralName::Unknown { tag, value } => der::tlv(*tag, value),
        }
    }

    pub fn from_tlv(tag: u8, content: &[u8]) -> Self {
        match tag {
            0xa0 => GeneralName::OtherName(content.to_vec()),
            0x81 => GeneralName::Rfc822Name(String::from_utf8_lossy(content).into_owned()),
            0x82 => GeneralName::DnsName(String::from_utf8_lossy(content).into_owned()),
            0xa3 => GeneralName::X400Address(content.to_vec()),
            0xa4 => GeneralName::DirectoryName(content.to_vec()),
            0xa5 => GeneralName::EdiPartyName(content.to_vec()),
            0x86 => GeneralName::Uri(String::from_utf8_lossy(content).into_owned()),
            0x87 => GeneralName::IpAddress(content.to_vec()),
            0x88 => GeneralName::RegisteredId(der::read_oid(content)),
            other => GeneralName::Unknown {
                tag: other,
                value: content.to_vec(),
            },
        }
    }

    /// For a directoryName, the DER of the Name.
    pub fn directory_name(&self) -> Option<&[u8]> {
        match self {
            GeneralName::DirectoryName(name) => Some(name.as_slice()),
            _ => None,
        }
    }
}

fn oid_content(dotted: &str) -> Vec<u8> {
    let encoded = der::oid(dotted);
    match der::read_tlv_at(&encoded, 0) {
        Ok((_, start, end)) => encoded[start..end].to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Compares two DER-encoded X.500 Names.
pub fn name_eq(left: &[u8], right: &[u8]) -> bool {
    if left == right {
        return true;
    }
    match (parse_name(left), parse_name(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// A canonical, order-insensitive view of a Name: one entry per RDN, each RDN
/// a sorted list of attributes.
type ParsedName = Vec<Vec<NameAttribute>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NameAttribute {
    oid: String,
    /// Present for the string types where X.500 matching is case-insensitive.
    text: Option<String>,
    /// The raw DER TLV for non-string values.
    raw: Vec<u8>,
}

fn parse_name(bytes: &[u8]) -> Result<ParsedName> {
    let mut outer = Reader::new(bytes).read_sequence()?;
    let mut rdns = Vec::new();
    while !outer.is_empty() {
        let mut rdn = outer.read_set()?;
        let mut attributes = Vec::new();
        while !rdn.is_empty() {
            let mut atv = rdn.read_sequence()?;
            let oid = atv.read_oid()?;
            let value = atv.read_raw_tlv()?;
            let (text, raw) = match der::read_tlv_at(value, 0)? {
                (tag, start, end) if is_directory_string(tag) => {
                    let text = decode_directory_string(tag, &value[start..end]);
                    (Some(normalize_text(&text)), Vec::new())
                }
                _ => (None, value.to_vec()),
            };
            attributes.push(NameAttribute { oid, text, raw });
            if !atv.is_empty() {
                return Err(OcspError::Malformed(
                    "trailing bytes in a name attribute".into(),
                ));
            }
        }
        attributes.sort();
        rdns.push(attributes);
    }
    Ok(rdns)
}

fn is_directory_string(tag: u8) -> bool {
    matches!(
        tag,
        der::TAG_UTF8_STRING
            | der::TAG_PRINTABLE_STRING
            | 0x12 // NumericString
            | 0x14 // TeletexString
            | 0x16 // IA5String
            | 0x1a // VisibleString
            | 0x1c // UniversalString
            | 0x1e // BMPString
    )
}

fn decode_directory_string(tag: u8, bytes: &[u8]) -> String {
    match tag {
        0x1e => {
            // BMPString is UTF-16BE without a byte-order mark.
            if !bytes.len().is_multiple_of(2) {
                return String::new();
            }
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        0x1c => {
            if !bytes.len().is_multiple_of(4) {
                return String::new();
            }
            let mut text = String::new();
            for chunk in bytes.chunks(4) {
                let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if let Some(character) = char::from_u32(value) {
                    text.push(character);
                }
            }
            text
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Applies the loose matching described by RFC 4518: case folding and
/// collapsing runs of whitespace.
fn normalize_text(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut last_was_space = true;
    for character in text.chars() {
        if character.is_whitespace() {
            if !last_was_space {
                normalized.push(' ');
                last_was_space = true;
            }
        } else {
            for lower in character.to_lowercase() {
                normalized.push(lower);
            }
            last_was_space = false;
        }
    }
    while normalized.ends_with(' ') {
        normalized.pop();
    }
    normalized
}

/// Renders a directoryName for error messages.
pub fn describe_name(bytes: &[u8]) -> String {
    match parse_name_display(bytes) {
        Ok(text) => text,
        Err(_) => "<unreadable name>".to_string(),
    }
}

fn parse_name_display(bytes: &[u8]) -> Result<String> {
    let mut outer = Reader::new(bytes).read_sequence()?;
    let mut parts = Vec::new();
    while !outer.is_empty() {
        let mut rdn = outer.read_set()?;
        while !rdn.is_empty() {
            let mut atv = rdn.read_sequence()?;
            let oid = atv.read_oid()?;
            let value = atv.read_raw_tlv()?;
            let text = match der::read_tlv_at(value, 0)? {
                (tag, start, end) if is_directory_string(tag) => {
                    decode_directory_string(tag, &value[start..end])
                }
                _ => {
                    let content = match der::read_tlv_at(value, 0) {
                        Ok((_, start, end)) => &value[start..end],
                        Err(_) => value,
                    };
                    content
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                }
            };
            parts.push(format!("{}={}", short_name(&oid), text));
        }
    }
    if parts.is_empty() {
        return Err(OcspError::Malformed("empty name".into()));
    }
    Ok(parts.join(", "))
}

fn short_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SURNAME",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        other => other,
    }
}
