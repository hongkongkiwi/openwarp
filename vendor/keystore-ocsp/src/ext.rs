//! OCSP extensions and the handful of values RFC 6960 defines for them.

use keystore_pki::der::{self, Reader};

use crate::error::{OcspError, Result};
use crate::time::encode_generalized_time;

/// The OID of the basic OCSP response type.
pub const OID_BASIC_RESPONSE: &str = "1.3.6.1.5.5.7.48.1.1";
/// The OID of the OCSP nonce extension.
pub const OID_NONCE: &str = "1.3.6.1.5.5.7.48.1.2";
/// The OID of the CRL references extension.
pub const OID_CRL_REFERENCES: &str = "1.3.6.1.5.5.7.48.1.3";
/// The OID of the acceptable response types extension.
pub const OID_ACCEPTABLE_RESPONSE_TYPES: &str = "1.3.6.1.5.5.7.48.1.4";
/// The OID of the no-check extension.
pub const OID_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";
/// The OID of the archive cutoff extension.
pub const OID_ARCHIVE_CUTOFF: &str = "1.3.6.1.5.5.7.48.1.6";
/// The OID of the service locator extension.
pub const OID_SERVICE_LOCATOR: &str = "1.3.6.1.5.5.7.48.1.7";
/// The OID of the preferred signature algorithms extension.
pub const OID_PREFERRED_SIGNATURE_ALGORITHMS: &str = "1.3.6.1.5.5.7.48.1.8";
/// The OID of the extended revoke extension.
pub const OID_EXTENDED_REVOKE: &str = "1.3.6.1.5.5.7.48.1.9";

/// The OID of the id-kp-OCSPSigning extended key usage.
pub const OID_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// The OIDs RFC 6960 defines for OCSP itself.
pub fn known_ocsp_extension(oid: &str) -> bool {
    matches!(
        oid,
        OID_NONCE
            | OID_CRL_REFERENCES
            | OID_ACCEPTABLE_RESPONSE_TYPES
            | OID_NO_CHECK
            | OID_ARCHIVE_CUTOFF
            | OID_SERVICE_LOCATOR
            | OID_PREFERRED_SIGNATURE_ALGORITHMS
            | OID_EXTENDED_REVOKE
    )
}

/// One OCSP `Extension`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspExtension {
    pub oid: String,
    pub critical: bool,
    /// The bytes inside `extnValue`, still DER encoded as the extension
    /// defines them.
    pub value: Vec<u8>,
}

impl OcspExtension {
    pub fn new(oid: impl Into<String>, critical: bool, value: Vec<u8>) -> Self {
        OcspExtension {
            oid: oid.into(),
            critical,
            value,
        }
    }

    /// The nonce extension: the nonce is wrapped in an OCTET STRING.
    pub fn nonce(nonce: &[u8]) -> Self {
        OcspExtension::new(OID_NONCE, false, der::octet_string(nonce))
    }

    /// The acceptable response types extension.
    pub fn acceptable_response_types(oids: &[String]) -> Self {
        let encoded: Vec<Vec<u8>> = oids.iter().map(|oid| der::oid(oid.as_str())).collect();
        OcspExtension::new(
            OID_ACCEPTABLE_RESPONSE_TYPES,
            false,
            der::sequence(&encoded),
        )
    }

    /// The archive cutoff extension.
    pub fn archive_cutoff(seconds: i64) -> Result<Self> {
        Ok(OcspExtension::new(
            OID_ARCHIVE_CUTOFF,
            false,
            encode_generalized_time(seconds)?,
        ))
    }

    pub fn to_der(&self) -> Vec<u8> {
        let mut parts = vec![der::oid(&self.oid)];
        if self.critical {
            parts.push(der::boolean(true));
        }
        parts.push(der::octet_string(&self.value));
        der::sequence(&parts)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let value = Self::parse(&mut reader)?;
        if !reader.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after Extension".into(),
            ));
        }
        Ok(value)
    }

    pub fn parse(reader: &mut Reader<'_>) -> Result<Self> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_oid()?;
        let critical = if sequence.peek_tag() == Some(der::TAG_BOOLEAN) {
            sequence.read_tagged(der::TAG_BOOLEAN)? != [0u8]
        } else {
            false
        };
        let value = sequence.read_octet_string()?;
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after Extension".into(),
            ));
        }
        Ok(OcspExtension {
            oid,
            critical,
            value,
        })
    }

    /// The nonce carried by this extension, if it is the nonce extension.
    pub fn nonce_value(&self) -> Result<Option<Vec<u8>>> {
        if self.oid.as_str() != OID_NONCE {
            return Ok(None);
        }
        Ok(Some(decode_embedded_octet_string(&self.value)?))
    }

    /// The response types carried by an acceptable-response-types extension.
    pub fn acceptable_response_type_list(&self) -> Result<Option<Vec<String>>> {
        if self.oid.as_str() != OID_ACCEPTABLE_RESPONSE_TYPES {
            return Ok(None);
        }
        let mut sequence = Reader::new(&self.value).read_sequence()?;
        let mut oids = Vec::new();
        while !sequence.is_empty() {
            oids.push(sequence.read_oid()?);
        }
        Ok(Some(oids))
    }
}

/// Decodes the OCTET STRING inside an extension value.
///
/// RFC 6960 wraps the nonce in an OCTET STRING, so the extension's own
/// `extnValue` contains `04 .. <nonce>`. A few responders put the raw nonce
/// there instead; accepting both costs one branch and keeps them working.
pub fn decode_embedded_octet_string(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    match der::read_tlv_at(bytes, 0) {
        Ok((tag, start, end)) if tag == der::TAG_OCTET_STRING => {
            if end != bytes.len() {
                return Err(OcspError::Malformed(
                    "trailing bytes after OCSP extension OCTET STRING".into(),
                ));
            }
            Ok(bytes[start..end].to_vec())
        }
        Ok((0x24, start, end)) => {
            // BER constructed OCTET STRING: concatenate the segments.
            if end != bytes.len() {
                return Err(OcspError::Malformed(
                    "trailing bytes after constructed OCTET STRING".into(),
                ));
            }
            let mut out = Vec::new();
            let mut inner = Reader::new(&bytes[start..end]);
            while !inner.is_empty() {
                let (tag, content) = inner.read_tlv()?;
                if tag != der::TAG_OCTET_STRING {
                    return Err(OcspError::Malformed(format!(
                        "constructed OCTET STRING contains tag {tag:#04x}"
                    )));
                }
                out.extend_from_slice(content);
            }
            Ok(out)
        }
        _ => Ok(bytes.to_vec()),
    }
}

/// Encodes an Extensions value (the `SEQUENCE SIZE (1..MAX) OF Extension`).
pub fn encode_extensions(extensions: &[OcspExtension]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = extensions.iter().map(OcspExtension::to_der).collect();
    der::sequence(&encoded)
}

/// Parses the contents of an `[n] EXPLICIT Extensions` wrapper.
pub fn parse_extensions(bytes: &[u8]) -> Result<Vec<OcspExtension>> {
    let mut sequence = Reader::new(bytes).read_sequence()?;
    let mut extensions = Vec::new();
    while !sequence.is_empty() {
        extensions.push(OcspExtension::parse(&mut sequence)?);
    }
    Ok(extensions)
}

/// Finds an extension by OID.
pub fn find_extension<'a>(extensions: &'a [OcspExtension], oid: &str) -> Option<&'a OcspExtension> {
    extensions
        .iter()
        .find(|extension| extension.oid.as_str() == oid)
}

/// Every nonce value carried by an extension list.
pub fn nonces(extensions: &[OcspExtension]) -> Result<Vec<Vec<u8>>> {
    let mut values = Vec::new();
    for extension in extensions {
        if let Some(value) = extension.nonce_value()? {
            values.push(value);
        }
    }
    Ok(values)
}

/// The single nonce in an extension list, rejecting duplicates.
pub fn unique_nonce(extensions: &[OcspExtension]) -> Result<Option<Vec<u8>>> {
    let mut values = nonces(extensions)?;
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop()),
        _ => Err(OcspError::MultipleNonces),
    }
}

/// The acceptable response types named by an extension list.
pub fn acceptable_response_types(extensions: &[OcspExtension]) -> Result<Vec<String>> {
    match find_extension(extensions, OID_ACCEPTABLE_RESPONSE_TYPES) {
        Some(extension) => Ok(extension
            .acceptable_response_type_list()?
            .unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

/// Rejects any critical extension this crate does not understand.
pub fn check_critical_extensions(extensions: &[OcspExtension]) -> Result<()> {
    for extension in extensions {
        if extension.critical && !known_ocsp_extension(&extension.oid) {
            return Err(OcspError::UnsupportedCriticalExtension(
                extension.oid.clone(),
            ));
        }
    }
    Ok(())
}
