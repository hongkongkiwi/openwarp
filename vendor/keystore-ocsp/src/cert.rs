//! Certificate parsing for the fields OCSP needs: the raw Subject and Issuer
//! names, the SubjectPublicKeyInfo, the serial number, the validity window and
//! the extensions that decide whether a responder may sign.

use keystore_pki::der::{self, Reader};
use keystore_pki::{SignatureAlgorithm, ext, sig};

use crate::alg::{AlgorithmIdentifier, HashAlgorithm};
use crate::error::{OcspError, Result};
use crate::ext::{self as ocsp_ext, OID_OCSP_SIGNING, OcspExtension};
use crate::name::{describe_name, name_eq};
use crate::time::read_time;

const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
const OID_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// The parts of an X.509 certificate OCSP inspects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCertificate {
    /// The complete certificate.
    pub der: Vec<u8>,
    /// The DER TBSCertificate, including its header.
    pub tbs: Vec<u8>,
    /// The DER of the Name in the issuer field.
    pub issuer_name: Vec<u8>,
    /// The DER of the Name in the subject field.
    pub subject_name: Vec<u8>,
    /// The complete SubjectPublicKeyInfo.
    pub spki: Vec<u8>,
    /// The subjectPublicKey BIT STRING contents, without the unused-bits byte.
    pub subject_public_key: Vec<u8>,
    /// The serial number as an unsigned big-endian magnitude.
    pub serial: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub extensions: Vec<OcspExtension>,
}

impl ParsedCertificate {
    pub fn parse(der: &[u8]) -> Result<Self> {
        let mut outer = Reader::new(der).read_sequence()?;
        let tbs = outer.read_raw_tlv()?.to_vec();
        let signature_algorithm = AlgorithmIdentifier::parse(&mut outer)?;
        let signature = outer.read_bit_string()?;
        if !outer.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after Certificate".into(),
            ));
        }

        let mut fields = Reader::new(&tbs).read_sequence()?;
        if fields.peek_tag() == Some(der::context_tag(0)) {
            let version = fields.read_tagged(der::context_tag(0))?;
            let mut version = Reader::new(version).read_integer()?;
            while version.len() > 1 && version[0] == 0 {
                version.remove(0);
            }
            if version.len() > 1 || version.first().copied().unwrap_or(0) > 2 {
                return Err(OcspError::Malformed(
                    "unsupported certificate version".into(),
                ));
            }
        }
        let serial = fields.read_integer()?;
        let _inner_algorithm = AlgorithmIdentifier::parse(&mut fields)?;
        let issuer_name = fields.read_raw_tlv()?.to_vec();
        let mut validity = fields.read_sequence()?;
        let not_before = read_time(&mut validity)?;
        let not_after = read_time(&mut validity)?;
        let subject_name = fields.read_raw_tlv()?.to_vec();
        let spki = fields.read_raw_tlv()?.to_vec();

        let mut spki_fields = Reader::new(&spki).read_sequence()?;
        let _algorithm = AlgorithmIdentifier::parse(&mut spki_fields)?;
        let subject_public_key = spki_fields.read_bit_string()?;

        let extensions = ext::parse_tbs_extensions(&tbs)?
            .into_iter()
            .map(|extension| OcspExtension {
                oid: extension.oid,
                critical: extension.critical,
                value: extension.value,
            })
            .collect();

        Ok(ParsedCertificate {
            der: der.to_vec(),
            tbs,
            issuer_name,
            subject_name,
            spki,
            subject_public_key,
            serial,
            not_before,
            not_after,
            signature_algorithm,
            signature,
            extensions,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::parse(der)
    }

    /// The digest of the subject Name, as CertID.issuerNameHash defines it.
    pub fn subject_name_hash(&self, algorithm: &HashAlgorithm) -> Result<Vec<u8>> {
        algorithm.digest(&self.subject_name)
    }

    /// The digest of the subjectPublicKey bits, as CertID.issuerKeyHash
    /// defines it.
    pub fn subject_key_hash(&self, algorithm: &HashAlgorithm) -> Result<Vec<u8>> {
        algorithm.digest(&self.subject_public_key)
    }

    /// The SHA-1 key hash ResponderID byKey carries.
    pub fn responder_key_hash(&self) -> Result<Vec<u8>> {
        self.subject_key_hash(&HashAlgorithm::Sha1)
    }

    pub fn extension(&self, oid: &str) -> Option<&OcspExtension> {
        ocsp_ext::find_extension(&self.extensions, oid)
    }

    /// The extendedKeyUsage extension, if any: (critical, OIDs).
    pub fn extended_key_usage(&self) -> Result<Option<(bool, Vec<String>)>> {
        let Some(extension) = self.extension(OID_EXTENDED_KEY_USAGE) else {
            return Ok(None);
        };
        let mut sequence = Reader::new(&extension.value).read_sequence()?;
        let mut oids = Vec::new();
        while !sequence.is_empty() {
            oids.push(sequence.read_oid()?);
        }
        Ok(Some((extension.critical, oids)))
    }

    /// True when the certificate carries id-kp-OCSPSigning.
    pub fn has_ocsp_signing_eku(&self) -> Result<bool> {
        Ok(self
            .extended_key_usage()?
            .map(|(_, oids)| oids.iter().any(|oid| oid.as_str() == OID_OCSP_SIGNING))
            .unwrap_or(false))
    }

    /// Checks this certificate's signature against an issuer certificate.
    pub fn verify_signature(&self, issuer: &ParsedCertificate) -> Result<()> {
        let algorithm =
            SignatureAlgorithm::from_oid(&self.signature_algorithm.oid).ok_or_else(|| {
                OcspError::UnsupportedAlgorithm(format!(
                    "signature algorithm {}",
                    self.signature_algorithm.oid
                ))
            })?;
        let key = sig::parse_public_key(&issuer.spki)?;
        match sig::verify(algorithm, &key, &self.tbs, &self.signature) {
            Ok(()) => Ok(()),
            Err(keystore_core::Error::UnsupportedAlgorithm(algorithm)) => {
                Err(OcspError::UnsupportedAlgorithm(algorithm))
            }
            Err(_) => Err(OcspError::InvalidSignature),
        }
    }

    /// Checks that this certificate is issued by `issuer` and is within its
    /// validity window.
    pub fn verify_issued_by(&self, issuer: &ParsedCertificate, at: i64) -> Result<()> {
        if !name_eq(&self.issuer_name, &issuer.subject_name) {
            return Err(OcspError::WrongIssuer);
        }
        self.verify_signature(issuer)?;
        if !self.is_valid_at(at) {
            return Err(OcspError::ResponderCertificateExpired);
        }
        Ok(())
    }

    pub fn is_valid_at(&self, at: i64) -> bool {
        at >= self.not_before && at <= self.not_after
    }

    /// The OCSP responder URLs in the certificate's AIA extension.
    pub fn ocsp_urls(&self) -> Result<Vec<String>> {
        let Some(extension) = self.extension(OID_AUTHORITY_INFO_ACCESS) else {
            return Ok(Vec::new());
        };
        let mut sequence = Reader::new(&extension.value).read_sequence()?;
        let mut urls = Vec::new();
        while !sequence.is_empty() {
            let mut access = sequence.read_sequence()?;
            let method = access.read_oid()?;
            let (tag, content) = access.read_tlv()?;
            if method.as_str() == OID_AD_OCSP && tag == 0x86 {
                urls.push(String::from_utf8_lossy(content).into_owned());
            }
        }
        Ok(urls)
    }

    pub fn subject_description(&self) -> String {
        describe_name(&self.subject_name)
    }

    pub fn issuer_description(&self) -> String {
        describe_name(&self.issuer_name)
    }

    pub fn serial_hex(&self) -> String {
        hex_string(&self.serial)
    }
}

/// The first OCSP access location in a DER certificate.
pub fn ocsp_endpoint(certificate_der: &[u8]) -> Result<String> {
    let certificate = ParsedCertificate::parse(certificate_der)?;
    certificate
        .ocsp_urls()?
        .into_iter()
        .next()
        .ok_or(OcspError::NoOcspEndpoint)
}

/// Lower-case hexadecimal, without separators.
pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Normalizes an INTEGER magnitude: leading zeros removed, zero kept as one
/// byte.
pub(crate) fn normalize_integer(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes.to_vec();
    while value.len() > 1 && value[0] == 0 {
        value.remove(0);
    }
    if value.is_empty() {
        value.push(0);
    }
    value
}
