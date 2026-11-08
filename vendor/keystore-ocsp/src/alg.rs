//! Algorithm identifiers, digests and the small amount of OID bookkeeping
//! OCSP needs on top of `keystore-pki`.

use keystore_pki::SignatureAlgorithm;
use keystore_pki::der::{self, Reader};
use sha2::Digest;

use crate::error::{OcspError, Result};

/// The OID of SHA-1, as used by CertID and ResponderID byKey.
pub const OID_SHA1: &str = "1.3.14.3.2.26";
/// The OID of SHA-256.
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// The OID of SHA-384.
pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
/// The OID of SHA-512.
pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// An `AlgorithmIdentifier` with its parameters kept as opaque DER.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AlgorithmIdentifier {
    pub oid: String,
    /// The complete DER TLV of the parameters, when present.
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    pub fn new(oid: impl Into<String>) -> Self {
        AlgorithmIdentifier {
            oid: oid.into(),
            parameters: None,
        }
    }

    pub fn with_parameters(oid: impl Into<String>, parameters: Vec<u8>) -> Self {
        AlgorithmIdentifier {
            oid: oid.into(),
            parameters: Some(parameters),
        }
    }

    /// The AlgorithmIdentifier keytool and BouncyCastle emit for signatures.
    pub fn for_signature(algorithm: SignatureAlgorithm) -> Self {
        if algorithm.is_rsa() {
            AlgorithmIdentifier::with_parameters(algorithm.oid(), der::null())
        } else {
            AlgorithmIdentifier::new(algorithm.oid())
        }
    }

    pub fn parse(reader: &mut Reader<'_>) -> Result<Self> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_oid()?;
        let parameters = if sequence.is_empty() {
            None
        } else {
            Some(sequence.read_raw_tlv()?.to_vec())
        };
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after AlgorithmIdentifier".into(),
            ));
        }
        Ok(AlgorithmIdentifier { oid, parameters })
    }

    pub fn to_der(&self) -> Vec<u8> {
        let mut parts = vec![der::oid(&self.oid)];
        if let Some(parameters) = &self.parameters {
            parts.push(parameters.clone());
        }
        der::sequence(&parts)
    }

    /// True when the parameters are an explicit NULL or absent.
    pub fn is_null_or_absent(&self) -> bool {
        match &self.parameters {
            None => true,
            Some(parameters) => {
                parameters.len() == 2 && parameters[0] == der::TAG_NULL && parameters[1] == 0
            }
        }
    }
}

/// A digest algorithm a CertID can name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Other(String),
}

impl HashAlgorithm {
    pub const ALL: [HashAlgorithm; 4] = [
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];

    pub fn oid(&self) -> &str {
        match self {
            HashAlgorithm::Sha1 => OID_SHA1,
            HashAlgorithm::Sha256 => OID_SHA256,
            HashAlgorithm::Sha384 => OID_SHA384,
            HashAlgorithm::Sha512 => OID_SHA512,
            HashAlgorithm::Other(oid) => oid,
        }
    }

    pub fn from_oid(oid: &str) -> Self {
        match oid {
            OID_SHA1 => HashAlgorithm::Sha1,
            OID_SHA256 => HashAlgorithm::Sha256,
            OID_SHA384 => HashAlgorithm::Sha384,
            OID_SHA512 => HashAlgorithm::Sha512,
            other => HashAlgorithm::Other(other.to_string()),
        }
    }

    pub fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        let digest = match self {
            HashAlgorithm::Sha1 => sha1::Sha1::digest(data).to_vec(),
            HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
            HashAlgorithm::Other(oid) => {
                return Err(OcspError::UnsupportedHashAlgorithm(oid.clone()));
            }
        };
        Ok(digest)
    }

    /// The AlgorithmIdentifier used when this algorithm is written into a
    /// CertID. SHA-1 carries an explicit NULL, matching BouncyCastle; the
    /// SHA-2 identifiers omit the parameters.
    pub fn algorithm_identifier(&self) -> AlgorithmIdentifier {
        match self {
            HashAlgorithm::Sha1 => AlgorithmIdentifier::with_parameters(OID_SHA1, der::null()),
            other => AlgorithmIdentifier::new(other.oid()),
        }
    }

    pub fn from_algorithm_identifier(identifier: &AlgorithmIdentifier) -> Result<Self> {
        if !identifier.is_null_or_absent() {
            return Err(OcspError::UnsupportedAlgorithm(format!(
                "hash algorithm {} has non-NULL parameters",
                identifier.oid
            )));
        }
        let algorithm = HashAlgorithm::from_oid(&identifier.oid);
        if let HashAlgorithm::Other(oid) = &algorithm {
            return Err(OcspError::UnsupportedHashAlgorithm(oid.clone()));
        }
        Ok(algorithm)
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha1 => formatter.write_str("SHA-1"),
            HashAlgorithm::Sha256 => formatter.write_str("SHA-256"),
            HashAlgorithm::Sha384 => formatter.write_str("SHA-384"),
            HashAlgorithm::Sha512 => formatter.write_str("SHA-512"),
            HashAlgorithm::Other(oid) => write!(formatter, "OID {oid}"),
        }
    }
}

/// The signature AlgorithmIdentifier for `algorithm`, as the JCA names it.
pub fn signature_algorithm(identifier: &AlgorithmIdentifier) -> Result<SignatureAlgorithm> {
    SignatureAlgorithm::from_oid(&identifier.oid).ok_or_else(|| {
        OcspError::UnsupportedAlgorithm(format!("signature algorithm {}", identifier.oid))
    })
}
