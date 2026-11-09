//! OCSP requests: CertID, Request, TBSRequest, the optional request signature,
//! the builder and the DER/BER/PEM codecs.

use keystore_pki::der::{self, Reader};
use keystore_pki::{SignatureAlgorithm, sig};

use crate::alg::{AlgorithmIdentifier, HashAlgorithm};
use crate::ber;
use crate::cert::{ParsedCertificate, hex_string, normalize_integer};
use crate::error::{OcspError, Result};
use crate::ext::{
    self as ocsp_ext, OID_ACCEPTABLE_RESPONSE_TYPES, OID_BASIC_RESPONSE, OID_NONCE, OcspExtension,
    acceptable_response_types, encode_extensions, parse_extensions, unique_nonce,
};
use crate::name::{GeneralName, name_eq};

/// The `CertID` that names one certificate to an OCSP responder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateId {
    pub hash_algorithm: AlgorithmIdentifier,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    /// The serial number as an unsigned big-endian magnitude.
    pub serial_number: Vec<u8>,
}

impl CertificateId {
    /// A CertID using the SHA-1 default both keytool and BouncyCastle use.
    pub fn new(issuer_der: &[u8], serial: &[u8]) -> Result<Self> {
        Self::from_issuer(issuer_der, serial, HashAlgorithm::Sha1)
    }

    /// A CertID using SHA-256.
    pub fn sha256(issuer_der: &[u8], serial: &[u8]) -> Result<Self> {
        Self::from_issuer(issuer_der, serial, HashAlgorithm::Sha256)
    }

    /// Builds a CertID for `serial` issued by the certificate in
    /// `issuer_der`.
    pub fn from_issuer(issuer_der: &[u8], serial: &[u8], hash: HashAlgorithm) -> Result<Self> {
        let issuer = ParsedCertificate::parse(issuer_der)?;
        Self::from_issuer_info(&issuer, serial, hash)
    }

    /// Builds a CertID from an already parsed issuer certificate.
    pub fn from_issuer_info(
        issuer: &ParsedCertificate,
        serial: &[u8],
        hash: HashAlgorithm,
    ) -> Result<Self> {
        Ok(CertificateId {
            hash_algorithm: hash.algorithm_identifier(),
            issuer_name_hash: issuer.subject_name_hash(&hash)?,
            issuer_key_hash: issuer.subject_key_hash(&hash)?,
            serial_number: normalize_integer(serial),
        })
    }

    /// Builds a CertID from the certificate itself and its issuer.
    pub fn from_certificate(
        certificate_der: &[u8],
        issuer_der: &[u8],
        hash: HashAlgorithm,
    ) -> Result<Self> {
        let certificate = ParsedCertificate::parse(certificate_der)?;
        let issuer = ParsedCertificate::parse(issuer_der)?;
        if !name_eq(&certificate.issuer_name, &issuer.subject_name) {
            return Err(OcspError::WrongIssuer);
        }
        Self::from_issuer_info(&issuer, &certificate.serial, hash)
    }

    /// The digest algorithm this CertID names.
    pub fn algorithm(&self) -> Result<HashAlgorithm> {
        HashAlgorithm::from_algorithm_identifier(&self.hash_algorithm)
    }

    /// Recomputes the issuer hashes and checks this CertID against them.
    pub fn verify_issuer(&self, issuer: &ParsedCertificate) -> Result<()> {
        let algorithm = self.algorithm()?;
        let name_hash = issuer.subject_name_hash(&algorithm)?;
        let key_hash = issuer.subject_key_hash(&algorithm)?;
        if name_hash != self.issuer_name_hash {
            return Err(OcspError::CertIdMismatch(
                "issuerNameHash does not match the issuer certificate".into(),
            ));
        }
        if key_hash != self.issuer_key_hash {
            return Err(OcspError::CertIdMismatch(
                "issuerKeyHash does not match the issuer certificate".into(),
            ));
        }
        Ok(())
    }

    /// Full CertID equality: hash algorithm, both issuer hashes and the serial.
    pub fn same_as(&self, other: &CertificateId) -> bool {
        self.hash_algorithm.oid.as_str() == other.hash_algorithm.oid.as_str()
            && self.issuer_name_hash == other.issuer_name_hash
            && self.issuer_key_hash == other.issuer_key_hash
            && self.serial_number == other.serial_number
    }

    /// Equality of the issuer half, ignoring the serial number.
    pub fn same_issuer(&self, other: &CertificateId) -> bool {
        self.hash_algorithm.oid.as_str() == other.hash_algorithm.oid.as_str()
            && self.issuer_name_hash == other.issuer_name_hash
            && self.issuer_key_hash == other.issuer_key_hash
    }

    pub fn serial_hex(&self) -> String {
        hex_string(&self.serial_number)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let value = Self::parse(&mut reader)?;
        if !reader.is_empty() {
            return Err(OcspError::Malformed("trailing bytes after CertID".into()));
        }
        Ok(value)
    }

    pub fn parse(reader: &mut Reader<'_>) -> Result<Self> {
        let mut sequence = reader.read_sequence()?;
        let hash_algorithm = AlgorithmIdentifier::parse(&mut sequence)?;
        let issuer_name_hash = sequence.read_octet_string()?;
        let issuer_key_hash = sequence.read_octet_string()?;
        let serial_number = normalize_integer(&sequence.read_integer()?);
        if !sequence.is_empty() {
            return Err(OcspError::Malformed("trailing bytes after CertID".into()));
        }
        Ok(CertificateId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    pub fn to_der(&self) -> Vec<u8> {
        der::sequence(&[
            self.hash_algorithm.to_der(),
            der::octet_string(&self.issuer_name_hash),
            der::octet_string(&self.issuer_key_hash),
            der::integer_bytes(&self.serial_number),
        ])
    }
}

/// One `Request` in the request list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestEntry {
    pub cert_id: CertificateId,
    pub extensions: Vec<OcspExtension>,
}

impl RequestEntry {
    pub fn new(cert_id: CertificateId) -> Self {
        RequestEntry {
            cert_id,
            extensions: Vec::new(),
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        let mut body = self.cert_id.to_der();
        if !self.extensions.is_empty() {
            body.extend(der::explicit(0, &encode_extensions(&self.extensions)));
        }
        der::tlv(der::TAG_SEQUENCE, &body)
    }

    fn parse(reader: &mut Reader<'_>) -> Result<Self> {
        let mut sequence = reader.read_sequence()?;
        let cert_id = CertificateId::parse(&mut sequence)?;
        let mut extensions = Vec::new();
        if sequence.peek_tag() == Some(der::context_tag(0)) {
            let content = sequence.read_tagged(der::context_tag(0))?;
            extensions = parse_extensions(content)?;
        }
        if !sequence.is_empty() {
            return Err(OcspError::Malformed("trailing bytes after Request".into()));
        }
        Ok(RequestEntry {
            cert_id,
            extensions,
        })
    }
}

/// The body of an OCSP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbsRequest {
    /// The protocol version; zero is v1, the only version RFC 6960 defines.
    pub version: u32,
    pub requestor_name: Option<GeneralName>,
    pub requests: Vec<RequestEntry>,
    pub extensions: Vec<OcspExtension>,
}

impl TbsRequest {
    pub fn extension(&self, oid: &str) -> Option<&OcspExtension> {
        ocsp_ext::find_extension(&self.extensions, oid)
    }

    pub fn nonce(&self) -> Result<Option<Vec<u8>>> {
        unique_nonce(&self.extensions)
    }

    pub fn acceptable_response_types(&self) -> Result<Vec<String>> {
        acceptable_response_types(&self.extensions)
    }

    pub fn to_der(&self) -> Vec<u8> {
        let mut body = Vec::new();
        if self.version != 0 {
            body.extend(der::explicit(0, &der::integer_u64(self.version as u64)));
        }
        if let Some(name) = &self.requestor_name {
            body.extend(der::explicit(1, &name.to_der()));
        }
        let requests: Vec<Vec<u8>> = self.requests.iter().map(RequestEntry::to_der).collect();
        body.extend(der::sequence(&requests));
        if !self.extensions.is_empty() {
            body.extend(der::explicit(2, &encode_extensions(&self.extensions)));
        }
        der::tlv(der::TAG_SEQUENCE, &body)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Self::parse(bytes)
    }

    fn parse(tbs_der: &[u8]) -> Result<Self> {
        let mut sequence = Reader::new(tbs_der).read_sequence()?;
        let version = if sequence.peek_tag() == Some(der::context_tag(0)) {
            let content = sequence.read_tagged(der::context_tag(0))?;
            let version = Reader::new(content).read_u64()?;
            if version > u32::MAX as u64 {
                return Err(OcspError::Malformed("request version is too large".into()));
            }
            u32::try_from(version)
                .map_err(|_| OcspError::Malformed("request version is too large".into()))?
        } else {
            0
        };
        let requestor_name = if sequence.peek_tag() == Some(der::context_tag(1)) {
            let content = sequence.read_tagged(der::context_tag(1))?;
            Some(parse_general_name(content)?)
        } else {
            None
        };
        let mut list = sequence.read_sequence()?;
        let mut requests = Vec::new();
        while !list.is_empty() {
            requests.push(RequestEntry::parse(&mut list)?);
        }
        let extensions = if sequence.peek_tag() == Some(der::context_tag(2)) {
            let content = sequence.read_tagged(der::context_tag(2))?;
            parse_extensions(content)?
        } else {
            Vec::new()
        };
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after TBSRequest".into(),
            ));
        }
        Ok(TbsRequest {
            version,
            requestor_name,
            requests,
            extensions,
        })
    }
}

fn parse_general_name(content: &[u8]) -> Result<GeneralName> {
    let mut reader = Reader::new(content);
    let (tag, value) = reader.read_tlv()?;
    if !reader.is_empty() {
        return Err(OcspError::Malformed(
            "trailing bytes after GeneralName".into(),
        ));
    }
    Ok(GeneralName::from_tlv(tag, value))
}

/// The optional signature on a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSignature {
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
}

impl RequestSignature {
    fn to_der(&self) -> Vec<u8> {
        let mut parts = vec![
            self.signature_algorithm.to_der(),
            der::bit_string(&self.signature),
        ];
        if !self.certificates.is_empty() {
            parts.push(der::explicit(0, &der::sequence(&self.certificates)));
        }
        der::sequence(&parts)
    }

    fn parse(content: &[u8]) -> Result<Self> {
        let mut sequence = Reader::new(content).read_sequence()?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut sequence)?;
        let signature = sequence.read_bit_string()?;
        let mut certificates = Vec::new();
        if sequence.peek_tag() == Some(der::context_tag(0)) {
            let content = sequence.read_tagged(der::context_tag(0))?;
            let mut certificates_reader = Reader::new(content).read_sequence()?;
            while !certificates_reader.is_empty() {
                certificates.push(certificates_reader.read_raw_tlv()?.to_vec());
            }
        }
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after request Signature".into(),
            ));
        }
        Ok(RequestSignature {
            signature_algorithm,
            signature,
            certificates,
        })
    }
}

/// A complete OCSP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspRequest {
    pub tbs_request: TbsRequest,
    /// The DER of `tbsRequest`, which is what a signature covers.
    pub tbs_der: Vec<u8>,
    pub signature: Option<RequestSignature>,
}

impl OcspRequest {
    /// A request for one certificate.
    pub fn new(cert_id: CertificateId) -> Self {
        OcspRequestBuilder::new().add_request(cert_id).build()
    }

    /// A request for several certificates.
    pub fn with_cert_ids(cert_ids: impl IntoIterator<Item = CertificateId>) -> Self {
        let mut builder = OcspRequestBuilder::new();
        for cert_id in cert_ids {
            builder = builder.add_request(cert_id);
        }
        builder.build()
    }

    /// Builds from parts, encoding `tbs_request` afresh.
    pub fn from_parts(tbs_request: TbsRequest, signature: Option<RequestSignature>) -> Self {
        let tbs_der = tbs_request.to_der();
        OcspRequest {
            tbs_request,
            tbs_der,
            signature,
        }
    }

    pub fn nonce(&self) -> Result<Option<Vec<u8>>> {
        self.tbs_request.nonce()
    }

    pub fn acceptable_response_types(&self) -> Result<Vec<String>> {
        self.tbs_request.acceptable_response_types()
    }

    /// Appends a CertID and drops any signature, which would no longer cover
    /// the request.
    pub fn add_certificate_id(&mut self, cert_id: CertificateId) {
        self.tbs_request.requests.push(RequestEntry::new(cert_id));
        self.signature = None;
        self.tbs_der = self.tbs_request.to_der();
    }

    /// Replaces the nonce extension.
    pub fn set_nonce(&mut self, nonce: &[u8]) {
        self.tbs_request
            .extensions
            .retain(|extension| extension.oid.as_str() != OID_NONCE);
        self.tbs_request
            .extensions
            .push(OcspExtension::nonce(nonce));
        self.signature = None;
        self.tbs_der = self.tbs_request.to_der();
    }

    /// Adds the acceptable response types extension.
    pub fn set_acceptable_response_types(&mut self, oids: &[String]) {
        self.tbs_request
            .extensions
            .retain(|extension| extension.oid.as_str() != OID_ACCEPTABLE_RESPONSE_TYPES);
        self.tbs_request
            .extensions
            .push(OcspExtension::acceptable_response_types(oids));
        self.signature = None;
        self.tbs_der = self.tbs_request.to_der();
    }

    /// Verifies the optional request signature with a signer certificate.
    pub fn verify_signature(&self, signer_certificate_der: &[u8]) -> Result<()> {
        let signature = self.signature.as_ref().ok_or(OcspError::NotSigned)?;
        let signer = ParsedCertificate::parse(signer_certificate_der)?;
        if self.tbs_der.is_empty() {
            return Err(OcspError::Malformed(
                "the request has no TBSRequest encoding to verify".into(),
            ));
        }
        if let Some(GeneralName::DirectoryName(name)) = &self.tbs_request.requestor_name {
            if !name_eq(name, &signer.subject_name) {
                return Err(OcspError::RequestorNameMismatch);
            }
        }
        let algorithm = SignatureAlgorithm::from_oid(&signature.signature_algorithm.oid)
            .ok_or_else(|| {
                OcspError::UnsupportedAlgorithm(format!(
                    "signature algorithm {}",
                    signature.signature_algorithm.oid
                ))
            })?;
        let key = sig::parse_public_key(&signer.spki)?;
        match sig::verify(algorithm, &key, &self.tbs_der, &signature.signature) {
            Ok(()) => Ok(()),
            Err(keystore_core::Error::UnsupportedAlgorithm(algorithm)) => {
                Err(OcspError::UnsupportedAlgorithm(algorithm))
            }
            Err(_) => Err(OcspError::InvalidSignature),
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        let tbs_der = if self.tbs_der.is_empty() {
            self.tbs_request.to_der()
        } else {
            self.tbs_der.clone()
        };
        match &self.signature {
            Some(signature) => der::sequence(&[tbs_der, der::explicit(0, &signature.to_der())]),
            None => der::sequence(&[tbs_der]),
        }
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        match Self::parse_der(bytes) {
            Ok(request) => Ok(request),
            Err(first_error) => match ber::normalize_request(bytes) {
                Ok(normalized) => Self::parse_der(&normalized),
                Err(_) => Err(first_error),
            },
        }
    }

    fn parse_der(bytes: &[u8]) -> Result<Self> {
        let mut outer = Reader::new(bytes).read_sequence()?;
        let tbs_der = outer.read_raw_tlv()?.to_vec();
        let tbs_request = TbsRequest::parse(&tbs_der)?;
        let signature = if outer.peek_tag() == Some(der::context_tag(0)) {
            let content = outer.read_tagged(der::context_tag(0))?;
            Some(RequestSignature::parse(content)?)
        } else {
            None
        };
        if !outer.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after OCSPRequest".into(),
            ));
        }
        Ok(OcspRequest {
            tbs_request,
            tbs_der,
            signature,
        })
    }

    /// Encodes as PEM with the `OCSP REQUEST` label.
    pub fn to_pem(&self) -> Result<String> {
        crate::pem::encode("OCSP REQUEST", &self.to_der())
    }

    /// Decodes a `OCSP REQUEST` PEM block.
    pub fn from_pem(text: &str) -> Result<Self> {
        let der = crate::pem::decode("OCSP REQUEST", text)?;
        Self::from_der(&der)
    }
}

/// Builder for [`OcspRequest`].
#[derive(Clone, Debug, Default)]
pub struct OcspRequestBuilder {
    version: u32,
    requestor_name: Option<GeneralName>,
    requests: Vec<RequestEntry>,
    extensions: Vec<OcspExtension>,
}

impl OcspRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    pub fn requestor_name(mut self, name: GeneralName) -> Self {
        self.requestor_name = Some(name);
        self
    }

    pub fn add_request(mut self, cert_id: CertificateId) -> Self {
        self.requests.push(RequestEntry::new(cert_id));
        self
    }

    pub fn add_request_with_extensions(
        mut self,
        cert_id: CertificateId,
        extensions: Vec<OcspExtension>,
    ) -> Self {
        self.requests.push(RequestEntry {
            cert_id,
            extensions,
        });
        self
    }

    pub fn request_extension(mut self, extension: OcspExtension) -> Self {
        self.extensions
            .retain(|existing| existing.oid.as_str() != extension.oid.as_str());
        self.extensions.push(extension);
        self
    }

    /// Adds the nonce extension verbatim.
    pub fn nonce(self, nonce: &[u8]) -> Self {
        self.request_extension(OcspExtension::nonce(nonce))
    }

    /// Draws a random nonce of `length` bytes.
    pub fn random_nonce(self, length: usize) -> Result<Self> {
        use rand::RngCore;
        if length == 0 {
            return Ok(self);
        }
        let mut nonce = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(self.nonce(&nonce))
    }

    /// Adds the acceptable response types extension.
    pub fn acceptable_response_types(mut self, oids: &[String]) -> Self {
        self.extensions
            .retain(|existing| existing.oid.as_str() != OID_ACCEPTABLE_RESPONSE_TYPES);
        self.extensions
            .push(OcspExtension::acceptable_response_types(oids));
        self
    }

    /// Asks for the basic OCSP response type, the one this crate speaks.
    pub fn accept_basic_response(self) -> Self {
        self.acceptable_response_types(&[OID_BASIC_RESPONSE.to_string()])
    }

    pub fn build(self) -> OcspRequest {
        let tbs_request = TbsRequest {
            version: self.version,
            requestor_name: self.requestor_name,
            requests: self.requests,
            extensions: self.extensions,
        };
        OcspRequest::from_parts(tbs_request, None)
    }

    /// Builds and signs the request. The `certificates` are included in the
    /// Signature so the responder can find the requestor's key.
    pub fn build_signed(
        self,
        private_key_pkcs8: &[u8],
        algorithm: SignatureAlgorithm,
        certificates: Vec<Vec<u8>>,
    ) -> Result<OcspRequest> {
        if self.requestor_name.is_none() {
            return Err(OcspError::RequestorNameRequired);
        }
        let tbs_request = TbsRequest {
            version: self.version,
            requestor_name: self.requestor_name,
            requests: self.requests,
            extensions: self.extensions,
        };
        let tbs_der = tbs_request.to_der();
        let signature = sig::sign(algorithm, private_key_pkcs8, &tbs_der)?;
        let request_signature = RequestSignature {
            signature_algorithm: AlgorithmIdentifier::for_signature(algorithm),
            signature,
            certificates,
        };
        Ok(OcspRequest {
            tbs_request,
            tbs_der,
            signature: Some(request_signature),
        })
    }
}
