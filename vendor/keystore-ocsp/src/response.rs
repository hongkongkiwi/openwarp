//! OCSP responses: status, ResponseBytes, BasicOCSPResponse, ResponseData,
//! SingleResponse, ResponderID and the builders that produce them.

use std::time::SystemTime;

use keystore_pki::SignatureAlgorithm;
use keystore_pki::der::{self, Reader};

use crate::alg::AlgorithmIdentifier;
use crate::ber;
use crate::cert::ParsedCertificate;
use crate::error::{OcspError, Result};
use crate::ext::{
    self as ocsp_ext, OID_BASIC_RESPONSE, OcspExtension, encode_extensions, parse_extensions,
    unique_nonce,
};
use crate::name::name_eq;
use crate::time::{encode_generalized_time, read_time, system_time_to_seconds};

/// The OCSPResponseStatus ENUMERATED.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
    Other(u8),
}

impl ResponseStatus {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ResponseStatus::Successful,
            1 => ResponseStatus::MalformedRequest,
            2 => ResponseStatus::InternalError,
            3 => ResponseStatus::TryLater,
            5 => ResponseStatus::SigRequired,
            6 => ResponseStatus::Unauthorized,
            other => ResponseStatus::Other(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            ResponseStatus::Successful => 0,
            ResponseStatus::MalformedRequest => 1,
            ResponseStatus::InternalError => 2,
            ResponseStatus::TryLater => 3,
            ResponseStatus::SigRequired => 5,
            ResponseStatus::Unauthorized => 6,
            ResponseStatus::Other(other) => other,
        }
    }

    pub fn is_successful(self) -> bool {
        self == ResponseStatus::Successful
    }
}

impl std::fmt::Display for ResponseStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseStatus::Successful => formatter.write_str("successful"),
            ResponseStatus::MalformedRequest => formatter.write_str("malformedRequest"),
            ResponseStatus::InternalError => formatter.write_str("internalError"),
            ResponseStatus::TryLater => formatter.write_str("tryLater"),
            ResponseStatus::SigRequired => formatter.write_str("sigRequired"),
            ResponseStatus::Unauthorized => formatter.write_str("unauthorized"),
            ResponseStatus::Other(value) => write!(formatter, "unknown status {value}"),
        }
    }
}

/// The CRLReason ENUMERATED carried by a revoked response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
    Other(u8),
}

impl RevocationReason {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => RevocationReason::Unspecified,
            1 => RevocationReason::KeyCompromise,
            2 => RevocationReason::CaCompromise,
            3 => RevocationReason::AffiliationChanged,
            4 => RevocationReason::Superseded,
            5 => RevocationReason::CessationOfOperation,
            6 => RevocationReason::CertificateHold,
            8 => RevocationReason::RemoveFromCrl,
            9 => RevocationReason::PrivilegeWithdrawn,
            10 => RevocationReason::AaCompromise,
            other => RevocationReason::Other(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            RevocationReason::Unspecified => 0,
            RevocationReason::KeyCompromise => 1,
            RevocationReason::CaCompromise => 2,
            RevocationReason::AffiliationChanged => 3,
            RevocationReason::Superseded => 4,
            RevocationReason::CessationOfOperation => 5,
            RevocationReason::CertificateHold => 6,
            RevocationReason::RemoveFromCrl => 8,
            RevocationReason::PrivilegeWithdrawn => 9,
            RevocationReason::AaCompromise => 10,
            RevocationReason::Other(other) => other,
        }
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationReason::Unspecified => formatter.write_str("unspecified"),
            RevocationReason::KeyCompromise => formatter.write_str("keyCompromise"),
            RevocationReason::CaCompromise => formatter.write_str("cACompromise"),
            RevocationReason::AffiliationChanged => formatter.write_str("affiliationChanged"),
            RevocationReason::Superseded => formatter.write_str("superseded"),
            RevocationReason::CessationOfOperation => formatter.write_str("cessationOfOperation"),
            RevocationReason::CertificateHold => formatter.write_str("certificateHold"),
            RevocationReason::RemoveFromCrl => formatter.write_str("removeFromCRL"),
            RevocationReason::PrivilegeWithdrawn => formatter.write_str("privilegeWithdrawn"),
            RevocationReason::AaCompromise => formatter.write_str("aACompromise"),
            RevocationReason::Other(value) => write!(formatter, "unknown reason {value}"),
        }
    }
}

/// The CertStatus CHOICE.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CertStatus {
    Good,
    Revoked {
        revocation_time: i64,
        reason: Option<RevocationReason>,
    },
    Unknown,
}

impl CertStatus {
    pub fn is_good(&self) -> bool {
        matches!(self, CertStatus::Good)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self, CertStatus::Revoked { .. })
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, CertStatus::Unknown)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let (tag, content) = reader.read_tlv()?;
        if !reader.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after CertStatus".into(),
            ));
        }
        Self::parse(tag, content)
    }

    fn to_der(&self) -> Result<Vec<u8>> {
        match self {
            CertStatus::Good => Ok(der::tlv(0x80, &[])),
            CertStatus::Unknown => Ok(der::tlv(0x82, &[])),
            CertStatus::Revoked {
                revocation_time,
                reason,
            } => {
                let mut body = encode_generalized_time(*revocation_time)?;
                if let Some(reason) = reason {
                    body.extend(der::explicit(0, &der::tlv(0x0a, &[(*reason).as_u8()])));
                }
                Ok(der::tlv(0xa1, &body))
            }
        }
    }

    fn parse(tag: u8, content: &[u8]) -> Result<Self> {
        match tag {
            0x80 => {
                if !content.is_empty() {
                    return Err(OcspError::Malformed(
                        "good CertStatus must be an empty NULL".into(),
                    ));
                }
                Ok(CertStatus::Good)
            }
            0x82 => {
                if !content.is_empty() {
                    return Err(OcspError::Malformed(
                        "unknown CertStatus must be an empty NULL".into(),
                    ));
                }
                Ok(CertStatus::Unknown)
            }
            0xa1 => {
                let mut info = Reader::new(content);
                let revocation_time = read_time(&mut info)?;
                let reason = if info.peek_tag() == Some(der::context_tag(0)) {
                    let reason_content = info.read_tagged(der::context_tag(0))?;
                    let mut reason_reader = Reader::new(reason_content);
                    let (tag, bytes) = reason_reader.read_tlv()?;
                    if tag != 0x0a || bytes.len() != 1 {
                        return Err(OcspError::Malformed(
                            "CRLReason must be a one-byte ENUMERATED".into(),
                        ));
                    }
                    Some(RevocationReason::from_u8(bytes[0]))
                } else {
                    None
                };
                if !info.is_empty() {
                    return Err(OcspError::Malformed("trailing bytes in RevokedInfo".into()));
                }
                Ok(CertStatus::Revoked {
                    revocation_time,
                    reason,
                })
            }
            other => Err(OcspError::Malformed(format!(
                "unknown CertStatus tag {other:#04x}"
            ))),
        }
    }
}

/// The ResponderID CHOICE.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResponderId {
    /// `[1]` byName: the DER of the responder's subject Name.
    ByName(Vec<u8>),
    /// `[2]` byKey: the SHA-1 digest of the responder's public key bits.
    ByKey(Vec<u8>),
}

impl ResponderId {
    /// The responder's subject name from its certificate.
    pub fn from_certificate(certificate_der: &[u8]) -> Result<Self> {
        let certificate = ParsedCertificate::parse(certificate_der)?;
        Ok(ResponderId::ByName(certificate.subject_name))
    }

    pub fn from_certificate_info(certificate: &ParsedCertificate) -> Self {
        ResponderId::ByName(certificate.subject_name.clone())
    }

    /// A byKey ResponderID built from the certificate's public key.
    pub fn by_key_from_certificate(certificate_der: &[u8]) -> Result<Self> {
        let certificate = ParsedCertificate::parse(certificate_der)?;
        Ok(ResponderId::ByKey(certificate.responder_key_hash()?))
    }

    /// True when `certificate` is the one this ResponderID names.
    pub fn matches(&self, certificate: &ParsedCertificate) -> Result<bool> {
        match self {
            ResponderId::ByName(name) => Ok(name_eq(name, &certificate.subject_name)),
            ResponderId::ByKey(key_hash) => {
                Ok(certificate.responder_key_hash()?.as_slice() == key_hash.as_slice())
            }
        }
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let (tag, content) = reader.read_tlv()?;
        if !reader.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after ResponderID".into(),
            ));
        }
        Self::parse(tag, content)
    }

    pub fn to_der(&self) -> Vec<u8> {
        match self {
            ResponderId::ByName(name) => der::tlv(0xa1, name),
            // OCSP's ASN.1 module uses EXPLICIT TAGS and ResponderID is a
            // CHOICE, so byKey is [2] EXPLICIT wrapping the OCTET STRING.
            ResponderId::ByKey(key_hash) => der::explicit(2, &der::octet_string(key_hash)),
        }
    }

    pub fn parse(tag: u8, content: &[u8]) -> Result<Self> {
        match tag {
            0xa1 => Ok(ResponderId::ByName(content.to_vec())),
            0xa2 => {
                let mut reader = Reader::new(content);
                let key_hash = reader.read_octet_string()?;
                if !reader.is_empty() {
                    return Err(OcspError::Malformed(
                        "trailing bytes after ResponderID byKey".into(),
                    ));
                }
                Ok(ResponderId::ByKey(key_hash))
            }
            // Tolerate the implicit form some older responders emit.
            0x82 => Ok(ResponderId::ByKey(content.to_vec())),
            other => Err(OcspError::Malformed(format!(
                "unknown ResponderID tag {other:#04x}"
            ))),
        }
    }
}

/// One `SingleResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleResponse {
    pub cert_id: crate::request::CertificateId,
    pub cert_status: CertStatus,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub extensions: Vec<OcspExtension>,
}

impl SingleResponse {
    pub fn new(
        cert_id: crate::request::CertificateId,
        cert_status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
    ) -> Self {
        SingleResponse {
            cert_id,
            cert_status,
            this_update,
            next_update,
            extensions: Vec::new(),
        }
    }

    pub fn extension(&self, oid: &str) -> Option<&OcspExtension> {
        ocsp_ext::find_extension(&self.extensions, oid)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let value = Self::parse(&mut reader)?;
        if !reader.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after SingleResponse".into(),
            ));
        }
        Ok(value)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut body = self.cert_id.to_der();
        body.extend(self.cert_status.to_der()?);
        body.extend(encode_generalized_time(self.this_update)?);
        if let Some(next_update) = self.next_update {
            body.extend(der::explicit(0, &encode_generalized_time(next_update)?));
        }
        if !self.extensions.is_empty() {
            body.extend(der::explicit(1, &encode_extensions(&self.extensions)));
        }
        Ok(der::tlv(der::TAG_SEQUENCE, &body))
    }

    fn parse(reader: &mut Reader<'_>) -> Result<Self> {
        let mut sequence = reader.read_sequence()?;
        let cert_id = crate::request::CertificateId::parse(&mut sequence)?;
        let (status_tag, status_content) = sequence.read_tlv()?;
        let cert_status = CertStatus::parse(status_tag, status_content)?;
        let this_update = read_time(&mut sequence)?;
        let next_update = if sequence.peek_tag() == Some(der::context_tag(0)) {
            let content = sequence.read_tagged(der::context_tag(0))?;
            Some(read_time(&mut Reader::new(content))?)
        } else {
            None
        };
        let extensions = if sequence.peek_tag() == Some(der::context_tag(1)) {
            let content = sequence.read_tagged(der::context_tag(1))?;
            parse_extensions(content)?
        } else {
            Vec::new()
        };
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after SingleResponse".into(),
            ));
        }
        Ok(SingleResponse {
            cert_id,
            cert_status,
            this_update,
            next_update,
            extensions,
        })
    }
}

/// The `ResponseData` carried inside a BasicOCSPResponse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseData {
    pub version: u32,
    pub responder_id: ResponderId,
    pub produced_at: i64,
    pub responses: Vec<SingleResponse>,
    pub extensions: Vec<OcspExtension>,
}

impl ResponseData {
    pub fn extension(&self, oid: &str) -> Option<&OcspExtension> {
        ocsp_ext::find_extension(&self.extensions, oid)
    }

    pub fn nonce(&self) -> Result<Option<Vec<u8>>> {
        unique_nonce(&self.extensions)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Self::parse(bytes)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        if self.version != 0 {
            body.extend(der::explicit(0, &der::integer_u64(self.version as u64)));
        }
        body.extend(self.responder_id.to_der());
        body.extend(encode_generalized_time(self.produced_at)?);
        let mut responses = Vec::with_capacity(self.responses.len());
        for response in &self.responses {
            responses.push(response.to_der()?);
        }
        body.extend(der::sequence(&responses));
        if !self.extensions.is_empty() {
            body.extend(der::explicit(1, &encode_extensions(&self.extensions)));
        }
        Ok(der::tlv(der::TAG_SEQUENCE, &body))
    }

    fn parse(tbs_der: &[u8]) -> Result<Self> {
        let mut sequence = Reader::new(tbs_der).read_sequence()?;
        let version = if sequence.peek_tag() == Some(der::context_tag(0)) {
            let content = sequence.read_tagged(der::context_tag(0))?;
            let value = Reader::new(content).read_u64()?;
            if value > u32::MAX as u64 {
                return Err(OcspError::Malformed("response version is too large".into()));
            }
            value as u32
        } else {
            0
        };
        let (responder_tag, responder_content) = sequence.read_tlv()?;
        let responder_id = ResponderId::parse(responder_tag, responder_content)?;
        let produced_at = read_time(&mut sequence)?;
        let mut responses_reader = sequence.read_sequence()?;
        let mut responses = Vec::new();
        while !responses_reader.is_empty() {
            responses.push(SingleResponse::parse(&mut responses_reader)?);
        }
        let extensions = if sequence.peek_tag() == Some(der::context_tag(1)) {
            let content = sequence.read_tagged(der::context_tag(1))?;
            parse_extensions(content)?
        } else {
            Vec::new()
        };
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after ResponseData".into(),
            ));
        }
        Ok(ResponseData {
            version,
            responder_id,
            produced_at,
            responses,
            extensions,
        })
    }
}

/// A BasicOCSPResponse, including the exact TBS bytes the signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    /// The DER of `tbsResponseData`, which is what the signature covers.
    pub tbs_response_data_der: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
}

impl BasicOcspResponse {
    /// Signs `response_data` and returns the BasicOCSPResponse.
    pub fn sign(
        response_data: ResponseData,
        private_key_pkcs8: &[u8],
        algorithm: SignatureAlgorithm,
        certificates: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let tbs_response_data_der = response_data.to_der()?;
        let signature =
            keystore_pki::sig::sign(algorithm, private_key_pkcs8, &tbs_response_data_der)?;
        Ok(BasicOcspResponse {
            tbs_response_data: response_data,
            tbs_response_data_der,
            signature_algorithm: AlgorithmIdentifier::for_signature(algorithm),
            signature,
            certificates,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let tbs = if self.tbs_response_data_der.is_empty() {
            self.tbs_response_data.to_der()?
        } else {
            self.tbs_response_data_der.clone()
        };
        let mut parts = vec![
            tbs,
            self.signature_algorithm.to_der(),
            der::bit_string(&self.signature),
        ];
        if !self.certificates.is_empty() {
            parts.push(der::explicit(0, &der::sequence(&self.certificates)));
        }
        Ok(der::sequence(&parts))
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        match Self::parse_der(bytes) {
            Ok(response) => Ok(response),
            Err(first_error) => match ber::normalize_basic_response(bytes) {
                Ok(normalized) => Self::parse_der(&normalized),
                Err(_) => Err(first_error),
            },
        }
    }

    fn parse_der(bytes: &[u8]) -> Result<Self> {
        let mut outer = Reader::new(bytes).read_sequence()?;
        let tbs_response_data_der = outer.read_raw_tlv()?.to_vec();
        let tbs_response_data = ResponseData::parse(&tbs_response_data_der)?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut outer)?;
        let signature = outer.read_bit_string()?;
        let mut certificates = Vec::new();
        if outer.peek_tag() == Some(der::context_tag(0)) {
            let content = outer.read_tagged(der::context_tag(0))?;
            let mut list = Reader::new(content).read_sequence()?;
            while !list.is_empty() {
                certificates.push(list.read_raw_tlv()?.to_vec());
            }
        }
        if !outer.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after BasicOCSPResponse".into(),
            ));
        }
        Ok(BasicOcspResponse {
            tbs_response_data,
            tbs_response_data_der,
            signature_algorithm,
            signature,
            certificates,
        })
    }

    pub fn to_pem(&self) -> Result<String> {
        crate::pem::encode("OCSP RESPONSE", &self.to_der()?)
    }

    pub fn from_pem(text: &str) -> Result<Self> {
        let der = crate::pem::decode("OCSP RESPONSE", text)?;
        Self::from_der(&der)
    }
}

/// The `ResponseBytes` inside an OCSPResponse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseBytes {
    pub response_type: String,
    /// The DER of the response of that type.
    pub response: Vec<u8>,
}

impl ResponseBytes {
    pub fn basic(basic: &BasicOcspResponse) -> Result<Self> {
        Ok(ResponseBytes {
            response_type: OID_BASIC_RESPONSE.to_string(),
            response: basic.to_der()?,
        })
    }

    fn to_der(&self) -> Vec<u8> {
        der::sequence(&[
            der::oid(&self.response_type),
            der::octet_string(&self.response),
        ])
    }

    fn parse(content: &[u8]) -> Result<Self> {
        let mut sequence = Reader::new(content).read_sequence()?;
        let response_type = sequence.read_oid()?;
        let response = sequence.read_octet_string()?;
        if !sequence.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after ResponseBytes".into(),
            ));
        }
        Ok(ResponseBytes {
            response_type,
            response,
        })
    }
}

/// A complete OCSPResponse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspResponse {
    pub status: ResponseStatus,
    pub response_bytes: Option<ResponseBytes>,
}

impl OcspResponse {
    /// Wraps a signed BasicOCSPResponse in a successful OCSPResponse.
    pub fn successful(basic: &BasicOcspResponse) -> Result<Self> {
        Ok(OcspResponse {
            status: ResponseStatus::Successful,
            response_bytes: Some(ResponseBytes::basic(basic)?),
        })
    }

    /// A response carrying only a status and no responseBytes.
    pub fn status_only(status: ResponseStatus) -> Self {
        OcspResponse {
            status,
            response_bytes: None,
        }
    }

    pub fn is_successful(&self) -> bool {
        self.status.is_successful()
    }

    /// The DER of the basic response, if this is one.
    pub fn basic_der(&self) -> Result<&[u8]> {
        let bytes = self
            .response_bytes
            .as_ref()
            .ok_or(OcspError::MissingResponseBytes)?;
        if bytes.response_type.as_str() != OID_BASIC_RESPONSE {
            return Err(OcspError::UnsupportedResponseType(
                bytes.response_type.clone(),
            ));
        }
        Ok(&bytes.response)
    }

    /// Parses the BasicOCSPResponse inside this response.
    pub fn basic_response(&self) -> Result<BasicOcspResponse> {
        if !self.status.is_successful() {
            return Err(OcspError::Unsuccessful(self.status));
        }
        BasicOcspResponse::from_der(self.basic_der()?)
    }

    pub fn to_der(&self) -> Vec<u8> {
        let mut body = der::tlv(0x0a, &[self.status.as_u8()]);
        if let Some(bytes) = &self.response_bytes {
            body.extend(der::explicit(0, &bytes.to_der()));
        }
        der::tlv(der::TAG_SEQUENCE, &body)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        match Self::parse_der(bytes) {
            Ok(response) => Ok(response),
            Err(first_error) => match ber::normalize_response(bytes) {
                Ok(normalized) => Self::parse_der(&normalized),
                Err(_) => Err(first_error),
            },
        }
    }

    fn parse_der(bytes: &[u8]) -> Result<Self> {
        let mut outer = Reader::new(bytes).read_sequence()?;
        let (status_tag, status_bytes) = outer.read_tlv()?;
        if status_tag != 0x0a || status_bytes.len() != 1 {
            return Err(OcspError::Malformed(
                "OCSPResponseStatus must be a one-byte ENUMERATED".into(),
            ));
        }
        let status = ResponseStatus::from_u8(status_bytes[0]);
        let response_bytes = if outer.peek_tag() == Some(der::context_tag(0)) {
            let content = outer.read_tagged(der::context_tag(0))?;
            Some(ResponseBytes::parse(content)?)
        } else {
            None
        };
        if !outer.is_empty() {
            return Err(OcspError::Malformed(
                "trailing bytes after OCSPResponse".into(),
            ));
        }
        Ok(OcspResponse {
            status,
            response_bytes,
        })
    }

    pub fn to_pem(&self) -> Result<String> {
        crate::pem::encode("OCSP RESPONSE", &self.to_der())
    }

    pub fn from_pem(text: &str) -> Result<Self> {
        let der = crate::pem::decode("OCSP RESPONSE", text)?;
        Self::from_der(&der)
    }
}

/// Builder for [`ResponseData`] / [`BasicOcspResponse`].
#[derive(Clone, Debug)]
pub struct BasicOcspResponseBuilder {
    responder_id: ResponderId,
    version: u32,
    produced_at: i64,
    responses: Vec<SingleResponse>,
    extensions: Vec<OcspExtension>,
}

impl BasicOcspResponseBuilder {
    pub fn new(responder_id: ResponderId) -> Result<Self> {
        Self::new_at(responder_id, SystemTime::now())
    }

    /// Constructs a builder without reading the platform clock.
    pub fn new_at(responder_id: ResponderId, produced_at: SystemTime) -> Result<Self> {
        Ok(BasicOcspResponseBuilder {
            responder_id,
            version: 0,
            produced_at: system_time_to_seconds(produced_at)?,
            responses: Vec::new(),
            extensions: Vec::new(),
        })
    }

    pub fn responder_id(mut self, responder_id: ResponderId) -> Self {
        self.responder_id = responder_id;
        self
    }

    pub fn produced_at(mut self, time: SystemTime) -> Result<Self> {
        self.produced_at = system_time_to_seconds(time)?;
        Ok(self)
    }

    pub fn produced_at_seconds(mut self, seconds: i64) -> Self {
        self.produced_at = seconds;
        self
    }

    pub fn add_response(
        &mut self,
        cert_id: crate::request::CertificateId,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
    ) -> &mut Self {
        self.responses.push(SingleResponse::new(
            cert_id,
            status,
            this_update,
            next_update,
        ));
        self
    }

    pub fn add_response_with_extensions(
        &mut self,
        cert_id: crate::request::CertificateId,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
        extensions: Vec<OcspExtension>,
    ) -> &mut Self {
        self.responses.push(SingleResponse {
            cert_id,
            cert_status: status,
            this_update,
            next_update,
            extensions,
        });
        self
    }

    pub fn response_extension(mut self, extension: OcspExtension) -> Self {
        self.extensions
            .retain(|existing| existing.oid.as_str() != extension.oid.as_str());
        self.extensions.push(extension);
        self
    }

    pub fn response_extensions(mut self, extensions: Vec<OcspExtension>) -> Self {
        self.extensions = extensions;
        self
    }

    pub fn response_data(&self) -> ResponseData {
        ResponseData {
            version: self.version,
            responder_id: self.responder_id.clone(),
            produced_at: self.produced_at,
            responses: self.responses.clone(),
            extensions: self.extensions.clone(),
        }
    }

    /// Signs the assembled ResponseData.
    pub fn build(
        &self,
        private_key_pkcs8: &[u8],
        algorithm: SignatureAlgorithm,
        certificates: Vec<Vec<u8>>,
    ) -> Result<BasicOcspResponse> {
        BasicOcspResponse::sign(
            self.response_data(),
            private_key_pkcs8,
            algorithm,
            certificates,
        )
    }
}

#[cfg(test)]
mod openwarp_tests {
    use super::{BasicOcspResponseBuilder, ResponderId};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn explicit_time_builder_preserves_timestamp() {
        let produced_at = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        let builder = BasicOcspResponseBuilder::new_at(
            ResponderId::ByName(vec![0x30, 0]), produced_at,
        ).expect("explicit timestamp is valid");
        assert_eq!(builder.response_data().produced_at, 1_767_225_600);
    }
}

/// Builder for a whole [`OcspResponse`].
#[derive(Clone, Debug)]
pub struct OcspResponseBuilder {
    status: ResponseStatus,
}

impl OcspResponseBuilder {
    pub fn new(status: ResponseStatus) -> Self {
        OcspResponseBuilder { status }
    }

    pub fn successful() -> Self {
        OcspResponseBuilder {
            status: ResponseStatus::Successful,
        }
    }

    pub fn build(&self, basic: Option<&BasicOcspResponse>) -> Result<OcspResponse> {
        match basic {
            Some(basic) => Ok(OcspResponse {
                status: self.status,
                response_bytes: Some(ResponseBytes::basic(basic)?),
            }),
            None => Ok(OcspResponse {
                status: self.status,
                response_bytes: None,
            }),
        }
    }
}
