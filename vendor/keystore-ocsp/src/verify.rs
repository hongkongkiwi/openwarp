//! Response verification: signature, responder authorization, CertID
//! recomputation, nonce, freshness and critical extensions.

use std::time::{Duration, SystemTime};

use keystore_pki::sig;

use crate::alg::signature_algorithm;
use crate::cert::{ParsedCertificate, hex_string, normalize_integer};
use crate::error::{OcspError, Result};
use crate::ext::{OID_BASIC_RESPONSE, OID_OCSP_SIGNING, check_critical_extensions, nonces};
use crate::name::name_eq;
use crate::request::{CertificateId, OcspRequest};
use crate::response::{BasicOcspResponse, CertStatus, OcspResponse, ResponderId, SingleResponse};
use crate::time::{now_seconds, system_time_to_seconds};

/// Policy knobs for [`OcspVerifier`].
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// Verification time. `None` means the wall clock.
    pub now: Option<SystemTime>,
    /// Tolerance applied to thisUpdate, nextUpdate, producedAt and revocation
    /// times.
    pub allowed_clock_skew: Duration,
    /// Maximum age of thisUpdate, in addition to any nextUpdate.
    pub max_age: Option<Duration>,
    /// Reject a response that has no nextUpdate.
    pub require_next_update: bool,
    /// Reject a response that does not echo a nonce the request carried.
    pub require_nonce_echo: bool,
    /// Require the delegated responder's id-kp-OCSPSigning EKU to be marked
    /// critical.
    pub require_ocsp_signing_eku_critical: bool,
    /// Validate a supplied responder chain up to the issuer.
    pub check_responder_chain: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            now: None,
            allowed_clock_skew: Duration::from_secs(300),
            max_age: None,
            require_next_update: false,
            require_nonce_echo: true,
            require_ocsp_signing_eku_critical: true,
            check_responder_chain: true,
        }
    }
}

/// The result of a successful verification.
#[derive(Clone, Debug)]
pub struct VerifiedResponse {
    pub basic: BasicOcspResponse,
    /// The certificate whose key verified the response: the issuer itself when
    /// it signed directly, otherwise the delegated responder.
    pub responder_certificate: Vec<u8>,
    /// True when the signer was a delegated responder rather than the issuer.
    pub delegated_responder: bool,
}

impl VerifiedResponse {
    pub fn response_data(&self) -> &crate::response::ResponseData {
        &self.basic.tbs_response_data
    }

    pub fn responder_id(&self) -> &ResponderId {
        &self.basic.tbs_response_data.responder_id
    }

    pub fn responses(&self) -> &[SingleResponse] {
        &self.basic.tbs_response_data.responses
    }

    pub fn single_for(&self, cert_id: &CertificateId) -> Option<&SingleResponse> {
        self.responses()
            .iter()
            .find(|single| single.cert_id.same_as(cert_id))
    }

    pub fn status_for(&self, cert_id: &CertificateId) -> Option<&CertStatus> {
        self.single_for(cert_id).map(|single| &single.cert_status)
    }

    /// The status for a serial number, normalized before comparison.
    pub fn status_for_serial(&self, serial: &[u8]) -> Option<&CertStatus> {
        let serial = normalize_integer(serial);
        self.responses()
            .iter()
            .find(|single| single.cert_id.serial_number == serial)
            .map(|single| &single.cert_status)
    }
}

/// Verifies OCSP responses against a trusted issuer certificate.
#[derive(Clone, Debug)]
pub struct OcspVerifier {
    issuer: ParsedCertificate,
    responder_certificate: Option<ParsedCertificate>,
    options: VerifyOptions,
}

impl OcspVerifier {
    /// A verifier that trusts `issuer_der` as the CA for the certificates
    /// being checked.
    pub fn new(issuer_der: &[u8]) -> Result<Self> {
        Ok(OcspVerifier {
            issuer: ParsedCertificate::parse(issuer_der)?,
            responder_certificate: None,
            options: VerifyOptions::default(),
        })
    }

    /// Supplies a responder certificate that is not carried in the response.
    pub fn with_responder_certificate(mut self, certificate_der: &[u8]) -> Result<Self> {
        self.responder_certificate = Some(ParsedCertificate::parse(certificate_der)?);
        Ok(self)
    }

    pub fn with_options(mut self, options: VerifyOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_now(mut self, now: SystemTime) -> Self {
        self.options.now = Some(now);
        self
    }

    pub fn options(&self) -> &VerifyOptions {
        &self.options
    }

    pub fn issuer(&self) -> &ParsedCertificate {
        &self.issuer
    }

    /// Verifies a response against the request it answers.
    pub fn verify(
        &self,
        response: &OcspResponse,
        request: &OcspRequest,
    ) -> Result<VerifiedResponse> {
        self.verify_impl(response, Some(request))
    }

    /// Verifies a response without a request. Signature, CertID, freshness and
    /// critical extensions are still checked; nonce and serial matching are
    /// impossible without the request.
    pub fn verify_without_request(&self, response: &OcspResponse) -> Result<VerifiedResponse> {
        self.verify_impl(response, None)
    }

    /// Verifies and returns the status for `certificate_der`.
    pub fn verify_for_certificate(
        &self,
        response: &OcspResponse,
        request: &OcspRequest,
        certificate_der: &[u8],
    ) -> Result<CertStatus> {
        let certificate = ParsedCertificate::parse(certificate_der)?;
        if !name_eq(&certificate.issuer_name, &self.issuer.subject_name) {
            return Err(OcspError::WrongIssuer);
        }
        let verified = self.verify(response, request)?;
        verified
            .status_for_serial(&certificate.serial)
            .cloned()
            .ok_or_else(|| OcspError::MissingResponse(hex_string(&certificate.serial)))
    }

    fn now(&self) -> Result<i64> {
        match self.options.now {
            Some(time) => system_time_to_seconds(time),
            None => now_seconds(),
        }
    }

    fn clock_skew(&self) -> Result<i64> {
        i64::try_from(self.options.allowed_clock_skew.as_secs())
            .map_err(|_| OcspError::Time("clock skew does not fit in an i64".into()))
    }

    fn verify_impl(
        &self,
        response: &OcspResponse,
        request: Option<&OcspRequest>,
    ) -> Result<VerifiedResponse> {
        if !response.status.is_successful() {
            return Err(OcspError::Unsuccessful(response.status));
        }
        let basic = response.basic_response()?;
        if basic.signature.is_empty() {
            return Err(OcspError::InvalidSignature);
        }
        if basic.tbs_response_data_der.is_empty() {
            return Err(OcspError::Malformed(
                "the basic response has no tbsResponseData encoding".into(),
            ));
        }
        if basic.tbs_response_data.version != 0 {
            return Err(OcspError::Malformed(format!(
                "unsupported OCSP response version {}",
                basic.tbs_response_data.version
            )));
        }

        let now = self.now()?;
        let skew = self.clock_skew()?;

        if basic.tbs_response_data.produced_at > now.saturating_add(skew) {
            return Err(OcspError::NotYetValid {
                field: "producedAt",
                value: basic.tbs_response_data.produced_at,
            });
        }

        let response_certificates = self.parse_response_certificates(&basic)?;
        let signer = self.select_signer(&basic, &response_certificates)?;
        let signer_is_issuer = signer.der.as_slice() == self.issuer.der.as_slice()
            || (name_eq(&signer.subject_name, &self.issuer.subject_name)
                && signer.subject_public_key.as_slice()
                    == self.issuer.subject_public_key.as_slice());
        let delegated = !signer_is_issuer;

        if delegated {
            self.check_delegated_responder(&signer, &response_certificates, now)?;
        }

        let algorithm = signature_algorithm(&basic.signature_algorithm)?;
        let key = sig::parse_public_key(&signer.spki)?;
        match sig::verify(
            algorithm,
            &key,
            &basic.tbs_response_data_der,
            &basic.signature,
        ) {
            Ok(()) => {}
            Err(keystore_core::Error::UnsupportedAlgorithm(algorithm)) => {
                return Err(OcspError::UnsupportedAlgorithm(algorithm));
            }
            Err(_) => return Err(OcspError::InvalidSignature),
        }

        check_critical_extensions(&basic.tbs_response_data.extensions)?;
        for single in &basic.tbs_response_data.responses {
            check_critical_extensions(&single.extensions)?;
        }

        if let Some(request) = request {
            self.check_response_type(request)?;
            self.check_nonce(request, &basic)?;
            self.check_request_matches(request, &basic)?;
        }

        for single in &basic.tbs_response_data.responses {
            single.cert_id.verify_issuer(&self.issuer)?;
            self.check_freshness(single, now, skew)?;
        }

        Ok(VerifiedResponse {
            basic,
            responder_certificate: signer.der,
            delegated_responder: delegated,
        })
    }

    fn parse_response_certificates(
        &self,
        basic: &BasicOcspResponse,
    ) -> Result<Vec<ParsedCertificate>> {
        let mut certificates = Vec::with_capacity(basic.certificates.len());
        for certificate in &basic.certificates {
            certificates.push(ParsedCertificate::parse(certificate)?);
        }
        Ok(certificates)
    }

    fn select_signer(
        &self,
        basic: &BasicOcspResponse,
        response_certificates: &[ParsedCertificate],
    ) -> Result<ParsedCertificate> {
        let responder_id = &basic.tbs_response_data.responder_id;

        for certificate in response_certificates {
            if responder_id.matches(certificate)? {
                return Ok(certificate.clone());
            }
        }
        if let Some(certificate) = &self.responder_certificate {
            if responder_id.matches(certificate)? {
                return Ok(certificate.clone());
            }
        }
        if responder_id.matches(&self.issuer)? {
            return Ok(self.issuer.clone());
        }
        if !response_certificates.is_empty() || self.responder_certificate.is_some() {
            return Err(OcspError::ResponderIdMismatch);
        }
        Err(OcspError::ResponderCertificateNotFound)
    }

    fn check_delegated_responder(
        &self,
        signer: &ParsedCertificate,
        response_certificates: &[ParsedCertificate],
        now: i64,
    ) -> Result<()> {
        let (critical, oids) = signer
            .extended_key_usage()?
            .ok_or(OcspError::MissingOcspSigningEku)?;
        if !oids.iter().any(|oid| oid.as_str() == OID_OCSP_SIGNING) {
            return Err(OcspError::MissingOcspSigningEku);
        }
        if self.options.require_ocsp_signing_eku_critical && !critical {
            return Err(OcspError::OcspSigningEkuNotCritical);
        }
        if !signer.is_valid_at(now) {
            return Err(OcspError::ResponderCertificateExpired);
        }
        if self.options.check_responder_chain {
            self.verify_responder_chain(signer, response_certificates, now)
        } else {
            signer.verify_issued_by(&self.issuer, now)
        }
    }

    /// Walks from `signer` up through the certificates carried in the response
    /// until a certificate is directly signed by the issuer.
    fn verify_responder_chain(
        &self,
        signer: &ParsedCertificate,
        response_certificates: &[ParsedCertificate],
        now: i64,
    ) -> Result<()> {
        let mut current = signer.clone();
        let mut visited = vec![current.der.clone()];
        for _ in 0..8 {
            if name_eq(&current.issuer_name, &self.issuer.subject_name) {
                current.verify_signature(&self.issuer)?;
                return Ok(());
            }
            let mut next_certificate = None;
            for candidate in response_certificates {
                if visited.iter().any(|der| der == &candidate.der) {
                    continue;
                }
                if !name_eq(&candidate.subject_name, &current.issuer_name) {
                    continue;
                }
                if !candidate.is_valid_at(now) {
                    return Err(OcspError::ResponderCertificateExpired);
                }
                if current.verify_signature(candidate).is_ok() {
                    next_certificate = Some(candidate.clone());
                    break;
                }
            }
            match next_certificate {
                Some(certificate) => {
                    visited.push(certificate.der.clone());
                    current = certificate;
                }
                None => return Err(OcspError::ResponderChainIncomplete),
            }
        }
        Err(OcspError::ResponderChainIncomplete)
    }

    fn check_response_type(&self, request: &OcspRequest) -> Result<()> {
        let acceptable = request.acceptable_response_types()?;
        if !acceptable.is_empty()
            && !acceptable
                .iter()
                .any(|oid| oid.as_str() == OID_BASIC_RESPONSE)
        {
            return Err(OcspError::UnacceptableResponseType);
        }
        Ok(())
    }

    fn check_nonce(&self, request: &OcspRequest, basic: &BasicOcspResponse) -> Result<()> {
        let request_nonce = request.nonce()?;
        let response_nonce = self.response_nonce(basic)?;
        match (request_nonce, response_nonce) {
            (Some(expected), Some(found)) => {
                if expected != found {
                    return Err(OcspError::NonceMismatch);
                }
            }
            (Some(_), None) if self.options.require_nonce_echo => {
                return Err(OcspError::NonceMismatch);
            }
            _ => {}
        }
        Ok(())
    }

    fn response_nonce(&self, basic: &BasicOcspResponse) -> Result<Option<Vec<u8>>> {
        let mut values = nonces(&basic.tbs_response_data.extensions)?;
        for single in &basic.tbs_response_data.responses {
            values.extend(nonces(&single.extensions)?);
        }
        values.sort();
        values.dedup();
        match values.len() {
            0 => Ok(None),
            1 => Ok(values.pop()),
            _ => Err(OcspError::MultipleNonces),
        }
    }

    fn check_request_matches(
        &self,
        request: &OcspRequest,
        basic: &BasicOcspResponse,
    ) -> Result<()> {
        if request.tbs_request.requests.is_empty() {
            return Err(OcspError::EmptyRequest);
        }
        for entry in &request.tbs_request.requests {
            if basic
                .tbs_response_data
                .responses
                .iter()
                .any(|single| single.cert_id.same_as(&entry.cert_id))
            {
                continue;
            }
            if let Some(single) = basic
                .tbs_response_data
                .responses
                .iter()
                .find(|single| single.cert_id.same_issuer(&entry.cert_id))
            {
                return Err(OcspError::SerialMismatch {
                    expected: entry.cert_id.serial_hex(),
                    found: single.cert_id.serial_hex(),
                });
            }
            return Err(OcspError::MissingResponse(entry.cert_id.serial_hex()));
        }
        Ok(())
    }

    fn check_freshness(&self, single: &SingleResponse, now: i64, skew: i64) -> Result<()> {
        if let Some(next_update) = single.next_update {
            if next_update < single.this_update {
                return Err(OcspError::InvalidValidity {
                    this_update: single.this_update,
                    next_update,
                });
            }
        }
        if single.this_update > now.saturating_add(skew) {
            return Err(OcspError::NotYetValid {
                field: "thisUpdate",
                value: single.this_update,
            });
        }
        if let Some(next_update) = single.next_update {
            if now.saturating_sub(skew) > next_update {
                return Err(OcspError::Expired { next_update });
            }
        } else if self.options.require_next_update {
            return Err(OcspError::MissingNextUpdate);
        }
        if let Some(max_age) = self.options.max_age {
            let max_age = i64::try_from(max_age.as_secs())
                .map_err(|_| OcspError::Time("max_age does not fit in an i64".into()))?;
            if now.saturating_sub(single.this_update) > max_age.saturating_add(skew) {
                return Err(OcspError::TooOld {
                    this_update: single.this_update,
                });
            }
        }
        if let CertStatus::Revoked {
            revocation_time, ..
        } = &single.cert_status
        {
            if *revocation_time > now.saturating_add(skew) {
                return Err(OcspError::RevocationTimeInFuture(*revocation_time));
            }
        }
        Ok(())
    }
}
