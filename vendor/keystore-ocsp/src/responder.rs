//! The responder: signs BasicOCSPResponses for the certificates named in a
//! request, echoes the nonce and carries the responder chain.

use std::time::{Duration, SystemTime};

use keystore_pki::SignatureAlgorithm;

use crate::cert::ParsedCertificate;
use crate::error::{OcspError, Result};
use crate::ext::{OID_BASIC_RESPONSE, OcspExtension};
use crate::request::{CertificateId, OcspRequest};
use crate::response::{
    BasicOcspResponse, BasicOcspResponseBuilder, CertStatus, OcspResponse, OcspResponseBuilder,
    ResponderId,
};
use crate::time::system_time_to_seconds;

/// Default lifetime of a generated response.
pub const DEFAULT_NEXT_UPDATE: Duration = Duration::from_secs(3600);

/// A signer that can answer OCSP requests.
#[derive(Clone, Debug)]
pub struct Responder {
    certificate: Vec<u8>,
    certificate_info: ParsedCertificate,
    private_key_pkcs8: Vec<u8>,
    algorithm: SignatureAlgorithm,
    chain: Vec<Vec<u8>>,
    responder_id: ResponderId,
    next_update: Option<Duration>,
    include_chain: bool,
}

impl Responder {
    /// Creates a responder from its certificate and PKCS#8 private key.
    ///
    /// The ResponderID defaults to the certificate's subject name, which is
    /// what BouncyCastle's RespID(X500Name) does.
    pub fn new(
        certificate_der: &[u8],
        private_key_pkcs8: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        let certificate_info = ParsedCertificate::parse(certificate_der)?;
        let responder_id = ResponderId::from_certificate_info(&certificate_info);
        Ok(Responder {
            certificate: certificate_der.to_vec(),
            certificate_info,
            private_key_pkcs8: private_key_pkcs8.to_vec(),
            algorithm,
            chain: Vec::new(),
            responder_id,
            next_update: Some(DEFAULT_NEXT_UPDATE),
            include_chain: true,
        })
    }

    /// Replaces the ResponderID. A byKey ID must be the SHA-1 digest of the
    /// responder certificate's public key for clients to match it.
    pub fn with_responder_id(mut self, responder_id: ResponderId) -> Self {
        self.responder_id = responder_id;
        self
    }

    /// Supplies the chain to include in responses, leaf-facing first. The
    /// signer certificate itself is always included when the chain is enabled.
    pub fn with_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.chain = chain;
        self
    }

    /// Sets the nextUpdate interval. `None` omits nextUpdate from responses.
    pub fn with_next_update(mut self, next_update: Option<Duration>) -> Self {
        self.next_update = next_update;
        self
    }

    /// Turns inclusion of the responder certificate and chain on or off.
    pub fn with_include_chain(mut self, include_chain: bool) -> Self {
        self.include_chain = include_chain;
        self
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    pub fn certificate_info(&self) -> &ParsedCertificate {
        &self.certificate_info
    }

    pub fn responder_id(&self) -> &ResponderId {
        &self.responder_id
    }

    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Answers every CertID in `request`, asking `status_of` for each status.
    pub fn respond<F>(&self, request: &OcspRequest, status_of: F) -> Result<OcspResponse>
    where
        F: FnMut(&CertificateId) -> CertStatus,
    {
        self.respond_at(request, status_of, SystemTime::now())
    }

    /// Answers a request at a caller-supplied producedAt.
    pub fn respond_at<F>(
        &self,
        request: &OcspRequest,
        status_of: F,
        produced_at: SystemTime,
    ) -> Result<OcspResponse>
    where
        F: FnMut(&CertificateId) -> CertStatus,
    {
        let basic = self.build_basic(request, status_of, produced_at)?;
        OcspResponseBuilder::successful().build(Some(&basic))
    }

    /// Produces just the signed BasicOCSPResponse.
    pub fn respond_basic<F>(&self, request: &OcspRequest, status_of: F) -> Result<BasicOcspResponse>
    where
        F: FnMut(&CertificateId) -> CertStatus,
    {
        self.build_basic(request, status_of, SystemTime::now())
    }

    /// Produces just the signed BasicOCSPResponse at a caller-supplied
    /// producedAt.
    pub fn respond_basic_at<F>(
        &self,
        request: &OcspRequest,
        status_of: F,
        produced_at: SystemTime,
    ) -> Result<BasicOcspResponse>
    where
        F: FnMut(&CertificateId) -> CertStatus,
    {
        self.build_basic(request, status_of, produced_at)
    }

    fn build_basic<F>(
        &self,
        request: &OcspRequest,
        mut status_of: F,
        produced_at: SystemTime,
    ) -> Result<BasicOcspResponse>
    where
        F: FnMut(&CertificateId) -> CertStatus,
    {
        if request.tbs_request.version != 0 {
            return Err(OcspError::Malformed(format!(
                "unsupported OCSP request version {}",
                request.tbs_request.version
            )));
        }
        let acceptable = request.acceptable_response_types()?;
        if !acceptable.is_empty()
            && !acceptable
                .iter()
                .any(|oid| oid.as_str() == OID_BASIC_RESPONSE)
        {
            return Err(OcspError::UnacceptableResponseType);
        }

        let produced_at_seconds = system_time_to_seconds(produced_at)?;
        let next_update = match self.next_update {
            Some(duration) => {
                let seconds = i64::try_from(duration.as_secs()).map_err(|_| {
                    OcspError::Time("nextUpdate interval does not fit in an i64".into())
                })?;
                Some(produced_at_seconds.saturating_add(seconds))
            }
            None => None,
        };

        let mut builder = BasicOcspResponseBuilder::new_at(self.responder_id.clone(), produced_at)?;
        for entry in &request.tbs_request.requests {
            let status = status_of(&entry.cert_id);
            builder.add_response(
                entry.cert_id.clone(),
                status,
                produced_at_seconds,
                next_update,
            );
        }
        if let Some(nonce) = request.nonce()? {
            builder = builder.response_extension(OcspExtension::nonce(&nonce));
        }

        builder.build(
            &self.private_key_pkcs8,
            self.algorithm,
            self.certificates_to_include(),
        )
    }

    /// Answers every CertID as good.
    pub fn respond_all_good(&self, request: &OcspRequest) -> Result<OcspResponse> {
        self.respond(request, |_| CertStatus::Good)
    }

    /// Answers from a list of IDs and statuses. A CertID with no entry is
    /// reported as unknown, which is the conservative answer.
    pub fn respond_with_statuses(
        &self,
        request: &OcspRequest,
        statuses: &[(CertificateId, CertStatus)],
    ) -> Result<OcspResponse> {
        self.respond(request, |cert_id| {
            statuses
                .iter()
                .find(|(known, _)| known.same_as(cert_id))
                .map(|(_, status)| status.clone())
                .unwrap_or(CertStatus::Unknown)
        })
    }

    /// The certificates placed in the response's `certs` field.
    pub fn certificates_to_include(&self) -> Vec<Vec<u8>> {
        let mut certificates = Vec::new();
        if !self.include_chain {
            return certificates;
        }
        certificates.push(self.certificate.clone());
        for certificate in &self.chain {
            if !certificates.iter().any(|existing| existing == certificate) {
                certificates.push(certificate.clone());
            }
        }
        certificates
    }
}
