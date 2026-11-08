//! The client half: a transport trait, a request/response pair and the
//! high-level `check` that builds, sends and verifies a request.
//!
//! There is deliberately no HTTP implementation here. Callers plug in
//! `reqwest`, `ureq`, `curl` or a test double by implementing [`Transport`].

use crate::alg::HashAlgorithm;
use crate::cert::ParsedCertificate;
use crate::error::{OcspError, Result};
use crate::name::name_eq;
use crate::request::{CertificateId, OcspRequest, OcspRequestBuilder};
use crate::response::{CertStatus, OcspResponse};
use crate::verify::{OcspVerifier, VerifiedResponse, VerifyOptions};

/// A minimal HTTP request as handed to a [`Transport`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// The HTTP method. The client uses POST, as RFC 6960 section 4.1.1
    /// describes, but the trait is not restricted to it.
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A minimal HTTP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        HttpResponse {
            status,
            headers,
            body,
        }
    }

    /// A header value, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The caller-supplied HTTP transport.
pub trait Transport {
    /// The OCSP endpoint for a certificate. The default reads the first
    /// id-ad-ocsp URI from the certificate's AIA extension.
    fn endpoint(&self, certificate: &[u8], _issuer: &[u8]) -> Result<String> {
        crate::cert::ocsp_endpoint(certificate)
    }

    /// Performs the request and returns the status, headers and body.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

/// Client policy.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// The digest CertID uses.
    pub hash_algorithm: HashAlgorithm,
    /// The nonce length in bytes. Zero disables the nonce.
    pub nonce_length: usize,
    /// An endpoint that overrides [`Transport::endpoint`].
    pub endpoint: Option<String>,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
    /// Verification policy.
    pub verify: VerifyOptions,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            hash_algorithm: HashAlgorithm::Sha1,
            nonce_length: 16,
            endpoint: None,
            headers: Vec::new(),
            verify: VerifyOptions::default(),
        }
    }
}

/// The result of a complete check.
#[derive(Clone, Debug)]
pub struct CheckResult {
    pub status: CertStatus,
    pub request: OcspRequest,
    pub response: OcspResponse,
    pub verified: VerifiedResponse,
}

/// A client that drives a [`Transport`] and verifies what comes back.
pub struct OcspClient<'a, T: Transport + ?Sized> {
    transport: &'a T,
    options: ClientOptions,
}

impl<'a, T: Transport + ?Sized> OcspClient<'a, T> {
    pub fn new(transport: &'a T) -> Self {
        OcspClient {
            transport,
            options: ClientOptions::default(),
        }
    }

    pub fn with_options(transport: &'a T, options: ClientOptions) -> Self {
        OcspClient { transport, options }
    }

    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// Builds the request this client would send for `certificate_der`.
    pub fn build_request(&self, certificate_der: &[u8], issuer_der: &[u8]) -> Result<OcspRequest> {
        let certificate = ParsedCertificate::parse(certificate_der)?;
        let issuer = ParsedCertificate::parse(issuer_der)?;
        if !name_eq(&certificate.issuer_name, &issuer.subject_name) {
            return Err(OcspError::WrongIssuer);
        }
        let cert_id = CertificateId::from_issuer_info(
            &issuer,
            &certificate.serial,
            self.options.hash_algorithm.clone(),
        )?;
        let mut builder = OcspRequestBuilder::new()
            .add_request(cert_id)
            .accept_basic_response();
        if self.options.nonce_length > 0 {
            builder = builder.random_nonce(self.options.nonce_length)?;
        }
        Ok(builder.build())
    }

    /// Runs the whole exchange and returns the certificate's status.
    pub fn check(&self, certificate_der: &[u8], issuer_der: &[u8]) -> Result<CertStatus> {
        Ok(self.check_detailed(certificate_der, issuer_der)?.status)
    }

    /// Runs the exchange and returns the request, the parsed response and the
    /// verified form alongside the status.
    pub fn check_detailed(&self, certificate_der: &[u8], issuer_der: &[u8]) -> Result<CheckResult> {
        let certificate = ParsedCertificate::parse(certificate_der)?;
        let request = self.build_request(certificate_der, issuer_der)?;
        let endpoint = match &self.options.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => self.transport.endpoint(certificate_der, issuer_der)?,
        };

        let mut headers = vec![
            (
                "Content-Type".to_string(),
                "application/ocsp-request".to_string(),
            ),
            (
                "Accept".to_string(),
                "application/ocsp-response".to_string(),
            ),
        ];
        headers.extend(self.options.headers.iter().cloned());

        let http_response = self.transport.send(&HttpRequest {
            method: "POST".to_string(),
            url: endpoint,
            headers,
            body: request.to_der(),
        })?;
        if !(200..300).contains(&http_response.status) {
            return Err(OcspError::HttpStatus(http_response.status));
        }
        if http_response.body.is_empty() {
            return Err(OcspError::EmptyResponseBody);
        }

        let response = OcspResponse::from_der(&http_response.body)?;
        let verifier = OcspVerifier::new(issuer_der)?.with_options(self.options.verify.clone());
        let verified = verifier.verify(&response, &request)?;
        let status = verified
            .status_for_serial(&certificate.serial)
            .cloned()
            .ok_or_else(|| {
                OcspError::MissingResponse(crate::cert::hex_string(&certificate.serial))
            })?;
        Ok(CheckResult {
            status,
            request,
            response,
            verified,
        })
    }
}

/// Convenience wrapper: build, send and verify an OCSP request.
pub fn check<T: Transport + ?Sized>(
    certificate_der: &[u8],
    issuer_der: &[u8],
    transport: &T,
) -> Result<CertStatus> {
    OcspClient::new(transport).check(certificate_der, issuer_der)
}

/// Convenience wrapper with explicit client options.
pub fn check_with_options<T: Transport + ?Sized>(
    certificate_der: &[u8],
    issuer_der: &[u8],
    transport: &T,
    options: ClientOptions,
) -> Result<CertStatus> {
    OcspClient::with_options(transport, options).check(certificate_der, issuer_der)
}
