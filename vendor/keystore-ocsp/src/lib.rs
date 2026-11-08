//! OCSP (RFC 6960): requests, responses, a responder and verification.
//!
//! The crate is deliberately independent of any HTTP library. Requests and
//! responses are built and parsed as DER (BER is accepted on the way in through
//! `rasn`), and the client talks to a caller-supplied [`Transport`].
//!
//! # Building a request
//!
//! ```
//! # fn example() -> Result<(), keystore_ocsp::OcspError> {
//! use keystore_ocsp::{CertificateId, HashAlgorithm, OcspRequestBuilder};
//! # let issuer_der: &[u8] = &[];
//! # let serial: &[u8] = &[1];
//! let cert_id = CertificateId::from_issuer(issuer_der, serial, HashAlgorithm::Sha1)?;
//! let request = OcspRequestBuilder::new()
//!     .add_request(cert_id)
//!     .random_nonce(16)?
//!     .accept_basic_response()
//!     .build();
//! let der = request.to_der();
//! # let _ = der;
//! # Ok(())
//! # }
//! ```
//!
//! # Signing a response
//!
//! [`Responder`] wraps a certificate, its PKCS#8 key and an optional chain. It
//! answers every CertID in a request, echoes the nonce and sets producedAt and
//! nextUpdate:
//!
//! ```ignore
//! let responder = Responder::new(&responder_cert, &responder_key, SignatureAlgorithm::Sha256WithEcdsa)?;
//! let response = responder.respond(&request, |cert_id| CertStatus::Good)?;
//! let der = response.to_der();
//! ```
//!
//! # Checking a certificate
//!
//! ```ignore
//! let status = keystore_ocsp::check(&leaf_cert, &issuer_cert, &my_transport)?;
//! ```
//!
//! The responder is checked against the issuer, the ResponderID, the CertID
//! hashes, the nonce, the validity window and the signed TBS bytes. A delegated
//! responder must carry the critical id-kp-OCSPSigning EKU and, when a chain is
//! supplied, must chain to the issuer.

#![forbid(unsafe_code)]

mod ber;

pub mod alg;
pub mod cert;
pub mod error;
pub mod ext;
pub mod name;
pub mod pem;
pub mod request;
pub mod responder;
pub mod response;
pub mod time;
pub mod transport;
pub mod verify;

pub use alg::{AlgorithmIdentifier, HashAlgorithm};
pub use cert::{ParsedCertificate, ocsp_endpoint};
pub use error::{OcspError, Result};
pub use ext::{
    OID_ACCEPTABLE_RESPONSE_TYPES, OID_ARCHIVE_CUTOFF, OID_BASIC_RESPONSE, OID_CRL_REFERENCES,
    OID_EXTENDED_REVOKE, OID_NO_CHECK, OID_NONCE, OID_OCSP_SIGNING,
    OID_PREFERRED_SIGNATURE_ALGORITHMS, OID_SERVICE_LOCATOR, OcspExtension, known_ocsp_extension,
};
pub use name::GeneralName;
pub use request::{
    CertificateId, OcspRequest, OcspRequestBuilder, RequestEntry, RequestSignature, TbsRequest,
};
pub use responder::{DEFAULT_NEXT_UPDATE, Responder};
pub use response::{
    BasicOcspResponse, BasicOcspResponseBuilder, CertStatus, OcspResponse, OcspResponseBuilder,
    ResponderId, ResponseBytes, ResponseData, ResponseStatus, RevocationReason, SingleResponse,
};
pub use time::{
    encode_generalized_time, now_seconds, seconds_to_system_time, system_time_to_seconds,
};
pub use transport::{
    CheckResult, ClientOptions, HttpRequest, HttpResponse, OcspClient, Transport, check,
    check_with_options,
};
pub use verify::{OcspVerifier, VerifiedResponse, VerifyOptions};

#[cfg(test)]
mod tests;
