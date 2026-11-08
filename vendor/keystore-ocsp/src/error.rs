//! The error type shared by the OCSP request, response, responder and
//! verification halves of the crate.

use crate::response::ResponseStatus;

/// Anything that can go wrong while building, parsing or verifying OCSP.
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    #[error("malformed OCSP structure: {0}")]
    Malformed(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(String),

    #[error("unsupported OCSP response type: {0}")]
    UnsupportedResponseType(String),

    #[error("OCSP response was not successful: {0}")]
    Unsuccessful(ResponseStatus),

    #[error("successful OCSP response carries no responseBytes")]
    MissingResponseBytes,

    #[error("the response is not a basic OCSP response")]
    NotBasicResponse,

    #[error("the OCSP response signature is invalid")]
    InvalidSignature,

    #[error("the responder certificate does not match the ResponderID")]
    ResponderIdMismatch,

    #[error("no responder certificate matches the ResponderID and the issuer did not sign")]
    ResponderCertificateNotFound,

    #[error("the responder certificate is not a delegated OCSP signer")]
    ResponderNotAuthorized,

    #[error("the responder certificate has no id-kp-OCSPSigning extended key usage")]
    MissingOcspSigningEku,

    #[error("the responder certificate marks id-kp-OCSPSigning non-critical")]
    OcspSigningEkuNotCritical,

    #[error("the responder certificate is outside its validity period")]
    ResponderCertificateExpired,

    #[error("the responder certificate chain does not reach the issuer")]
    ResponderChainIncomplete,

    #[error("certificate is not issued by the expected issuer")]
    WrongIssuer,

    #[error("the certificate ID does not match the issuer: {0}")]
    CertIdMismatch(String),

    #[error("serial number mismatch: expected {expected}, found {found}")]
    SerialMismatch { expected: String, found: String },

    #[error("the request has no entry for certificate serial {0}")]
    MissingResponse(String),

    #[error("the response contains an entry that was not requested")]
    ResponseNotRequested,

    #[error("the request contains no certificate IDs")]
    EmptyRequest,

    #[error("the response has no thisUpdate")]
    MissingThisUpdate,

    #[error("the response has no nextUpdate")]
    MissingNextUpdate,

    #[error("the response is stale: nextUpdate {next_update} has passed")]
    Expired { next_update: i64 },

    #[error("the response is stale: thisUpdate {this_update} is older than the maximum age")]
    TooOld { this_update: i64 },

    #[error("the response is not yet valid: {field} {value} is in the future")]
    NotYetValid { field: &'static str, value: i64 },

    #[error("nextUpdate {next_update} precedes thisUpdate {this_update}")]
    InvalidValidity { this_update: i64, next_update: i64 },

    #[error("the revocation time {0} is in the future")]
    RevocationTimeInFuture(i64),

    #[error("nonce mismatch")]
    NonceMismatch,

    #[error("the response carries more than one OCSP nonce")]
    MultipleNonces,

    #[error("the response contains unsupported critical extension {0}")]
    UnsupportedCriticalExtension(String),

    #[error("the response type is not acceptable to the requestor")]
    UnacceptableResponseType,

    #[error("the request is not signed")]
    NotSigned,

    #[error("a requestorName is required before a request can be signed")]
    RequestorNameRequired,

    #[error("the requestorName does not match the signing certificate")]
    RequestorNameMismatch,

    #[error("the certificate has no OCSP access location")]
    NoOcspEndpoint,

    #[error("the OCSP transport returned HTTP status {0}")]
    HttpStatus(u16),

    #[error("the OCSP transport returned an empty body")]
    EmptyResponseBody,

    #[error("transport failure: {0}")]
    Transport(String),

    #[error("time value is invalid: {0}")]
    Time(String),

    #[error("PEM decoding failed: {0}")]
    Pem(String),

    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Core(#[from] keystore_core::Error),
}

pub type Result<T> = std::result::Result<T, OcspError>;

impl From<der::Error> for OcspError {
    fn from(error: der::Error) -> Self {
        OcspError::Malformed(error.to_string())
    }
}
