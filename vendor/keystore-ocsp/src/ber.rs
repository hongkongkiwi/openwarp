//! BER acceptance.
//!
//! DER is the only encoding this crate writes. When a peer sends BER (for
//! example an indefinite-length outer SEQUENCE, a constructed OCTET STRING or a
//! non-minimal length), the strict parser fails; `rasn` can decode the structure
//! and re-encode it as DER, after which the same parser runs. Signed structures
//! keep their original TBS bytes in the strict path, so a signature is never
//! silently broken by this fallback: a BER block whose signature covers BER
//! still verifies against the bytes that arrived.

use crate::error::{OcspError, Result};

pub(crate) fn normalize_request(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: rasn_ocsp::OcspRequest = rasn::ber::decode(bytes)
        .map_err(|error| OcspError::Malformed(format!("BER OCSPRequest: {error:?}")))?;
    rasn::der::encode(&value)
        .map_err(|error| OcspError::Malformed(format!("DER OCSPRequest: {error:?}")))
}

pub(crate) fn normalize_response(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: rasn_ocsp::OcspResponse = rasn::ber::decode(bytes)
        .map_err(|error| OcspError::Malformed(format!("BER OCSPResponse: {error:?}")))?;
    rasn::der::encode(&value)
        .map_err(|error| OcspError::Malformed(format!("DER OCSPResponse: {error:?}")))
}

pub(crate) fn normalize_basic_response(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: rasn_ocsp::BasicOcspResponse = rasn::ber::decode(bytes)
        .map_err(|error| OcspError::Malformed(format!("BER BasicOCSPResponse: {error:?}")))?;
    rasn::der::encode(&value)
        .map_err(|error| OcspError::Malformed(format!("DER BasicOCSPResponse: {error:?}")))
}
