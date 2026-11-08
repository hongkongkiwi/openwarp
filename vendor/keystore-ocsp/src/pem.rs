//! PEM framing for OCSP requests and responses.

use crate::error::{OcspError, Result};

/// Wraps DER in a PEM block with `label`.
pub fn encode(label: &'static str, der: &[u8]) -> Result<String> {
    let document = der::Document::try_from(der)?;
    document
        .to_pem(label, der::pem::LineEnding::LF)
        .map_err(|error| OcspError::Pem(error.to_string()))
}

/// Unwraps a PEM block, insisting on `label`.
pub fn decode(label: &str, text: &str) -> Result<Vec<u8>> {
    let (found, document) =
        der::Document::from_pem(text).map_err(|error| OcspError::Pem(error.to_string()))?;
    let found = found.trim();
    if !found.eq_ignore_ascii_case(label) {
        return Err(OcspError::Pem(format!(
            "expected a {label} block, found {found}"
        )));
    }
    Ok(document.into_vec())
}
