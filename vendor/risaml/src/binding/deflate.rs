//! Raw DEFLATE (RFC 1951) used by the SAML HTTP-Redirect binding.

use std::io::{Error, ErrorKind, Write};

use flate2::write::DeflateEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};

use crate::error::SamlError;

/// Default maximum inflated size accepted by [`deflate_raw_decode`].
///
/// SAML does not define this number. It is a conservative library default for
/// HTTP-Redirect, where messages are decoded before XML or signature validation
/// and normally remain well below this size. Use
/// [`deflate_raw_decode_with_limit`] when a caller needs a different cap.
pub const MAX_DEFLATE_RAW_DECODE_BYTES: usize = 1024 * 1024;

const DEFLATE_OUTPUT_LIMIT_EXCEEDED: &str = "ERR_DEFLATE_OUTPUT_LIMIT_EXCEEDED";

/// Raw-DEFLATE compress `input` (no zlib/gzip header), as required by the
/// HTTP-Redirect binding.
pub fn deflate_raw_encode(input: &[u8]) -> Result<Vec<u8>, SamlError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}

/// Inflate raw-DEFLATE `input` produced by [`deflate_raw_encode`].
pub fn deflate_raw_decode(input: &[u8]) -> Result<Vec<u8>, SamlError> {
    deflate_raw_decode_with_limit(input, MAX_DEFLATE_RAW_DECODE_BYTES)
}

/// Inflate a complete raw-DEFLATE stream, failing if the inflated output
/// exceeds `max_output_len` bytes. Bytes following the stream are ignored.
pub fn deflate_raw_decode_with_limit(
    input: &[u8],
    max_output_len: usize,
) -> Result<Vec<u8>, SamlError> {
    let mut decoder = Decompress::new(false);
    let mut out = Vec::with_capacity(input.len().min(max_output_len));
    let read_limit = max_output_len.saturating_add(1);
    let mut buffer = [0; 4096];
    let mut input_offset = 0;

    loop {
        let output_len = buffer.len().min(read_limit.saturating_sub(out.len()));
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(
                &input[input_offset..],
                &mut buffer[..output_len],
                FlushDecompress::None,
            )
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let consumed = (decoder.total_in() - before_in) as usize;
        let written = (decoder.total_out() - before_out) as usize;
        input_offset += consumed;
        out.extend_from_slice(&buffer[..written]);

        if out.len() > max_output_len {
            return Err(SamlError::Invalid(DEFLATE_OUTPUT_LIMIT_EXCEEDED.into()));
        }

        match status {
            Status::StreamEnd => return Ok(out),
            Status::Ok | Status::BufError => {
                if consumed == 0 && written == 0 {
                    return Err(
                        Error::new(ErrorKind::UnexpectedEof, "incomplete DEFLATE stream").into(),
                    );
                }
            }
        }
    }
}
