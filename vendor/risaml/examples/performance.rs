//! Local fixture microbenchmarks for XML, bindings, and metadata lookup.
//!
//! Run with `cargo run --release --no-default-features --example performance`.
//! Results are aggregate wall-clock timings, not end-to-end SSO latency.

use std::hint::black_box;
use std::time::Instant;

use risaml::binding::{
    base64_decode, base64_decode_with_limit, base64_encode, deflate_raw_decode, deflate_raw_encode,
};
use risaml::constants::CertUse;
use risaml::metadata::{IdpMetadata, Metadata};
use risaml::xml::{dom, extract, fields, ExtractorField};

fn measure<T>(name: &str, iterations: usize, mut work: impl FnMut() -> T) {
    for _ in 0..100 {
        black_box(work());
    }
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(work());
        }
        samples.push(start.elapsed().as_nanos() / iterations as u128);
    }
    samples.sort_unstable();
    println!("{name}: median={} ns/op samples={samples:?}", samples[3]);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = include_str!("../tests/fixtures/response.xml");
    let request = include_str!("../tests/fixtures/misc/request.xml");
    let metadata = include_str!("../tests/fixtures/spmeta.xml");
    let rolling = IdpMetadata::from_xml(include_str!(
        "../tests/fixtures/misc/idpmeta_rollingcert.xml"
    ))?;
    let encoded = base64_encode(response.as_bytes());
    let spaced = encoded
        .as_bytes()
        .chunks(76)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()?
        .join("\r\n");
    let compressed = deflate_raw_encode(request.as_bytes())?;
    let response_doc = dom::parse(response)?;
    let assertion = extract(
        response,
        &[ExtractorField::new("assertion", &["Response", "Assertion"]).with_context()],
    )?;
    let assertion = assertion.get_str("assertion").ok_or("missing assertion")?;
    let login_fields = fields::login_response_fields(assertion);
    // Validate each fallible workload before timing it, so a future failure
    // cannot silently turn the measurement into an error-path benchmark.
    base64_decode(&encoded)?;
    base64_decode_with_limit(&encoded, response.len())?;
    base64_decode_with_limit(&spaced, response.len())?;
    deflate_raw_decode(&compressed)?;
    extract(response, &login_fields)?;
    Metadata::parse(metadata, Vec::new())?;
    println!(
        "response={} request={} metadata={} assertion={} encoded={} compressed={}",
        response.len(),
        request.len(),
        metadata.len(),
        assertion.len(),
        encoded.len(),
        compressed.len()
    );
    println!(
        "rolling signing certificates={}",
        rolling.x509_certificates(CertUse::Signing).len()
    );
    measure("base64_decode_compact", 20_000, || {
        base64_decode(black_box(&encoded))
    });
    measure("base64_decode_bounded_compact", 20_000, || {
        base64_decode_with_limit(black_box(&encoded), response.len())
    });
    measure("base64_decode_bounded_wrapped", 20_000, || {
        base64_decode_with_limit(black_box(&spaced), response.len())
    });
    measure("base64_encode_response", 20_000, || {
        base64_encode(black_box(response.as_bytes()))
    });
    measure("deflate_encode_request", 3_000, || {
        deflate_raw_encode(black_box(request.as_bytes()))
    });
    measure("deflate_decode_request", 20_000, || {
        deflate_raw_decode(black_box(&compressed))
    });
    measure("dom_parse_response", 10_000, || {
        dom::parse(black_box(response))
    });
    measure("dom_clone_response", 20_000, || {
        black_box(&response_doc).clone()
    });
    measure("dom_parse_metadata", 10_000, || {
        dom::parse(black_box(metadata))
    });
    measure("extract_login_response", 5_000, || {
        extract(black_box(response), black_box(&login_fields))
    });
    measure("metadata_parse_sp", 10_000, || {
        Metadata::parse(black_box(metadata), Vec::new())
    });
    measure("metadata_first_signing_certificate", 50_000, || {
        black_box(&rolling).get_x509_certificate(CertUse::Signing)
    });
    measure("metadata_all_signing_certificates", 50_000, || {
        black_box(&rolling).x509_certificates(CertUse::Signing)
    });
    Ok(())
}
