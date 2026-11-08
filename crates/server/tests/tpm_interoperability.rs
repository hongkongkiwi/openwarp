#[path = "../src/tpm_attestation.rs"] mod tpm_attestation;

#[test]
fn simulator_certify_and_quote_match_the_verifier() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!("fixtures/tpm/manifest.json")).unwrap();
    let evidence: serde_json::Value = serde_json::from_str(include_str!("fixtures/tpm/evidence.json")).unwrap();
    let pin = include_str!("fixtures/tpm/ak-public.b64").trim();
    let spki = include_bytes!("fixtures/tpm/spki.der");
    let nonce = manifest["nonce"].as_str().unwrap();
    let policy = manifest["expected_pcr_digest"].as_str().unwrap();
    assert_eq!(tpm_attestation::validate_ak(pin).unwrap().trim(),include_str!("fixtures/tpm/ak-public.pem").trim());
    let result = tpm_attestation::verify(&evidence, pin, spki, nonce, policy).expect("unmodified swtpm evidence must verify");
    assert_eq!(result["pcr_digest"], policy);
    assert!(tpm_attestation::verify(&evidence, pin, spki, "replayed-into-another-enrollment", policy).is_err());
    assert!(tpm_attestation::verify(&evidence, pin, spki, nonce, &"f".repeat(64)).is_err());
}
