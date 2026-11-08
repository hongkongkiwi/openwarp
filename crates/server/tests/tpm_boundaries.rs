// Synthetic TPM public areas exercise the pinned restricted-RSA profile, not hardware provenance.
#[path = "../src/tpm_attestation.rs"]
mod tpm_attestation;

use base64ct::{Base64, Encoding};
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey, traits::PublicKeyParts};
use std::sync::OnceLock;

fn key() -> &'static RsaPublicKey {
    static KEY: OnceLock<RsaPublicKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPublicKey::from(RsaPrivateKey::new(&mut OsRng, 2048).unwrap()))
}
fn sized(out: &mut Vec<u8>, value: &[u8]) { out.extend_from_slice(&(value.len() as u16).to_be_bytes()); out.extend_from_slice(value); }
fn public(attrs: u32, policy: &[u8], exponent: u32) -> Vec<u8> {
    let mut area = Vec::new(); area.extend_from_slice(&1u16.to_be_bytes()); area.extend_from_slice(&0xbu16.to_be_bytes());
    area.extend_from_slice(&attrs.to_be_bytes()); sized(&mut area, policy);
    for value in [0x10u16, 0x14, 0xb, 2048] { area.extend_from_slice(&value.to_be_bytes()); }
    area.extend_from_slice(&exponent.to_be_bytes()); sized(&mut area, &key().n().to_bytes_be());
    let mut out = Vec::new(); sized(&mut out, &area); out
}
fn validate(bytes: &[u8]) -> Result<String, String> { tpm_attestation::validate_ak(&Base64::encode_string(bytes)) }

#[test]
fn restricted_ak_requires_fixed_origin_signing_and_rejects_decrypt_and_stclear() {
    let required = (1u32 << 1) | (1 << 4) | (1 << 5) | (1 << 16) | (1 << 18);
    let expected = key().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    assert_eq!(validate(&public(required, &[], 0)).unwrap(), expected);
    for bit in [1, 4, 5, 16, 18] {
        assert!(validate(&public(required & !(1 << bit), &[], 0)).is_err(), "missing required attribute bit {}", bit);
    }
    for bit in [2, 17] {
        assert!(validate(&public(required | (1 << bit), &[], 0)).is_err(), "restricted signing profile must reject attribute bit {}", bit);
    }
    assert_eq!(validate(&public(required | (1 << 6), &[], 65537)).unwrap(), expected, "explicit default exponent and user authorization retain the same public key");
    assert_eq!(validate(&public(required | (1 << 7), &[0x51;32], 0)).unwrap(), expected, "SHA256 authPolicy must not alter exported SPKI");
}

#[test]
fn ak_public_size_policy_and_exponent_boundaries_fail_closed() {
    let attrs = (1u32 << 1) | (1 << 4) | (1 << 5) | (1 << 16) | (1 << 18);
    let valid = public(attrs, &[], 0); assert!(validate(&valid).is_ok());
    for len in 0..valid.len() { assert!(validate(&valid[..len]).is_err(), "truncated public area at byte {}", len); }
    let mut trailing = valid.clone(); trailing.push(0); assert!(validate(&trailing).is_err(), "outer TPM2B length cannot hide trailing bytes");
    for len in [1, 31, 33] { assert!(validate(&public(attrs, &vec![0x51;len], 0)).is_err(), "SHA256 authPolicy length {}", len); }
    for exponent in [1, 3, 65539] { assert!(validate(&public(attrs, &[], exponent)).is_err(), "unsupported RSA exponent {}", exponent); }
    for value in [serde_json::Value::Null, serde_json::json!([]), serde_json::json!({}), serde_json::json!({"ak_public": false})] {
        assert!(tpm_attestation::verify(&value, &Base64::encode_string(&valid), key().to_public_key_der().unwrap().as_bytes(), "nonce", &"00".repeat(32)).is_err(), "malformed evidence shape must not authorize attestation");
    }
}
