// Synthetic software-signed TPM wire structures, not evidence from real hardware.
#[path = "../src/tpm_attestation.rs"]
mod tpm_attestation;

use base64ct::{Base64, Encoding};
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15::SigningKey, pkcs8::EncodePublicKey, signature::{Signer, SignatureEncoding}, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

struct Fixture { evidence: Value, pin: String, spki: Vec<u8>, policy: String, ak: RsaPrivateKey }
fn sized(out: &mut Vec<u8>, bytes: &[u8]) { out.extend_from_slice(&(bytes.len() as u16).to_be_bytes()); out.extend_from_slice(bytes); }
fn area(key: &RsaPublicKey, restricted: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u16.to_be_bytes()); p.extend_from_slice(&0xbu16.to_be_bytes());
    let attrs: u32 = 0x40072 | if restricted { 0x10000 } else { 0 };
    p.extend_from_slice(&attrs.to_be_bytes()); sized(&mut p, &[]);
    p.extend_from_slice(&0x10u16.to_be_bytes()); p.extend_from_slice(&0x14u16.to_be_bytes()); p.extend_from_slice(&0xbu16.to_be_bytes());
    p.extend_from_slice(&2048u16.to_be_bytes()); p.extend_from_slice(&0u32.to_be_bytes()); sized(&mut p, &key.n().to_bytes_be());
    let mut out = Vec::new(); sized(&mut out, &p); out
}
fn object_name(area: &[u8]) -> Vec<u8> { let mut n = vec![0, 0x0b]; n.extend_from_slice(&Sha256::digest(&area[2..])); n }
fn header(kind: u16, spki: &[u8]) -> Vec<u8> {
    let mut b = Vec::new(); b.extend_from_slice(&0xff544347u32.to_be_bytes()); b.extend_from_slice(&kind.to_be_bytes());
    // Deliberately NOT the AK Name: qualified Names include hierarchy ancestry.
    let mut qualified = vec![0, 0x0b]; qualified.extend_from_slice(&[0x42; 32]); sized(&mut b, &qualified);
    let mut h = Sha256::new(); h.update(b"OpenWarp/TPM2/enroll/v1\0"); h.update(b"nonce"); h.update(Sha256::digest(spki)); sized(&mut b, &h.finalize());
    b.extend_from_slice(&100u64.to_be_bytes()); b.extend_from_slice(&2u32.to_be_bytes()); b.extend_from_slice(&3u32.to_be_bytes()); b.push(1); b.extend_from_slice(&4u64.to_be_bytes()); b
}
fn sign(key: &RsaPrivateKey, message: &[u8]) -> String {
    let sig = SigningKey::<Sha256>::new(key.clone()).sign(message).to_vec();
    let mut b = vec![0, 0x14, 0, 0x0b]; sized(&mut b, &sig); Base64::encode_string(&b)
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let ak = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let device = RsaPrivateKey::new(&mut OsRng, 2048).unwrap(); let device = RsaPublicKey::from(&device);
        let spki = device.to_public_key_der().unwrap().as_bytes().to_vec();
        let ak_area = area(&RsaPublicKey::from(&ak), true); let key_area = area(&device, false);
        let mut certify = header(0x8017, &spki); sized(&mut certify, &object_name(&key_area)); sized(&mut certify, &object_name(&key_area));
        let values = [0x23; 256]; let digest = Sha256::digest(values);
        let mut quote = header(0x8018, &spki); quote.extend_from_slice(&1u32.to_be_bytes()); quote.extend_from_slice(&[0, 0x0b, 3, 0xff, 0, 0]); sized(&mut quote, &digest);
        let pin = Base64::encode_string(&ak_area);
        let evidence = json!({"ak_public":pin,"key_public":Base64::encode_string(&key_area),"certify":Base64::encode_string(&certify),"certify_signature":sign(&ak,&certify),"quote":Base64::encode_string(&quote),"quote_signature":sign(&ak,&quote),"pcrs":vec![Base64::encode_string(&[0x23;32]);8]});
        Fixture { evidence, pin, spki, policy: digest.iter().map(|b| format!("{b:02x}")).collect(), ak }
    })
}
fn verify(e: &Value) -> Result<Value, String> { let f = fixture(); tpm_attestation::verify(e, &f.pin, &f.spki, "nonce", &f.policy) }
fn mutate_signed(e: &mut Value, field: &str, change: impl FnOnce(&mut Vec<u8>)) {
    let mut b = Base64::decode_vec(e[field].as_str().unwrap()).unwrap(); change(&mut b);
    e[field] = json!(Base64::encode_string(&b)); e[format!("{field}_signature")] = json!(sign(&fixture().ak, &b));
}
#[test]
fn synthetic_valid_quote_and_certify() {
    let f = fixture(); let summary = verify(&f.evidence).unwrap();
    assert_eq!(summary["trust"], "operator_pinned_ak"); assert_eq!(summary["pcr_digest"], f.policy);
    assert_eq!(summary["quote_clock"]["restart_count"], 3);
    assert!(tpm_attestation::validate_ak(&f.pin).unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));
}
#[test]
fn nonce_and_spki_must_match() {
    let f = fixture();
    assert!(tpm_attestation::verify(&f.evidence, &f.pin, &f.spki, "other", &f.policy).unwrap_err().contains("binding"));
    let ak_spki = RsaPublicKey::from(&f.ak).to_public_key_der().unwrap();
    assert!(tpm_attestation::verify(&f.evidence, &f.pin, ak_spki.as_bytes(), "nonce", &f.policy).unwrap_err().contains("CSR SPKI"));
}
#[test]
fn operator_pin_is_exact_public_area_not_just_rsa_key() {
    let mut e = fixture().evidence.clone(); let mut b = Base64::decode_vec(e["ak_public"].as_str().unwrap()).unwrap(); b[9] ^= 0x40; e["ak_public"] = json!(Base64::encode_string(&b));
    assert!(verify(&e).unwrap_err().contains("pin"));
}
#[test]
fn unsigned_tampering_fails_both_signatures() {
    for field in ["quote", "certify"] {
        let mut e = fixture().evidence.clone(); let mut b = Base64::decode_vec(e[field].as_str().unwrap()).unwrap(); b[20] ^= 1; e[field] = json!(Base64::encode_string(&b));
        assert!(verify(&e).unwrap_err().contains("signature verification"));
    }
}
#[test]
fn signed_magic_type_name_and_binding_are_checked() {
    for (field, offset) in [("quote", 0), ("quote", 5), ("certify", 108), ("certify", 45)] {
        let mut e = fixture().evidence.clone(); mutate_signed(&mut e, field, |b| b[offset] ^= 1); assert!(verify(&e).is_err());
    }
}
#[test]
fn signed_pcr_bank_selection_and_digest_cannot_choose_policy() {
    // Header is 101 bytes; selection is count(4), bank(2), size(1), bitmap(3).
    for offset in [106, 107, 108, 109, 113] {
        let mut e = fixture().evidence.clone(); mutate_signed(&mut e, "quote", |b| b[offset] ^= 1); assert!(verify(&e).is_err());
    }
    let mut e = fixture().evidence.clone(); e["pcrs"][0] = json!(Base64::encode_string(&[0;32])); assert!(verify(&e).unwrap_err().contains("PCR digest"));
    let f = fixture(); assert!(tpm_attestation::verify(&f.evidence, &f.pin, &f.spki, "nonce", "").is_err());
    assert!(tpm_attestation::verify(&f.evidence, &f.pin, &f.spki, "nonce", &"00".repeat(32)).is_err());
}
#[test]
fn qualified_name_is_not_object_name_but_signers_must_agree() {
    assert!(verify(&fixture().evidence).is_ok());
    let mut e = fixture().evidence.clone(); mutate_signed(&mut e, "quote", |b| b[10] ^= 1); assert!(verify(&e).unwrap_err().contains("qualified signers"));
}
#[test]
fn unsafe_clock_is_rejected() {
    let mut e = fixture().evidence.clone(); mutate_signed(&mut e, "quote", |b| b[92] = 0); assert!(verify(&e).unwrap_err().contains("clock"));
}
#[test]
fn trailing_and_truncated_structures_fail_closed() {
    for field in ["quote", "certify"] {
        for append in [true, false] {
            let mut e = fixture().evidence.clone(); mutate_signed(&mut e, field, |b| { if append { b.push(0); } else { b.pop(); } }); assert!(verify(&e).is_err());
        }
    }
    for field in ["ak_public", "key_public", "quote_signature", "certify_signature"] {
        let mut e = fixture().evidence.clone(); let mut b = Base64::decode_vec(e[field].as_str().unwrap()).unwrap(); b.push(0); e[field] = json!(Base64::encode_string(&b)); assert!(verify(&e).is_err());
    }
}
#[test]
fn malformed_inputs_and_unbounded_values_are_rejected() {
    for field in ["ak_public", "key_public", "quote", "certify", "quote_signature", "certify_signature"] {
        for bad in ["!".to_owned(), "A".repeat(12000)] { let mut e = fixture().evidence.clone(); e[field] = json!(bad); assert!(verify(&e).is_err()); }
    }
    let mut e = fixture().evidence.clone(); e["pcrs"] = json!([]); assert!(verify(&e).is_err());
    assert!(tpm_attestation::validate_ak("AAAA").is_err());
}
#[test]
fn public_attributes_and_signature_scheme_are_enforced() {
    let f = fixture();
    for offset in [8, 9, 11, 17] {
        let mut b = Base64::decode_vec(&f.pin).unwrap(); b[offset] ^= 1;
        assert!(tpm_attestation::validate_ak(&Base64::encode_string(&b)).is_err());
    }
    let mut e = f.evidence.clone(); let mut b = Base64::decode_vec(e["key_public"].as_str().unwrap()).unwrap(); b[7] |= 1; e["key_public"] = json!(Base64::encode_string(&b)); assert!(verify(&e).is_err());
}
