//! TPM2 restricted RSA AK profile. Trust comes only from an operator-pinned TPM2B_PUBLIC
//! provisioned over a trusted channel, not an AK certificate, EK proof, or these attributes.
use base64ct::{Base64, Encoding};
use rsa::{BigUint, RsaPublicKey, pkcs1v15::{Signature, VerifyingKey}, pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding}, signature::Verifier, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SHA256: u16 = 0x000b;
const NULL: u16 = 0x0010;
const RSASSA: u16 = 0x0014;
const FIXED: u32 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 18);
const RESTRICTED: u32 = 1 << 16;

struct Reader<'a> { bytes: &'a [u8], pos: usize }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("TPM length overflow")?;
        let bytes = self.bytes.get(self.pos..end).ok_or("truncated TPM structure")?;
        self.pos = end; Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, String> { let b = self.take(2)?; Ok(u16::from_be_bytes([b[0], b[1]])) }
    fn u32(&mut self) -> Result<u32, String> { let b = self.take(4)?; Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }
    fn u64(&mut self) -> Result<u64, String> { let b = self.take(8)?; Ok(u64::from_be_bytes(b.try_into().map_err(|_| "invalid clock")?)) }
    fn sized(&mut self) -> Result<&'a [u8], String> { let n = self.u16()? as usize; self.take(n) }
    fn end(&self) -> Result<(), String> { if self.pos == self.bytes.len() { Ok(()) } else { Err("trailing TPM bytes".into()) } }
}
fn decode(s: &str, max: usize) -> Result<Vec<u8>, String> {
    if s.len() > max * 4 / 3 + 4 { return Err("TPM value too large".into()); }
    let bytes = Base64::decode_vec(s).map_err(|_| "invalid TPM base64")?;
    if bytes.len() > max { return Err("TPM value too large".into()); } Ok(bytes)
}
fn field(e: &Value, key: &str, max: usize) -> Result<Vec<u8>, String> {
    decode(e.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing TPM {key}"))?, max)
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn name(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != 34 || bytes[..2] != SHA256.to_be_bytes() { return Err("expected SHA256 TPM Name".into()); } Ok(())
}
struct Public { key: RsaPublicKey, name: Vec<u8> }
fn public(bytes: &[u8], ak: bool) -> Result<Public, String> {
    let mut outer = Reader::new(bytes); let area = outer.sized()?; outer.end()?;
    let mut r = Reader::new(area);
    if r.u16()? != 1 || r.u16()? != SHA256 { return Err("only RSA SHA256 TPM public areas supported".into()); }
    let attrs = r.u32()?;
    // This narrow profile rejects other attribute bits, including decrypt and stClear.
    let allowed = FIXED | (1 << 6) | (1 << 7) | (1 << 10) | if ak { RESTRICTED } else { 0 };
    if attrs & FIXED != FIXED || attrs & !allowed != 0 || (ak && attrs & RESTRICTED == 0) { return Err("invalid TPM signing key attributes".into()); }
    let policy = r.sized()?;
    if !policy.is_empty() && policy.len() != 32 { return Err("invalid SHA256 authPolicy".into()); }
    if r.u16()? != NULL { return Err("TPM signing key symmetric algorithm must be NULL".into()); }
    let scheme = r.u16()?;
    match scheme {
        RSASSA => if r.u16()? != SHA256 { return Err("TPM signing scheme must use SHA256".into()); },
        NULL if !ak => (),
        _ => return Err("TPM signing scheme must be RSASSA SHA256".into()),
    }
    let bits = r.u16()?;
    if ![2048, 3072, 4096].contains(&bits) { return Err("unsupported TPM RSA size".into()); }
    let exponent = match r.u32()? { 0 => 65537, n => n };
    if exponent != 65537 { return Err("unsupported TPM RSA exponent".into()); }
    let modulus = r.sized()?; r.end()?;
    if modulus.len() != bits as usize / 8 || modulus[0] & 0x80 == 0 || modulus[modulus.len() - 1] & 1 == 0 { return Err("invalid TPM RSA modulus".into()); }
    let key = RsaPublicKey::new(BigUint::from_bytes_be(modulus), BigUint::from(exponent)).map_err(|_| "invalid TPM RSA public key")?;
    let mut object_name = SHA256.to_be_bytes().to_vec(); object_name.extend_from_slice(&Sha256::digest(area));
    Ok(Public { key, name: object_name })
}

/// Validates a restricted AK public area and exports its SPKI PEM. Store the original
/// base64 TPM2B_PUBLIC as the pin; this PEM alone does not preserve TPM attributes.
pub fn validate_ak(tpm_public_b64: &str) -> Result<String, String> {
    public(&decode(tpm_public_b64, 1024)?, true)?.key.to_public_key_pem(LineEnding::LF).map_err(|_| "cannot encode AK public key".into())
}
fn signature(ak: &Public, message: &[u8], bytes: &[u8]) -> Result<(), String> {
    let mut r = Reader::new(bytes);
    if r.u16()? != RSASSA || r.u16()? != SHA256 { return Err("unsupported TPM signature algorithm".into()); }
    let sig = r.sized()?; r.end()?;
    if sig.len() != ak.key.size() { return Err("invalid TPM signature size".into()); }
    let sig = Signature::try_from(sig).map_err(|_| "invalid TPM signature")?;
    VerifyingKey::<Sha256>::new(ak.key.clone()).verify(message, &sig).map_err(|_| "TPM signature verification failed".into())
}
struct Attest<'a> { reader: Reader<'a>, signer: Vec<u8>, clock: Value }
fn attest<'a>(bytes: &'a [u8], kind: u16, binding: &[u8]) -> Result<Attest<'a>, String> {
    let mut r = Reader::new(bytes);
    if r.u32()? != 0xff544347 || r.u16()? != kind { return Err("invalid TPM attestation magic or type".into()); }
    let signer = r.sized()?.to_vec(); name(&signer)?;
    if r.sized()? != binding { return Err("TPM nonce/CSR binding mismatch".into()); }
    let clock = r.u64()?; let reset_count = r.u32()?; let restart_count = r.u32()?;
    if r.u8()? != 1 { return Err("TPM clock is not safe".into()); }
    let firmware = r.u64()?;
    Ok(Attest { reader: r, signer, clock: json!({"clock":clock,"reset_count":reset_count,"restart_count":restart_count,"safe":true,"firmware_version":firmware}) })
}

/// Inputs certify/quote are raw TPMS_ATTEST (no TPM2B size wrapper), signatures are
/// TPMT_SIGNATURE, and public areas are TPM2B_PUBLIC, all standard padded base64.
/// extraData for BOTH attestations is SHA256("OpenWarp/TPM2/enroll/v1\0" ||
/// nonce UTF8 || SHA256(csr_spki_der)). Caller owns nonce uniqueness and consumption.
/// PCR policy is exactly SHA256 PCRs 0..7; expected_pcr_digest is hex SHA256 of
/// their eight concatenated 32-byte values. pcrs is an array of eight base64 values.
/// qualifiedSigner is a signed qualified Name, NOT the AK Name. Its ancestry is
/// unknown from this pin; we only require both signatures to report the same one.
pub fn verify(evidence: &Value, trusted_ak_public: &str, csr_spki_der: &[u8], nonce: &str, expected_pcr_digest: &str) -> Result<Value, String> {
    if nonce.is_empty() || nonce.len() > 4096 || csr_spki_der.is_empty() || csr_spki_der.len() > 8192 { return Err("invalid TPM binding input".into()); }
    if expected_pcr_digest.len() != 64 || !expected_pcr_digest.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("TPM SHA256 PCR 0..7 policy is required".into()); }
    let trusted = decode(trusted_ak_public, 1024)?;
    if field(evidence, "ak_public", 1024)? != trusted { return Err("TPM AK does not match provisioning pin".into()); }
    let ak = public(&trusted, true)?;
    let key = public(&field(evidence, "key_public", 1024)?, false)?;
    let csr_key = RsaPublicKey::from_public_key_der(csr_spki_der).map_err(|_| "CSR SPKI must be RSA")?;
    if csr_key != key.key { return Err("certified TPM key does not match CSR SPKI".into()); }
    let csr_digest = Sha256::digest(csr_spki_der);
    let mut binding = Sha256::new(); binding.update(b"OpenWarp/TPM2/enroll/v1\0"); binding.update(nonce.as_bytes()); binding.update(csr_digest);
    let binding = binding.finalize();
    let certify_bytes = field(evidence, "certify", 2048)?;
    signature(&ak, &certify_bytes, &field(evidence, "certify_signature", 1024)?)?;
    let mut certify = attest(&certify_bytes, 0x8017, &binding)?;
    if certify.reader.sized()? != key.name { return Err("TPM Certify Name mismatch".into()); }
    name(certify.reader.sized()?)?; certify.reader.end()?;
    let quote_bytes = field(evidence, "quote", 2048)?;
    signature(&ak, &quote_bytes, &field(evidence, "quote_signature", 1024)?)?;
    let mut quote = attest(&quote_bytes, 0x8018, &binding)?;
    if quote.signer != certify.signer { return Err("TPM qualified signers differ".into()); }
    // A single SHA256 bank and an exact bitmap prevent evidence-selected policies.
    if quote.reader.u32()? != 1 || quote.reader.u16()? != SHA256 || quote.reader.u8()? != 3 || quote.reader.take(3)? != [0xff, 0, 0] { return Err("TPM quote must select SHA256 PCRs 0..7 only".into()); }
    let quoted_digest = quote.reader.sized()?; quote.reader.end()?;
    let pcrs = evidence.get("pcrs").and_then(Value::as_array).ok_or("missing TPM PCR values")?;
    if pcrs.len() != 8 { return Err("expected eight TPM PCR values".into()); }
    let mut pcr_hash = Sha256::new();
    for pcr in pcrs {
        let value = decode(pcr.as_str().ok_or("invalid TPM PCR value")?, 32)?;
        if value.len() != 32 { return Err("TPM PCR value must be SHA256".into()); } pcr_hash.update(value);
    }
    let pcr_digest = pcr_hash.finalize();
    if quoted_digest != &pcr_digest[..] || !hex(&pcr_digest).eq_ignore_ascii_case(expected_pcr_digest) { return Err("TPM PCR digest does not match policy".into()); }
    Ok(json!({"type":"tpm2","trust":"operator_pinned_ak","algorithm":"rsassa-sha256","ak_name":hex(&ak.name),"qualified_signer":hex(&quote.signer),"csr_sha256":hex(&csr_digest),"pcr_digest":hex(&pcr_digest),"pcr_bank":"sha256","pcr_indices":[0,1,2,3,4,5,6,7],"certify_clock":certify.clock,"quote_clock":quote.clock}))
}
