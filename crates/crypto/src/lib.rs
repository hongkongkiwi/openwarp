//! Phase-compatible construction: ephemeral X25519 + XChaCha20-Poly1305.
//! Wire format: base64( ephemeral_pub(32) || nonce(24) || ciphertext )
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::OsRng as PwOsRng};
use base64ct::{Base64, Encoding};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

pub fn b64(e: &[u8]) -> String { Base64::encode_string(e) }
pub fn unb64(s: &str) -> Result<Vec<u8>, String> { Base64::decode_vec(s.trim()).map_err(|e| e.to_string()) }

#[derive(Clone)]
pub struct Keypair { pub public: String, secret: StaticSecret }
impl Keypair {
    pub fn generate() -> Self { let s = StaticSecret::random_from_rng(OsRng); let p = PublicKey::from(&s); Self { public: b64(p.as_bytes()), secret: s } }
    pub fn from_secret_b64(s: &str) -> Result<Self, String> { let b = unb64(s)?; let a: [u8;32] = b.try_into().map_err(|_| "bad key len")?; let secret = StaticSecret::from(a); let public = b64(PublicKey::from(&secret).as_bytes()); Ok(Self{public, secret}) }
    pub fn secret_b64(&self) -> String { b64(&self.secret.to_bytes()) }
    pub fn decrypt(&self, payload: &str) -> Result<Vec<u8>, String> { decrypt_with(&self.secret, payload) }
}

fn derive(shared: &[u8;32]) -> [u8;32] { let mut h = Sha256::new(); h.update(b"openwarp-session-v1"); h.update(shared); h.finalize().into() }

pub fn encrypt_to(public_b64: &str, plaintext: &[u8]) -> Result<String, String> {
    let b = unb64(public_b64)?; let a: [u8;32] = b.try_into().map_err(|_| "bad pubkey")?;
    let recipient = PublicKey::from(a);
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    let key = derive(shared.as_bytes());
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8;24]; OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext).map_err(|_| "encrypt failed")?;
    let mut out = Vec::new(); out.extend_from_slice(eph_pub.as_bytes()); out.extend_from_slice(&nonce); out.extend_from_slice(&ct);
    Ok(b64(&out))
}
fn decrypt_with(secret: &StaticSecret, payload: &str) -> Result<Vec<u8>, String> {
    let raw = unb64(payload)?; if raw.len() < 56 { return Err("ciphertext too short".into()) }
    let (eph_bytes, rest) = raw.split_at(32); let (nonce, ct) = rest.split_at(24);
    let mut a=[0u8;32]; a.copy_from_slice(eph_bytes);
    let shared = secret.diffie_hellman(&PublicKey::from(a));
    let key = derive(shared.as_bytes());
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| "decrypt failed (wrong key or tampered)".into())
}
/// Password wrap a private key: Argon2id-derived key + XChaCha. Format b64(salt16||nonce24||ct)
pub fn wrap_with_password(password: &str, plaintext: &[u8]) -> Result<String, String> {
    let mut salt=[0u8;16]; OsRng.fill_bytes(&mut salt);
    let mut key=[0u8;32]; Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key).map_err(|e| e.to_string())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce=[0u8;24]; OsRng.fill_bytes(&mut nonce);
    let ct=cipher.encrypt(XNonce::from_slice(&nonce), plaintext).map_err(|_| "wrap failed")?; key.zeroize();
    let mut out=Vec::new(); out.extend_from_slice(&salt); out.extend_from_slice(&nonce); out.extend_from_slice(&ct); Ok(b64(&out))
}
pub fn unwrap_with_password(password: &str, payload: &str) -> Result<Vec<u8>, String> {
    let raw=unb64(payload)?; if raw.len()<40 { return Err("wrapped blob too short".into()) }
    let (salt,rest)=raw.split_at(16); let (nonce,ct)=rest.split_at(24);
    let mut key=[0u8;32]; Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let r=cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| "unwrap failed (wrong password)".into()); key.zeroize(); r
}
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut PwOsRng);
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| e.to_string())?.to_string())
}
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::PasswordVerifier; use argon2::password_hash::PasswordHash;
    match PasswordHash::new(hash) { Ok(h) => Argon2::default().verify_password(password.as_bytes(), &h).is_ok(), Err(_) => false }
}
/// Symmetric encrypt with a raw 32-byte key (env data keys, lockbox).
pub fn encrypt_symmetric(key: &[u8;32], plaintext: &[u8]) -> String {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce=[0u8;24]; OsRng.fill_bytes(&mut nonce);
    let ct=cipher.encrypt(XNonce::from_slice(&nonce), plaintext).expect("encrypt");
    let mut out=nonce.to_vec(); out.extend_from_slice(&ct); b64(&out)
}
pub fn decrypt_symmetric(key: &[u8;32], payload: &str) -> Result<Vec<u8>, String> {
    let raw=unb64(payload)?; if raw.len()<24 { return Err("too short".into()) }
    let (nonce,ct)=raw.split_at(24); let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| "decrypt failed".into())
}
/// Versioned AEAD that binds ciphertext to its record (environment, secret,
/// field). The `ow2:` prefix distinguishes it from legacy unauthenticated-data
/// ciphertext so both can be read during migration.
pub fn encrypt_symmetric_aad(key: &[u8;32], aad: &[u8], plaintext: &[u8]) -> String {
    use chacha20poly1305::aead::Payload;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce=[0u8;24]; OsRng.fill_bytes(&mut nonce);
    let ct=cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad }).expect("encrypt");
    let mut out=nonce.to_vec(); out.extend_from_slice(&ct);
    format!("ow2:{}", b64(&out))
}
pub fn decrypt_symmetric_aad(key: &[u8;32], aad: &[u8], payload: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::Payload;
    let body = payload.strip_prefix("ow2:").ok_or("not an ow2 ciphertext")?;
    let raw=unb64(body)?; if raw.len()<24 { return Err("too short".into()) }
    let (nonce,ct)=raw.split_at(24); let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad }).map_err(|_| "decrypt failed".into())
}
/// Read either a bound `ow2:` ciphertext or a legacy one. New writes should use
/// `encrypt_symmetric_aad`; this keeps existing rows readable.
pub fn decrypt_symmetric_compat(key: &[u8;32], aad: &[u8], payload: &str) -> Result<Vec<u8>, String> {
    if payload.starts_with("ow2:") { decrypt_symmetric_aad(key, aad, payload) } else { decrypt_symmetric(key, payload) }
}
/// libsodium sealed box (GitHub Actions): ephemeral X25519 + XSalsa20-Poly1305, nonce=BLAKE2b24(eph_pk||recipient_pk)
pub fn seal_github(recipient_pub_b64_std: &str, plaintext: &[u8]) -> Result<String, String> {
    use crypto_box::{PublicKey as CbPublic, SecretKey as CbSecret, SalsaBox, aead::{Aead, generic_array::GenericArray}};
    use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
    let raw = base64ct::Base64::decode_vec(recipient_pub_b64_std.trim()).map_err(|e| e.to_string())?;
    let arr: [u8;32] = raw.try_into().map_err(|_| "bad github pubkey")?;
    let recipient = CbPublic::from(arr);
    let eph_secret = CbSecret::generate(&mut OsRng);
    let eph_public = CbPublic::from(&eph_secret);
    let mut hasher = Blake2bVar::new(24).map_err(|e| e.to_string())?;
    hasher.update(eph_public.as_bytes()); hasher.update(recipient.as_bytes());
    let mut nonce = [0u8;24]; hasher.finalize_variable(&mut nonce).map_err(|e| e.to_string())?;
    let bx = SalsaBox::new(&recipient, &eph_secret);
    let ct = bx.encrypt(GenericArray::from_slice(&nonce), plaintext).map_err(|_| "sealed box encrypt failed")?;
    let mut out = eph_public.as_bytes().to_vec(); out.extend_from_slice(&ct);
    use base64ct::Encoding as _; Ok(base64ct::Base64::encode_string(&out))
}
pub fn random_key() -> [u8;32] { let mut k=[0u8;32]; OsRng.fill_bytes(&mut k); k }
pub fn random_token(prefix: &str) -> String { let mut b=[0u8;32]; OsRng.fill_bytes(&mut b); format!("{}_{}", prefix, b64(&b).replace(['+', '/', '='], "")) }
pub fn hash_token(token: &str) -> String { let mut h=Sha256::new(); h.update(token.as_bytes()); b64(&h.finalize()) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn roundtrip_and_tamper() {
        let kp=Keypair::generate(); let ct=encrypt_to(&kp.public, b"hello secret").unwrap();
        assert_eq!(kp.decrypt(&ct).unwrap(), b"hello secret");
        let mut bad=unb64(&ct).unwrap(); let n=bad.len()-1; bad[n]^=1;
        assert!(kp.decrypt(&b64(&bad)).is_err());
        let other=Keypair::generate(); assert!(other.decrypt(&ct).is_err());
    }
    #[test] fn password_wrap() {
        let kp=Keypair::generate(); let w=wrap_with_password("correct horse", kp.secret_b64().as_bytes()).unwrap();
        assert_eq!(unwrap_with_password("correct horse",&w).unwrap(), kp.secret_b64().as_bytes());
        assert!(unwrap_with_password("wrong",&w).is_err());
    }
    #[test] fn symmetric_and_password_hash() {
        let k=random_key(); let ct=encrypt_symmetric(&k,b"v"); assert_eq!(decrypt_symmetric(&k,&ct).unwrap(),b"v");
        let h=hash_password("pw").unwrap(); assert!(verify_password("pw",&h)); assert!(!verify_password("no",&h));
    }
}
