//! Root-key operations through a small HTTP bridge. The bridge is deliberately
//! provider-neutral: an operator adapts it to AWS KMS, GCP KMS, Azure Key Vault,
//! Vault Transit, or an HSM. The server never stores the root key it receives.
use openwarp_crypto as oc;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_INFLIGHT: usize = 16;

fn url_ok(u: &str) -> bool { let u = u.trim().to_ascii_lowercase(); (u.starts_with("https://") || u.starts_with("http://")) && !u.contains(' ') && !u.contains('\n') }

pub struct Kms { url: String, token: String, key_id: String }

impl Kms {
    pub fn from_env() -> Result<Option<Kms>, String> {
        let url = match std::env::var("OPENWARP_KMS_URL") {
            Ok(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
            _ => return Ok(None) };
        // A configured-but-invalid bridge must stop the server, not silently
        // fall back to a locally generated root.
        if !url_ok(&url) { return Err("OPENWARP_KMS_URL must be an http(s) URL".into()); }
        let key_id = std::env::var("OPENWARP_KMS_KEY_ID").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "primary".into());
        Ok(Some(Kms { url, token: std::env::var("OPENWARP_KMS_TOKEN").unwrap_or_default(), key_id }))
    }
    pub fn key_id(&self) -> &str { &self.key_id }
    /// Returns `owkms:<key-id>:<adapter blob>`. The key id travels with the
    /// ciphertext so a rotation can rewrap old values without guessing.
    pub fn wrap(&self, plaintext: &[u8], context: &str) -> Result<String, String> {
        let v = self.post("wrap", json!({"key_id": self.key_id, "plaintext": oc::b64(plaintext), "context": context}))?;
        let wrapped = v.get("wrapped").and_then(|x| x.as_str()).ok_or("KMS wrap response has no wrapped value")?;
        Ok(format!("owkms:{}:{}", self.key_id, wrapped))
    }
    pub fn unwrap(&self, payload: &str, context: &str) -> Result<Vec<u8>, String> {
        let rest = payload.strip_prefix("owkms:").ok_or("not a KMS-wrapped value")?;
        let (key_id, blob) = rest.split_once(':').ok_or("bad KMS payload")?;
        let v = self.post("unwrap", json!({"key_id": key_id, "wrapped": blob, "context": context}))?;
        let plain = v.get("plaintext").and_then(|x| x.as_str()).ok_or("KMS unwrap response has no plaintext")?;
        oc::unb64(plain)
    }
    fn post(&self, op: &str, body: Value) -> Result<Value, String> {
        // Each request takes a blocking thread. Cap concurrency so an outage or
        // a flood of secret reads cannot exhaust the process.
        if INFLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT {
            INFLIGHT.fetch_sub(1, Ordering::SeqCst);
            return Err("KMS request budget exhausted; try again".into());
        }
        let url = format!("{}/{}", self.url, op);
        let token = self.token.clone();
        let out = std::thread::spawn(move || {
            let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).build().map_err(|e| e.to_string())?;
            let mut req = client.post(&url).json(&body);
            if !token.is_empty() { req = req.bearer_auth(token); }
            let resp = req.send().map_err(|e| e.to_string())?;
            if !resp.status().is_success() { return Err(format!("KMS returned HTTP {}", resp.status())); }
            resp.json::<Value>().map_err(|e| e.to_string())
        }).join().map_err(|_| "KMS request thread panicked".to_string());
        INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        out?
    }
}
