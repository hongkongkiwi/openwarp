//! Provider-neutral root-key operations through an asynchronous HTTP bridge.
use openwarp_crypto as oc;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_INFLIGHT: usize = 16;
struct RequestBudget;
impl Drop for RequestBudget { fn drop(&mut self) { INFLIGHT.fetch_sub(1, Ordering::SeqCst); } }

pub struct Kms { url: String, token: String, key_id: String }
impl Kms {
    pub fn from_env() -> Result<Option<Kms>, String> {
        let url = match crate::envcfg::var("OPENWARP_KMS_URL") {
            Ok(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
            _ => return Ok(None) };
        let parsed = crate::http::Url::parse(&url).map_err(|_| "OPENWARP_KMS_URL must be an http(s) URL".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some() || parsed.fragment().is_some() { return Err("OPENWARP_KMS_URL must be an http(s) URL without credentials, query or fragment".into()); }
        let host = parsed.host_str().unwrap_or("");
        let loopback = host.eq_ignore_ascii_case("localhost") || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
        if crate::production() && parsed.scheme() == "http" && !loopback { return Err("OPENWARP_KMS_URL requires HTTPS except on loopback in production".into()); }
        let key_id = crate::envcfg::var("OPENWARP_KMS_KEY_ID").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "primary".into());
        if key_id.contains(':') { return Err("OPENWARP_KMS_KEY_ID must not contain ':'".into()); }
        Ok(Some(Kms { url, token: crate::envcfg::var("OPENWARP_KMS_TOKEN").unwrap_or_default(), key_id }))
    }
    pub fn key_id(&self) -> &str { &self.key_id }
    pub async fn wrap(&self, plaintext: &[u8], context: &str) -> Result<String, String> {
        let v = self.post("wrap", json!({"key_id": self.key_id, "plaintext": oc::b64(plaintext), "context": context})).await?;
        let wrapped = v.get("wrapped").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).ok_or("KMS wrap response has no wrapped value")?;
        Ok(format!("owkms:{}:{}", self.key_id, wrapped))
    }
    pub async fn unwrap(&self, payload: &str, context: &str) -> Result<Vec<u8>, String> {
        let rest = payload.strip_prefix("owkms:").ok_or("not a KMS-wrapped value")?;
        let (key_id, blob) = rest.split_once(':').filter(|(k, b)| !k.is_empty() && !b.is_empty()).ok_or("bad KMS payload")?;
        let v = self.post("unwrap", json!({"key_id": key_id, "wrapped": blob, "context": context})).await?;
        let plain = v.get("plaintext").and_then(|x| x.as_str()).ok_or("KMS unwrap response has no plaintext")?;
        oc::unb64(plain)
    }
    async fn post(&self, op: &str, body: Value) -> Result<Value, String> {
        if INFLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT {
            INFLIGHT.fetch_sub(1, Ordering::SeqCst);
            return Err("KMS request budget exhausted; try again".into());
        }
        let _budget = RequestBudget;
        #[cfg(not(target_arch = "wasm32"))]
        let client = crate::http::Client::builder().redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "KMS client initialization failed")?;
        #[cfg(target_arch = "wasm32")]
        let client = crate::http::Client::new();
        let mut req = client.post(format!("{}/{}", self.url, op)).timeout(Duration::from_secs(10)).json(&body);
        if !self.token.is_empty() { req = req.bearer_auth(&self.token); }
        let bytes = crate::http::provider_post_bounded(req, 1024 * 1024).await?;
        serde_json::from_slice(&bytes).map_err(|_| "KMS response is not valid JSON".into())
    }
}
