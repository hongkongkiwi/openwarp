#[cfg(feature = "pki")] use crate::tpm_attestation;
use crate::{db, edition, inference_leases, integrations, kms, mailer, mfa, ssh_keys, ui};
#[cfg(feature = "ssh-ca")]
use crate::ssh_ca;
#[path = "transit_compat.rs"] mod transit_compat;
#[path = "workloads.rs"] mod workloads;
#[path = "path_policy.rs"] mod path_policy;
#[path = "static_rotation.rs"] mod static_rotation;
#[cfg(feature = "workload-identity")]
#[path = "workload.rs"] mod workload;
#[cfg(feature = "transit")]
#[path = "transit.rs"] mod transit;
#[cfg(feature = "change-requests")]
#[path = "change_requests.rs"] mod change_requests;
#[cfg(feature = "ldap")] use crate::ldap;
use axum::body::Bytes;
use axum::{extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, middleware::Next, response::{Html, IntoResponse, Response}, routing::{delete, get, post, put}, Json, Router};
#[cfg(not(target_arch = "wasm32"))]
use axum::{extract::{WebSocketUpgrade, ws::{Message, WebSocket}}};
use db::{Db, Row};
#[cfg(all(test,feature="redis-cache",not(target_arch="wasm32")))]
include!("webhook_execution_tests.rs");
#[cfg(all(test,not(target_arch="wasm32")))]
include!("master_publication_tests.rs");
#[path = "workspaces.rs"] mod workspaces;
use openwarp_crypto as oc;
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
use risaml::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpDescriptor, MetadataTrustPolicy, Pending, PendingSnapshot, PrivateKeyPem, RelayStateParam,
    ReplayCache, ReplayKey, ReplayPolicy, Saml, SamlError, SamlInstant, SamlValidationContext,
    SpConfig, SpValidationPolicy, SsoResponse, StartSso,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, sync::atomic::{AtomicUsize, Ordering as AtomicOrdering}};
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::broadcast;

/// Native replicas poll persisted events; Workers drains them to hibernating sockets after each request.
#[cfg(not(target_arch = "wasm32"))]
pub type LiveSender = broadcast::Sender<Arc<str>>;
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Default)]
pub struct LiveSender;
#[cfg(target_arch = "wasm32")]
impl LiveSender {
    pub fn send(&self, _event: Arc<str>) -> Result<usize, &'static str> { Ok(0) }
    pub fn receiver_count(&self) -> usize { 0 }
    pub fn subscribe(&self) -> LiveReceiver { LiveReceiver }
}
#[cfg(target_arch = "wasm32")]
pub struct LiveReceiver;


/// Client address for rate limiting and IP allowlists. Native fills it from the
/// TCP peer; the Worker fills it from `CF-Connecting-IP`.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub std::net::IpAddr);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<PeerAddr>().copied().unwrap_or(PeerAddr(std::net::IpAddr::from([0, 0, 0, 0]))))
    }
}

pub struct AppState {
    // Shared with the delivery thread so it writes status through the same
    // handle. Reopening by URL would acquire the migration lock again and
    // could not reach an in-memory database.
    pub(crate) db: Arc<Db>,
    instance_id: String,
    pub(crate) pub_url: String,
    master: std::sync::RwLock<[u8; 32]>,
    #[cfg(not(target_arch = "wasm32"))]
    secret_health_credentials: Arc<tokio::sync::Mutex<()>>,
    #[cfg(not(target_arch="wasm32"))]
    pub(crate) ai_credentials: tokio::sync::Mutex<()>,
    #[cfg(not(target_arch="wasm32"))]
    key_lifecycle: Arc<tokio::sync::RwLock<()>>,
    #[cfg(not(target_arch="wasm32"))]
    transit_gate: Arc<tokio::sync::Mutex<()>>,
    #[cfg(not(target_arch="wasm32"))]
    lifecycle: Arc<tokio::sync::RwLock<()>>,
    // Master-rotation fence shared with the transit key store; an Arc so the
    // write guard can move into the blocking rotation task.
    transit_lifecycle: Arc<TransitLifecycle>,
    kms: std::sync::OnceLock<Option<kms::Kms>>,
    key_gate: tokio::sync::RwLock<()>,
    #[cfg(feature = "redis-cache")] redis: std::sync::Mutex<Option<redis::Connection>>,
    license: edition::LicenseState,
    live: LiveSender,
}
#[cfg(not(target_arch = "wasm32"))]
type TransitLifecycle = tokio::sync::RwLock<()>;
#[cfg(target_arch = "wasm32")]
#[derive(Default)]
struct TransitLifecycle;
#[cfg(target_arch = "wasm32")]
impl TransitLifecycle { #[allow(dead_code)] pub async fn read(&self) {} }
pub type S = Arc<AppState>;
pub fn new_state(db: Db, _db_url: String, instance_id: String, pub_url: String, master: [u8; 32], live: LiveSender, #[cfg(feature = "redis-cache")] redis: Option<redis::Connection>) -> S {
    Arc::new(AppState { db: Arc::new(db), instance_id, pub_url, master: std::sync::RwLock::new(master), #[cfg(not(target_arch = "wasm32"))] secret_health_credentials: Arc::new(tokio::sync::Mutex::new(())), #[cfg(not(target_arch="wasm32"))] ai_credentials: tokio::sync::Mutex::new(()), #[cfg(not(target_arch="wasm32"))] key_lifecycle: Arc::new(tokio::sync::RwLock::new(())), #[cfg(not(target_arch="wasm32"))] transit_gate: Arc::new(tokio::sync::Mutex::new(())), #[cfg(not(target_arch="wasm32"))] lifecycle: Arc::new(tokio::sync::RwLock::new(())), transit_lifecycle: Arc::new(TransitLifecycle::default()), kms: std::sync::OnceLock::new(), key_gate: tokio::sync::RwLock::new(()), #[cfg(feature = "redis-cache")] redis: std::sync::Mutex::new(redis), license: edition::LicenseState::from_env(), live })
}
/// Install the validated bridge before serving requests on either runtime.
pub fn install_kms(st: &S, kms: Option<kms::Kms>) { assert!(st.kms.set(kms).is_ok(), "KMS already initialized"); }
#[cfg(target_arch = "wasm32")]
pub(crate) fn initialize_master(st: &S, master: [u8; 32]) { *st.master.write().unwrap_or_else(|e| e.into_inner()) = master; }
pub type Res = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn issuer(st: &S, h: &HeaderMap) -> String { if !st.pub_url.is_empty() { return st.pub_url.trim_end_matches('/').to_string(); } let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("127.0.0.1:8080"); format!("http://{}", host) }
fn cookie_val(h: &HeaderMap, name: &str) -> String { h.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").split(';').filter_map(|p| p.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string()).unwrap_or_default() }
pub(crate) fn session_cookie(token: &str) -> String {
    let secure = crate::envcfg::var("OPENWARP_PUBLIC_URL").map(|v| v.starts_with("https://")).unwrap_or(false)
        || crate::envcfg::var("OPENWARP_SECURE_COOKIES").map(|v| v == "1").unwrap_or(false);
    format!("ow_session={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800{}", token, if secure { "; Secure" } else { "" }) }
pub(crate) fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) { (code, Json(json!({"error": msg}))) }
pub(crate) fn bad(msg: &str) -> (StatusCode, Json<Value>) { err(StatusCode::BAD_REQUEST, msg) }
fn unique_violation(e: &str) -> bool { let e = e.to_ascii_lowercase(); e.contains("unique constraint") || e.contains("duplicate key") || e.contains("duplicate entry") }
fn master_write_error(e: String) -> (StatusCode, Json<Value>) { if e == webhooks::EPOCH_STALE { webhooks::epoch_stale() } else { bad(&e) } }
pub(crate) fn mfa_failure(e: String) -> (StatusCode, Json<Value>) { if e == webhooks::EPOCH_STALE { webhooks::epoch_stale() } else { err(StatusCode::SERVICE_UNAVAILABLE, "two-factor verification is temporarily unavailable") } }
pub(crate) fn epoch_failure_msg(e: (StatusCode, Json<Value>)) -> String { if e.1.0.get("code").and_then(|v| v.as_str()) == Some(webhooks::EPOCH_STALE) { webhooks::EPOCH_STALE.into() } else { "instance key epoch check failed".into() } }
pub(crate) fn now() -> i64 { crate::clock::now() }
pub(crate) fn id() -> String { oc::random_token("id").replace("id_", "") }
pub(crate) fn j(v: impl Into<Value>) -> Json<Value> { Json(v.into()) }
fn esc(s: &str) -> String { s.chars().map(|c| match c { '&' => "&amp;".into(), '<' => "&lt;".into(), '>' => "&gt;".into(), '"' => "&quot;".into(), '\'' => "&#39;".into(), c => c.to_string() }).collect() }
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac key");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut bytes = [0u8; 32]; bytes.copy_from_slice(&out); bytes }
pub(crate) fn hmac_hex(key: &[u8], data: &[u8]) -> String { hmac_sha256(key, data).iter().map(|b| format!("{:02x}", b)).collect() }
fn sha256_hex(data: &[u8]) -> String { use sha2::{Digest, Sha256}; Sha256::digest(data).iter().map(|b| format!("{:02x}", b)).collect() }
// An audit row's hash covers the previous row's hash, so deleting or editing a
// row breaks every later link. Field order is fixed here and in verification.
#[allow(clippy::too_many_arguments)] // every field of the row is part of the hash
fn audit_hash(prev: &str, seq: i64, org: &str, app: &str, env: &str, actor: &str, action: &str, detail: &str, created_at: i64) -> String {
    sha256_hex(json!([prev, seq, org, app, env, actor, action, detail, created_at]).to_string().as_bytes()) }
// Reuse detection stores a keyed digest, never a bare hash: an operator with
// the database but not the master key cannot test a password list offline.
// The workspace id is part of the input so equal values in two workspaces do
// not produce equal fingerprints.
fn value_fingerprint(master: &[u8; 32], org: &str, value: &str) -> String {
    let key = hmac_sha256(master, b"openwarp:reuse-fingerprint-key:v1");
    let mut data = Vec::with_capacity(32 + org.len() + value.len());
    data.extend_from_slice(b"openwarp:reuse-fingerprint:v1\0");
    data.extend_from_slice(org.as_bytes());
    data.push(0);
    data.extend_from_slice(value.as_bytes());
    hmac_hex(&key, &data) }
#[cfg(any(feature = "pki", feature = "saml"))]
fn hex_encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}",b)).collect() }
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect() }
const OAUTH_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const OAUTH_AUTH_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const OAUTH_AUTH_JS: &str = r#"<script src="/auth-v2.js"></script><script>
document.getElementById('oauthlogin').addEventListener('submit', function(e) {
  e.preventDefault();
  var f = e.target;
  (async function() {
    try {
      function add(name, value) { var i = document.createElement('input'); i.type = 'hidden'; i.name = name; i.value = value; f.appendChild(i); }
      var kdf = await AuthV2.kdf(f.email.value);
      if (kdf.version === 1) { add('approve', '1'); f.submit(); return; }
      var keys = await AuthV2.deriveKeys(f.password.value, kdf.salt, kdf.iterations);
      var ch = await AuthV2.challenge(f.email.value);
      var proof = await AuthV2.proof(keys.auth, ch.challenge, ch.challenge_id);
      f.password.value = '';
      add('challenge_id', ch.challenge_id);
      add('proof', proof);
      add('approve', '1');
      f.submit();
    } catch (err) { alert(err.message || String(err)); }
  })();
});
</script>"#;
fn html_csp(body: String) -> Response { html_csp_with(OAUTH_CSP, body) }
fn html_csp_with(csp: &'static str, body: String) -> Response { let mut r = Html(body).into_response(); r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(csp)); r }
// Only authorization parameters may survive a failed attempt. Passwords,
// proofs and one-time codes must never be echoed back into the page.
fn hidden_fields(form: &HashMap<String, String>) -> String {
    ["client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "resource"]
        .iter().filter_map(|k| form.get(*k).map(|v| format!("<input type=hidden name=\"{}\" value=\"{}\">", esc(k), esc(v)))).collect() }
fn bearer_token(h: &HeaderMap) -> String { h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").strip_prefix("Bearer ").unwrap_or("").to_string() }
// Managed roles keep their historic breadth; custom roles are exactly their
// stored permission list, deny by default.
const DEVELOPER_PERMS: &[&str] = &["secrets:read","secrets:write","secrets:delete","integrations:write","leases:write","rotations:write","proposals:write","tokens:create","access:request"];
fn valid_secret_key(k: &str) -> bool { !k.is_empty() && k.len() <= 128 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') }
fn valid_path(p: &str) -> bool { !p.is_empty() && p.len() <= 256 && !p.chars().any(|c| c.is_control()) }
fn scan_rules(value: &str) -> Vec<&'static str> {
    let mut rules = Vec::new();
    let tokens: Vec<&str> = value.split(|c: char| c.is_whitespace() || "\"'=,;()[]{}".contains(c)).filter(|s| !s.is_empty()).collect();
    for t in tokens {
        if t.len() == 20 && t.starts_with("AKIA") && t[4..].bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) { rules.push("aws_access_key"); }
        if (t.starts_with("ghp_") && t.len() >= 40) || t.starts_with("github_pat_") { rules.push("github_pat"); }
        if t.starts_with("xoxb-") || t.starts_with("xoxp-") || t.starts_with("xoxa-") || t.starts_with("xoxr-") || t.starts_with("xoxs-") { rules.push("slack_token"); }
        if t.starts_with("sk_live_") || t.starts_with("rk_live_") { rules.push("stripe_live_key"); }
        if t.starts_with("AIza") && t.len() == 39 { rules.push("google_api_key"); }
    }
    if value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----") { rules.push("private_key"); }
    rules.sort_unstable(); rules.dedup(); rules
}
fn valid_cidr_list(list: &str) -> bool {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
        .all(|s| s.parse::<ipnet::IpNet>().is_ok() || s.parse::<std::net::IpAddr>().is_ok()) }
fn valid_domain_list(list: &str) -> bool {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
        .all(|d| !d.is_empty() && d.len() <= 253 && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')) }
fn valid_email(e: &str) -> bool {
    let e = e.trim();
    let Some((local, domain)) = e.split_once('@') else { return false };
    !local.is_empty() && !domain.is_empty() && e.len() <= 254 && !e.contains(char::is_whitespace) && domain.contains('.') }
#[derive(Deserialize, Default)] struct AuthReq { email: String, password: String }
#[derive(Deserialize, Default)] struct NameReq { #[serde(default)] name: String, #[serde(default)] email: String, #[serde(default)] role: String, #[serde(default)] readme: String, #[serde(default)] env_id: String, #[serde(default)] expires_in: i64, #[serde(default)] scopes: String,
    // Delegated environments: the client generates the environment key and
    // supplies it wrapped to itself and to the customer-run sync runner.
    #[serde(default)] mode: String, #[serde(default)] runner_id: String, #[serde(default)] wrapped_key: String, #[serde(default)] runner_wrapped_key: String }
#[derive(Deserialize, Default, Clone)] struct SecretIn { key: String, value: String, #[serde(default = "def_path")] path: String, #[serde(default)] comment: String, #[serde(default)] tags: String, #[serde(default, rename = "type")] secret_type: String, #[serde(default)] expected_version: Option<i64> }
fn def_path() -> String { "/".into() }
#[derive(Deserialize, Default)] struct DeployReq { #[serde(default)] secrets: Vec<SecretIn>, #[serde(default)] text: String }
#[derive(Deserialize, Default)] struct ReuseReq { #[serde(default)] secrets: Vec<SecretIn>, #[serde(default)] exclude: Vec<String> }

include!("outbox.rs");
impl AppState {
    pub(crate) fn edition(&self) -> &edition::LicenseState { &self.license }
    pub(crate) fn require_enterprise(&self, feature: edition::Feature) -> Result<(), (StatusCode, Json<Value>)> {
        if self.license.allows(feature) { Ok(()) } else { Err(edition::locked(feature)) } }
    pub(crate) async fn audit(&self, org: &str, app: &str, env: &str, actor: &str, action: &str, detail: &str) {
        if let Err(error)=self.audited_batch(&[], &[], [org,app,env,actor,action,detail]).await { tracing::error!(%error,"audit observation failed"); }
    }

    pub fn db(&self) -> &Db { &self.db }
    pub fn instance_id(&self) -> &str { &self.instance_id }
    pub fn live(&self) -> &LiveSender { &self.live }
    async fn emergency_locked(&self, org: &str) -> Result<bool, (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT emergency_locked FROM orgs WHERE id=?", &[json!(org)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "workspace emergency status unavailable"))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "workspace not found"))?;
        Ok(db::n(&row, "emergency_locked") != 0) }
    async fn require_running(&self, org: &str) -> Result<(), (StatusCode, Json<Value>)> {
        if self.emergency_locked(org).await? { return Err(err(StatusCode::FORBIDDEN, "workspace emergency lockdown is active")); } Ok(()) }
    async fn app_emergency(&self, app: &str) -> Result<(String, bool, bool), (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT a.org_id,a.emergency_locked AS direct_locked,o.emergency_locked AS workspace_locked FROM apps a JOIN orgs o ON o.id=a.org_id WHERE a.id=?", &[json!(app)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "app not found"))?;
        Ok((db::s(&row, "org_id"), db::n(&row, "direct_locked") != 0, db::n(&row, "workspace_locked") != 0)) }
    async fn require_app_running(&self, app: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let (_, direct, workspace) = self.app_emergency(app).await?;
        if direct || workspace { return Err(err(StatusCode::FORBIDDEN, "project emergency lockdown is active")); } Ok(()) }
    pub(crate) async fn require_org_running(&self, org: &str) -> Result<(), (StatusCode, Json<Value>)> {
        self.require_running(org).await?;
        if self.db.one("SELECT id FROM apps WHERE org_id=? AND emergency_locked<>0 LIMIT 1", &[json!(org)]).await.map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::FORBIDDEN, "a project emergency lockdown is active")); } Ok(()) }
    async fn require_env_running(&self, env: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let (_, app) = self.env_org_app(env).await?; self.require_app_running(&app).await }
    pub(crate) async fn env_key(&self, env_id: &str) -> Result<[u8;32], (StatusCode, Json<Value>)> {
        self.require_env_running(env_id).await?;
        let master = self.epoch_ok().await.map(|_| self.master())?;
        let row = self.db.one("SELECT env_key_wrapped FROM envs WHERE id=?", &[json!(env_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        let wrapped = db::s(&row, "env_key_wrapped");
        if wrapped.is_empty() { return Err(err(StatusCode::CONFLICT, "this environment is client-encrypted; the server has no key for it")); }
        if wrapped.starts_with("owkms:") {
            let kms = self.kms().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "this environment is wrapped by a KMS that is not configured"))?;
            let raw = kms.unwrap(&wrapped, &format!("env:{}", env_id)).await.map_err(|e| bad(&format!("KMS could not unwrap the environment key: {}", e)))?;
            return raw.try_into().map_err(|_| bad("bad env key")); }
        // A row written before KMS was enabled is rewrapped on first use. The
        // legacy master stays valid for every other root-encrypted record.
        let raw = oc::decrypt_symmetric(&master, &wrapped).map_err(|e| bad(&e))?;
        if let Some(kms) = self.kms() {
            if let Ok(rewrapped) = kms.wrap(&raw, &format!("env:{}", env_id)).await {
                let _ = self.epoch_write(&[("UPDATE envs SET env_key_wrapped=? WHERE id=?".into(), vec![json!(&rewrapped), json!(&env_id)])], &[], master).await;
            }
        }
        raw.try_into().map_err(|_| bad("bad env key"))
    }
    fn kms(&self) -> Option<&kms::Kms> { self.kms.get().and_then(|k| k.as_ref()) }
    pub(crate) fn master(&self) -> [u8; 32] { *self.master.read().unwrap_or_else(|e| e.into_inner()) }
    async fn reuse_enabled(&self, org: &str, app: &str) -> bool {
        let org_on = self.db.one("SELECT reuse_check FROM orgs WHERE id=?", &[json!(org)]).await.ok().flatten()
            .map(|r| db::n(&r, "reuse_check") != 0).unwrap_or(false);
        if !org_on { return false; }
        self.db.one("SELECT reuse_check FROM apps WHERE id=?", &[json!(app)]).await.ok().flatten()
            .map(|r| db::n(&r, "reuse_check") != 0).unwrap_or(false) }
    pub(crate) async fn token_user(&self, headers: &HeaderMap) -> Result<String, (StatusCode, Json<Value>)> {
        let bearer = headers.get("authorization").map(|v| v.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")).filter(|s| !s.is_empty()).ok_or_else(|| err(StatusCode::UNAUTHORIZED,"invalid Authorization header"))).transpose()?;
        let cookie_only=bearer.is_none();
        let token=bearer.map(str::to_string).unwrap_or_else(|| cookie_val(headers,"ow_session"));
        if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "missing Bearer token")); }
        let hash = oc::hash_token(&token);
        self.token_user_by_hash(&hash, cookie_only).await
    }
    // The live-event socket keeps the credential hash, not the token, so the
    // identity checks must run from the hash without a header.
    async fn token_user_by_hash(&self, hash: &str, cookie_only: bool) -> Result<String, (StatusCode, Json<Value>)> {
        #[cfg(all(feature = "redis-cache", not(target_arch = "wasm32")))]
        if self.cache_revoked(hash) { return Err(err(StatusCode::UNAUTHORIZED, "session revoked")); }
        if cookie_only && self.db.one("SELECT user_id FROM sessions WHERE token_hash=?", &[json!(hash)]).await.map_err(|e| bad(&e))?.is_none() {
            return Err(err(StatusCode::UNAUTHORIZED, "ow_session requires an account session")); }
        if !cookie_only {
        // OAuth 2.1 access tokens (CLI / MCP clients)
        if let Some(row) = self.db.one("SELECT user_id FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(hash), json!(now())]).await.map_err(|e| bad(&e))? {
            let uid = db::s(&row, "user_id");
            if !self.principal_active(&uid).await { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
            return Ok(uid); }
        // service / personal access tokens
        if let Some(row) = self.db.one("SELECT * FROM tokens WHERE token_hash=?", &[json!(hash)]).await.map_err(|e| bad(&e))? {
            // A workload token is only usable while its trust record is live. A
            // build without the feature cannot mint them, so any row left over
            // from another build is rejected rather than trusted.
            #[cfg(feature = "workload-identity")]
            if db::s(&row, "kind") == "workload" && (db::n(&row, "expires_at") <= now() || !workload::live(self, &row).await) { return Err(err(StatusCode::UNAUTHORIZED, "invalid workload proof")); }
            #[cfg(not(feature = "workload-identity"))]
            if db::s(&row, "kind") == "workload" { return Err(err(StatusCode::UNAUTHORIZED, "workload identity is not enabled in this build")); }
            let expires = db::n(&row, "expires_at");
            if expires > 0 && expires <= now() { return Err(err(StatusCode::UNAUTHORIZED, "token expired")); }
            if db::s(&row, "kind") == "machine" && db::n(&row, "created_at") + 3600 < now() { return Err(err(StatusCode::UNAUTHORIZED, "machine token expired (1h TTL); login again via Universal Auth")); }
            let uid = db::s(&row, "created_by");
            let revision = db::s(&row,"workload_revision");
            if !revision.is_empty() && self.db.one("SELECT w.revision FROM workload_bindings w JOIN identities i ON i.id=w.identity_id AND i.org_id=w.org_id WHERE w.identity_id=? AND w.revision=?", &[json!(&uid),json!(revision)]).await.map_err(|_| err(StatusCode::UNAUTHORIZED,"workload trust unavailable"))?.is_none() { return Err(err(StatusCode::UNAUTHORIZED,"workload trust revoked")); }
            if !uid.is_empty() {
                if !self.principal_active(&uid).await { return Err(err(StatusCode::UNAUTHORIZED, "token owner is deactivated")); }
                if db::n(&row, "last_used_at") + 60 < now() { let _ = self.db.exec("UPDATE tokens SET last_used_at=? WHERE token_hash=?", &[json!(now()), json!(&hash)]).await; }
                return Ok(uid); }
        }
        }
        let row = self.db.one("SELECT user_id,created_at FROM sessions WHERE token_hash=?", &[json!(hash)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
        if db::n(&row, "created_at") + 7 * 86400 < now() { let _ = self.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(hash)]).await; return Err(err(StatusCode::UNAUTHORIZED, "session expired (7d); login again")); }
        let uid = db::s(&row, "user_id");
        if !self.principal_active(&uid).await { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        Ok(uid)
    }
    // Redis may only deny: a revoked token hash is remembered so repeated use is
    // rejected without a database read. Nothing that grants access is cached.
    #[cfg(all(feature = "redis-cache", not(target_arch = "wasm32")))]
    fn cache_revoked(&self, hash: &str) -> bool { let mut g = self.redis.lock().unwrap(); let Some(c) = g.as_mut() else { return false }; let v: Option<String> = redis::Commands::get(c, format!("revoked:{}", hash)).ok(); v.is_some() }
    #[cfg(all(feature = "redis-cache", not(target_arch = "wasm32")))]
    fn cache_revoke(&self, hash: &str) { let mut g = self.redis.lock().unwrap(); if let Some(c) = g.as_mut() { let _: Result<(), _> = redis::Commands::set_ex(c, format!("revoked:{}", hash), "1", 7 * 86400u64); } }

    async fn org_role(&self, org: &str, user: &str) -> Option<String> {
        self.db.one("SELECT role FROM org_members WHERE org_id=? AND user_id=?", &[json!(org), json!(user)]).await.ok().flatten().map(|r| db::s(&r, "role"))
    }
    pub(crate) async fn check_scope(&self, headers: &HeaderMap, env_id: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""); let token = auth.strip_prefix("Bearer ").unwrap_or("");
        self.check_scope_by_hash(&oc::hash_token(token), env_id).await }
    async fn check_scope_by_hash(&self, hash: &str, env_id: &str) -> Result<(), (StatusCode, Json<Value>)> {
        if let Some(row) = self.db.one("SELECT env_id FROM tokens WHERE token_hash=?", &[json!(hash)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE,"credential scope unavailable"))? { let scope = db::s(&row, "env_id"); if !scope.is_empty() && scope != env_id { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); } }
        Ok(()) }
    async fn role_perms(&self, org: &str, role: &str) -> Vec<String> {
        match role {
            "owner" | "admin" => vec!["*".to_string()],
            "developer" => DEVELOPER_PERMS.iter().map(|p| p.to_string()).collect(),
            _ => self.db.one("SELECT permissions FROM roles WHERE org_id=? AND name=?", &[json!(org), json!(role)]).await.ok().flatten()
                .and_then(|row| serde_json::from_str::<Vec<String>>(&db::s(&row, "permissions")).ok()).unwrap_or_default(),
        } }
    // A custom role carrying "*" or "org:admin" is admin by another name, so
    // every owner-only grant has to test permissions, not the label.
    async fn role_privileged(&self, org: &str, role: &str) -> bool {
        self.role_perms(org, role).await.iter().any(|p| p == "*" || p == "org:admin") }
    pub(crate) async fn check_perm(&self, org: &str, user: &str, action: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let role = self.require_org(org, user).await?;
        let perms = self.role_perms(org, &role).await;
        if perms.iter().any(|p| p == "*" || p == action) { Ok(()) } else { Err(err(StatusCode::FORBIDDEN, &format!("role {} lacks permission {}", role, action))) } }
    pub(crate) async fn check_admin(&self, org: &str, user: &str) -> Result<(), (StatusCode, Json<Value>)> { self.check_perm(org, user, "org:admin").await }
    // Counters live in the database so a restart, or a second replica behind a
    // load balancer, does not reset an attacker's budget.
    // MySQL keys rate_limits on a VARCHAR(255), and an email-length suffix can
    // exceed it. Hash the key so every backend stores a bounded, collision-free
    // value instead of silently failing the upsert.
    fn rate_key(key: &str) -> String { oc::hash_token(key) }
    pub(crate) async fn rate_ok(&self, key: &str, max: usize, window: i64) -> bool {
        let key = Self::rate_key(key);
        let cutoff = now() - window;
        let count = self.db.one("SELECT count FROM rate_limits WHERE key=? AND window_start>?", &[json!(&key), json!(cutoff)]).await
            .ok().flatten().map(|r| db::n(&r, "count")).unwrap_or(0);
        (count as usize) < max }
    pub(crate) async fn rate_fail(&self, key: &str, window: i64) {
        let key = Self::rate_key(key);
        let current = now(); let cutoff = current - window;
        // MySQL has neither ON CONFLICT nor RETURNING, and `key` is reserved.
        #[cfg(not(target_arch = "wasm32"))]
        if self.db.backend() == db::Backend::Mysql {
            let _ = self.db.exec(
                "INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,1) \
                 ON DUPLICATE KEY UPDATE count = IF(window_start <= ?, 1, count + 1), \
                   window_start = IF(window_start <= ?, ?, window_start)",
                &[json!(&key), json!(current), json!(cutoff), json!(cutoff), json!(current)]).await;
            return; }
        let _ = self.db.query(
            "INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,1) \
             ON CONFLICT(key) DO UPDATE SET \
               count = CASE WHEN rate_limits.window_start <= ? THEN 1 ELSE rate_limits.count + 1 END, \
               window_start = CASE WHEN rate_limits.window_start <= ? THEN ? ELSE rate_limits.window_start END \
             RETURNING count",
            &[json!(&key), json!(current), json!(cutoff), json!(cutoff), json!(current)]).await; }
    pub(crate) async fn rate_clear(&self, key: &str) {
        let key = Self::rate_key(key);
        let _ = self.db.exec("DELETE FROM rate_limits WHERE key=?", &[json!(&key)]).await; }
    // Deactivated users and deleted identities must lose every credential at once.
    async fn principal_active(&self, uid: &str) -> bool {
        match self.db.one("SELECT active,email_verified FROM users WHERE id=?", &[json!(uid)]).await {
            Ok(Some(row)) => {
                if db::n(&row, "active") == 0 { return false; }
                if db::n(&row, "email_verified") == 0 { return false; }
                true },
            Ok(None) => self.db.one("SELECT id FROM identities WHERE id=?", &[json!(uid)]).await.ok().flatten().is_some(),
            Err(_) => false,
        } }
    pub(crate) async fn require_org(&self, org: &str, user: &str) -> Result<String, (StatusCode, Json<Value>)> {
        if let Some(r) = self.org_role(org, user).await { return Ok(r); }
        // machine identities belong to an org directly
        if let Ok(Some(idn)) = self.db.one("SELECT role FROM identities WHERE id=? AND org_id=?", &[json!(user), json!(org)]).await { self.require_running(org).await?; return Ok(db::s(&idn, "role")); }
        Err(err(StatusCode::FORBIDDEN, "not an organisation member")) }
    /// Enterprise surfaces a workspace may use: both a compiled feature and a
    /// grant are required, and the grant row is the only mutable half.
    async fn feature_grants(&self, org: &str) -> Vec<String> {
        self.db.one("SELECT features FROM feature_grants WHERE org_id=?", &[json!(org)]).await.ok().flatten()
            .map(|r| db::s(&r, "features").split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    }
    // Called only from the gated handlers, so a core-only build sees no caller.
    #[allow(dead_code)]
    async fn feature_granted(&self, org: &str, name: &str) -> bool {
        crate::features::compiled(name) && self.feature_grants(org).await.iter().any(|f| f == name)
    }
    #[allow(dead_code)]
    async fn require_feature(&self, org: &str, name: &str) -> Result<(), (StatusCode, Json<Value>)> {
        if !crate::features::compiled(name) { return Err(err(StatusCode::NOT_FOUND, &format!("{} is not available in this build", name))); }
        if self.feature_granted(org, name).await { return Ok(()); }
        Err(err(StatusCode::FORBIDDEN, &format!("{} is not enabled for this workspace", name)))
    }
    /// Replacement semantics: the caller sends the full set it wants.
    async fn set_feature_grants(&self, org: &str, names: &[String], actor: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        if refs.iter().any(|n| !crate::features::known(n)) { return Err(bad("unknown feature name")); }
        if refs.iter().any(|n| !crate::features::compiled(n)) { return Err(bad("this build does not include one of the requested features")); }
        let joined = crate::features::normalize(refs).join(" ");
        let sql = "INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(org_id) DO UPDATE SET features=excluded.features,updated_by=excluded.updated_by,updated_at=excluded.updated_at";
        #[cfg(not(target_arch = "wasm32"))]
        let sql = if self.db.backend() == db::Backend::Mysql { "INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE features=VALUES(features),updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)" } else { sql };
        self.db.exec(sql, &[json!(org), json!(&joined), json!(actor), json!(now())]).await.map_err(|e| bad(&e))?;
        Ok(())
    }
    async fn env_org_app(&self, env_id: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT a.org_id AS org_id, e.app_id AS app_id FROM envs e JOIN apps a ON a.id=e.app_id WHERE e.id=?", &[json!(env_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        Ok((db::s(&row, "org_id"), db::s(&row, "app_id")))
    }
    pub(crate) async fn require_env(&self, env_id: &str, user: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
        let (org, app) = self.env_org_app(env_id).await?; self.require_app_running(&app).await?; let role = self.require_org(&org, user).await?;
        if role == "owner" || role == "admin" { return Ok((org, app)); }
        let env = self.db.one("SELECT restricted FROM envs WHERE id=?", &[json!(env_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        let restricted = db::n(&env, "restricted") == 1;
        // Only an explicit restriction narrows access. require_approval gates
        // writes, not membership, so it must never lock readers out.
        if !restricted { return Ok((org, app)); }
        let env_rows = self.db.query("SELECT user_id FROM env_members WHERE env_id=?", &[json!(env_id)]).await.map_err(|e| bad(&e))?;
        if env_rows.iter().any(|r| db::s(r, "user_id") == user) { return Ok((org, app)); }
        let app_rows = self.db.query("SELECT user_id FROM app_members WHERE app_id=?", &[json!(&app)]).await.map_err(|e| bad(&e))?;
        if app_rows.iter().any(|r| db::s(r, "user_id") == user) { return Ok((org, app)); }
        if self.db.one("SELECT g.team_id FROM team_env_grants g JOIN team_members tm ON tm.team_id=g.team_id WHERE g.env_id=? AND tm.user_id=? LIMIT 1", &[json!(env_id), json!(user)]).await.map_err(|e| bad(&e))?.is_some() { return Ok((org, app)); }
        Err(err(StatusCode::FORBIDDEN, "no access to this environment"))
    }
    async fn decrypt_secret(&self, key: &[u8;32], row: &Row, user: Option<&str>) -> Value {
        let sid = db::s(row, "id"); let env = db::s(row, "env_id"); let version = db::n(row, "version");
        let (mut value, mut decrypt_error) = match decrypt_secret_value(key, &env, &sid, "value", version, &db::s(row, "value_enc")) {
            Ok(b) => (String::from_utf8_lossy(&b).into_owned(), false),
            Err(_) => (String::new(), true) };
        if let Some(user) = user {
            if let Ok(Some(ov)) = self.db.one("SELECT value_enc FROM overrides WHERE secret_id=? AND user_id=?", &[json!(sid), json!(user)]).await {
                if let Ok(b) = decrypt_secret_value(key, &env, &sid, &format!("override:{}", user), version, &db::s(&ov, "value_enc")) { value = String::from_utf8_lossy(&b).into_owned(); decrypt_error = false; }
            }
        }
        let stype = db::s(row, "secret_type");
        let path = if db::s(row, "path_enc").is_empty() { db::s(row, "path") } else {
            decrypt_secret_value(key, &env, &sid, "path", version, &db::s(row, "path_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|_| db::s(row, "path")) };
        let tags = if db::s(row, "tags_enc").is_empty() { db::s(row, "tags") } else {
            decrypt_secret_value(key, &env, &sid, "tags", version, &db::s(row, "tags_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|_| db::s(row, "tags")) };
        json!({"id": sid, "key": oc::decrypt_symmetric_compat(key, &secret_aad(&env, &sid, "key"), &db::s(row, "key_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            "value": if stype == "sealed" { Value::Null } else { json!(value) }, "decrypt_error": decrypt_error,
            "path": path, "comment": decrypt_secret_value(key, &env, &sid, "comment", version, &db::s(row,"comment_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            "tags": tags, "type": stype, "version": version, "updated_at": db::n(row,"updated_at")})
    }
    #[allow(clippy::type_complexity)]
    async fn list_secrets_with(&self, env_id: &str, user: Option<&str>, subject: Option<&str>) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        let key = self.env_key(env_id).await?;
        let rows = self.db.query("SELECT * FROM secrets WHERE env_id=? AND deleted=0 ORDER BY key_index, key_hash", &[json!(env_id)]).await.map_err(|e| bad(&e))?;
        let mut out = Vec::new();
        for r in &rows { if let Some(uid) = subject { if self.restricted_env(env_id, uid).await? { let Ok(path) = self.stored_path(&key, r) else { continue }; if !self.path_allowed(env_id, uid, &path, "read").await? { continue; } } } let v = self.decrypt_secret(&key, r, user).await; out.push((v["key"].as_str().unwrap_or("").to_string(), v["value"].as_str().unwrap_or("").to_string(), v)); }
        // resolve ${KEY} and ${/path/KEY} references
        let map: HashMap<String, String> = out.iter().map(|(k, v, raw)| (format!("{}{}", raw["path"].as_str().unwrap_or("/"), k), v.clone())).collect();
        let by_key: HashMap<String, String> = out.iter().map(|(k, v, _)| (k.clone(), v.clone())).collect();
        for item in out.iter_mut() { if item.2["type"].as_str() == Some("sealed") { continue; } for _ in 0..5 { let before = item.1.clone(); item.1 = resolve_refs(&item.1, &map, &by_key); if item.1 == before { break; } } item.2["value"] = json!(item.1); }
        Ok(out)
    }
    #[allow(clippy::type_complexity)]
    async fn list_secrets_decrypted(&self, env_id: &str, user: &str) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        self.list_secrets_with(env_id, Some(user), Some(user)).await }
    // Integrations must never deploy a caller's personal override as the shared value.
    #[allow(clippy::type_complexity)]
    async fn list_secrets_base(&self, env_id: &str) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        self.list_secrets_with(env_id, None, None).await }
}
// Bind ciphertext to the record it belongs to. The version is deliberately not
// included in the key/path/tags fields: restore and point-in-time recovery copy
// those, and a version binding would make the copy unreadable. Value and
// comment are bound to the version and re-encrypted when restored.
pub(crate) fn secret_aad(env: &str, sid: &str, field: &str) -> Vec<u8> { format!("ow-secret:v2|{}|{}|{}", env, sid, field).into_bytes() }
// A deterministic index is still needed to look a secret up. HMAC under the
// environment key removes the offline dictionary attack a bare SHA-256 allows.
fn key_index(env_key: &[u8;32], path: &str, key: &str) -> String { hmac_hex(env_key, format!("ow-key-index:v1|{}|{}", path, key).as_bytes()) }
fn secret_aad_v(env: &str, sid: &str, field: &str, version: i64) -> Vec<u8> { format!("ow-secret:v2|{}|{}|{}|v{}", env, sid, field, version).into_bytes() }
fn integration_aad(env: &str, iid: &str, field: &str) -> Vec<u8> { format!("ow-integration:v1|{}|{}|{}", env, iid, field).into_bytes() }
fn lease_aad(env: &str, lid: &str, field: &str) -> Vec<u8> { format!("ow-lease:v1|{}|{}|{}", env, lid, field).into_bytes() }
fn proposal_aad(env: &str, pid: &str, field: &str) -> Vec<u8> { format!("ow-proposal:v1|{}|{}|{}", env, pid, field).into_bytes() }
// Version rows are bound to their version, but value and comment ciphertext
// written before that binding (or by an earlier release) must stay readable.
pub(crate) fn decrypt_secret_value(key: &[u8;32], env: &str, sid: &str, field: &str, version: i64, payload: &str) -> Result<Vec<u8>, String> {
    if payload.starts_with("ow2:") {
        if let Ok(v) = oc::decrypt_symmetric_aad(key, &secret_aad_v(env, sid, field, version), payload) { return Ok(v); }
        if let Ok(v) = oc::decrypt_symmetric_aad(key, &secret_aad(env, sid, field), payload) { return Ok(v); }
    }
    oc::decrypt_symmetric(key, payload)
}
fn resolve_refs(v: &str, by_path: &HashMap<String, String>, by_key: &HashMap<String, String>) -> String {
    let mut out = String::new(); let mut rest = v;
    while let Some(start) = rest.find("${") { out.push_str(&rest[..start]); let tail = &rest[start + 2..];
        match tail.find('}') { Some(end) => { let name = &tail[..end]; let val = by_path.get(name).or_else(|| by_key.get(name)).cloned().unwrap_or_else(|| format!("${{{}}}", name)); out.push_str(&val); rest = &tail[end + 1..]; } None => { out.push_str(&rest[start..]); return out; } } }
    out.push_str(rest); out
}

// ---------- auth ----------
async fn register(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let rl = format!("register:{}", addr);
    if !st.rate_ok(&rl, 5, 3600).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many registrations from this address; try again later")); }
    st.rate_fail(&rl, 3600).await;
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password registration is disabled on this instance; sign in with a configured provider")); }
    if r.email.is_empty() || r.password.len() < 8 { return Err(bad("email and password (>=8 chars) required")); }
    if !signups_open(&st).await { return Err(err(StatusCode::FORBIDDEN, "signups are disabled on this instance; ask an administrator to invite you")); }
    if production() && !mailer::MailConfig::from_env().enabled() { return Err(err(StatusCode::SERVICE_UNAVAILABLE, "password signup is unavailable: no email provider is configured; use a configured sign-in provider or ask an administrator")); }
    let kp = oc::Keypair::generate();
    let wrapped = oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    let uid = id(); let hash = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    // A password signup proves nothing about the address until the link is opened.
    // The instance-owner claim in particular waits for verification.
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,0)", &[json!(uid), json!(r.email.to_lowercase()), json!(hash), json!(kp.public), json!(wrapped), json!(now())]).await.map_err(|_| err(StatusCode::CONFLICT, "an account with this email already exists"))?;
    let oid = workspaces::default_workspace(&st, &uid,  &r.email).await?;
    mfa::note_password_login(&st, &uid).await;
    let link_token = issue_auth_token(&st, &uid, "verify", 86400).await;
    let link = format!("{}/api/auth/verify?token={}", issuer(&st, &h), link_token);
    send_template(&r.email, "verify", &[("link", &link), ("email", &r.email)]).await;
    let mut out = json!({"user_id":uid,"public_key":kp.public,"recovery_kit":kp.secret_b64(),"verification_required":true});
    if let Some(oid) = oid { out["org_id"] = json!(oid); } Ok((HeaderMap::new(),j(out)))
}
pub(crate) async fn make_session(st: &S, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { let t = oc::random_token("ow"); st.db.exec("INSERT INTO sessions(id,token_hash,user_id,created_at) VALUES(?,?,?,?)", &[json!(id()), json!(oc::hash_token(&t)), json!(uid), json!(now())]).await.map_err(|e| bad(&e))?; Ok(t) }
async fn login(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance; use a configured provider")); }
    let key = format!("login:{}:{}", addr, r.email.trim().to_lowercase());
    if !st.rate_ok(&key, 5, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later")); }
    let row = match st.db.one("SELECT * FROM users WHERE email=?", &[json!(r.email.trim().to_lowercase())]).await.map_err(|e| bad(&e))? { Some(x) => x, None => { st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); } };
    if db::n(&row, "active") == 0 && row.contains_key("active") { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
    // A version 2 account has no server-usable password, even if an old reset
    // path left a hash behind; it must use the challenge login.
    if db::n(&row, "auth_version") == 2 { st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    if !oc::verify_password(&r.password, &db::s(&row, "pass_hash")) { st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    if db::n(&row, "email_verified") == 0 { return Err(err(StatusCode::FORBIDDEN, "verify your email address before signing in; POST /api/auth/resend-verification for a new link")); }
    st.rate_clear(&key).await;
    let uid = db::s(&row, "id");
    mfa::note_password_login(&st, &uid).await;
    if mfa::required(&st, &uid).await {
        let challenge = mfa::new_challenge(&st, &uid).await?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge,
            "methods": mfa::methods(&st, &uid).await, "email_available": mfa::email_available() && mfa::email_enabled(&st, &uid).await})))); }
    let token = make_session(&st, &uid).await?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "public_key": db::s(&row, "pubkey")}))))
}

// ---------- client-derived auth (version 2) ----------
const KDF_ITERATIONS: i64 = 600_000;
const KDF_ALGO: &str = "pbkdf2-sha256";
fn auth_key_aad(uid: &str) -> Vec<u8> { format!("auth-key|{}", uid).into_bytes() }
fn valid_kdf(salt: &str, iterations: i64, algo: &str) -> bool {
    algo == KDF_ALGO && (600_000..=5_000_000).contains(&iterations) && oc::unb64(salt).map(|b| b.len() == 16).unwrap_or(false) }
fn valid_key32(s: &str) -> bool { oc::unb64(s).map(|b| b.len() == 32).unwrap_or(false) }
fn valid_wrapped_key(s: &str) -> bool { s.starts_with("owv2:") && s.len() <= 4096 }
fn verify_proof(auth_key: &[u8], challenge: &str, challenge_id: &str, proof_hex: &str) -> bool {
    use hmac::Mac;
    let Some(proof) = hex_decode(proof_hex) else { return false };
    let Ok(mut mac) = hmac::Hmac::<sha2::Sha256>::new_from_slice(auth_key) else { return false };
    mac.update(format!("{}|{}", challenge, challenge_id).as_bytes());
    mac.verify_slice(&proof).is_ok() }
async fn login_outcome(st: &S, uid: &str, pubkey: &str, wrapped: Option<&str>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if mfa::required(st, uid).await {
        let challenge = mfa::new_challenge(st, uid).await?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge,
            "methods": mfa::methods(st, uid).await, "email_available": mfa::email_available() && mfa::email_enabled(st, uid).await})))); }
    let token = make_session(st, uid).await?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    let mut out = json!({"token": token, "user_id": uid, "public_key": pubkey});
    if let Some(wrapped) = wrapped { out["wrapped_privkey"] = json!(wrapped); }
    Ok((hdr, j(out))) }
async fn auth_kdf(State(st): State<S>, PeerAddr(addr): PeerAddr, Query(q): Query<HashMap<String,String>>) -> Res {
    let key = format!("kdf:{}", addr);
    if !st.rate_ok(&key, 60, 60).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many requests; try again later")); }
    st.rate_fail(&key, 60).await;
    let email = q.get("email").cloned().unwrap_or_default().trim().to_lowercase();
    if let Some(r) = st.db.one("SELECT auth_version,kdf_salt,kdf_iterations,kdf_algo FROM users WHERE email=?", &[json!(&email)]).await.map_err(|e| bad(&e))? {
        if db::n(&r, "auth_version") == 2 {
            if !valid_kdf(&db::s(&r,"kdf_salt"), db::n(&r,"kdf_iterations"), &db::s(&r,"kdf_algo")) {
                return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "this account's sign-in parameters are invalid; reset your password")); }
            return Ok(j(json!({"version":2, "salt":db::s(&r,"kdf_salt"), "iterations":db::n(&r,"kdf_iterations"), "algo":db::s(&r,"kdf_algo")}))); }
        return Ok(j(json!({"version":1}))); }
    Ok(j(json!({"version":2, "salt":oc::b64(&oc::random_key()[..16]), "iterations":KDF_ITERATIONS, "algo":KDF_ALGO}))) }
#[derive(Deserialize, Default)] struct RegisterV2Req { email: String, salt: String, iterations: i64, algo: String, auth_key: String, public_key: String, wrapped_privkey: String }
async fn register_v2(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Json(r): Json<RegisterV2Req>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let rl = format!("register:{}", addr);
    if !st.rate_ok(&rl, 5, 3600).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many registrations from this address; try again later")); }
    st.rate_fail(&rl, 3600).await;
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password registration is disabled on this instance; sign in with a configured provider")); }
    if production() && !mailer::MailConfig::from_env().enabled() { return Err(err(StatusCode::SERVICE_UNAVAILABLE, "password signup is unavailable: no email provider is configured; use a configured sign-in provider or ask an administrator")); }
    let email = r.email.trim().to_lowercase();
    if email.is_empty() || !valid_email(&email) { return Err(bad("email required")); }
    if !signups_open(&st).await { return Err(err(StatusCode::FORBIDDEN, "signups are disabled on this instance; ask an administrator to invite you")); }
    if !valid_kdf(&r.salt, r.iterations, &r.algo) { return Err(bad("unsupported KDF parameters")); }
    let auth_key = oc::unb64(&r.auth_key).map_err(|_| bad("auth_key must be base64"))?;
    if auth_key.len() != 32 { return Err(bad("auth_key must decode to 32 bytes")); }
    if !valid_key32(&r.public_key) { return Err(bad("public_key must be 32-byte base64")); }
    if !valid_wrapped_key(&r.wrapped_privkey) { return Err(bad("wrapped_privkey must be an owv2 payload")); }
    let uid = id(); let master = st.master();
    let auth_key_enc = oc::encrypt_symmetric_aad(&master, &auth_key_aad(&uid), &auth_key);
    let hash = oc::hash_password(&oc::random_token("v2")).map_err(|e| bad(&e))?;
    st.audited_batch_master(&[
        ("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified,auth_version,kdf_salt,kdf_iterations,kdf_algo,auth_key_enc) VALUES(?,?,?,?,?,?,0,2,?,?,?,?)".into(),
            vec![json!(&uid), json!(&email), json!(hash), json!(&r.public_key), json!(&r.wrapped_privkey), json!(now()), json!(&r.salt), json!(r.iterations), json!(&r.algo), json!(auth_key_enc)]),
    ], &[], ["", "", "", &uid, "auth.register_v2", &email], master).await.map_err(|e| if e==webhooks::EPOCH_STALE {webhooks::epoch_stale()} else if unique_violation(&e) {err(StatusCode::CONFLICT, "an account with this email already exists")} else {bad(&e)})?;
    let oid = workspaces::default_workspace(&st, &uid, &email).await?;
    claim_instance_owner(&st, &uid).await;
    // A v2 account never proves a password, so factor management must not ask
    // for one; the session or auth-key proof is the credential.
    let link_token = issue_auth_token(&st, &uid, "verify", 86400).await;
    let link = format!("{}/api/auth/verify?token={}", issuer(&st, &h), link_token);
    send_template(&email, "verify", &[("link", &link), ("email", &email)]).await;
    let mut out = json!({"user_id":uid,"public_key":r.public_key,"verification_required":true});
    if let Some(oid) = oid { out["org_id"] = json!(oid); } Ok((HeaderMap::new(),j(out))) }
#[derive(Deserialize, Default)] struct ChallengeReq { email: String }
async fn auth_challenge(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<ChallengeReq>) -> Res {
    let key = format!("challenge:{}", addr);
    if !st.rate_ok(&key, 30, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many requests; try again later")); }
    st.rate_fail(&key, 900).await;
    let email = r.email.trim().to_lowercase();
    let user = st.db.one("SELECT id,auth_version FROM users WHERE email=?", &[json!(&email)]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    if db::n(&user, "auth_version") != 2 { return Err(bad("this account uses password sign-in")); }
    let uid = db::s(&user, "id");
    let _ = st.db.exec("DELETE FROM auth_challenges WHERE user_id=?", &[json!(&uid)]).await;
    let cid = oc::random_token("ch"); let challenge = oc::random_token("chal");
    st.db.exec("INSERT INTO auth_challenges(id_hash,user_id,challenge,created_at) VALUES(?,?,?,?)",
        &[json!(oc::hash_token(&cid)), json!(&uid), json!(&challenge), json!(now())]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"challenge_id": cid, "challenge": challenge, "expires_at": now() + 120}))) }
#[derive(Deserialize, Default)] struct LoginV2Req { email: String, challenge_id: String, proof: String }
async fn login_v2(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<LoginV2Req>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance; use a configured provider")); }
    let email = r.email.trim().to_lowercase();
    let key = format!("login:{}:{}", addr, email);
    if !st.rate_ok(&key, 5, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later")); }
    let row = match st.db.one("SELECT c.user_id AS user_id,c.challenge AS challenge,c.created_at AS created_at,u.email AS email,u.auth_version AS auth_version,u.active AS active,u.email_verified AS email_verified,u.pubkey AS pubkey,u.wrapped_privkey AS wrapped_privkey,u.auth_key_enc AS auth_key_enc,u.kdf_salt AS kdf_salt,u.kdf_iterations AS kdf_iterations,u.kdf_algo AS kdf_algo FROM auth_challenges c JOIN users u ON u.id=c.user_id WHERE c.id_hash=?", &[json!(oc::hash_token(&r.challenge_id))]).await.map_err(|e| bad(&e))? {
        Some(x) => x, None => { st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); } };
    if db::n(&row, "created_at") + 120 < now() || db::s(&row, "email") != email || db::n(&row, "auth_version") != 2
        || !valid_kdf(&db::s(&row,"kdf_salt"), db::n(&row,"kdf_iterations"), &db::s(&row,"kdf_algo")) {
        st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    let uid = db::s(&row, "user_id");
    st.epoch_ok().await?;
    let auth_key = oc::decrypt_symmetric_aad(&st.master(), &auth_key_aad(&uid), &db::s(&row, "auth_key_enc")).map_err(|_| bad("authentication key is unavailable"))?;
    if !verify_proof(&auth_key, &db::s(&row, "challenge"), &r.challenge_id, &r.proof) {
        st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    // Consume atomically: two concurrent requests with the same proof must not
    // both mint a session.
    let consumed = st.db.exec("DELETE FROM auth_challenges WHERE id_hash=?", &[json!(oc::hash_token(&r.challenge_id))]).await.unwrap_or(0);
    if consumed == 0 { st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    st.rate_clear(&key).await;
    if db::n(&row, "active") == 0 { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
    if db::n(&row, "email_verified") == 0 { return Err(err(StatusCode::FORBIDDEN, "verify your email address before signing in; POST /api/auth/resend-verification for a new link")); }
    st.audit("", "", "", &uid, "auth.login_v2", "").await;
    login_outcome(&st, &uid, &db::s(&row, "pubkey"), Some(&db::s(&row, "wrapped_privkey"))).await }
#[derive(Deserialize, Default)] struct ResetV2Req { token: String, salt: String, iterations: i64, algo: String, auth_key: String, public_key: String, wrapped_privkey: String, #[serde(default)] discard_e2e_key: bool }
async fn reset_password_v2(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<ResetV2Req>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance")); }
    let key = format!("reset:{}", addr);
    if !st.rate_ok(&key, 10, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again later")); }
    if !valid_kdf(&r.salt, r.iterations, &r.algo) { return Err(bad("unsupported KDF parameters")); }
    let auth_key = oc::unb64(&r.auth_key).map_err(|_| bad("auth_key must be base64"))?;
    if auth_key.len() != 32 { return Err(bad("auth_key must decode to 32 bytes")); }
    if !valid_key32(&r.public_key) { return Err(bad("public_key must be 32-byte base64")); }
    if !valid_wrapped_key(&r.wrapped_privkey) { return Err(bad("wrapped_privkey must be an owv2 payload")); }
    let hash = oc::hash_token(r.token.trim());
    let row = st.db.one("SELECT user_id FROM auth_tokens WHERE token_hash=? AND kind='reset' AND used=0 AND expires_at>?", &[json!(&hash), json!(now())]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| bad("reset link is invalid, already used, or expired"))?;
    st.rate_fail(&key, 900).await;
    let uid = db::s(&row, "user_id");
    let user = st.db.one("SELECT pubkey FROM users WHERE id=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("account not found"))?;
    let stored_pub = db::s(&user, "pubkey");
    let replaced = r.public_key != stored_pub;
    if replaced && !r.discard_e2e_key {
        return Err(bad("recovery kit does not match this account; pass discard_e2e_key=true to replace your key and lose end-to-end access")); }
    let master = st.master();
    let auth_key_enc = oc::encrypt_symmetric_aad(&master, &auth_key_aad(&uid), &auth_key);
    let pass = oc::hash_password(&oc::random_token("v2")).map_err(|e| bad(&e))?;
    st.audited_batch_master(&[
        ("UPDATE users SET pass_hash=?,pubkey=?,wrapped_privkey=?,email_verified=1,auth_version=2,kdf_salt=?,kdf_iterations=?,kdf_algo=?,auth_key_enc=? WHERE id=?".into(),
            vec![json!(pass), json!(&r.public_key), json!(&r.wrapped_privkey), json!(&r.salt), json!(r.iterations), json!(&r.algo), json!(auth_key_enc), json!(&uid)]),
        ("UPDATE auth_tokens SET used=1 WHERE token_hash=?".into(), vec![json!(&hash)]),
        ("DELETE FROM sessions WHERE user_id=?".into(), vec![json!(&uid)]),
        ("DELETE FROM oauth_tokens WHERE user_id=?".into(), vec![json!(&uid)]),
    ], &[], ["", "", "", &uid, "auth.password_reset_v2", if replaced { "key replaced" } else { "kit supplied" }], master).await.map_err(master_write_error)?;
    login_outcome(&st, &uid, &r.public_key, Some(&r.wrapped_privkey)).await }
#[derive(Deserialize, Default)] struct ResetInfoReq { token: String }
async fn reset_info(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<ResetInfoReq>) -> Res {
    let key = format!("reset-info:{}", addr);
    if !st.rate_ok(&key, 20, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again later")); }
    st.rate_fail(&key, 900).await;
    let hash = oc::hash_token(r.token.trim());
    let row = st.db.one("SELECT u.pubkey AS public_key,u.auth_version AS auth_version FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.kind='reset' AND t.used=0 AND t.expires_at>?",
        &[json!(&hash), json!(now())]).await.map_err(|_| bad("reset link is invalid, already used, or expired"))?
        .ok_or_else(|| bad("reset link is invalid, already used, or expired"))?;
    Ok(j(json!({"public_key": db::s(&row, "public_key"), "auth_version": db::n(&row, "auth_version")}))) }
async fn me_auth(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT auth_version,kdf_salt,kdf_iterations,kdf_algo,pubkey,wrapped_privkey FROM users WHERE id=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
    Ok(j(json!({"auth_version": db::n(&row,"auth_version"), "kdf_salt": db::s(&row,"kdf_salt"), "kdf_iterations": db::n(&row,"kdf_iterations"), "kdf_algo": db::s(&row,"kdf_algo"), "public_key": db::s(&row,"pubkey"), "wrapped_privkey": db::s(&row,"wrapped_privkey")}))) }
#[derive(Deserialize, Default)] struct InviteV2Req { token: String, #[serde(default)] salt: String, #[serde(default)] iterations: i64, #[serde(default)] algo: String, #[serde(default)] auth_key: String, #[serde(default)] public_key: String, #[serde(default)] wrapped_privkey: String }
async fn accept_invite_v2(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Json(r): Json<InviteV2Req>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let row = workspaces::valid_invite(&st,&r.token,&h,addr).await?;
    if let Some(out) = workspaces::existing(&st,&row,&r.token,&h).await? { return Ok(out); }
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance; sign in with the configured provider to redeem this invite")); }
    let rl = format!("invite-accept:{}", addr);
    if !st.rate_ok(&rl, 10, 3600).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many invite attempts; try again later")); }
    st.rate_fail(&rl, 3600).await;
    if !valid_kdf(&r.salt, r.iterations, &r.algo) { return Err(bad("unsupported KDF parameters")); }
    let auth_key = oc::unb64(&r.auth_key).map_err(|_| bad("auth_key must be base64"))?;
    if auth_key.len() != 32 { return Err(bad("auth_key must decode to 32 bytes")); }
    if !valid_key32(&r.public_key) { return Err(bad("public_key must be 32-byte base64")); }
    if !valid_wrapped_key(&r.wrapped_privkey) { return Err(bad("wrapped_privkey must be an owv2 payload")); }
    let email = db::s(&row,"email"); let org = db::s(&row,"org_id"); let role = db::s(&row,"role");
    st.require_running(&org).await?;
    // The consent path above already handled an existing matching account; a
    // row here means nobody matching is signed in, so refuse instead of
    // colliding with the users.email unique index.
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).await.map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in instead")); }
    let uid = id(); let master = st.master();
    let auth_key_enc = oc::encrypt_symmetric_aad(&master, &auth_key_aad(&uid), &auth_key);
    let pass = oc::hash_password(&oc::random_token("v2")).map_err(|e| bad(&e))?;
    workspaces::invite_batch(&st,&row,&[],&[
        workspaces::consume(&st,&row,&r.token).await?,
        ("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified,auth_version,kdf_salt,kdf_iterations,kdf_algo,auth_key_enc) VALUES(?,?,?,?,?,?,1,2,?,?,?,?)".into(),
            vec![json!(&uid),json!(&email),json!(pass),json!(&r.public_key),json!(&r.wrapped_privkey),json!(now()),json!(&r.salt),json!(r.iterations),json!(&r.algo),json!(auth_key_enc)]),
        ("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)".into(),vec![json!(&org),json!(&uid),json!(&role)]),
    ],&[0,1,2]).await?;
    st.audit(&org, "", "", &uid, "member.accept_invite", &email).await;
    claim_instance_owner(&st, &uid).await;
    login_outcome(&st, &uid, &r.public_key, Some(&r.wrapped_privkey)).await }

async fn me(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h).await?; let r = st.db.one("SELECT id,email,pubkey FROM users WHERE id=?", &[json!(uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
    // A caller can always learn the environment its own credential is confined to.
    let mut out = db::obj(&r); out["env_scope"] = json!(env_scope_of(&st, &h).await?); Ok(j(out)) }
// Browser sessions are listable by a stable id. Older rows predate the id column,
// so one is assigned on first listing instead of exposing token hashes.
async fn list_sessions(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h).await?;
    let current = oc::hash_token(&bearer_token_or_cookie(&h));
    let rows = st.db.query("SELECT id,token_hash,created_at FROM sessions WHERE user_id=? ORDER BY created_at DESC", &[json!(&uid)]).await.map_err(|e| bad(&e))?;
    let mut out = Vec::new();
    for r in rows { let mut sid = db::s(&r, "id");
        if sid.is_empty() { sid = id(); let _ = st.db.exec("UPDATE sessions SET id=? WHERE token_hash=?", &[json!(&sid), json!(&db::s(&r, "token_hash"))]).await; }
        out.push(json!({"id": sid, "created_at": db::n(&r, "created_at"), "current": db::s(&r, "token_hash") == current})); }
    Ok(j(json!(out))) }
fn bearer_token_or_cookie(h: &HeaderMap) -> String { let t = bearer_token(h); if t.is_empty() { cookie_val(h, "ow_session") } else { t } }
async fn revoke_session(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let current = oc::hash_token(&bearer_token_or_cookie(&h));
    let row = st.db.one("SELECT token_hash FROM sessions WHERE id=? AND user_id=?", &[json!(&sid), json!(&uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "session not found"))?;
    st.db.exec("DELETE FROM sessions WHERE id=? AND user_id=?", &[json!(&sid), json!(&uid)]).await.map_err(|e| bad(&e))?;
    let was_current = db::s(&row, "token_hash") == current;
    st.audit("", "", "", &uid, "auth.session_revoked", &sid).await;
    Ok(j(json!({"revoked": sid, "current": was_current}))) }
async fn revoke_all_sessions(State(st): State<S>, h: HeaderMap) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let uid = st.token_user(&h).await?;
    let token = bearer_token_or_cookie(&h);
    if st.db.one("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=?", &[json!(oc::hash_token(&token)), json!(&uid)]).await.map_err(|e| bad(&e))?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "sign in to the console to end browser sessions; API keys and OAuth tokens cannot do this")); }
    let n = st.db.exec("DELETE FROM sessions WHERE user_id=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?;
    st.audit("", "", "", &uid, "auth.sessions_revoked", &format!("{n} session(s)")).await;
    let mut headers=HeaderMap::new();
    headers.insert(axum::http::header::SET_COOKIE, session_cookie("").replace("Max-Age=604800", "Max-Age=0").parse().unwrap());
    Ok((headers, j(json!({"ok": true, "revoked": n})))) }
// Ownership grants and account deletion serialize on the same user rows.
async fn user_guarded_batch(st: &S, users: &[&str], statements: &[(String, Vec<Value>)], require_one: &[usize]) -> Result<(), (StatusCode, Json<Value>)> {
    user_guarded_commit(st, users, statements, require_one, None).await
}
async fn user_guarded_commit(st: &S, users: &[&str], statements: &[(String, Vec<Value>)], require_one: &[usize], audit: Option<[&str;6]>) -> Result<(), (StatusCode, Json<Value>)> {
    let mut users = users.to_vec(); users.sort_unstable(); users.dedup();
    let mut batch: Vec<(String, Vec<Value>)> = users.iter().map(|uid| ("UPDATE users SET active=active WHERE id=?".into(), vec![json!(uid)])).collect();
    let mut checked: Vec<usize> = (0..batch.len()).collect();
    checked.extend(require_one.iter().map(|index| batch.len() + index));
    batch.extend_from_slice(statements);
    let result=if let Some(fields)=audit { st.audited_batch(&batch,&checked,fields).await } else { st.db.batch_checked(&batch,&checked).await };
    result.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "account or ownership changed; refresh and try again") } else { bad(&e) })
}
#[cfg(any(feature = "scim", feature = "saml", feature = "ldap"))]
async fn add_provisioned_member(st: &S, org: &str, uid: &str, role: &str) -> Result<(), (StatusCode, Json<Value>)> {
    user_guarded_batch(st, &[uid], &[
        ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(uid)]),
        ("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)".into(), vec![json!(org), json!(uid), json!(role)]),
    ], &[0, 1]).await
}
// Account destruction requires the same session credential used to authenticate.
async fn delete_me(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res {
    let uid = st.token_user(&h).await?;
    let bearer = bearer_token(&h); let token = if bearer.is_empty() { cookie_val(&h, "ow_session") } else { bearer };
    if st.db.one("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=?", &[json!(oc::hash_token(&token)), json!(&uid)]).await.map_err(|e| bad(&e))?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "sign in to the console to delete your account; API keys and OAuth tokens cannot delete an account")); }
    let owned = st.db.query("SELECT o.id AS id,o.name AS name FROM org_members m JOIN orgs o ON o.id=m.org_id WHERE m.user_id=? AND m.role='owner' ORDER BY o.name", &[json!(&uid)]).await.map_err(|e| bad(&e))?;
    if !owned.is_empty() { return Err((StatusCode::CONFLICT, Json(json!({"error":"transfer ownership of every workspace you own before deleting your account", "workspaces": owned.iter().map(db::obj).collect::<Vec<_>>()})))); }
    let owns_instance = instance_owner(&st).await.as_deref() == Some(uid.as_str());
    if owns_instance {
        let others = st.db.one("SELECT COUNT(*) AS n FROM users WHERE id<>? AND active=1 AND email_verified=1", &[json!(&uid)]).await.map_err(|e| bad(&e))?.map(|r| db::n(&r,"n")).unwrap_or(0);
        if others > 0 { return Err((StatusCode::CONFLICT, Json(json!({"error":"this account owns the instance; transfer instance ownership before deleting it"})))); }
    }
    let api_keys = st.db.one("SELECT COUNT(*) AS n FROM tokens WHERE created_by=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?.map(|r| db::n(&r,"n")).unwrap_or(0);
    let oauth_sessions = st.db.one("SELECT COUNT(DISTINCT pair_id) AS n FROM oauth_tokens WHERE user_id=? AND kind='access' AND expires_at>?", &[json!(&uid), json!(now())]).await.map_err(|e| bad(&e))?.map(|r| db::n(&r,"n")).unwrap_or(0);
    let confirm = q.get("confirm").map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes")).unwrap_or(false);
    if (api_keys > 0 || oauth_sessions > 0) && !confirm { return Err((StatusCode::CONFLICT, Json(json!({
        "error":format!("deleting this account revokes {} API key(s) and {} CLI/OAuth session(s) immediately", api_keys, oauth_sessions),
        "confirmation_required":true, "api_keys":api_keys, "oauth_sessions":oauth_sessions, "hint":"repeat with ?confirm=true to delete anyway"})))); }
    #[cfg(not(target_arch = "wasm32"))]
    let _credential_guard = st.secret_health_credentials.lock().await;
    let mut stmts: Vec<(String, Vec<Value>)> = vec![
        ("UPDATE users SET active=active WHERE id=? AND NOT EXISTS (SELECT 1 FROM org_members WHERE user_id=? AND role='owner')".into(), vec![json!(&uid), json!(&uid)]),
        ("UPDATE meta SET v=v WHERE k='instance_owner' AND (v<>? OR NOT EXISTS (SELECT 1 FROM users WHERE id<>? AND active=1 AND email_verified=1))".into(), vec![json!(&uid), json!(&uid)]),
    ];
    stmts.extend([
        "DELETE FROM sessions WHERE user_id=?", "DELETE FROM oauth_tokens WHERE user_id=?",
        "DELETE FROM oauth_codes WHERE user_id=?", "DELETE FROM auth_tokens WHERE user_id=?",
        "DELETE FROM mfa_challenges WHERE user_id=?", "DELETE FROM auth_challenges WHERE user_id=?",
        "DELETE FROM step_up_challenges WHERE user_id=?", "DELETE FROM step_up_grants WHERE user_id=?",
        "DELETE FROM passkeys WHERE user_id=?", "DELETE FROM passkey_registrations WHERE user_id=?",
        "DELETE FROM mfa_passkey_states WHERE user_id=?", "DELETE FROM email_codes WHERE user_id=?",
        "DELETE FROM tokens WHERE created_by=?", "DELETE FROM wrap_tokens WHERE created_by=?", "UPDATE ssh_certs SET revoked=1 WHERE actor=?",
        "DELETE FROM env_keys WHERE user_id=?",
        "DELETE FROM overrides WHERE user_id=?", "DELETE FROM org_members WHERE user_id=?",
        "DELETE FROM team_members WHERE user_id=?", "DELETE FROM app_members WHERE user_id=?",
        "DELETE FROM env_members WHERE user_id=?", "DELETE FROM oidc_subjects WHERE user_id=?",
        "DELETE FROM social_subjects WHERE user_id=?", "DELETE FROM identity_bindings WHERE user_id=?",
        "DELETE FROM saml_subjects WHERE user_id=?", "DELETE FROM ldap_subjects WHERE user_id=?",
    ].iter().map(|sql| (sql.to_string(), vec![json!(&uid)])));
    for key in ["totp_enabled", "totp_secret", "totp_pending", "totp_recovery", "totp_last", "email_mfa_enabled", "password_known", "hibp_api_key", "enzoic_credentials"] {
        stmts.push(("DELETE FROM meta WHERE k=?".into(), vec![json!(format!("{}:{}", key, uid))])); }
    stmts.push(("DELETE FROM meta WHERE k='instance_owner' AND v=?".into(), vec![json!(&uid)]));
    stmts.push(("DELETE FROM users WHERE id=?".into(), vec![json!(&uid)]));
    user_guarded_commit(&st, &[&uid], &stmts, &[0, 1, stmts.len()-1], Some(["","","",&uid,"account.delete",&format!("revoked {} key(s), {} oauth session(s)",api_keys,oauth_sessions)])).await?;
    Ok(j(json!({"deleted":true, "revoked_api_keys":api_keys, "revoked_oauth_sessions":oauth_sessions}))) }
async fn list_orgs(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h).await?;
    let human = emergency_session(&st, &h).await.is_ok();
    let rows = st.db.query("SELECT o.id,o.name,o.ip_allowlist,m.role,(SELECT COUNT(*) FROM org_members om WHERE om.org_id=o.id) AS members FROM orgs o JOIN org_members m ON m.org_id=o.id WHERE m.user_id=? AND (?=1 OR o.emergency_locked=0)", &[json!(uid), json!(if human { 1 } else { 0 })]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_org(State(st): State<S>, h: HeaderMap, Json(r): Json<NameReq>) -> Res { let uid = workspaces::human(&st,&h).await?; let oid = id();
    if r.name.trim().is_empty() { return Err(bad("workspace name required")); }
    if !workspaces::creation_open(&st).await? { return Err(err(StatusCode::FORBIDDEN,"workspace creation is disabled; accept an invitation instead")); }
    let mut stmts = vec![workspaces::policy_lock()];
    if crate::envcfg::var("OPENWARP_WORKSPACE_CREATION").is_err() { stmts.push(workspaces::creation_guard()); }
    let mut checked: Vec<usize> = (0..stmts.len()).collect(); let offset = stmts.len();
    stmts.extend([
        ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(&uid)]),
        ("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)".into(), vec![json!(&oid), json!(r.name), json!(now())]),
        ("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')".into(), vec![json!(&oid), json!(&uid)]),
    ]); checked.extend([offset,offset+2]);
    user_guarded_batch(&st, &[&uid], &stmts, &checked).await?; Ok(j(json!({"id": oid}))) }
async fn update_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid, &uid).await?;
    if r.name.trim().is_empty() { return Err(bad("organisation name required")); }
    st.audited_batch(&[("UPDATE orgs SET name=? WHERE id=?".into(), vec![json!(r.name.trim()),json!(&oid)])], &[0], [&oid,"","",&uid,"org.rename",r.name.trim()]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn delete_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?;
    if st.require_org(&oid, &uid).await? != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can delete a workspace")); }
    let confirm = q.get("confirm").map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes")).unwrap_or(false);
    let name = st.db.one("SELECT name FROM orgs WHERE id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"name")).unwrap_or_default();
    if !confirm { return Err((StatusCode::CONFLICT, Json(json!({"error":format!("deleting {} removes every app, environment, secret, token and identity in it", name), "confirmation_required":true, "hint":"repeat with ?confirm=true to delete the workspace"})))); }
    let envs = "SELECT e.id FROM envs e JOIN apps a ON a.id=e.app_id WHERE a.org_id=?";
    let apps = "SELECT id FROM apps WHERE org_id=?";
    let teams = "SELECT id FROM teams WHERE org_id=?";
    let cas = "SELECT id FROM pki_cas WHERE org_id=?";
    let streams = "SELECT id FROM log_streams WHERE org_id=?";
    let integrations = "SELECT i.id FROM integrations i JOIN envs e ON e.id=i.env_id JOIN apps a ON a.id=e.app_id WHERE a.org_id=?";
    let statements = vec![
        "DELETE FROM tokens WHERE org_id=?".to_string(),
        "DELETE FROM tokens WHERE created_by IN (SELECT id FROM identities WHERE org_id=?)".to_string(),
        "DELETE FROM identity_credentials WHERE identity_id IN (SELECT id FROM identities WHERE org_id=?)".to_string(),
        format!("DELETE FROM tokens WHERE app_id IN ({})", apps),
        format!("DELETE FROM tokens WHERE env_id IN ({})", envs),
        format!("DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN ({}))", envs),
        format!("DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN ({}))", envs),
        format!("DELETE FROM wrap_tokens WHERE env_id IN ({})", envs),
        format!("DELETE FROM env_keys WHERE env_id IN ({})", envs),
        format!("DELETE FROM runner_env_keys WHERE env_id IN ({})", envs),
        "DELETE FROM runner_env_keys WHERE runner_id IN (SELECT id FROM runners WHERE org_id=?)".to_string(),
        format!("DELETE FROM sync_jobs WHERE env_id IN ({})", envs),
        format!("DELETE FROM sync_jobs WHERE integration_id IN ({})", integrations),
        "DELETE FROM sync_jobs WHERE runner_id IN (SELECT id FROM runners WHERE org_id=?)".to_string(),
        "DELETE FROM runners WHERE org_id=?".to_string(),
        format!("DELETE FROM leases WHERE env_id IN ({})", envs),
        format!("DELETE FROM integration_sync_state WHERE integration_id IN ({})", integrations),
        format!("DELETE FROM integrations WHERE env_id IN ({})", envs),
        format!("DELETE FROM proposals WHERE env_id IN ({})", envs),
        format!("DELETE FROM access_requests WHERE env_id IN ({})", envs),
        format!("DELETE FROM rotation_schedules WHERE env_id IN ({})", envs),
        format!("DELETE FROM env_members WHERE env_id IN ({})", envs),
        format!("DELETE FROM team_env_grants WHERE env_id IN ({})", envs),
        // AI folders are environment descendants; drop them before the envs
        // they reference so teardown stays inside the guarded transaction.
        format!("DELETE FROM folders WHERE env_id IN ({})", envs),
        format!("DELETE FROM secrets WHERE env_id IN ({})", envs),
        format!("DELETE FROM envs WHERE app_id IN ({})", apps),
        format!("DELETE FROM app_members WHERE app_id IN ({})", apps),
        "DELETE FROM apps WHERE org_id=?".to_string(),
        format!("DELETE FROM team_env_grants WHERE team_id IN ({})", teams),
        format!("DELETE FROM team_members WHERE team_id IN ({})", teams),
        "DELETE FROM teams WHERE org_id=?".to_string(),
        "DELETE FROM roles WHERE org_id=?".to_string(),
        format!("DELETE FROM log_deliveries WHERE stream_id IN ({})", streams),
        "DELETE FROM log_streams WHERE org_id=?".to_string(),
        format!("DELETE FROM pki_certs WHERE ca_id IN ({})", cas),
        format!("DELETE FROM ssh_certs WHERE ca_id IN ({})", cas),
        format!("DELETE FROM ssh_principal_grants WHERE ca_id IN ({})", cas),
        format!("DELETE FROM ssh_hosts WHERE ca_id IN ({})", cas),
        "DELETE FROM pki_cas WHERE org_id=?".to_string(),
        "DELETE FROM saml_configs WHERE org_id=?".to_string(),
        "DELETE FROM saml_pending WHERE org_id=?".to_string(),
        "DELETE FROM saml_subjects WHERE org_id=?".to_string(),
        "DELETE FROM ldap_configs WHERE org_id=?".to_string(),
        "DELETE FROM ldap_subjects WHERE org_id=?".to_string(),
        "DELETE FROM oidc_states WHERE org_id=?".to_string(),
        "DELETE FROM rotation_hooks WHERE org_id=?".to_string(),
        "DELETE FROM invites WHERE org_id=?".to_string(),
        "DELETE FROM workload_bindings WHERE org_id=?".to_string(),
        "DELETE FROM compat_transit_versions WHERE key_id IN (SELECT id FROM compat_transit_keys WHERE org_id=?)".to_string(),
        "DELETE FROM compat_transit_keys WHERE org_id=?".to_string(),
        "DELETE FROM transit_versions WHERE key_id IN (SELECT id FROM transit_keys WHERE org_id=?)".to_string(),
        "DELETE FROM transit_keys WHERE org_id=?".to_string(),
        format!("DELETE FROM path_policies WHERE env_id IN ({})", envs),
        "DELETE FROM identities WHERE org_id=?".to_string(),
        "DELETE FROM audit WHERE org_id=?".to_string(),
        "DELETE FROM live_events WHERE org_id=?".to_string(),
        // AI records hold the wrapped BYOK provider key, plans, drafts and
        // finding state for this org only; nothing may outlive the workspace.
        "DELETE FROM ai_settings WHERE org_id=?".to_string(),
        "DELETE FROM ai_plans WHERE org_id=?".to_string(),
        "DELETE FROM ai_activity WHERE org_id=?".to_string(),
        "DELETE FROM ai_finding_states WHERE org_id=?".to_string(),
        "DELETE FROM ai_finding_history WHERE org_id=?".to_string(),
        "DELETE FROM ai_usage WHERE org_id=?".to_string(),
        "DELETE FROM integration_drafts WHERE org_id=?".to_string(),
        "DELETE FROM org_members WHERE org_id=?".to_string(),
        "DELETE FROM orgs WHERE id=?".to_string(),
    ];
    let metadata_envs = st.db.query(envs, &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    // Rotation claims and lease reservations share their locks with teardown.
    let mut stmts = vec![
        ("UPDATE meta SET v=v WHERE k='rotation_lifecycle'".into(), vec![]),
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&oid)]),
        (format!("UPDATE orgs SET name=name WHERE id=? AND NOT EXISTS (SELECT 1 FROM leases WHERE env_id IN ({}) AND revoked<>1) AND NOT EXISTS (SELECT 1 FROM rotation_schedules WHERE env_id IN ({}) AND (pending_enc<>'' OR execution_token<>''))", envs, envs), vec![json!(&oid), json!(&oid), json!(&oid)]),
        ("UPDATE org_members SET role=role WHERE org_id=? AND user_id=? AND role='owner'".into(), vec![json!(&oid), json!(&uid)]),
    ];
    for row in metadata_envs { stmts.push(("DELETE FROM meta WHERE k=?".into(), vec![json!(format!("rekey_required:{}", db::s(&row, "id")))])); }
    stmts.extend(statements.into_iter().map(|sql| (sql, vec![json!(&oid)])));
    for key in ["oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_redirect_uri", "oidc_auto_provision", "oidc_allowed_domains", "audit_webhook"] {
        stmts.push(("DELETE FROM meta WHERE k=?".into(), vec![json!(format!("{}:{}", key, oid))])); }
    stmts.push(("DELETE FROM meta WHERE k=?".into(), vec![json!(format!("ai:background:{}", oid))]));
    let mut guarded = vec![workspaces::policy_lock()];
    let guard = if crate::envcfg::var("OPENWARP_WORKSPACE_CREATION").is_ok() {
        if workspaces::creation_open(&st).await? { "UPDATE meta SET v=v WHERE k='workspace_policy_lock'" } else { "UPDATE meta SET v=v WHERE k='workspace_policy_lock' AND (SELECT COUNT(*) FROM orgs)>1" }
    } else { "UPDATE meta SET v=v WHERE k='workspace_creation_open' AND (v<>'0' OR (SELECT COUNT(*) FROM orgs)>1)" };
    guarded.push((guard.into(),vec![])); guarded.extend(stmts);
    user_guarded_commit(&st, &[&uid], &guarded, &[0, 1, 2, 3, 4, 5], Some(["","","",&uid,"org.delete",&format!("{} ({})",name,oid)])).await.map_err(|e| if e.0 == StatusCode::CONFLICT { err(StatusCode::CONFLICT, "workspace ownership changed, has unresolved leases or rotations, or is the last workspace while creation is disabled; refresh, reconcile, or enable creation first") } else { e })?;
    Ok(j(json!({"deleted":true, "workspace":name}))) }
async fn leave_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let role = st.require_org(&oid, &uid).await?;
    if role == "owner" {
        let owners = st.db.query("SELECT user_id FROM org_members WHERE org_id=? AND role='owner'", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
        if owners.len() <= 1 { return Err(err(StatusCode::CONFLICT, "transfer ownership before leaving; an organisation needs an owner")); }
    }
    st.audited_batch(&[
        ("DELETE FROM org_members WHERE org_id=? AND user_id=?".into(),vec![json!(&oid),json!(&uid)]),
        ("DELETE FROM team_members WHERE user_id=? AND team_id IN (SELECT id FROM teams WHERE org_id=?)".into(),vec![json!(&uid),json!(&oid)]),
    ], &[], [&oid,"","",&uid,"org.leave",""]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn transfer_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    if st.require_org(&oid, &uid).await? != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can transfer ownership")); }
    let target = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    if target.is_empty() || target == uid { return Err(bad("user_id of another member required")); }
    let member = st.db.one("SELECT u.active AS active,u.email_verified AS email_verified FROM org_members m JOIN users u ON u.id=m.user_id WHERE m.org_id=? AND m.user_id=?", &[json!(&oid), json!(target)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "member not found"))?;
    if db::n(&member,"active") == 0 || db::n(&member,"email_verified") == 0 { return Err(err(StatusCode::CONFLICT, "the new owner needs an active, verified account")); }
    user_guarded_commit(&st, &[&uid, target], &[
        ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(target)]),
        ("UPDATE org_members SET role=role WHERE org_id=? AND user_id=? AND role='owner'".into(), vec![json!(&oid), json!(&uid)]),
        ("UPDATE org_members SET role='owner' WHERE org_id=? AND user_id=?".into(), vec![json!(&oid), json!(target)]),
        ("UPDATE org_members SET role='admin' WHERE org_id=? AND user_id=? AND role='owner'".into(), vec![json!(&oid), json!(&uid)]),
    ], &[0, 1, 2, 3], Some([&oid,"","",&uid,"org.transfer",target])).await?; Ok(j(json!({"ok":true, "owner":target, "previous_owner_role":"admin"}))) }
async fn update_member_role(State(st): State<S>, h: HeaderMap, Path((oid, target)): Path<(String, String)>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid, &uid).await?;
    let caller_role = st.require_org(&oid, &uid).await?;
    let target_role = st.org_role(&oid, &target).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "member not found"))?;
    let new_role = r.role.trim();
    if new_role.is_empty() { return Err(bad("role required")); }
    if !["owner", "admin", "developer"].contains(&new_role) && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(&oid), json!(new_role)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    if st.role_privileged(&oid, new_role).await && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can grant a role with admin rights")); }
    if target_role == "owner" && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can change another owner")); }
    if target_role == "owner" && new_role != "owner" {
        let owners = st.db.query("SELECT user_id FROM org_members WHERE org_id=? AND role='owner'", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
        if owners.len() <= 1 { return Err(err(StatusCode::CONFLICT, "an organisation needs at least one owner")); }
    }
    let audit: [&str;6] = [&oid, "", "", &uid, "member.role", &format!("{}={}", target, new_role)];
    if new_role == "owner" {
        user_guarded_commit(&st, &[&uid, &target], &[
            ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(&target)]),
            ("UPDATE org_members SET role=role WHERE org_id=? AND user_id=? AND role='owner'".into(), vec![json!(&oid), json!(&uid)]),
            ("UPDATE org_members SET role='owner' WHERE org_id=? AND user_id=?".into(), vec![json!(&oid), json!(&target)]),
        ], &[0, 1, 2], Some(audit)).await?;
    } else {
        st.audited_batch(&[("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?".into(), vec![json!(new_role), json!(&oid), json!(&target)])], &[], audit).await.map_err(|e| bad(&e))?;
    }
    Ok(j(json!({"ok": true}))) }
async fn invite_member(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?;
    let caller_role = st.require_org(&oid, &uid).await?; st.check_admin(&oid, &uid).await?;
    let email = r.email.trim().to_lowercase();
    if email.is_empty() { return Err(bad("email required")); }
    let new_role = if r.role.trim().is_empty() { "developer".to_string() } else { r.role.trim().to_string() };
    if new_role != "owner" && new_role != "admin" && new_role != "developer" && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(&oid), json!(&new_role)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    // Existence first: role permissions cannot change after creation, so the
    // privilege read cannot race a role being created between the two checks.
    if st.role_privileged(&oid, &new_role).await && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can grant a role with admin rights")); }
    if let Some(target) = st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).await.map_err(|e| bad(&e))? {
        if st.org_role(&oid,&db::s(&target,"id")).await.is_some() { return Err(err(StatusCode::CONFLICT,"user is already a member")); }
    }
    if !valid_email(&email) { return Err(bad("email required")); }
    // The invitee redeems a single-use link with a password, a v2 key, or a
    // configured provider; issuing it never adds membership by itself.
    let token = oc::random_token("inv"); let expires = now()+7*86400; let iid = id();
    st.db.batch(&[
        ("DELETE FROM invites WHERE email=? AND org_id=? AND accepted=0".into(),vec![json!(&email),json!(&oid)]),
        ("INSERT INTO invites(id,token_hash,email,org_id,role,invited_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)".into(),vec![json!(&iid),json!(oc::hash_token(&token)),json!(&email),json!(&oid),json!(&new_role),json!(&uid),json!(now()),json!(expires)]),
    ]).await.map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"member.invite",&email).await;
    Ok(j(workspaces::share(&st,&iid,&token,expires))) }

#[derive(Deserialize)] struct InviteReq { token: String, #[serde(default)] password: String }
async fn accept_invite(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Json(r): Json<InviteReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let row = workspaces::valid_invite(&st,&r.token,&h,addr).await?;
    if let Some(out) = workspaces::existing(&st,&row,&r.token,&h).await? { return Ok(out); }
    if !auth_enabled(&st,"password").await { return Err(err(StatusCode::FORBIDDEN,"password sign-in is disabled; sign in with a configured provider to join")); }
    if r.password.len()<8 { return Err(bad("password (>=8 chars) required")); }
    let email = db::s(&row,"email"); let org = db::s(&row,"org_id"); let role = db::s(&row,"role");
    st.require_running(&org).await?;
    // The consent path above already handled an existing matching account; a
    // row here means nobody matching is signed in, so refuse instead of
    // colliding with the users.email unique index.
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).await.map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in instead")); }
    let kp = oc::Keypair::generate(); let uid = id();
    let pass_hash = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    let wrapped = oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    // The invite token reached this address, which is the proof a password
    // signup would otherwise obtain by email.
    workspaces::invite_batch(&st,&row,&[],&[
        workspaces::consume(&st,&row,&r.token).await?,
        ("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)".into(),vec![json!(&uid),json!(&email),json!(pass_hash),json!(kp.public),json!(wrapped),json!(now())]),
        ("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)".into(),vec![json!(&org),json!(&uid),json!(&role)]),
    ],&[0,1,2]).await?;
    st.audit(&org, "", "", &uid, "member.accept_invite", &email).await;
    claim_instance_owner(&st, &uid).await;
    let token = make_session(&st, &uid).await?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "org_id": org, "role": role})))) }
async fn create_app(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid, &uid).await?; st.check_perm(&oid, &uid, "secrets:write").await?; let master = st.master();
    let aid = id(); let mut stmts = vec![
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&oid)]),
        ("INSERT INTO apps(id,org_id,name,readme,created_at) VALUES(?,?,?,?,?)".into(), vec![json!(&aid), json!(&oid), json!(&r.name), json!(&r.readme), json!(now())]),
    ];
    for name in ["Development", "Staging", "Production"] { stmts.push(env_insert(&st, &id(), &aid, name).await?); }
    st.audited_batch_master(&stmts, &[0], [&oid,&aid,"",&uid,"app.create",&r.name], master).await.map_err(master_write_error)?; Ok(j(json!({"id": aid}))) }
async fn env_insert(st: &S, eid: &str, app_id: &str, name: &str) -> Result<(String, Vec<Value>), (StatusCode, Json<Value>)> {
    let key = oc::random_key();
    let wrapped = match st.kms() {
        Some(kms) => kms.wrap(&key, &format!("env:{}", eid)).await.map_err(|e| bad(&format!("KMS could not wrap the environment key: {}", e)))?,
        None => oc::encrypt_symmetric(&st.master(), &key),
    };
    Ok(("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)".into(), vec![json!(eid), json!(app_id), json!(name), json!(wrapped), json!(now())])) }
#[cfg(test)]
async fn create_env_batch(st: &S, org: &str, aid: &str, inserts: &[(String, Vec<Value>)]) -> Result<(), (StatusCode, Json<Value>)> {
    let mut stmts = vec![
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(org)]),
        ("UPDATE apps SET name=name WHERE id=? AND org_id=?".into(), vec![json!(aid), json!(org)]),
    ];
    stmts.extend_from_slice(inserts);
    st.db.batch_checked(&stmts, &[0, 1]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "workspace or application was deleted before environment creation") } else { bad(&e) })
}
async fn list_apps(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid, &uid).await?;
    let human = emergency_session(&st, &h).await.is_ok();
    let rows = st.db.query("SELECT id,org_id,name,readme,created_at,reuse_check FROM apps WHERE org_id=? AND (?=1 OR emergency_locked=0)", &[json!(oid), json!(if human { 1 } else { 0 })]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(|r| json!({"id": db::s(r,"id"), "org_id": db::s(r,"org_id"), "name": db::s(r,"name"), "readme": db::s(r,"readme"), "created_at": db::n(r,"created_at"), "reuse_check": db::n(r,"reuse_check") != 0})).collect::<Vec<_>>()))) }
async fn create_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    if !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || r.name.is_empty() || r.name.len() > 32 { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    if r.mode == "delegated" {
        if r.runner_id.is_empty() || r.wrapped_key.is_empty() || r.runner_wrapped_key.is_empty() {
            return Err(bad("delegated environments need runner_id, wrapped_key and runner_wrapped_key")); }
        if st.db.one("SELECT id FROM runners WHERE id=? AND org_id=?", &[json!(&r.runner_id), json!(&org)]).await.map_err(|e| bad(&e))?.is_none() {
            return Err(bad("runner not found in this organisation")); }
        let eid = id();
        st.audited_batch(&[
            ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&org)]),
            ("UPDATE apps SET name=name WHERE id=? AND org_id=?".into(), vec![json!(&aid), json!(&org)]),
            ("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,runner_id,created_at) VALUES(?,?,?,'','delegated',?,?)".into(), vec![json!(&eid), json!(&aid), json!(&r.name), json!(&r.runner_id), json!(now())]),
            ("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)".into(), vec![json!(&eid), json!(&uid), json!(&r.wrapped_key)]),
            ("INSERT INTO runner_env_keys(runner_id,env_id,wrapped_key) VALUES(?,?,?)".into(), vec![json!(&r.runner_id), json!(&eid), json!(&r.runner_wrapped_key)]),
        ], &[0,1], [&org, &aid, &eid, &uid, "env.create.delegated", &r.runner_id]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "workspace or application was deleted before environment creation") } else { bad(&e) })?;
        return Ok(j(json!({"id": eid, "mode": "delegated", "runner_id": r.runner_id}))); }
    let eid = id(); let master = st.master(); st.audited_batch_master(&[
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&org)]),
        ("UPDATE apps SET name=name WHERE id=? AND org_id=?".into(), vec![json!(&aid), json!(&org)]),
        env_insert(&st, &eid, &aid, &r.name).await?,
    ], &[0,1], [&org,&aid,&eid,&uid,"env.create",&r.name], master).await.map_err(|e| if e==webhooks::EPOCH_STALE {webhooks::epoch_stale()} else if e.contains("version conflict") { err(StatusCode::CONFLICT, "workspace or application was deleted before environment creation") } else { bad(&e) })?; Ok(j(json!({"id": eid}))) }
async fn list_envs(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"), &uid).await?;
    let rows = st.db.query("SELECT id,app_id,name,mode,runner_id,restricted,require_approval,created_at FROM envs WHERE app_id=? ORDER BY created_at", &[json!(aid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let (org, app) = st.require_env(&eid, &uid).await?;
    st.check_admin(&org, &uid).await?;
    let mut stmts = vec![
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&org)]),
        ("UPDATE envs SET name=name WHERE id=? AND app_id=? AND NOT EXISTS (SELECT 1 FROM leases WHERE env_id=? AND revoked<>1)".into(), vec![json!(&eid), json!(&app), json!(&eid)]),
    ];
    for sql in [
        "DELETE FROM wrap_tokens WHERE env_id=?",
        "DELETE FROM tokens WHERE env_id=?",
        "DELETE FROM team_env_grants WHERE env_id=?",
        "DELETE FROM folders WHERE env_id=?",
        "DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id=?)",
        "DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id=?)",
        "DELETE FROM secrets WHERE env_id=?",
        "DELETE FROM env_keys WHERE env_id=?",
        "DELETE FROM runner_env_keys WHERE env_id=?",
        "DELETE FROM sync_jobs WHERE env_id=?",
        "DELETE FROM leases WHERE env_id=?",
        "DELETE FROM integration_sync_state WHERE integration_id IN (SELECT id FROM integrations WHERE env_id=?)",
        "DELETE FROM integrations WHERE env_id=?",
        "DELETE FROM proposals WHERE env_id=?",
        "DELETE FROM access_requests WHERE env_id=?",
        "DELETE FROM rotation_schedules WHERE env_id=?",
        "DELETE FROM env_members WHERE env_id=?",
        "DELETE FROM path_policies WHERE env_id=?",
        "DELETE FROM envs WHERE id=?",
    ] { stmts.push((sql.into(), vec![json!(&eid)])); }
    stmts.push(("DELETE FROM meta WHERE k=?".into(), vec![json!(format!("rekey_required:{}", eid))]));
    st.audited_rotation_batch(&stmts, &[0,1], [&org,&app,&eid,&uid,"env.delete",""],None,"SELECT id FROM rotation_schedules WHERE env_id=? AND (pending_enc<>'' OR execution_token<>'')",&[json!(&eid)]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "environment changed or has unresolved leases; revoke every lease before deleting it") } else { bad(&e) })?; Ok(j(json!({"ok": true}))) }
async fn set_env_policy(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_admin(&org, &uid).await?;
    let mut changed = Vec::new();
    for field in ["restricted", "require_approval"] {
        if let Some(v) = body.get(field).and_then(|v| v.as_bool()) {
            statements.push((format!("UPDATE envs SET {}=? WHERE id=?", field).to_string(), ([json!(if v { 1 } else { 0 }), json!(&eid)]).to_vec()));
            changed.push(format!("{}={}", field, v)); } }
    if let Some(v) = body.get("max_versions").and_then(|v| v.as_i64()) {
        if !(0..=1000).contains(&v) { return Err(bad("max_versions must be between 0 and 1000")); }
        statements.push((("UPDATE envs SET max_versions=? WHERE id=?").to_string(), ([json!(v), json!(&eid)]).to_vec()));
        changed.push(format!("max_versions={}", v)); }
    if changed.is_empty() { return Err(bad("restricted, require_approval or max_versions required")); }
    st.audited_batch(&statements, &[], [&org, &app, &eid, &uid, "env.policy", &changed.join(",")]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"ok": true, "policy": changed}))) }
async fn list_members(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid, &uid).await?;
    let rows = st.db.query("SELECT u.id AS id, u.email AS email, u.created_at AS created_at, m.role AS role FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? ORDER BY m.role, u.email", &[json!(oid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn remove_member(State(st): State<S>, h: HeaderMap, Path((oid, target)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?;
    let role = st.require_org(&oid, &uid).await?; st.check_admin(&oid, &uid).await?;
    if target == uid { return Err(bad("use another admin to remove yourself; leaving your own organisation is not supported")); }
    let target_role = st.org_role(&oid, &target).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "member not found"))?;
    if target_role == "owner" && role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can remove an owner")); }
    st.audited_batch(&[("DELETE FROM org_members WHERE org_id=? AND user_id=? AND (role<>'owner' OR (SELECT COUNT(*) FROM org_members WHERE org_id=? AND role='owner')>1)".into(), vec![json!(oid), json!(target), json!(oid)])], &[0], [&oid, "", "", &uid, "member.remove", &target]).await.map_err(|e| if e.contains("version conflict") {bad("cannot remove the last owner")} else {bad(&e)})?;
    Ok(j(json!({"ok": true}))) }
async fn update_app(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app, "org_id"); st.check_admin(&org, &uid).await?;
    let name = body.get("name").and_then(|v| v.as_str()).map(str::trim).unwrap_or("");
    let readme = body.get("readme").and_then(|v| v.as_str());
    if name.is_empty() && readme.is_none() { return Err(bad("name or readme required")); }
    if !name.is_empty() {
        st.audited_batch(&[("UPDATE apps SET name=? WHERE id=?".into(), vec![json!(name), json!(aid)])], &[], [&org, &aid, "", &uid, "app.rename", name]).await.map_err(|e|bad(&e))?; }
    if let Some(readme) = readme {
        st.audited_batch(&[("UPDATE apps SET readme=? WHERE id=?".into(), vec![json!(readme), json!(aid)])], &[], [&org, &aid, "", &uid, "app.readme", &format!("{} bytes", readme.len())]).await.map_err(|e|bad(&e))?; }
    Ok(j(json!({"ok": true}))) }
async fn get_app_settings(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT org_id,reuse_check FROM apps WHERE id=?", &[json!(&aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    st.require_org(&db::s(&row,"org_id"), &uid).await?;
    Ok(j(json!({"reuse_check": db::n(&row,"reuse_check") != 0}))) }
async fn put_app_settings(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let row = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(&aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&row,"org_id"); st.check_admin(&org, &uid).await?;
    let value = body.get("reuse_check").and_then(|v| v.as_bool()).ok_or_else(|| bad("reuse_check (boolean) required"))?;
    statements.push((("UPDATE apps SET reuse_check=? WHERE id=?").to_string(), ([json!(if value {1} else {0}), json!(&aid)]).to_vec()));
    st.audited_batch(&statements, &[], [&org, &aid, "", &uid, "app.settings", &format!("reuse_check={}", value)]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"ok": true}))) }
async fn delete_app(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app, "org_id"); st.check_admin(&org, &uid).await?;
    let mut stmts = vec![
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&org)]),
        ("UPDATE apps SET name=name WHERE id=? AND org_id=? AND NOT EXISTS (SELECT 1 FROM leases WHERE env_id IN (SELECT id FROM envs WHERE app_id=?) AND revoked<>1)".into(), vec![json!(&aid), json!(&org), json!(&aid)]),
    ];
    for sql in [
        "DELETE FROM wrap_tokens WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM tokens WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM team_env_grants WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM folders WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM env_keys WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM runner_env_keys WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM sync_jobs WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM leases WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM integration_sync_state WHERE integration_id IN (SELECT id FROM integrations WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM integrations WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM proposals WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM access_requests WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM rotation_schedules WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM env_members WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM path_policies WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM envs WHERE app_id=?",
        "DELETE FROM app_members WHERE app_id=?",
        "DELETE FROM tokens WHERE app_id=?",
        "DELETE FROM apps WHERE id=?",
    ] { stmts.push((sql.into(), vec![json!(&aid)])); }
    st.audited_rotation_batch(&stmts, &[0,1], [&org,&aid,"",&uid,"app.delete",""],None,"SELECT id FROM rotation_schedules WHERE env_id IN (SELECT id FROM envs WHERE app_id=?) AND (pending_enc<>'' OR execution_token<>'')",&[json!(&aid)]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "application changed or has unresolved leases; revoke every lease before deleting it") } else { bad(&e) })?; Ok(j(json!({"ok": true}))) }
async fn update_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    if r.name.is_empty() || r.name.len() > 32 || !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    statements.push((("UPDATE envs SET name=? WHERE id=?").to_string(), ([json!(r.name), json!(eid)]).to_vec()));
    st.audited_batch(&statements, &[], [&org, &app, &eid, &uid, "env.rename", &r.name]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn clone_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let target = body.get("target_env_id").and_then(|v| v.as_str()).unwrap_or("");
    if target.is_empty() || target == eid { return Err(bad("target_env_id of another environment required")); }
    let (torg, tapp) = st.require_env(target, &uid).await?; st.check_perm(&torg, &uid, "secrets:write").await?;
    if torg != org || tapp != app { return Err(bad("source and target must belong to the same app")); }
    let overwrite = body.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
    for id in [eid.as_str(), target] { let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(id)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"mode")).unwrap_or_default(); if mode == "e2e" || mode == "delegated" { return Err(bad("client-encrypted environments cannot be cloned server-side; use the CLI")); } }
    let items = st.list_secrets_base(&eid).await?; let key = st.env_key(target).await?; let master = st.master();
    let mut cloned = 0; let mut skipped = 0; let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let mut require_one: Vec<usize> = Vec::new();
    for (_, _, raw) in items {
        let stype = raw["type"].as_str().unwrap_or("secret");
        if stype == "sealed" { skipped += 1; continue; }
        let s = SecretIn{ key: raw["key"].as_str().unwrap_or("").into(), value: raw["value"].as_str().unwrap_or("").into(), path: raw["path"].as_str().unwrap_or("/").into(), comment: raw["comment"].as_str().unwrap_or("").into(), tags: raw["tags"].as_str().unwrap_or("").into(), secret_type: stype.into(), expected_version: None };
        let kname = s.key.to_uppercase();
        let khash = key_index(&key, &s.path, &kname);
        let legacy = oc::hash_token(&format!("{}:{}", s.path, kname));
        if !overwrite && st.db.one("SELECT id FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(target), json!(&khash), json!(&legacy)]).await.map_err(|e| bad(&e))?.is_some() { skipped += 1; continue; }
        require_one.push(statements.len()); statements.push(("UPDATE envs SET id=id WHERE id=?".into(), vec![json!(target)]));
        require_one.push(statements.len()); statements.extend(secret_statements(&st, target, &org, &key, &uid, &s, &master).await?); cloned += 1;
    }
    st.audited_batch_master(&statements, &require_one, [&org, &app, &eid, &uid, "env.clone", &format!("{}->{} cloned={} skipped={}", eid, target, cloned, skipped)], master).await.map_err(secret_batch_error)?;
    let sync_errors = trigger_sync(&st, target, &uid).await;
    Ok(j(json!({"cloned": cloned, "skipped": skipped, "sync_errors": sync_errors}))) }
async fn compare_envs(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?;
    let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let other = q.get("other").cloned().unwrap_or_default();
    if other.is_empty() || other == eid { return Err(bad("other environment id required")); }
    let (oorg, _) = st.require_env(&other, &uid).await?; st.check_perm(&oorg, &uid, "secrets:read").await?;
    if oorg != org { return Err(bad("environments must belong to the same organisation")); }
    let source = st.list_secrets_base(&eid).await?; let target = st.list_secrets_base(&other).await?;
    let map = |items: &[(String,String,Value)]| -> HashMap<String,String> { items.iter().map(|(k,_,raw)| (format!("{}{}", raw["path"].as_str().unwrap_or("/"), k), raw["value"].as_str().unwrap_or("").to_string())).collect() };
    let a = map(&source); let b = map(&target);
    let mut only_source = Vec::new(); let mut only_target = Vec::new(); let mut changed = Vec::new(); let mut same = 0;
    for (k, v) in &a { match b.get(k) { None => only_source.push(k.clone()), Some(w) if w != v => changed.push(k.clone()), Some(_) => same += 1 } }
    for k in b.keys() { if !a.contains_key(k) { only_target.push(k.clone()); } }
    only_source.sort(); only_target.sort(); changed.sort();
    Ok(j(json!({"only_in_source": only_source, "only_in_target": only_target, "changed": changed, "same": same}))) }

async fn list_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?; st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let items = st.list_secrets_decrypted(&eid, &uid).await?; st.audit(&org, &app, &eid, &uid, "secret.list", &format!("{}", items.len())).await;
    let tag = q.get("tag").cloned().unwrap_or_default();
    let items: Vec<(String,String,Value)> = items.into_iter().filter(|(_,_,raw)| tag.is_empty() || raw["tags"].as_str().unwrap_or("").split(|c: char| c == ',' || c.is_whitespace()).any(|t| t.eq_ignore_ascii_case(&tag))).collect();
    let total = items.len();
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(500).clamp(1, 1000);
    let offset = q.get("offset").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
    let page: Vec<Value> = items.iter().skip(offset).take(limit).map(|x| x.2.clone()).collect();
    crate::ai::activity(&st,(&org,&app,&eid),&uid,&h,"secret.list","",page.len()).await;
    Ok(j(json!({"secrets": page, "total": total, "limit": limit, "offset": offset}))) }
async fn list_tags(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.check_scope(&h, &eid).await?;
    let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let mut counts: HashMap<String, i64> = HashMap::new();
    for (_, _, raw) in st.list_secrets_decrypted(&eid, &uid).await? {
        for tag in raw["tags"].as_str().unwrap_or("").split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
            *counts.entry(tag.to_ascii_lowercase()).or_insert(0) += 1; }
    }
    let mut tags: Vec<Value> = counts.into_iter().map(|(tag, count)| json!({"tag": tag, "count": count})).collect();
    tags.sort_by(|a, b| a["tag"].as_str().unwrap_or("").cmp(b["tag"].as_str().unwrap_or("")));
    Ok(j(json!({"tags": tags}))) }
// Lifecycle mutations apply the same approval gate as ordinary value writes.
async fn require_approval_for_write(st: &S, eid: &str, org: &str, uid: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let policy = st.db.one("SELECT require_approval FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?;
    if policy.map(|p| db::n(&p, "require_approval") == 1).unwrap_or(false) {
        let role = st.require_org(org, uid).await.unwrap_or_default();
        if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "this environment requires an approved proposal; submit a proposal or ask an admin")); }
    }
    Ok(()) }
async fn deploy_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h).await?; st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    require_approval_for_write(&st, &eid, &org, &uid).await?;
    let mut inputs = r.secrets.clone(); if inputs.is_empty() && !r.text.is_empty() { inputs = parse_env(&r.text); }
    let mut deduped: Vec<SecretIn> = Vec::new();
    for s in inputs {
        if s.key.trim().is_empty() { continue; }
        if let Some(pos) = deduped.iter().position(|x| x.path == s.path && x.key.trim().to_uppercase() == s.key.trim().to_uppercase()) { deduped[pos] = s; }
        else { deduped.push(s); }
    }
    let inputs = deduped;
    for s in &inputs { st.check_path(&eid, &uid, &s.path, "write").await?; }
    let scan_findings: Vec<Value> = inputs.iter().filter(|s| s.secret_type != "sealed").filter_map(|s| {
        let rules = scan_rules(&s.value);
        if rules.is_empty() { None } else { Some(json!({"key": s.key, "path": s.path, "rules": rules})) }
    }).collect();
    let key = st.env_key(&eid).await?; let count = inputs.len(); let master = st.master();
    let mut statements = vec![("UPDATE envs SET id=id WHERE id=?".to_string(), vec![json!(&eid)])]; let mut require_one = vec![0];
    for s in &inputs {
        let prepared = secret_statements(&st, &eid, &org, &key, &uid, s, &master).await?;
        require_one.push(statements.len()); statements.extend(prepared);
    }
    st.audited_batch_master(&statements, &require_one, [&org,&app,&eid,&uid,"secret.deploy",&format!("{} secrets",count)], master).await.map_err(secret_batch_error)?;
    let sync_errors = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"deployed": count, "sync_errors": sync_errors, "scan_findings": scan_findings}))) }
fn secret_batch_error(e: String) -> (StatusCode, Json<Value>) {
    if e == webhooks::EPOCH_STALE { webhooks::epoch_stale() } else if e.starts_with("version conflict:") { err(StatusCode::CONFLICT, &e) } else { bad(&e) }
}
async fn upsert_secret(st: &S, eid: &str, org: &str, key: &[u8;32], uid: &str, s: &SecretIn) -> Result<(), (StatusCode, Json<Value>)> {
    let mut statements = vec![("UPDATE envs SET id=id WHERE id=?".to_string(), vec![json!(eid)])];
    let master=st.master();
    statements.extend(secret_statements(st, eid, org, key, uid, s, &master).await?);
    st.audited_batch_master(&statements,&[0,1],[org,"",eid,uid,"secret.update",&s.key],master).await.map_err(secret_batch_error)?;
    Ok(())
}
#[allow(clippy::type_complexity)]
async fn secret_statements(st: &S, eid: &str, org: &str, key: &[u8;32], uid: &str, s: &SecretIn, master: &[u8;32]) -> Result<Vec<(String, Vec<Value>)>, (StatusCode, Json<Value>)> {
    st.require_env_running(eid).await?;
    if uid != "rotation-scheduler" { st.check_path(eid, uid, &s.path, "write").await?; }
    let mut statements = Vec::new();
    let limit = st.db.one("SELECT max_versions FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.map(|r| db::n(&r, "max_versions")).unwrap_or(0);
    let kname = s.key.trim().to_uppercase();
    if !valid_secret_key(&kname) { return Err(bad("secret key must match [A-Za-z0-9_.-]{1,128}")); }
    if !valid_path(&s.path) { return Err(bad("secret path must be 1-256 printable characters")); }
    let khash = key_index(key, &s.path, &kname);
    let legacy = oc::hash_token(&format!("{}:{}", s.path, kname));
    let existing = st.db.one("SELECT id,version,secret_type FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid), json!(&khash), json!(&legacy)]).await.map_err(|e| bad(&e))?;
    let current_version = existing.as_ref().map(|r| db::n(r, "version")).unwrap_or(0);
    // Check-and-set: 0 means create-only, n means the caller last saw version n.
    if let Some(expected) = s.expected_version {
        if expected != current_version {
            return Err(err(StatusCode::CONFLICT, &format!("version conflict: expected {}, current {}", expected, current_version)));
        }
    }
    let mut stype = if s.secret_type.is_empty() { "secret".to_string() } else { s.secret_type.clone() };
    if !matches!(stype.as_str(), "secret" | "sealed" | "ssh_key" | "config") { return Err(bad("secret type must be secret, sealed, ssh_key or config")); }
    if stype == "ssh_key" && ssh_keys::public_key_error(&kname, &s.value).is_some() { return Err(bad("an ssh_key value must be a single-line OpenSSH public key")); }
    if let Some(row) = &existing { if db::s(row, "secret_type") == "sealed" { if stype != "sealed" { return Err(bad("sealed secrets cannot change type; delete and recreate")); } stype = "sealed".to_string(); } }
    // Only real secret values are indexed. Sealed values are excluded so a
    // match cannot confirm a value the caller is not allowed to read; config
    // and public ssh keys are not credentials.
    let fp = if stype == "secret" && !s.value.is_empty() { value_fingerprint(master, org, &s.value) } else { String::new() };
    if let Some(row) = existing { let sid = db::s(&row, "id"); let ver = db::n(&row, "version") + 1;
        let value_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "value", ver), s.value.as_bytes());
        let comment_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "comment", ver), s.comment.as_bytes());
        let path_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "path"), s.path.as_bytes());
        let tags_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "tags"), s.tags.as_bytes());
        // Preparation happens before the transaction, so every update binds its snapshot.
        let mut update = "UPDATE secrets SET value_enc=?,value_fp=?,comment_enc=?,path='',path_enc=?,tags='',tags_enc=?,key_hash=?,key_index=?,secret_type=?,version=?,updated_at=?,updated_by=? WHERE id=? AND version=? AND deleted=0".to_string();
        let mut args = vec![json!(value_enc), json!(&fp), json!(comment_enc), json!(path_enc), json!(tags_enc), json!(&khash), json!(&khash), json!(stype), json!(ver), json!(now()), json!(uid), json!(&sid), json!(current_version)];
        if uid!="rotation-scheduler" {
            update.push_str(" AND NOT EXISTS (SELECT 1 FROM rotation_schedules WHERE env_id=? AND key_name=? AND path=? AND static_target IS NOT NULL AND (pending_enc<>'' OR execution_token<>''))");
            args.extend([json!(eid),json!(&kname),json!(&s.path)]);
        }
        statements.push((update, args));
        statements.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)".into(),
            vec![json!(id()), json!(sid), json!(ver), json!(oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "key"), kname.as_bytes())), json!(value_enc), json!(comment_enc), json!(stype), json!(s.path), json!(s.tags), json!(now()), json!(uid)]));
        if limit > 0 && ver > limit { statements.push(("DELETE FROM secret_versions WHERE secret_id=? AND version<=?".into(), vec![json!(&sid), json!(ver - limit)])); }
    } else { let sid = id();
        let key_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "key"), kname.as_bytes());
        let value_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "value", 1), s.value.as_bytes());
        let comment_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "comment", 1), s.comment.as_bytes());
        let path_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "path"), s.path.as_bytes());
        let tags_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "tags"), s.tags.as_bytes());
        // The environment row lock serialises create-only checks without a live-key unique index.
        statements.push(("INSERT INTO secrets(id,env_id,path,path_enc,key_enc,key_hash,key_index,value_enc,value_fp,comment_enc,tags,tags_enc,secret_type,version,updated_at,updated_by) SELECT ?,?,'',?,?,?,?,?,?,?,'',?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0)".into(),
            vec![json!(sid), json!(eid), json!(path_enc), json!(key_enc), json!(&khash), json!(&khash), json!(value_enc), json!(&fp), json!(comment_enc), json!(tags_enc), json!(stype), json!(now()), json!(uid), json!(eid), json!(&khash), json!(&legacy)]));
        statements.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,path,tags,created_at,created_by) VALUES(?,?,1,?,?,?,?,?,?,?,?)".into(),
            vec![json!(id()), json!(sid), json!(key_enc), json!(value_enc), json!(comment_enc), json!(stype), json!(s.path), json!(s.tags), json!(now()), json!(uid)]));
    } Ok(statements) }
async fn prune_versions(st: &S, eid: &str, sid: &str, current: i64) -> Result<(), (StatusCode, Json<Value>)> {
    let limit = st.db.one("SELECT max_versions FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.map(|r| db::n(&r, "max_versions")).unwrap_or(0);
    if limit > 0 && current > limit {
        st.db.exec("DELETE FROM secret_versions WHERE secret_id=? AND version<=?", &[json!(sid), json!(current - limit)]).await.map_err(|e| bad(&e))?;
    }
    Ok(()) }
fn parse_env(text: &str) -> Vec<SecretIn> { let mut out = Vec::new(); let mut pending_comment = String::new();
    for line in text.lines() { let l = line.trim(); if l.is_empty() { continue; } else if l.starts_with('#') { pending_comment = l.trim_start_matches('#').trim().to_string(); continue; }
        if let Some((k, v)) = l.trim_start_matches("export ").split_once('=') { out.push(SecretIn{ key: k.trim().to_string(), value: v.trim().trim_matches('"').trim_matches('\'').to_string(), path: "/".into(), comment: pending_comment.clone(), tags: "".into(), secret_type: "".into(), expected_version: None }); pending_comment.clear(); } } out }
async fn rotation_secret_batch(st: &S, eid: &str, sid: &str, statements: &[(String,Vec<Value>)], fields: [&str;6], master: Option<[u8;32]>) -> Result<(),(StatusCode,Json<Value>)> {
    let mut blocked="SELECT id FROM rotation_schedules WHERE env_id=? AND static_target IS NOT NULL AND (pending_enc<>'' OR execution_token<>'')".to_string();
    let mut params=vec![json!(eid)];
    if !sid.is_empty() {
        let row=st.db.one("SELECT * FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?;
        if db::n(&row,"e2e")==0 {
            let key=st.env_key(eid).await?;
            let name=oc::decrypt_symmetric_compat(&key,&secret_aad(eid,sid,"key"),&db::s(&row,"key_enc")).map_err(|e| bad(&e))?;
            blocked.push_str(" AND key_name=? AND path=?");
            params.extend([json!(String::from_utf8(name).map_err(|_| bad("invalid secret name"))?),json!(st.stored_path(&key,&row)?)]);
        }
    }
    let checked=if fields[4]=="secret.delete" { vec![0] } else { Vec::new() };
    st.audited_rotation_batch(statements,&checked,fields,master,&blocked,&params).await.map_err(secret_batch_error)?;
    Ok(())
}
async fn delete_secret(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?;
    let eid = db::s(&row, "env_id"); st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:delete").await?; st.check_secret_path(&sid, &uid, "delete").await?;
    rotation_secret_batch(&st,&eid,&sid,&[("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=? WHERE id=?".into(), vec![json!(now()),json!(now()),json!(sid)])], [&org,&app,&eid,&uid,"secret.delete",&sid], None).await?; let _ = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"ok": true}))) }
async fn undelete_secret(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "secret not found"))?;
    let eid = db::s(&row, "env_id"); st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    require_approval_for_write(&st, &eid, &org, &uid).await?;
    st.audited_batch(&[("UPDATE secrets SET deleted=0,deleted_at=0,updated_at=? WHERE id=? AND deleted=1".into(),vec![json!(now()),json!(sid)])], &[0], [&org,&app,&eid,&uid,"secret.undelete",&sid]).await.map_err(|e| if e.contains("version conflict") {bad("secret is not deleted")} else {bad(&e)})?; let _ = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"ok": true}))) }
// Unlike delete (a recoverable tombstone), destroy removes the value and its
// history permanently. Point-in-time recovery cannot bring it back.
async fn destroy_secret(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "secret not found"))?;
    let eid = db::s(&row, "env_id"); st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:delete").await?;
    require_approval_for_write(&st, &eid, &org, &uid).await?;
    statements.push((("DELETE FROM secret_versions WHERE secret_id=?").to_string(), ([json!(sid)]).to_vec()));
    statements.push((("DELETE FROM overrides WHERE secret_id=?").to_string(), ([json!(sid)]).to_vec()));
    statements.push((("DELETE FROM secrets WHERE id=?").to_string(), ([json!(sid)]).to_vec()));
    rotation_secret_batch(&st,&eid,&sid,&statements,[&org, &app, &eid, &uid, "secret.destroy", &sid],None).await?; let _ = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"destroyed": true}))) }
async fn history(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    st.check_scope(&h, &eid).await?; st.check_secret_path(&sid, &uid, "read").await?;
    let key = st.env_key(&eid).await?; let sealed = st.db.one("SELECT secret_type FROM secrets WHERE id=?", &[json!(sid)]).await.map(|r| r.map(|x| db::s(&x,"secret_type") == "sealed").unwrap_or(false)).unwrap_or(false);
    let rows = st.db.query("SELECT * FROM secret_versions WHERE secret_id=? ORDER BY version DESC", &[json!(sid)]).await.map_err(|e| bad(&e))?;
    let mut visible_rows = Vec::new(); for r in rows { if st.path_allowed(&eid, &uid, &db::s(&r,"path"), "read").await? { visible_rows.push(r); } }
    let items: Vec<Value> = visible_rows.iter().map(|r| json!({"version": db::n(r,"version"), "path": db::s(r,"path"), "tags": db::s(r,"tags"), "value": if sealed { "[SEALED]".to_string() } else { decrypt_secret_value(&key, &eid, &sid, "value", db::n(r,"version"), &db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() }, "created_at": db::n(r,"created_at"), "created_by": db::s(r,"created_by")})).collect();
    Ok(j(json!(items))) }
async fn restore(State(st): State<S>, h: HeaderMap, Path((sid, ver)): Path<(String, i64)>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    st.check_scope(&h, &eid).await?; st.check_secret_path(&sid, &uid, "write").await?;
    // An E2E environment has no server-side key; restoring its ciphertext
    // still works, it just cannot produce a reusable fingerprint.
    let key = st.env_key(&eid).await.ok();
    let v = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND version=?", &[json!(sid), json!(ver)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("version not found"))?;
    st.check_path(&eid, &uid, &db::s(&v,"path"), "read").await?;
    let cur = st.db.one("SELECT version FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?;
    let new_ver = cur.as_ref().map(|r| db::n(r,"version")).unwrap_or(0) + 1;
    let vpath = { let p = db::s(&v,"path"); if p.is_empty() { "/".to_string() } else { p } };
    // Version ciphertext is bound to its version, so restoring it under a new
    // version means decrypting and re-binding rather than copying the blob.
    // A client-encrypted environment has no server key; its blob is copied.
    let master = st.master();
    let (value_enc, comment_enc, restored_fp, tags_plain, tags_enc) = match key {
        Some(key) => {
            let plain_value = decrypt_secret_value(&key, &eid, &sid, "value", ver, &db::s(&v,"value_enc")).map_err(|e| bad(&e))?;
            let plain_comment = decrypt_secret_value(&key, &eid, &sid, "comment", ver, &db::s(&v,"comment_enc")).map_err(|e| bad(&e))?;
            let fp = if db::s(&v,"secret_type") == "secret" { value_fingerprint(&master, &org, &String::from_utf8_lossy(&plain_value)) } else { String::new() };
            (oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid,&sid,"value",new_ver), &plain_value),
             oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid,&sid,"comment",new_ver), &plain_comment),
             fp, String::new(),
             oc::encrypt_symmetric_aad(&key, &secret_aad(&eid,&sid,"tags"), db::s(&v,"tags").as_bytes()))
        }
        None => (db::s(&v,"value_enc"), db::s(&v,"comment_enc"), String::new(), db::s(&v,"tags"), String::new()),
    };
    rotation_secret_batch(&st,&eid,&sid,&[
        ("UPDATE secrets SET value_enc=?,value_fp=?,comment_enc=?,tags=?,tags_enc=?,version=?,deleted=0,deleted_at=0,updated_at=?,updated_by=? WHERE id=?".into(), vec![json!(value_enc), json!(&restored_fp), json!(comment_enc), json!(tags_plain), json!(tags_enc), json!(new_ver), json!(now()), json!(uid), json!(sid)]),
        ("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)".into(), vec![json!(id()), json!(sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(value_enc), json!(comment_enc), json!(db::s(&v,"secret_type")), json!(vpath), json!(db::s(&v,"tags")), json!(now()), json!(uid)]),
    ], [&org,&app,&eid,&uid,"secret.restore",&format!("{}->v{}",sid,ver)], Some(master)).await?;
    prune_versions(&st, &eid, &sid, new_ver).await?;
    let _ = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"ok":true,"version":new_ver}))) }
async fn set_override(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row,"env_id"); st.check_scope(&h, &eid).await?; let (org, _) = st.require_env(&eid,&uid).await?;
    if st.restricted_env(&eid,&uid).await? { st.check_perm(&org,&uid,"secrets:write").await?; st.check_secret_path(&sid,&uid,"write").await?; }
    let key = st.env_key(&eid).await?; let val = r.secrets.first().map(|s| s.value.clone()).unwrap_or_default();
    let enc = oc::encrypt_symmetric_aad(&key, &secret_aad(&eid, &sid, &format!("override:{}", uid)), val.as_bytes());
    if st.db.exec("INSERT INTO overrides(secret_id,user_id,value_enc) VALUES(?,?,?)", &[json!(sid), json!(uid), json!(&enc)]).await.is_err() {
        st.db.exec("UPDATE overrides SET value_enc=? WHERE secret_id=? AND user_id=?", &[json!(&enc), json!(sid), json!(uid)]).await.map_err(|e| bad(&e))?;
    }
    Ok(j(json!({"ok":true}))) }

async fn get_override(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id,key_enc,version FROM secrets WHERE id=? AND deleted=0", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "secret not found"))?;
    let eid = db::s(&row,"env_id"); st.check_scope(&h, &eid).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?; st.check_secret_path(&sid,&uid,"read").await?;
    let ov = st.db.one("SELECT value_enc FROM overrides WHERE secret_id=? AND user_id=?", &[json!(sid), json!(uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "no personal override"))?;
    let key = st.env_key(&eid).await?;
    let value = decrypt_secret_value(&key, &eid, &sid, &format!("override:{}", uid), db::n(&row,"version"), &db::s(&ov,"value_enc")).map_err(|e| bad(&e))?;
    let key_name = oc::decrypt_symmetric_compat(&key, &secret_aad(&eid, &sid, "key"), &db::s(&row,"key_enc")).map_err(|e| bad(&e))?;
    Ok(j(json!({"key": String::from_utf8_lossy(&key_name), "value": String::from_utf8_lossy(&value)}))) }
async fn delete_override(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=? AND deleted=0", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "secret not found"))?;
    let eid = db::s(&row,"env_id"); st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?; st.check_secret_path(&sid,&uid,"read").await?;
    st.audited_batch(&[("DELETE FROM overrides WHERE secret_id=? AND user_id=?".into(),vec![json!(sid),json!(uid)])], &[0], [&org,&app,&eid,&uid,"secret.override_delete",&sid]).await.map_err(|e|if e.contains("version conflict") {err(StatusCode::NOT_FOUND,"no personal override")} else {bad(&e)})?;
    Ok(j(json!({"deleted": true}))) }

async fn scan_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let items = st.list_secrets_decrypted(&eid, &uid).await?;
    let mut findings = Vec::new();
    for (_, _, raw) in items {
        if raw["type"].as_str() == Some("sealed") { continue; }
        let rules = scan_rules(raw["value"].as_str().unwrap_or(""));
        if !rules.is_empty() { findings.push(json!({"key": raw["key"], "path": raw["path"], "rules": rules})); }
    }
    st.audit(&org,&app,&eid,&uid,"secret.scan",&format!("{} findings", findings.len())).await;
    Ok(j(json!({"findings": findings}))) }
// Advisory preflight for the console. It compares keyed fingerprints, never
// values, and only reports occurrences in environments the caller can open.
async fn reuse_check(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<ReuseReq>) -> Res {
    let uid = st.token_user(&h).await?; st.epoch_ok().await?; st.check_scope(&h, &eid).await?;
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    if !st.reuse_enabled(&org, &app).await { return Ok(j(json!({"enabled": false, "matches": []}))); }
    let master = st.master();
    let mut candidates: Vec<(usize, String, String, String)> = Vec::new();
    for (index, s) in r.secrets.iter().enumerate() {
        let stype = if s.secret_type.is_empty() { "secret" } else { s.secret_type.as_str() };
        if stype != "secret" || s.value.is_empty() { continue; }
        candidates.push((index, value_fingerprint(&master, &org, &s.value), s.key.clone(), s.path.clone()));
    }
    if candidates.is_empty() { return Ok(j(json!({"enabled": true, "matches": []}))); }
    let mut visible: HashMap<String, bool> = HashMap::new();
    let mut env_keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut by_fp: HashMap<String, Vec<Value>> = HashMap::new();
    for chunk in candidates.chunks(100) {
        let mut params: Vec<Value> = vec![json!(&org)];
        let mut marks: Vec<&str> = Vec::new();
        for c in chunk { marks.push("?"); params.push(json!(&c.1)); }
        let sql = format!("SELECT s.id AS id,s.env_id AS env_id,s.key_enc AS key_enc,s.path AS path,s.path_enc AS path_enc,s.value_fp AS value_fp,s.updated_at AS updated_at,e.name AS env_name,a.id AS app_id,a.name AS app_name \
            FROM secrets s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id \
            WHERE a.org_id=? AND s.deleted=0 AND s.e2e=0 AND s.secret_type='secret' AND s.value_fp IN ({})", marks.join(","));
        let rows = st.db.query(&sql, &params).await.map_err(|e| bad(&e))?;
        for row in &rows {
            let sid = db::s(row, "id");
            if r.exclude.iter().any(|x| x == &sid) { continue; }
            let menv = db::s(row, "env_id");
            // An environment-scoped token stays confined to its own environment
            // even when the person behind it could open the others.
            if st.check_scope(&h, &menv).await.is_err() { continue; }
            let allowed = match visible.get(&menv) {
                Some(v) => *v,
                None => { let v = st.require_env(&menv, &uid).await.is_ok(); visible.insert(menv.clone(), v); v },
            };
            if !allowed { continue; }
            let key = match env_keys.get(&menv) {
                Some(k) => *k,
                None => { match st.env_key(&menv).await { Ok(k) => { env_keys.insert(menv.clone(), k); k }, Err(_) => continue } },
            };
            if st.restricted_env(&menv,&uid).await? { let Ok(path) = st.stored_path(&key,row) else { continue }; if !st.path_allowed(&menv,&uid,&path,"read").await? { continue; } }
            let matched_key = oc::decrypt_symmetric_compat(&key, &secret_aad(&menv, &sid, "key"), &db::s(row, "key_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
            let matched_path = if db::s(row, "path_enc").is_empty() { db::s(row, "path") } else {
                oc::decrypt_symmetric_compat(&key, &secret_aad(&menv, &sid, "path"), &db::s(row, "path_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|_| db::s(row, "path")) };
            by_fp.entry(db::s(row, "value_fp")).or_default().push(json!({
                "secret_id": sid, "key": matched_key, "path": matched_path,
                "app_id": db::s(row, "app_id"), "app_name": db::s(row, "app_name"),
                "env_id": menv, "env_name": db::s(row, "env_name"),
                "updated_at": db::n(row, "updated_at")
            }));
        }
    }
    let mut matches: Vec<Value> = Vec::new();
    for (index, fp, key, path) in &candidates {
        if let Some(items) = by_fp.get(fp) { matches.push(json!({"index": index, "key": key, "path": path, "items": items})); }
    }
    if !matches.is_empty() { st.audit(&org, &app, &eid, &uid, "secret.reuse_warned", &format!("{} values", matches.len())).await; }
    Ok(j(json!({"enabled": true, "matches": matches}))) }
async fn export_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?; st.check_scope(&h, &eid).await?; let (org, app) = st.require_env(&eid,&uid).await?; st.check_perm(&org,&uid,"secrets:read").await?;
    // base=1 skips the caller's personal overrides. Deployments must not pick up
    // whichever stand-in values the token owner happens to keep locally.
    let items = if q.get("base").map(|v| v == "1" || v == "true").unwrap_or(false) { st.list_secrets_with(&eid, None, Some(&uid)).await? } else { st.list_secrets_decrypted(&eid,&uid).await? };
    let total = items.len();
    let visible: Vec<(String,String,Value)> = items.into_iter().filter(|(_,_,raw)| raw["type"].as_str() != Some("sealed")).collect();
    let omitted = total - visible.len();
    let text = visible.iter().map(|(k,v,_)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n");
    st.audit(&org,&app,&eid,&uid,"secret.export",&format!("{} secrets, {} sealed omitted", visible.len(), omitted)).await;
    crate::ai::activity(&st,(&org,&app,&eid),&uid,&h,"secret.export","",visible.len()).await;
    Ok(j(json!({"text": text, "secrets": visible.iter().map(|x| x.2.clone()).collect::<Vec<_>>(), "omitted_sealed": omitted}))) }
// An environment-scoped token cannot list workspaces, so it needs a way to name
// the one environment it is confined to. The path also passes scope_path_ok.
async fn env_meta(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.check_scope(&h, &eid).await?;
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let read_name = |table: &'static str, id: String| { let st = st.clone(); async move {
        st.db.one(&format!("SELECT name FROM {} WHERE id=?", table), &[json!(id)]).await.ok().flatten().map(|r| db::s(&r, "name")).unwrap_or_default()
    } };
    let env_name = read_name("envs", eid.clone()).await;
    let app_name = read_name("apps", app.clone()).await;
    let workspace = read_name("orgs", org.clone()).await;
    let policy = st.db.one("SELECT restricted,require_approval,max_versions FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.unwrap_or_default();
    Ok(j(json!({"id": eid, "name": env_name, "app": app_name, "workspace": workspace,
        "policy": {"restricted": db::n(&policy,"restricted") != 0, "require_approval": db::n(&policy,"require_approval") != 0, "max_versions": db::n(&policy,"max_versions")}}))) }
async fn search(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?; let needle = q.get("q").cloned().unwrap_or_default().to_uppercase();
    let orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).await.map_err(|e| bad(&e))?;
    let mut results = Vec::new();
    for o in &orgs { let org = db::s(o,"org_id");
        if st.check_perm(&org, &uid, "secrets:read").await.is_err() { continue; }
        let apps = st.db.query("SELECT id,name FROM apps WHERE org_id=?", &[json!(&org)]).await.map_err(|e| bad(&e))?;
        for a in &apps { let app_id = db::s(a,"id");
            let envs = st.db.query("SELECT id,name FROM envs WHERE app_id=?", &[json!(&app_id)]).await.map_err(|e| bad(&e))?;
            for e in &envs { let eid = db::s(e,"id");
                // Environment and application grants narrow the org-wide default.
                if st.require_env(&eid, &uid).await.is_err() { continue; }
                if let Ok(items) = st.list_secrets_decrypted(&eid, &uid).await { for (k,_,raw) in items { if needle.is_empty() || k.contains(&needle) { results.push(json!({"app": db::s(a,"name"), "env": db::s(e,"name"), "key": k, "path": raw["path"]})); } } } } } }
    Ok(j(json!({"results": results}))) }
async fn create_token(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?;
    // A 1h machine credential must not be convertible into a permanent one.
    if let Ok(Some(caller)) = st.db.one("SELECT env_id,kind FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(&h)))]).await {
        if db::s(&caller, "kind") == "machine" { return Err(err(StatusCode::FORBIDDEN, "machine tokens cannot mint service tokens; use the identity's 1h token")); }
        if !db::s(&caller, "env_id").is_empty() { return Err(err(StatusCode::FORBIDDEN, "environment-scoped tokens cannot mint new tokens")); } }
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app,"org_id"); st.check_perm(&org, &uid, "tokens:create").await?;
    if !r.env_id.is_empty() {
        let env = st.db.one("SELECT app_id FROM envs WHERE id=?", &[json!(r.env_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
        if db::s(&env, "app_id") != aid { return Err(bad("env does not belong to this app")); }
    }
    let token = oc::random_token("owp"); let tid = id();
    let scopes: Vec<&str> = r.scopes.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).collect();
    for s in &scopes { if !matches!(*s, "secrets:read" | "secrets:write" | "org:admin" | "pki:read" | "pki:write" | "transit:manage" | "transit:encrypt" | "transit:decrypt" | "transit:rewrap" | "*") { return Err(bad("scopes may contain secrets:read, secrets:write, org:admin, pki:read, pki:write, transit:manage, transit:encrypt, transit:decrypt, transit:rewrap or *")); } }
    let scopes = scopes.join(" ");
    let expires_at = if r.expires_in > 0 { now() + r.expires_in.clamp(60, 365 * 86400) } else { 0 };
    st.db.exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,expires_at,scopes,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)", &[json!(tid), json!(org), json!(aid), json!(r.env_id), json!(if r.name.is_empty(){"token".into()}else{r.name.clone()}), json!(oc::hash_token(&token)), json!(expires_at), json!(scopes), json!(now()), json!(uid)]).await.map_err(|e| bad(&e))?;
    crate::ai::activity(&st,(&org,&aid,&r.env_id),&uid,&h,"token.create",&tid,1).await;
    Ok(j(json!({"id": tid, "token": token, "expires_at": expires_at, "scopes": scopes}))) }
async fn audit_list(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid,&uid).await?;
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(500).clamp(1, 1000);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0);
    let redacted = match st.require_org_running(&oid).await { Ok(()) => false, Err((StatusCode::FORBIDDEN, _)) => true, Err(e) => return Err(e) };
    let rows = st.db.query("SELECT * FROM audit WHERE org_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?", &[json!(oid), json!(limit), json!(offset)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(|r| { let mut value = db::obj(r); if redacted { value["detail"] = json!(""); if let Some(obj) = value.as_object_mut() { obj.remove("hash"); obj.remove("prev_hash"); } } value }).collect::<Vec<_>>()))) }
async fn audit_verify(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid,&uid).await?; st.check_admin(&oid,&uid).await?;
    let rows = st.db.query("SELECT seq,app_id,env_id,actor,action,detail,created_at,prev_hash,hash FROM audit WHERE org_id=? AND seq>0 ORDER BY seq", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    let mut checked = 0i64; let mut first_bad: Option<i64> = None; let mut prev = String::new(); let mut expect = 1i64;
    for r in &rows { let seq = db::n(r,"seq");
        if seq != expect || db::s(r,"prev_hash") != prev { first_bad = Some(seq); break; }
        let computed = audit_hash(&prev, seq, &oid, &db::s(r,"app_id"), &db::s(r,"env_id"), &db::s(r,"actor"), &db::s(r,"action"), &db::s(r,"detail"), db::n(r,"created_at"));
        if computed != db::s(r,"hash") { first_bad = Some(seq); break; }
        prev = computed; expect += 1; checked += 1; }
    let unchained = st.db.one("SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND seq=0", &[json!(&oid)]).await.ok().flatten().map(|r| db::n(&r,"n")).unwrap_or(0);
    let head = st.db.one("SELECT seq,hash FROM audit_heads WHERE org_id=?", &[json!(&oid)]).await.ok().flatten();
    let (head_seq, head_hash) = head.as_ref().map(|r| (db::n(r,"seq"), db::s(r,"hash"))).unwrap_or((0, String::new()));
    let head_ok = head_seq == expect - 1 && (head_seq == 0 || head_hash == prev);
    Ok(j(json!({"ok": first_bad.is_none() && head_ok, "checked": checked, "first_bad": first_bad, "unchained": unchained, "head_seq": head_seq, "head_matches": head_ok}))) }
async fn create_team(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let tid = id(); st.db.exec("INSERT INTO teams(id,org_id,name) VALUES(?,?,?)", &[json!(tid), json!(oid), json!(r.name)]).await.map_err(|e| bad(&e))?; Ok(j(json!({"id": tid}))) }
async fn list_teams(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid,&uid).await?;
    let rows = st.db.query("SELECT * FROM teams WHERE org_id=?", &[json!(oid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn list_team_grants(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let rows = st.db.query("SELECT t.id AS team_id,t.name AS name FROM team_env_grants g JOIN teams t ON t.id=g.team_id WHERE g.env_id=? ORDER BY t.name", &[json!(&eid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn add_team_grant(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_admin(&org, &uid).await?;
    let tid = body.get("team_id").and_then(|v| v.as_str()).unwrap_or("");
    if st.db.one("SELECT id FROM teams WHERE id=? AND org_id=?", &[json!(tid), json!(&org)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "team not found in this organisation")); }
    statements.push((("INSERT INTO team_env_grants(team_id,env_id) VALUES(?,?)").to_string(), ([json!(tid), json!(&eid)]).to_vec()));
    st.audited_batch(&statements, &[], [&org,&app,&eid,&uid,"team.grant",tid]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn remove_team_grant(State(st): State<S>, h: HeaderMap, Path((eid, tid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_admin(&org, &uid).await?;
    statements.push((("DELETE FROM team_env_grants WHERE team_id=? AND env_id=?").to_string(), ([json!(&tid), json!(&eid)]).to_vec()));
    st.audited_batch(&statements, &[], [&org,&app,&eid,&uid,"team.revoke",&tid]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn list_team_members(State(st): State<S>, h: HeaderMap, Path((oid, tid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?;
    st.require_org(&oid, &uid).await?;
    if st.db.one("SELECT id FROM teams WHERE id=? AND org_id=?", &[json!(&tid), json!(&oid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "team not found")); }
    let rows = st.db.query("SELECT u.id AS user_id,u.email AS email FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=? ORDER BY u.email", &[json!(&tid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn add_team_member(State(st): State<S>, h: HeaderMap, Path((oid, tid)): Path<(String, String)>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    st.check_admin(&oid, &uid).await?;
    if st.db.one("SELECT id FROM teams WHERE id=? AND org_id=?", &[json!(&tid), json!(&oid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "team not found")); }
    let target = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    if st.org_role(&oid, target).await.is_none() { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    statements.push((("INSERT INTO team_members(team_id,user_id) VALUES(?,?)").to_string(), ([json!(&tid), json!(target)]).to_vec()));
    st.audited_batch(&statements, &[], [&oid,"","",&uid,"team.member.add",target]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn remove_team_member(State(st): State<S>, h: HeaderMap, Path((oid, tid, target)): Path<(String, String, String)>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    st.check_admin(&oid, &uid).await?;
    statements.push((("DELETE FROM team_members WHERE team_id=? AND user_id=? AND team_id IN (SELECT id FROM teams WHERE org_id=?)").to_string(), ([json!(&tid), json!(&target), json!(&oid)]).to_vec()));
    st.audited_batch(&statements, &[], [&oid,"","",&uid,"team.member.remove",&target]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }

async fn create_lockbox(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let _ = uid;
    let val = body.get("secrets").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|s| s.get("value")).and_then(|v| v.as_str())
        .or_else(|| body.get("text").and_then(|v| v.as_str())).unwrap_or("");
    if val.is_empty() { return Err(bad("value required")); }
    let expires_in = body.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(86400).clamp(60, 7 * 86400);
    let max_views = body.get("max_views").and_then(|v| v.as_i64()).unwrap_or(1).clamp(1, 10);
    let key = oc::random_key(); let lid = id(); let created_at = now(); let expires_at = created_at + expires_in;
    st.db.exec("INSERT INTO lockbox(id,value_enc,expires_at,max_views,created_at) VALUES(?,?,?,?,?)", &[json!(lid), json!(oc::encrypt_symmetric(&key, val.as_bytes())), json!(expires_at), json!(max_views), json!(created_at)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"id": lid, "key": oc::b64(&key), "url": format!("/lockbox/{}#{}", lid, oc::b64(&key)), "expires_at": expires_at, "max_views": max_views}))) }
async fn open_lockbox(State(st): State<S>, Path(lid): Path<String>, h: HeaderMap) -> Res {
    let key_b64 = h.get("x-lockbox-key").and_then(|v| v.to_str().ok()).unwrap_or(""); let kb = oc::unb64(key_b64).map_err(|e| bad(&e))?; let key: [u8;32] = kb.try_into().map_err(|_| bad("bad key"))?;
    let row = st.db.one("SELECT * FROM lockbox WHERE id=?", &[json!(lid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lockbox not found or already viewed"))?;
    if db::n(&row,"expires_at") < now() || db::n(&row,"views") >= db::n(&row,"max_views") { let _ = st.db.exec("DELETE FROM lockbox WHERE id=?", &[json!(lid)]).await; return Err(err(StatusCode::GONE,"expired")); }
    let val = oc::decrypt_symmetric(&key, &db::s(&row,"value_enc")).map_err(|e| bad(&e))?;
    // Only return plaintext after atomically claiming a view.
    let max_views = db::n(&row, "max_views").max(1);
    let taken = if max_views == 1 {
        st.db.exec("DELETE FROM lockbox WHERE id=? AND expires_at>=?", &[json!(lid), json!(now())]).await
    } else {
        st.db.exec("UPDATE lockbox SET views=views+1 WHERE id=? AND views<max_views AND expires_at>=?", &[json!(lid), json!(now())]).await
    }.map_err(|e| bad(&e))?;
    if taken == 0 { return Err(err(StatusCode::NOT_FOUND,"lockbox not found or already viewed")); }
    let remaining = if max_views == 1 { 0 } else {
        st.db.one("SELECT views,max_views FROM lockbox WHERE id=?", &[json!(&lid)]).await.map_err(|e| bad(&e))?
            .map(|r| (db::n(&r,"max_views") - db::n(&r,"views")).max(0)).unwrap_or(0) };
    Ok(j(json!({"value": String::from_utf8_lossy(&val), "views_remaining": remaining}))) }
// Response wrapping: a single-use token whose ciphertext is bound to one
// environment and a short TTL. The holder can look it up before redeeming it.
async fn create_wrap(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    st.check_scope(&h, &eid).await?;
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(300).clamp(60, 86400);
    let key = st.env_key(&eid).await?;
    let env_name = st.db.one("SELECT name FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"name")).unwrap_or_default();
    let wanted: Vec<String> = body.get("keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.trim().to_uppercase()).collect()).unwrap_or_default();
    // Base exports are unfiltered; restricted principals must never wrap them.
    let items = st.list_secrets_base(&eid).await?;
    let mut secrets = serde_json::Map::new();
    for (k, value, raw) in &items {
        if raw["type"].as_str() == Some("sealed") { continue; }
        // Two secrets can share a key name in different paths, so non-root
        // entries carry their path instead of overwriting one another.
        let path = raw["path"].as_str().unwrap_or("/");
        let name = if path == "/" { k.clone() } else { format!("{}{}", path, k) };
        if !wanted.is_empty() && !wanted.contains(k) && !wanted.contains(&name) { continue; }
        secrets.insert(name, json!(value));
    }
    if secrets.is_empty() { return Err(bad("no wrappable secrets: sealed and client-encrypted values are excluded")); }
    let payload = json!({"env": env_name, "secrets": secrets});
    let token = oc::random_token("owwrap"); let expires = now() + ttl;
    st.audited_batch(&[("INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?)".into(),vec![json!(oc::hash_token(&token)),json!(&eid),json!(oc::encrypt_symmetric(&key,payload.to_string().as_bytes())),json!(&uid),json!(now()),json!(expires)])], &[0], [&org,&app,&eid,&uid,"secret.wrap",&format!("{} secrets, {}s",secrets.len(),ttl)]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"token": token, "expires_at": expires, "single_use": true, "note": "send the token as a Bearer credential to /api/unwrap"}))) }
async fn lookup_wrap(State(st): State<S>, h: HeaderMap) -> Res { let token = bearer_token(&h);
    if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "wrapping token required")); }
    let row = st.db.one("SELECT env_id,created_by,created_at,expires_at,used FROM wrap_tokens WHERE token_hash=?", &[json!(oc::hash_token(&token))]).await.map_err(|e| bad(&e))?;
    match row {
        Some(r) => { st.require_env_running(&db::s(&r,"env_id")).await?;
            if db::n(&r,"expires_at") <= now() { return Err(err(StatusCode::GONE, "wrapping token expired")); }
            Ok(j(json!({"env_id": db::s(&r,"env_id"), "created_by": db::s(&r,"created_by"), "created_at": db::n(&r,"created_at"), "expires_at": db::n(&r,"expires_at"), "used": db::n(&r,"used") != 0}))) }
        None => Err(err(StatusCode::NOT_FOUND, "wrapping token not found or already used")) } }
async fn consume_wrap(State(st): State<S>, h: HeaderMap) -> Res { let token = bearer_token(&h);
    if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "wrapping token required")); }
    let hash = oc::hash_token(&token);
    let row = st.db.one("SELECT * FROM wrap_tokens WHERE token_hash=?", &[json!(&hash)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "wrapping token not found or already used"))?;
    st.require_env_running(&db::s(&row,"env_id")).await?;
    if db::n(&row,"expires_at") <= now() { let _ = st.db.exec("DELETE FROM wrap_tokens WHERE token_hash=?", &[json!(&hash)]).await; return Err(err(StatusCode::GONE, "wrapping token expired")); }
    // Decode before consuming: a transient key or parse failure must leave the
    // token redeemable rather than burning it with nothing returned.
    let eid = db::s(&row,"env_id"); let key = st.env_key(&eid).await?;
    let plain = oc::decrypt_symmetric(&key, &db::s(&row,"payload_enc")).map_err(|e| bad(&e))?;
    let payload: Value = serde_json::from_slice(&plain).map_err(|e| bad(&e.to_string()))?;
    let claimed = st.db.exec("UPDATE wrap_tokens SET used=1 WHERE token_hash=? AND used=0", &[json!(&hash)]).await.map_err(|e| bad(&e))?;
    if claimed == 0 { return Err(err(StatusCode::NOT_FOUND, "wrapping token not found or already used")); }
    let _ = st.db.exec("DELETE FROM wrap_tokens WHERE token_hash=?", &[json!(&hash)]).await;
    if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org, &app, &eid, "wrap-token", "secret.unwrap", "single-use token redeemed").await; }
    Ok(j(payload)) }
async fn list_leases(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let key = st.env_key(&eid).await?; let rows = st.db.query("SELECT * FROM leases WHERE env_id=? AND revoked=0 AND expires_at>?", &[json!(eid), json!(now())]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "value": oc::decrypt_symmetric_compat(&key, &lease_aad(&eid, &db::s(r,"id"), "value"), &db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(), "expires_at": db::n(r,"expires_at")})).collect::<Vec<_>>()))) }

async fn create_integration(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "integrations:write").await?;
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or(""); if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
    let config = body.get("config").cloned().unwrap_or(json!({}));
    let iid = id();
    let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")).unwrap_or_default();
    let config_enc = if mode == "delegated" { seal_to_runner(&st, &eid, &iid, &config).await? }
        else { oc::encrypt_symmetric_aad(&st.env_key(&eid).await?, &integration_aad(&eid, &iid, "config"), config.to_string().as_bytes()) };
    st.db.exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES(?,?,?,?,?,?)", &[json!(iid), json!(eid), json!(kind), json!(body.get("name").and_then(|v| v.as_str()).unwrap_or(kind)), json!(config_enc), json!(now())]).await.map_err(|e| bad(&e))?;
    crate::ai::activity(&st,(&org,"",&eid),&uid,&h,"integration.create",&iid,1).await;
    Ok(j(json!({"id": iid}))) }
async fn list_integrations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let rows = st.db.query("SELECT id,env_id,kind,name,created_at FROM integrations WHERE env_id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn sync_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let (org, _) = st.require_env(&db::s(&row, "env_id"), &uid).await?; st.check_perm(&org, &uid, "integrations:write").await?;
    let result = sync_one(&st, &iid, &uid).await;
    crate::ai::activity(&st,(&org,"",&db::s(&row,"env_id")),&uid,&h,if result.is_ok() { "integration.sync" } else { "integration.sync_failed" },&iid,1).await;
    let msg = result?; Ok(j(json!({"ok": true, "detail": msg}))) }
async fn test_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "integrations:write").await?;
    if st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")) == Some("delegated".into()) {
        enqueue_sync(&st, &eid, &iid, "test").await?;
        return Ok(j(json!({"ok": true, "detail": "connection test queued for the customer runner"}))); }
    let key = st.env_key(&eid).await?;
    let config: Value = serde_json::from_slice(&oc::decrypt_symmetric_compat(&key, &integration_aad(&eid, &iid, "config"), &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    let kind = db::s(&row, "kind");
    if integrations::has_test(&kind) { let result = integrations::test(&kind, &config).await;
        crate::ai::activity(&st,(&org,"",&eid),&uid,&h,if result.is_ok() { "integration.test" } else { "integration.test_failed" },&iid,1).await;
        let msg = result.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    Err(err(StatusCode::NOT_IMPLEMENTED, &format!("connection test is not implemented for kind {}; use Sync to verify it against the live service", kind))) }
async fn integration_history(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(&iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "integration not found"))?;
    let (org, _) = st.require_env(&db::s(&row, "env_id"), &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let prefix = format!("{}%", iid);
    let rows = st.db.query("SELECT action,detail,created_at,actor FROM audit WHERE org_id=? AND action IN ('integration.sync','integration.sync_failed') AND detail LIKE ? ORDER BY created_at DESC LIMIT 50", &[json!(&org), json!(&prefix)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn update_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(&iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "integrations:write").await?;
    let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")).unwrap_or_default();
    if let Some(kind) = body.get("kind").and_then(|v| v.as_str()) {
        if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
        statements.push((("UPDATE integrations SET kind=? WHERE id=?").to_string(), ([json!(kind), json!(&iid)]).to_vec())); }
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) { statements.push((("UPDATE integrations SET name=? WHERE id=?").to_string(), ([json!(name), json!(&iid)]).to_vec())); }
    if let Some(config) = body.get("config") {
        let enc = if mode == "delegated" { seal_to_runner(&st, &eid, &iid, config).await? }
            else { oc::encrypt_symmetric_aad(&st.env_key(&eid).await?, &integration_aad(&eid, &iid, "config"), config.to_string().as_bytes()) };
        statements.push((("UPDATE integrations SET config_enc=? WHERE id=?").to_string(), ([json!(enc), json!(&iid)]).to_vec())); }
    st.audited_batch(&statements, &[], [&org,&app,&eid,&uid,"integration.update",&iid]).await.map_err(|e|bad(&e))?;
    crate::ai::activity(&st,(&org,&app,&eid),&uid,&h,"integration.update",&iid,1).await; Ok(j(json!({"ok": true}))) }
async fn delete_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(&iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "integrations:write").await?;
    statements.push((("DELETE FROM integration_sync_state WHERE integration_id=?").to_string(), ([json!(&iid)]).to_vec()));
    statements.push(("DELETE FROM sync_jobs WHERE integration_id=?".into(), vec![json!(&iid)]));
    statements.push(("DELETE FROM integrations WHERE id=?".into(), vec![json!(&iid)]));
    st.audited_batch(&statements, &[], [&org,&app,&eid,&uid,"integration.delete",&iid]).await.map_err(|e|bad(&e))?; Ok(j(json!({"deleted": iid}))) }
async fn trigger_sync(st: &S, eid: &str, uid: &str) -> Vec<String> { if st.restricted_principal(uid).await.unwrap_or(true) { return Vec::new(); } trigger_sync_with(st, eid, uid, true).await }
async fn trigger_sync_internal(st: &S, eid: &str) -> Vec<String> { trigger_sync_with(st, eid, "rotation-scheduler", false).await }
async fn trigger_sync_with(st: &S, eid: &str, uid: &str, enforce: bool) -> Vec<String> {
    let mut errors = Vec::new();
    if let Ok(rows) = st.db.query("SELECT id FROM integrations WHERE env_id=?", &[json!(eid)]).await {
        for r in &rows { let iid = db::s(r, "id");
            if let Err((_, Json(v))) = sync_one_inner(st, &iid, uid, enforce, false, false).await {
                let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("integration sync failed").to_string();
                if let Ok((org, app)) = st.env_org_app(eid).await { st.audit(&org, &app, eid, uid, "integration.sync_failed", &format!("{}: {}", iid, msg)).await; }
                errors.push(format!("{}: {}", iid, msg)); } }
    }
    errors
}
async fn sync_one(st: &S, iid: &str, uid: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let out = sync_one_inner(st, iid, uid, true, true, false).await;
    if let Err((_, Json(v))) = &out {
        if let Ok(Some(row)) = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).await {
            let eid = db::s(&row, "env_id");
            if let Ok((org, app)) = st.env_org_app(&eid).await {
                let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("integration sync failed");
                st.audit(&org, &app, &eid, uid, "integration.sync_failed", &format!("{}: {}", iid, msg)).await; } } }
    out }
async fn sync_one_for_webhook(st: &S, iid: &str, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { sync_one_inner(st, iid, uid, true, true, true).await }
async fn sync_one_inner(st: &S, iid: &str, uid: &str, enforce: bool, manual: bool, webhook: bool) -> Result<String, (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    if webhook && db::s(&row,"kind")=="ssh" { return Err(err(StatusCode::CONFLICT,"incoming SSH sync requires a cancellation-aware adapter")); }
    let eid = db::s(&row, "env_id");
    let (org, app) = if enforce { st.require_env(&eid, uid).await? } else { st.env_org_app(&eid).await? };
    st.require_app_running(&app).await?;
    if st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")) == Some("delegated".into()) {
        enqueue_sync(st, &eid, iid, "sync").await?;
        return Ok("queued for the customer runner".into()); }
    let key = st.env_key(&eid).await?;
    let mut config: Value = serde_json::from_slice(&oc::decrypt_symmetric_compat(&key, &integration_aad(&eid, iid, "config"), &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    let kind = db::s(&row, "kind");
    if !manual && config.get("auto_sync").and_then(Value::as_bool) == Some(false) { return Ok(format!("{}: skipped (auto_sync is disabled)", kind)); }
    integrations::validate_sync_config(&kind, &config).map_err(|e| bad(&e))?;
    let env_name = st.db.one("SELECT name FROM envs WHERE id=?", &[json!(&eid)]).await.map(|r| r.map(|x| db::s(&x, "name")).unwrap_or_default()).unwrap_or_default();
    config["_environment"] = json!(env_name);
    let prev_rows = st.db.query("SELECT remote_name FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]).await.map_err(|e| bad(&e))?;
    let prev: Vec<String> = prev_rows.iter().map(|r| db::s(r, "remote_name")).collect();
    let initial = config.get("initial_sync").and_then(Value::as_str).unwrap_or("overwrite");
    if !matches!(initial, "overwrite" | "import_local" | "import_remote") { return Err(bad("initial_sync must be overwrite, import_local or import_remote")); }
    if initial != "overwrite" && prev.is_empty() {
        if !integrations::is_stateful(&kind) {
            return Err(bad("initial_sync is only supported for stateful sync adapters"));
        }
        let imported = integrations::pull(&kind, &config).await.map_err(|e| bad(&e))?;
        let existing: HashMap<String, String> = st.list_secrets_base(&eid).await?.iter().map(|(k, _, raw)| (k.clone(), raw["type"].as_str().unwrap_or("secret").to_string())).collect();
        let env_key = st.env_key(&eid).await?; let master = st.master();
        let mut count = 0; let mut skipped: Vec<String> = Vec::new(); let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let mut require_one: Vec<usize> = Vec::new();
        for (name, value) in imported {
            let kname = name.trim().to_uppercase();
            if !valid_secret_key(&kname) { skipped.push(name); continue; }
            if initial == "import_local" && existing.contains_key(&kname) { continue; }
            if initial == "import_remote" && existing.get(&kname).map(String::as_str) == Some("sealed") { skipped.push(format!("{} (sealed)", kname)); continue; }
            let s = SecretIn { key: kname, value, path: "/".into(), comment: "imported by integration sync".into(), tags: "import".into(), secret_type: "secret".into(), expected_version: None };
            require_one.push(statements.len()); statements.push(("UPDATE envs SET id=id WHERE id=?".into(), vec![json!(&eid)]));
            require_one.push(statements.len()); statements.extend(secret_statements(st, &eid, &org, &env_key, uid, &s, &master).await?);
            count += 1;
        }
        st.audited_batch_master(&statements, &require_one, [&org, &app, &eid, uid, "integration.import", &format!("{} keys from {}", count, kind)], master).await.map_err(secret_batch_error)?;
        if !skipped.is_empty() { return Err(bad(&format!("imported {} keys but skipped: {}", count, skipped.join(", ")))); }
    }
    // Sealed secrets are never readable, so they must never be pushed: an empty
    // string would overwrite the value on the remote side. Personal overrides are
    // a per-user view and must not become the shared deployed value either.
    let items = st.list_secrets_base(&eid).await?;
    let located: Vec<(String, String, String, String)> = items.iter().filter(|(_, _, raw)| raw["type"].as_str() != Some("sealed") && integrations::path_selected(&config, raw["path"].as_str().unwrap_or("/"))).map(|(k, v, raw)| (raw["path"].as_str().unwrap_or("/").to_string(), k.clone(), v.clone(), raw["type"].as_str().unwrap_or("secret").to_string())).collect();
    let pairs = integrations::secret_keys(&located);
    let mut tags_by_name: HashMap<String, String> = HashMap::new();
    for (k, _, raw) in items.iter().filter(|(_, _, raw)| raw["type"].as_str() != Some("sealed") && integrations::path_selected(&config, raw["path"].as_str().unwrap_or("/"))) {
        tags_by_name.entry(integrations::desired_name(&config, k)).or_insert_with(|| raw["tags"].as_str().unwrap_or("").to_string());
    }
    st.require_app_running(&app).await?;
    if integrations::is_stateful(&kind) {
        let dry = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
        let result = integrations::sync_managed_with_tags(&kind, &config, &located, &tags_by_name, &prev).await.unwrap_or_else(|| Err(format!("unsupported sync kind {}", kind)));
        let (msg, managed) = match result {
            Ok(x) => x,
            Err(e) => {
                if !dry {
                    // Some writes may have landed before the failure; keep ownership of them
                    // so a later mirror sync can still prune the remote.
                    let mut union = prev.clone();
                    let mut names = integrations::desired_names(&config, &pairs);
                    if kind == "ssh" { names = integrations::ssh_owned_names(&config, &located).unwrap_or(names); }
                    for n in names { if !union.contains(&n) { union.push(n); } }
                    let _ = st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]).await;
                    for n in &union { let base = integrations::local_name(&config, n); let hv = pairs.iter().find(|(k, _)| k.as_str() == base).map(|(_, v)| oc::hash_token(v)).unwrap_or_default(); let _ = st.db.exec("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)", &[json!(iid), json!(n), json!(hv)]).await; }
                }
                return Err(bad(&e));
            }
        };
        if !dry {
            let mut statements = vec![("DELETE FROM integration_sync_state WHERE integration_id=?".into(), vec![json!(iid)])];
            for n in &managed { let base = integrations::local_name(&config, n); let hv = pairs.iter().find(|(k, _)| k.as_str() == base).map(|(_, v)| oc::hash_token(v)).unwrap_or_default();
                statements.push(("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)".into(), vec![json!(iid), json!(n), json!(hv)])); }
            st.audited_batch(&statements, &[], [&org, &app, &eid, uid, "integration.sync", &format!("{}: {}", iid, msg)]).await.map_err(|e| bad(&format!("sync succeeded but state could not be saved: {}", e)))?;
            return Ok(msg); }
        st.audit(&org, &app, &eid, uid, "integration.sync", &format!("{}: {}", iid, msg)).await; return Ok(msg); }
    let msg = integrations::sync_with_tags(&kind, &config, &pairs, &tags_by_name).await.map_err(|e| bad(&e))?;
    st.audit(&org, &app, &eid, uid, "integration.sync", &format!("{}: {}", iid, msg)).await; Ok(msg)
}

async fn pitr(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org, app) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    let key = st.env_key(&eid).await.ok();
    let ts = body.get("timestamp").and_then(|v| v.as_i64()).unwrap_or_else(now);
    // Restore the whole environment as it stood at ts: a secret created later
    // must disappear, and a secret deleted before ts must stay deleted.
    let rows = st.db.query("SELECT id,version,deleted_at,path FROM secrets WHERE env_id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?;
    let mut restored = 0; let mut removed = 0; let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let master = st.master();
    let mut checked=Vec::new();
    for r in &rows {
        let sid = db::s(r,"id"); let cur = db::n(r,"version"); let del_at = db::n(r,"deleted_at");
        let v = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND created_at<=? ORDER BY created_at DESC, version DESC LIMIT 1", &[json!(&sid), json!(ts)]).await.map_err(|e| bad(&e))?;
        match v {
            Some(v) => {
                let was_deleted = del_at > 0 && del_at <= ts;
                let new_ver = cur + 1;
                let tomb = if was_deleted { 1 } else { 0 };
                let tomb_at = if was_deleted { if del_at > 0 { del_at } else { now() } } else { 0 };
                let src_ver = db::n(&v, "version");
                let (value_enc, comment_enc, fp, tags_plain, tags_enc) = match key {
                    Some(key) => {
                        let plain_value = decrypt_secret_value(&key, &eid, &sid, "value", src_ver, &db::s(&v,"value_enc")).map_err(|e| bad(&e))?;
                        let plain_comment = decrypt_secret_value(&key, &eid, &sid, "comment", src_ver, &db::s(&v,"comment_enc")).map_err(|e| bad(&e))?;
                        let fp = if db::s(&v,"secret_type") == "secret" { value_fingerprint(&master, &org, &String::from_utf8_lossy(&plain_value)) } else { String::new() };
                        (oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid,&sid,"value",new_ver), &plain_value),
                         oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid,&sid,"comment",new_ver), &plain_comment),
                         fp, String::new(),
                         oc::encrypt_symmetric_aad(&key, &secret_aad(&eid,&sid,"tags"), db::s(&v,"tags").as_bytes()))
                    }
                    None => (db::s(&v,"value_enc"), db::s(&v,"comment_enc"), String::new(), db::s(&v,"tags"), String::new()),
                };
                let vpath = { let p = db::s(r,"path"); if p.is_empty() { let p = db::s(&v,"path"); if p.is_empty() { "/".to_string() } else { p } } else { p } };
                checked.push(statements.len());
                statements.push(("UPDATE secrets SET key_enc=?,value_enc=?,value_fp=?,comment_enc=?,secret_type=?,tags=?,tags_enc=?,version=?,deleted=?,deleted_at=?,updated_at=?,updated_by=? WHERE id=? AND version=?".into(),
                    vec![json!(db::s(&v,"key_enc")), json!(value_enc), json!(&fp), json!(comment_enc), json!(db::s(&v,"secret_type")), json!(tags_plain), json!(tags_enc), json!(new_ver), json!(tomb), json!(tomb_at), json!(now()), json!(&uid), json!(&sid), json!(cur)]));
                statements.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)".into(),
                    vec![json!(id()), json!(&sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(value_enc), json!(comment_enc), json!(db::s(&v,"secret_type")), json!(vpath), json!(db::s(&v,"tags")), json!(now()), json!(&uid)]));
                if was_deleted { removed += 1 } else { restored += 1 }
            }
            None => {
                checked.push(statements.len());
                statements.push(("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=? WHERE id=? AND version=?".into(),vec![json!(now()), json!(now()), json!(&sid), json!(cur)]));
                removed += 1;
            }
        }
    }
    st.audited_rotation_batch(&statements, &checked, [&org,&app,&eid,&uid,"env.pitr",&format!("ts={} restored={} removed={}",ts,restored,removed)], Some(master),"SELECT id FROM rotation_schedules WHERE env_id=? AND (pending_enc<>'' OR execution_token<>'')",&[json!(&eid)]).await.map_err(secret_batch_error)?;
    let _ = trigger_sync(&st, &eid, &uid).await;
    Ok(j(json!({"restored": restored, "removed": removed}))) }


async fn get_org_settings(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let row = st.db.one("SELECT ip_allowlist,reuse_check FROM orgs WHERE id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("org not found"))?;
    let ip = db::s(&row,"ip_allowlist");
    match st.require_org_running(&oid).await {
        Ok(()) => {},
        Err((StatusCode::FORBIDDEN, _)) => return Ok(j(json!({"ip_allowlist": ip, "reuse_check": db::n(&row,"reuse_check") != 0}))),
        Err(e) => return Err(e),
    }
    let secret = meta_get(&st, &format!("oidc_client_secret:{}", oid)).await;
    Ok(j(json!({
        "ip_allowlist": ip,
        "reuse_check": db::n(&row,"reuse_check") != 0,
        "oidc_issuer": meta_get(&st, &format!("oidc_issuer:{}", oid)).await,
        "oidc_client_id": meta_get(&st, &format!("oidc_client_id:{}", oid)).await,
        "oidc_redirect_uri": meta_get(&st, &format!("oidc_redirect_uri:{}", oid)).await,
        "oidc_client_secret_set": !secret.is_empty(),
        "oidc_auto_provision": meta_get(&st, &format!("oidc_auto_provision:{}", oid)).await == "1",
        "oidc_allowed_domains": meta_get(&st, &format!("oidc_allowed_domains:{}", oid)).await,
        "audit_webhook": meta_get(&st, &format!("audit_webhook:{}", oid)).await,
    }))) }
async fn org_settings(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let master = st.master();
    st.check_admin(&oid,&uid).await?;
    let wants_oidc = ["oidc_issuer","oidc_client_id","oidc_client_secret","oidc_redirect_uri","oidc_allowed_domains"].iter()
        .any(|k| body.get(*k).and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false))
        || body.get("oidc_auto_provision").and_then(|v| v.as_bool()) == Some(true);
    if wants_oidc { st.require_enterprise(edition::Feature::OrgOidc)?; }
    if body.get("audit_webhook").and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false) { st.require_enterprise(edition::Feature::AuditStreaming)?; }
    if let Some(v)=body.get("ip_allowlist").and_then(|x|x.as_str()) {
        if !valid_cidr_list(v) { return Err(bad("ip_allowlist must be comma-separated IP addresses or CIDR ranges")); }
        statements.push(("UPDATE orgs SET ip_allowlist=? WHERE id=?".into(), vec![json!(v), json!(&oid)])); }
    if let Some(v)=body.get("reuse_check").and_then(|x|x.as_bool()) {
        statements.push(("UPDATE orgs SET reuse_check=? WHERE id=?".into(), vec![json!(if v {1} else {0}), json!(&oid)])); }
    if let Some(v)=body.get("audit_webhook").and_then(|x|x.as_str()) { if !v.is_empty() && (!url_ok(v) || !egress_allowed(v)) { return Err(bad("audit_webhook must be an http(s) URL outside private networks; set OPENWARP_ALLOW_PRIVATE_EGRESS=1 to allow one")); } statements.extend(meta_statements(&format!("audit_webhook:{}",oid), v)); }
    if let Some(v)=body.get("oidc_redirect_uri").and_then(|x|x.as_str()) { if !v.is_empty() && !url_ok(v) { return Err(bad("oidc_redirect_uri must be an http(s) URL")); } }
    if let Some(v)=body.get("oidc_allowed_domains").and_then(|x|x.as_str()) { if !valid_domain_list(v) { return Err(bad("oidc_allowed_domains must be comma-separated DNS domains")); } }
    // A stored client secret belongs to the issuer that was configured with it.
    // Changing the issuer without supplying a new secret drops the old one so it
    // is never sent to a different identity provider.
    let new_issuer = body.get("oidc_issuer").and_then(|x| x.as_str());
    if let Some(issuer) = new_issuer {
        if !url_ok(issuer) { return Err(bad("oidc_issuer must be an http(s) URL")); }
        let stored_issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)).await;
        let supplied_secret = body.get("oidc_client_secret").and_then(|x| x.as_str()).unwrap_or("");
        if issuer != stored_issuer && supplied_secret.is_empty() { statements.extend(meta_statements(&format!("oidc_client_secret:{}", oid), "")); }
    }
    if let Some(v)=body.get("oidc_auto_provision").and_then(|x|x.as_bool()) { statements.extend(meta_statements(&format!("oidc_auto_provision:{}",oid), if v {"1"} else {"0"})); }
    for (field, enc) in [("oidc_issuer", false), ("oidc_client_id", false), ("oidc_redirect_uri", false), ("oidc_allowed_domains", false), ("oidc_client_secret", true)] {
        if let Some(v)=body.get(field).and_then(|x|x.as_str()) {
            // An omitted secret keeps the stored one; an explicit empty secret
            // clears it only when the caller asks for that.
            if field == "oidc_client_secret" && v.is_empty() && !body.get("clear_oidc_client_secret").and_then(|x|x.as_bool()).unwrap_or(false) { continue; }
            let stored = if enc { oc::encrypt_symmetric(&master, v.as_bytes()) } else { v.to_string() };
            statements.extend(meta_statements(&format!("{}:{}", field, oid), &stored)); } }
    st.audited_batch_master(&statements, &[], [&oid, "", "", &uid, "org.settings", ""], master).await.map_err(master_write_error)?;
    Ok(j(json!({"ok":true}))) }
async fn get_rotation_hook(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid, &uid).await?;
    let hook = st.db.one("SELECT url,secret_enc FROM rotation_hooks WHERE org_id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    Ok(j(match hook { Some(row) => json!({"configured": true, "url": db::s(&row,"url"), "secret_set": !db::s(&row,"secret_enc").is_empty()}), None => json!({"configured": false}) })) }
async fn put_rotation_hook(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new(); let master = st.master();
    st.check_admin(&oid, &uid).await?;
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !url_ok(&url) || !egress_allowed(&url) { return Err(bad("rotation hook url must be http(s) and outside private networks unless OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let secret = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let existing = st.db.one("SELECT secret_enc FROM rotation_hooks WHERE org_id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    let secret_enc = if secret.is_empty() { existing.as_ref().map(|r| db::s(r,"secret_enc")).unwrap_or_default() } else { oc::encrypt_symmetric(&master, secret.as_bytes()) };
    if existing.is_some() {
        statements.push((("UPDATE rotation_hooks SET url=?,secret_enc=? WHERE org_id=?").to_string(), ([json!(&url), json!(&secret_enc), json!(&oid)]).to_vec()));
    } else {
        statements.push((("INSERT INTO rotation_hooks(org_id,url,secret_enc,created_at) VALUES(?,?,?,?)").to_string(), ([json!(&oid), json!(&url), json!(&secret_enc), json!(now())]).to_vec()));
    }
    st.audited_batch_master(&statements, &[], [&oid, "", "", &uid, "rotation_hook.set", &url], master).await.map_err(master_write_error)?; Ok(j(json!({"ok": true}))) }
async fn delete_rotation_hook(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    st.check_admin(&oid, &uid).await?;
    statements.push((("DELETE FROM rotation_hooks WHERE org_id=?").to_string(), ([json!(&oid)]).to_vec()));
    st.audited_batch(&statements, &[], [&oid, "", "", &uid, "rotation_hook.delete", ""]).await.map_err(|e|bad(&e))?; Ok(j(json!({"ok": true}))) }
async fn fire_rotation_hook(st: &S, org: &str, env: &str, key: &str, value: &str) -> Option<String> {
    if let Err(e)=st.epoch_ok().await { return Some(if e.1.0.get("code").and_then(|v|v.as_str())==Some(webhooks::EPOCH_STALE) {"instance key epoch changed".into()} else {"instance key check unavailable".into()}); }
    if st.require_running(org).await.is_err() { return Some("workspace emergency lockdown or unavailable status".into()); }
    let hook = match st.db.one("SELECT url,secret_enc FROM rotation_hooks WHERE org_id=?", &[json!(org)]).await { Ok(Some(r)) => r, _ => return None };
    let url = db::s(&hook, "url"); if url.is_empty() { return None; }
    let secret = { let enc = db::s(&hook, "secret_enc"); if enc.is_empty() { String::new() } else { match oc::decrypt_symmetric(&st.master(), &enc) { Ok(b)=>String::from_utf8_lossy(&b).into_owned(), Err(_)=>return Some("rotation hook secret is unavailable".into()) } } };
    let payload = json!({"event": "secret.rotated", "org_id": org, "env_id": env, "key": key, "value": value, "ts": now()});
    let body = payload.to_string(); let signed_at = now();
    let mut req = http_client().post(&url).header("content-type", "application/json").body(body.clone());
    if !secret.is_empty() { let sig = hmac_hex(secret.as_bytes(), format!("{}.{}", signed_at, body).as_bytes()); req = req.header("X-OpenWarp-Timestamp", signed_at.to_string()).header("X-OpenWarp-Signature", format!("t={},v1={}", signed_at, sig)); }
    match req.send().await { Ok(r) if r.status().is_success() => None, Ok(r) => Some(format!("rotation hook returned HTTP {}", r.status())), Err(e) => Some(e.to_string()) } }
async fn rotate_secret(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org,app)=st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    let key_name = body.get("key").and_then(|v|v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v|v.as_str()).unwrap_or("/");
    let new_val = body.get("value").and_then(|v|v.as_str()).map(|s|s.to_string()).unwrap_or_else(|| oc::random_token("rot"));
    let key = st.env_key(&eid).await?; let kname = key_name.to_uppercase(); let master = st.master();
    let khash = key_index(&key, path, &kname); let legacy = oc::hash_token(&format!("{}:{}", path, kname));
    let row = st.db.one("SELECT id FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid), json!(&khash), json!(&legacy)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found; create it first"))?;
    let mut statements = vec![("UPDATE envs SET id=id WHERE id=?".to_string(), vec![json!(&eid)])];
    statements.extend(secret_statements(&st,&eid,&org,&key,&uid,&SecretIn{key:key_name.into(),value:new_val.clone(),path:path.into(),comment:"auto-rotation".into(),tags:"".into(),secret_type:"secret".into(),expected_version:None},&master).await?);
    st.audited_batch_master(&statements,&[0,1],[&org,&app,&eid,&uid,"secret.rotate",key_name],master).await.map_err(secret_batch_error)?;
    let sync_errors = trigger_sync(&st, &eid, &uid).await;
    let rotation_hook_error = fire_rotation_hook(&st, &org, &eid, key_name, &new_val).await;
    Ok(j(json!({"key":key_name,"value":new_val,"secret_id":db::s(&row,"id"),"sync_errors":sync_errors,"rotation_hook_error":rotation_hook_error}))) }
#[cfg(feature = "scim")]
async fn scim_org(st: &S, h: &HeaderMap, q: &HashMap<String, String>) -> Result<String, (StatusCode, Json<Value>)> {
    st.require_enterprise(edition::Feature::DirectorySync)?;
    if oauth_access(st, h).await.is_some() { return Err(err(StatusCode::FORBIDDEN, "OAuth access tokens cannot call SCIM; use a session or a service token")); }
    let uid = st.token_user(h).await?;
    let oid = q.get("org_id").cloned().unwrap_or_default();
    if oid.is_empty() { return Err(bad("org_id query parameter required")); }
    st.require_running(&oid).await?;
    let role = st.require_org(&oid, &uid).await?;
    if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "SCIM requires admin of this organisation")); }
    st.require_feature(&oid, "scim").await?;
    Ok(oid) }
#[cfg(feature = "scim")]
async fn scim_member(st: &S, org: &str, user: &str) -> bool { st.db.one("SELECT user_id FROM org_members WHERE org_id=? AND user_id=?", &[json!(org), json!(user)]).await.ok().flatten().is_some() }
#[cfg(feature = "scim")]
fn scim_page(q: &HashMap<String, String>) -> (usize, usize) {
    let start = q.get("startIndex").and_then(|s| s.parse::<usize>().ok()).unwrap_or(1).max(1);
    let count = q.get("count").and_then(|s| s.parse::<usize>().ok()).unwrap_or(100).clamp(1, 1000);
    (start, count) }
#[cfg(feature = "scim")]
fn scim_eq_filter(q: &HashMap<String, String>) -> Option<String> {
    q.get("filter").and_then(|f| f.split(" eq ").nth(1)).map(|s| s.trim().trim_matches('"').to_string()) }
#[cfg(feature = "scim")]
async fn scim_service_config() -> impl IntoResponse { Json(json!({
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "patch": {"supported": true}, "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
    "filter": {"supported": true, "maxResults": 1000}, "changePassword": {"supported": false},
    "sort": {"supported": false}, "etag": {"supported": false},
    "authenticationSchemes": [{"type": "bearer", "name": "Bearer", "primary": true}]
})) }
#[cfg(feature = "scim")]
async fn scim_resource_types() -> impl IntoResponse { Json(json!([
    {"id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User"},
    {"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"}
])) }
#[cfg(feature = "scim")]
async fn scim_schemas() -> impl IntoResponse { Json(json!([
    {"id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User",
     "attributes": [{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
                    {"name": "active", "type": "boolean"}, {"name": "emails", "type": "complex", "multiValued": true}]},
    {"id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group",
     "attributes": [{"name": "displayName", "type": "string", "required": true},
                    {"name": "members", "type": "complex", "multiValued": true}]}
])) }
#[cfg(feature = "scim")]
async fn scim_create_user(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res {
    let org = scim_org(&st, &h, &q).await?;
    let email = body.get("userName").and_then(|v| v.as_str()).unwrap_or(""); if email.is_empty() { return Err(bad("userName required")); }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("scim"); let nid = id();
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)", &[json!(nid), json!(email.to_lowercase()), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).await.map_err(|_| bad("user exists"))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')", &[json!(org), json!(nid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"id":nid,"userName":email,"active":true,"temp_password":pw}))) }
#[cfg(feature = "scim")]
async fn scim_list_users(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res {
    let org = scim_org(&st, &h, &q).await?;
    let (start, count) = scim_page(&q); let filter = scim_eq_filter(&q);
    let rows = if let Some(email) = filter {
        st.db.query("SELECT u.id AS id, u.email AS email FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? AND u.email=? ORDER BY u.created_at", &[json!(&org), json!(email.to_lowercase())]).await.map_err(|e| bad(&e))?
    } else {
        st.db.query("SELECT u.id AS id, u.email AS email FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? ORDER BY u.created_at", &[json!(&org)]).await.map_err(|e| bad(&e))?
    };
    let total = rows.len(); let page: Vec<Value> = rows.iter().skip(start - 1).take(count).map(|r| json!({"id":db::s(r,"id"),"userName":db::s(r,"email"),"active":true})).collect();
    let page_len = page.len();
    Ok(j(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": page, "totalResults": total, "startIndex": start, "itemsPerPage": page_len}))) }


async fn create_e2e_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if name.is_empty() || name.len() > 32 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c=='-' || c=='_') { return Err(bad("bad env name")); }
    let user = st.db.one("SELECT pubkey FROM users WHERE id=?", &[json!(uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
    let eid = id();
    let provided = body.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
    let (wrapped, server_generated) = if provided.is_empty() {
        let env_key = oc::random_key(); (oc::encrypt_to(&db::s(&user,"pubkey"), &env_key).map_err(|e| bad(&e))?, true)
    } else { (provided.to_string(), false) };
    st.audited_batch(&[
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(&org)]),
        ("UPDATE apps SET name=name WHERE id=? AND org_id=?".into(), vec![json!(&aid), json!(&org)]),
        ("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,'','e2e',?)".into(), vec![json!(&eid), json!(&aid), json!(&name), json!(now())]),
        ("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)".into(), vec![json!(&eid), json!(&uid), json!(wrapped)]),
    ], &[0,1], [&org, &aid, &eid, &uid, "env.create.e2e", &name]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "workspace or application was deleted before environment creation") } else { bad(&e) })?;
    Ok(j(json!({"id": eid, "mode": "e2e", "server_generated": server_generated}))) }
async fn e2e_put(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"mode")).unwrap_or_default();
    if mode != "e2e" && mode != "delegated" { return Err(bad("env is not client-encrypted")); }
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN, "no wrapped env key for caller")); }
    let mut count = 0; let mut statements: Vec<(String,Vec<Value>)> = Vec::new();
    for s in body.get("secrets").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let key_enc = s.get("key_enc").and_then(|v| v.as_str()).unwrap_or(""); let value_enc = s.get("value_enc").and_then(|v| v.as_str()).unwrap_or("");
        let key_hash = s.get("key_hash").and_then(|v| v.as_str()).unwrap_or("");
        let path_enc = s.get("path_enc").and_then(|v| v.as_str()).unwrap_or("");
        // Legacy clients still send a plaintext path; console clients encrypt it.
        let path = if path_enc.is_empty() { s.get("path").and_then(|v| v.as_str()).unwrap_or("/") } else { "" };
        if key_enc.is_empty() || key_hash.is_empty() { continue; }
        if let Some(row) = st.db.one("SELECT id,version FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid), json!(key_hash), json!(key_hash)]).await.map_err(|e| bad(&e))? {
            let ver = db::n(&row,"version")+1; let sid = db::s(&row,"id");
            statements.push(("UPDATE secrets SET key_enc=?,value_enc=?,path=?,path_enc=?,key_index=?,version=?,updated_at=?,updated_by=? WHERE id=?".into(), vec![json!(key_enc), json!(value_enc), json!(path), json!(path_enc), json!(key_hash), json!(ver), json!(now()), json!(uid), json!(sid)]));
            statements.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)".into(), vec![json!(id()), json!(sid), json!(ver), json!(key_enc), json!(value_enc), json!(&path), json!(""), json!(now()), json!(uid)]));
        } else { let sid = id();
            statements.push(("INSERT INTO secrets(id,env_id,path,path_enc,key_enc,key_hash,key_index,value_enc,e2e,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,1,1,?,?)".into(), vec![json!(sid), json!(eid), json!(path), json!(path_enc), json!(key_enc), json!(key_hash), json!(key_hash), json!(value_enc), json!(now()), json!(uid)]));
            statements.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,path,tags,created_at,created_by) VALUES(?,?,1,?,?,?,?,?,?)".into(), vec![json!(id()), json!(sid), json!(key_enc), json!(value_enc), json!(&path), json!(""), json!(now()), json!(uid)]));
        } count += 1;
    }
    st.audited_batch(&statements, &[], [&org,&app,&eid,&uid,"secret.e2e_deploy",&format!("{} secrets",count)]).await.map_err(|e|bad(&e))?; Ok(j(json!({"deployed": count}))) }
async fn e2e_get(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let wrapped = st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN, "no wrapped env key for caller; ask a member to grant access"))?;
    let rows = st.db.query("SELECT id,path,path_enc,key_hash,key_enc,value_enc,version,updated_at FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1", &[json!(eid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"wrapped_key": db::s(&wrapped,"wrapped_key"), "secrets": rows.iter().map(db::obj).collect::<Vec<_>>()}))) }
async fn e2e_grant(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN, "caller has no env key to grant")); }
    let email = body.get("email").and_then(|v| v.as_str()).unwrap_or(""); let wrapped = body.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
    if email.is_empty() || wrapped.is_empty() { return Err(bad("email and wrapped_key (wrapped client-side for grantee) required")); }
    let target = st.db.one("SELECT id FROM users WHERE email=?", &[json!(email.to_lowercase())]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("user not found"))?;
    if st.db.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(eid), json!(db::s(&target,"id")), json!(wrapped)]).await.is_err() {
        st.db.exec("UPDATE env_keys SET wrapped_key=? WHERE env_id=? AND user_id=?", &[json!(wrapped), json!(eid), json!(db::s(&target,"id"))]).await.map_err(|e| bad(&e))?;
    }
    Ok(j(json!({"ok": true}))) }
async fn e2e_grants(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let rows = st.db.query("SELECT k.user_id AS user_id, u.email AS email, u.pubkey AS pubkey FROM env_keys k JOIN users u ON u.id=k.user_id WHERE k.env_id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn e2e_meta(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let env = st.db.one("SELECT mode,runner_id FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
    let runner = if db::s(&env, "runner_id").is_empty() { Value::Null } else {
        st.db.one("SELECT id,pubkey FROM runners WHERE id=?", &[json!(db::s(&env, "runner_id"))]).await.ok().flatten()
            .map(|r| json!({"id": db::s(&r,"id"), "public_key": db::s(&r,"pubkey")})).unwrap_or(Value::Null) };
    Ok(j(json!({"mode": db::s(&env, "mode"), "runner": runner, "rekey_required": meta_get(&st, &format!("rekey_required:{}", eid)).await == "1"}))) }
async fn e2e_rekey(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    let env = st.db.one("SELECT mode,runner_id FROM envs WHERE id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
    let mode = db::s(&env, "mode");
    if mode != "e2e" && mode != "delegated" { return Err(bad("only client-encrypted environments can be rekeyed")); }
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(&eid), json!(&uid)]).await.map_err(|e| bad(&e))?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "caller has no grant for this environment")); }
    let secrets = body.get("secrets").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if secrets.is_empty() { return Err(bad("secrets array required")); }
    let mut current = std::collections::HashSet::new();
    for r in st.db.query("SELECT key_hash FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1", &[json!(&eid)]).await.map_err(|e| bad(&e))? { current.insert(db::s(&r, "key_hash")); }
    let mut incoming = std::collections::HashSet::new();
    for s in &secrets {
        let kh = s.get("key_hash").and_then(|v| v.as_str()).unwrap_or("");
        if kh.is_empty() || s.get("key_enc").and_then(|v| v.as_str()).unwrap_or("").is_empty() || s.get("value_enc").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
            return Err(bad("each secret needs key_hash, key_enc and value_enc")); }
        incoming.insert(kh.to_string());
    }
    if incoming != current { return Err(bad("the rekey payload must cover exactly the environment's current secrets; refresh and retry")); }

    let grants = body.get("grants").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if grants.is_empty() { return Err(bad("grants array required")); }
    let current_grants: std::collections::HashSet<String> = st.db.query("SELECT user_id FROM env_keys WHERE env_id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?
        .iter().map(|r| db::s(r, "user_id")).collect();
    let mut ids = std::collections::HashSet::new();
    for g in &grants {
        let gid = g.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
        let wrapped = g.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
        if gid.is_empty() || wrapped.is_empty() { return Err(bad("each grant needs user_id and wrapped_key")); }
        if !current_grants.contains(gid) { return Err(bad("a rekey may remove grants but cannot add a grantee who does not already hold the key; grant access first")); }
        if st.db.one("SELECT id FROM users WHERE id=?", &[json!(gid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad("grant refers to an unknown user")); }
        ids.insert(gid.to_string());
    }
    if !ids.contains(&uid) { return Err(bad("the new grants must include the caller, or the environment would become unreadable to them")); }
    let remove_user = body.get("remove_user").and_then(|v| v.as_str()).unwrap_or("");
    if !remove_user.is_empty() {
        if remove_user == uid { return Err(bad("the caller cannot remove their own grant in a rekey")); }
        if !current_grants.contains(remove_user) { return Err(bad("remove_user has no grant in this environment")); }
        if ids.contains(remove_user) { return Err(bad("remove_user cannot also appear in the new grants")); }
    }
    let runner_wrapped = body.get("runner_wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
    if mode == "delegated" {
        if runner_wrapped.is_empty() { return Err(bad("runner_wrapped_key required for a delegated environment")); }
        if st.db.one("SELECT 1 AS n FROM runner_env_keys WHERE runner_id=? AND env_id=?", &[json!(db::s(&env, "runner_id")), json!(&eid)]).await.map_err(|e| bad(&e))?.is_none() {
            return Err(bad("this environment has no runner key grant to update")); }
    }

    let mut rekeyed = 0;
    let mut stmts: Vec<(String, Vec<Value>)> = Vec::new();
    for s in &secrets {
        let kh = s.get("key_hash").and_then(|v| v.as_str()).unwrap_or("");
        let key_enc = s.get("key_enc").and_then(|v| v.as_str()).unwrap_or("");
        let value_enc = s.get("value_enc").and_then(|v| v.as_str()).unwrap_or("");
        let path_enc = s.get("path_enc").and_then(|v| v.as_str()).unwrap_or("");
        if path_enc.is_empty() { return Err(bad("path_enc is required in the rekey payload")); }
        let path_val = "";
        let existing = st.db.one("SELECT id,version FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0 AND e2e=1", &[json!(&eid), json!(kh)]).await.map_err(|e| bad(&e))?;
        let (sid, ver) = match existing {
            Some(r) => (db::s(&r, "id"), db::n(&r, "version") + 1),
            None => { return Err(bad("rekey payload does not match the stored secrets")); }
        };
        stmts.push(("UPDATE secrets SET key_enc=?,value_enc=?,path=?,path_enc=?,key_index=?,version=?,updated_at=?,updated_by=? WHERE id=?".into(),
            vec![json!(key_enc), json!(value_enc), json!(path_val), json!(path_enc), json!(kh), json!(ver), json!(now()), json!(&uid), json!(&sid)]));
        // Old history is encrypted under the old key and cannot be read after
        // the rotation; replace it rather than leave undecryptable rows.
        stmts.push(("DELETE FROM secret_versions WHERE secret_id=?".into(), vec![json!(&sid)]));
        stmts.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)".into(),
            vec![json!(id()), json!(&sid), json!(ver), json!(key_enc), json!(value_enc), json!(path_val), json!(""), json!(now()), json!(&uid)]));
        rekeyed += 1;
    }
    stmts.push(("DELETE FROM env_keys WHERE env_id=?".into(), vec![json!(&eid)]));
    for g in &grants {
        let gid = g.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
        let wrapped = g.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
        stmts.push(("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)".into(), vec![json!(&eid), json!(gid), json!(wrapped)]));
    }
    if mode == "delegated" {
        stmts.push(("UPDATE runner_env_keys SET wrapped_key=? WHERE runner_id=? AND env_id=?".into(),
            vec![json!(runner_wrapped), json!(db::s(&env, "runner_id")), json!(&eid)]));
    }
    // One transaction: a failed grant write must not leave the environment
    // re-encrypted under a key nobody can unwrap.
    stmts.extend(meta_statements(&format!("rekey_required:{}", eid), "0"));
    let detail = if remove_user.is_empty() { format!("{} secrets, {} grants", rekeyed, grants.len()) } else { format!("{} secrets, {} grants, removed {}", rekeyed, grants.len(), remove_user) };
    st.audited_batch(&stmts, &[], [&org, &app, &eid, &uid, "e2e.rekey", &detail]).await.map_err(|e| bad(&format!("rekey did not complete: {}", e)))?;
    Ok(j(json!({"rekeyed": rekeyed, "grants": grants.len()}))) }
async fn e2e_revoke(State(st): State<S>, h: HeaderMap, Path((eid, target)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?;
    let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:write").await?;
    let mut statements=vec![("DELETE FROM env_keys WHERE env_id=? AND user_id=?".into(), vec![json!(&eid), json!(&target)])];
    statements.extend(meta_statements(&format!("rekey_required:{}", eid), "1"));
    st.audited_batch(&statements, &[0], [&org,&app,&eid,&uid,"e2e.revoke",&target]).await.map_err(|e| if e.contains("version conflict") {err(StatusCode::NOT_FOUND,"no key grant for that user")} else {bad(&e)})?; Ok(j(json!({"revoked": target, "rekey_required": true}))) }
async fn user_lookup(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?;
    let email = q.get("email").cloned().unwrap_or_default();
    // One response for "no such account" and "exists but shares no organisation"
    // so the endpoint is not an account-existence oracle.
    let denied = || err(StatusCode::FORBIDDEN, "no user with this email shares an organisation with you");
    let row = st.db.one("SELECT id,email,pubkey FROM users WHERE email=?", &[json!(email.to_lowercase())]).await.map_err(|e| bad(&e))?.ok_or_else(denied)?;
    let tid = db::s(&row, "id");
    if tid != uid { let shared = st.db.query("SELECT a.org_id FROM org_members a JOIN org_members b ON b.org_id=a.org_id WHERE a.user_id=? AND b.user_id=?", &[json!(uid), json!(&tid)]).await.map_err(|e| bad(&e))?; if shared.is_empty() { return Err(denied()); } }
    Ok(j(json!({"id": db::s(&row,"id"), "email": db::s(&row,"email"), "pubkey": db::s(&row,"pubkey")}))) }


pub(crate) async fn meta_get(st: &S, k: &str) -> String { st.db.one("SELECT v FROM meta WHERE k=?", &[json!(k)]).await.ok().flatten().map(|r| db::s(&r,"v")).unwrap_or_default() }
// Seed or verify the instance key epoch before traffic and background workers.
// This operation writes only the instance key fingerprint to webhook_serialization.
pub async fn seed_epoch(db: &Db, master: &[u8;32]) -> Result<(),String> {
    let master=*master;
    db.webhook_atomic(move |tx| { webhooks::epoch_lock(tx,&master)?; Ok(()) }).await
}
// One pass over pre-existing secrets. New writes compute their fingerprint
// inline, so this only needs to run once per database.
pub async fn backfill_value_fingerprints(st: &S) {
    if st.epoch_ok().await.is_err() { return; }
    #[cfg(not(target_arch="wasm32"))] let _guard=st.lifecycle.read().await;
    if st.db.one("SELECT v FROM meta WHERE k='migration:value_fp'", &[]).await.ok().flatten().is_some() { return; }
    let rows = match st.db.query("SELECT id,env_id,version,value_enc,secret_type,e2e FROM secrets WHERE value_fp='' AND deleted=0", &[]).await { Ok(rows) => rows, Err(_) => return };
    let mut keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut orgs: HashMap<String, String> = HashMap::new();
    let mut failed = false; let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let master = st.master();
    for row in &rows {
        if db::n(row, "e2e") == 1 || db::s(row, "secret_type") != "secret" { continue; }
        let eid = db::s(row, "env_id");
        let key = match keys.get(&eid) {
            Some(k) => *k,
            None => match st.env_key(&eid).await { Ok(k) => { keys.insert(eid.clone(), k); k }, Err(_) => continue },
        };
        let org = match orgs.get(&eid) {
            Some(o) => o.clone(),
            None => match st.env_org_app(&eid).await { Ok((o, _)) => { orgs.insert(eid.clone(), o.clone()); o }, Err(_) => continue },
        };
        let value = match decrypt_secret_value(&key, &eid, &db::s(row, "id"), "value", db::n(row, "version"), &db::s(row, "value_enc")) { Ok(v) => v, Err(_) => continue };
        if value.is_empty() { continue; }
        let fp = value_fingerprint(&master, &org, &String::from_utf8_lossy(&value));
        // If a concurrent write replaced the ciphertext, keep the fingerprint
        // that write just computed instead of overwriting it with a stale one.
        statements.push(("UPDATE secrets SET value_fp=? WHERE id=? AND value_enc=?".into(), vec![json!(fp), json!(db::s(row, "id")), json!(db::s(row, "value_enc"))]));
    }
    if !failed && !statements.is_empty() && st.epoch_write(&statements, &[], master).await.is_err() { failed = true; }
    if !failed { meta_set(st, "migration:value_fp", &now().to_string()).await; } }
fn url_ok(u: &str) -> bool { let u = u.trim().to_ascii_lowercase(); (u.starts_with("https://") || u.starts_with("http://")) && !u.contains(' ') && !u.contains('\n') }
// Admin-configured URLs are trusted, but production should not be usable as a
// probe into loopback or private networks. Self-hosted services can opt out.
pub(crate) fn egress_allowed(u: &str) -> bool {
    if crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false) { return true; }
    if !crate::envcfg::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) { return true; }
    let Ok(url) = reqwest::Url::parse(u) else { return false };
    let Some(host) = url.host_str() else { return false };
    if host.eq_ignore_ascii_case("localhost") { return false; }
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()),
            std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local()),
        };
    }
    true }
// Outbound OIDC/SAML metadata may only use TLS, except for a loopback IdP used in
// development or tests. The URL is parsed so credentials cannot disguise the
// host: string slicing reads `http://[::1]@host` as loopback while the request
// actually goes to `host` over plain HTTP. Metadata-service hosts are refused.
pub(crate) fn issuer_url_ok(issuer: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(issuer.trim()) else { return false };
    if u.scheme() != "https" && u.scheme() != "http" { return false; }
    if !u.username().is_empty() || u.password().is_some() { return false; }
    let Some(host) = u.host_str() else { return false };
    if host.contains("169.254.169.254") || host.eq_ignore_ascii_case("metadata.google.internal") { return false; }
    if u.scheme() == "https" { return true; }
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost") || host == "[::1]" }
// A bracketed IPv6 literal contains colons, so it has to be read as a unit
// before the port is stripped. Only the host-parsing tests call this.
#[cfg(test)]
fn url_host(u: &str) -> &str {
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://")).unwrap_or(u);
    let rest = rest.split('/').next().unwrap_or("");
    match (rest.starts_with('['), rest.find(']')) {
        (true, Some(end)) => &rest[..=end],
        _ => rest.split(':').next().unwrap_or("") } }
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn http_client() -> crate::http::Client { crate::http::Client::builder().timeout(std::time::Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| crate::http::Client::new()) }
#[cfg(target_arch = "wasm32")]
pub(crate) fn http_client() -> crate::http::Client { crate::http::Client::new() }
// Dynamic database leases dial a host from the request. Nothing may dial unless
// the operator named that host: this is the SSRF boundary for the feature.
fn db_target_allowed(conn: &str) -> Result<&'static str, String> {
    let allow = crate::envcfg::var("OPENWARP_ALLOWED_DB_HOSTS").unwrap_or_default();
    let entries: Vec<String> = allow.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if entries.is_empty() { return Err("dynamic database leases are disabled; set OPENWARP_ALLOWED_DB_HOSTS=host[:port],... to enable them".into()); }
    let lower = conn.to_ascii_lowercase();
    let (scheme, targets) = if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        ("postgres", crate::pglease::targets(conn)?)
    } else if lower.starts_with("mysql://") || lower.starts_with("mariadb://") {
        ("mysql", crate::mysqllease::targets(conn)?)
    } else { return Err("connection string must be a postgres://, mysql:// or mariadb:// URL".into()) };
    if targets.len() != 1 { return Err("multi-host connection strings are not allowed".into()); }
    let (host, port) = &targets[0];
    let target = format!("{}:{}", host, port);
    if entries.iter().any(|e| e == host || e == &target || e == &format!("[{}]:{}", host, port)) { return Ok(scheme); }
    Err(format!("{} host is not permitted; OPENWARP_ALLOWED_DB_HOSTS must list {} (allowed: {})", scheme, target, entries.join(","))) }
async fn oidc_discovery(issuer: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    http_client().get(&url).send().await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string())) }
async fn oidc_start(State(st): State<S>, Path(oid): Path<String>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    st.require_enterprise(edition::Feature::OrgOidc)?;
    // Per-workspace SSO is configured by that workspace's admins, so it is not
    // governed by the instance-wide sign-in method switch.
    st.epoch_ok().await?;
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)).await; let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)).await; let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid)).await;
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid)).await;
    let client_secret = oc::decrypt_symmetric(&st.master(), &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).map_err(|e| bad(&format!("OIDC client secret is unavailable: {}", e)))?;
    if issuer.is_empty() || client_id.is_empty() || redirect_uri.is_empty() { return Err(bad("OIDC not configured for this org (set oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri via org settings)")); }
    if client_secret.is_empty() { return Err(bad("OIDC client secret is not configured or was cleared by an issuer change; re-enter the client secret in org settings")); }
    if !issuer_url_ok(&issuer) || !egress_allowed(&issuer) { return Err(bad("OIDC issuer must be https, or http on a loopback address; private addresses need OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let disc = oidc_discovery(&issuer).await?; let auth_ep = disc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    if !url_ok(auth_ep) || !egress_allowed(auth_ep) { return Err(bad("OIDC discovery returned no usable authorization_endpoint")); }
    let state = oc::random_token("st"); let nonce = oc::random_token("n");
    st.db.exec("INSERT INTO oidc_states(state,org_id,created_at,nonce) VALUES(?,?,?,?)", &[json!(state), json!(oid), json!(now()), json!(nonce)]).await.map_err(|e| bad(&e))?;
    let url = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&nonce={}", auth_ep, urlencode(&client_id), urlencode(&redirect_uri), state, nonce);
    Ok(axum::response::Redirect::temporary(&url)) }
fn urlencode(s: &str) -> String { s.chars().map(|c| match c { 'A'..='Z'|'a'..='z'|'0'..='9'|'-'|'_'|'.'|'~' => c.to_string(), _ => format!("%{:02X}", c as u32) }).collect() }
async fn oidc_callback(State(st): State<S>, Query(q): Query<HashMap<String,String>>) -> Result<axum::response::Response, (StatusCode, Json<Value>)> {
    st.epoch_ok().await?;
    let code = q.get("code").cloned().unwrap_or_default(); let state = q.get("state").cloned().unwrap_or_default();
    let srow = st.db.one("SELECT org_id,created_at,nonce FROM oidc_states WHERE state=?", &[json!(state)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    let oid = db::s(&srow, "org_id"); let expected_nonce = db::s(&srow, "nonce");
    let _ = st.db.exec("DELETE FROM oidc_states WHERE state=?", &[json!(state)]).await;
    if db::n(&srow, "created_at") + 600 < now() { return Err(bad("invalid or expired state")); }
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)).await; let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)).await; let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid)).await;
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid)).await; let client_secret = oc::decrypt_symmetric(&st.master(), &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).map_err(|e| bad(&format!("OIDC client secret is unavailable: {}", e)))?;
    if !issuer_url_ok(&issuer) || !egress_allowed(&issuer) { return Err(bad("OIDC issuer must be https, or http on a loopback address; private addresses need OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let disc = oidc_discovery(&issuer).await?;
    let (subject, email) = oidc_identity_from_doc(&disc, &issuer, &client_id, &client_secret, &redirect_uri, &code, "", &expected_nonce, false, if issuer.contains("login.microsoftonline.com") { "microsoft" } else { "oidc" }).await.map_err(|e| bad(&e))?;
    let issuer_key = issuer.clone();
    // A pending invite admits an account, but membership requires explicit token acceptance.
    let pending = st.db.one("SELECT token_hash FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(&email), json!(&oid), json!(now())]).await.map_err(|e| bad(&e))?;
    let auto = meta_get(&st, &format!("oidc_auto_provision:{}", oid)).await == "1";
    let domains = meta_get(&st, &format!("oidc_allowed_domains:{}", oid)).await;
    let domain = email.split('@').nth(1).unwrap_or("");
    let domain_ok = domains.is_empty() || domains.split(',').any(|d| d.trim().eq_ignore_ascii_case(domain));
    let provision_allowed = pending.is_some() || (auto && domain_ok && signups_open(&st).await);
    let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let mut require_one: Vec<usize> = Vec::new(); let mut newly_provisioned = false;
    let uid = if let Some(bound) = st.db.one("SELECT user_id FROM oidc_subjects WHERE issuer=? AND subject=?", &[json!(issuer_key), json!(subject)]).await.map_err(|e| bad(&e))? { db::s(&bound, "user_id") } else {
        if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).await.map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password, or ask an organisation admin to link this identity")); }
        st.require_org_running(&oid).await?;
        if !provision_allowed { return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow SSO self-provisioning; ask an administrator to invite you or enable it in organisation settings")); }
        let kp = oc::Keypair::generate(); let pw = oc::random_token("oidc"); let nid = id();
        let pass_hash = oc::hash_password(&pw).map_err(|e| bad(&e))?;
        let wrapped = oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
        // The organisation's IdP asserted this address; no local verification.
        statements.push(("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)".into(), vec![json!(nid), json!(email), json!(pass_hash), json!(kp.public), json!(wrapped), json!(now())]));
        statements.push(("INSERT INTO oidc_subjects(issuer,subject,user_id,created_at) VALUES(?,?,?,?)".into(), vec![json!(issuer_key), json!(subject), json!(nid), json!(now())]));
        newly_provisioned = true;
        nid };
    if let Some(u) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(uid)]).await.map_err(|e| bad(&e))? { if db::n(&u, "active") == 0 { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); } }
    if st.org_role(&oid, &uid).await.is_none() {
        st.require_org_running(&oid).await?;
        // The invitee accepts the invitation token explicitly; login alone joins nobody.
        if pending.is_none() {
            if auto && domain_ok && signups_open(&st).await {
                require_one.push(statements.len()); statements.push(("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')".into(), vec![json!(&oid), json!(&uid)]));
            } else {
                return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow SSO self-provisioning; ask an administrator to invite you or enable it in organisation settings"));
            }
        } }
    st.audited_batch(&statements, &require_one, [&oid,"","",&uid,"auth.oidc_login",&format!("{} sub={}", email, subject)]).await.map_err(|e| if e.contains("version conflict") {err(StatusCode::CONFLICT, "account or ownership changed; refresh and try again")} else {bad(&e)})?;
    if newly_provisioned { claim_instance_owner(&st, &uid).await; }
    if mfa::required(&st, &uid).await {
        let challenge = mfa::new_challenge(&st, &uid).await?;
        return Ok(axum::response::Redirect::temporary(&format!("/#mfa={}&org={}", challenge, oid)).into_response()); }
    let token = make_session(&st, &uid).await?;
    // Every other login helper sets the account-session cookie; emergency
    // endpoints require it and reject any Authorization header.
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, axum::response::Redirect::temporary(&format!("/#token={}&org={}", token, oid))).into_response()) }

// ---------- SAML 2.0 service provider ----------
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
struct SamlReplayCache { st: S }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
impl ReplayCache for SamlReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        let expires = expires_at.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_else(|_| now() + 600);
        // The risaml trait is synchronous but this runs inside the async ACS
        // handler. Move the DB write onto the runtime without nesting runtimes
        // in the normal multi-thread server; unit callers use a fresh runtime.
        let st = self.st.clone();
        let stored = cache_key.clone();
        let write = async move {
            st.db.exec("INSERT INTO saml_replay(key,expires_at) VALUES(?,?)", &[json!(stored), json!(expires)]).await
        };
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(write)),
            Err(_) => match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(write),
                Err(e) => Err(e.to_string()),
            },
        };
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(SamlError::ReplayDetected { key: cache_key }),
        } } }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn saml_config_row(st: &S, org: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    st.db.one("SELECT * FROM saml_configs WHERE org_id=?", &[json!(org)]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "SAML is not configured for this organisation")) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
fn saml_sp_entity(base: &str, org: &str) -> String { format!("{}/api/auth/saml/{}/metadata", base.trim_end_matches('/'), org) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
fn saml_acs_url(base: &str, org: &str) -> String { format!("{}/api/auth/saml/{}/acs", base.trim_end_matches('/'), org) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
fn saml_signing_keypair(cn: &str) -> Result<(String, String), String> {
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|e| e.to_string())?;
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).map_err(|e| e.to_string())?.to_string();
    let kp = rcgen::KeyPair::from_pem(&pem).map_err(|e| e.to_string())?;
    let cert = ca_params(cn, false).self_signed(&kp).map_err(|e| e.to_string())?;
    Ok((pem, cert.pem())) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
fn saml_descriptor(idp_entity: &str, xml: &str, trusted_cert: &str, allow_unsigned: bool) -> Result<IdpDescriptor, String> {
    let entity = EntityId::try_new(idp_entity).map_err(|e| e.to_string())?;
    if !trusted_cert.trim().is_empty() {
        let certs = [CertificatePem::new(trusted_cert.trim().to_string())];
        IdpDescriptor::from_metadata_xml_for(entity, xml, MetadataTrustPolicy::RequireSignature { trusted_certificates: &certs }).map_err(|e| e.to_string())
    } else if allow_unsigned {
        IdpDescriptor::from_metadata_xml_for(entity, xml, MetadataTrustPolicy::UnsignedForCompatibility).map_err(|e| e.to_string())
    } else { Err("SAML metadata must be signed by metadata_trusted_cert, or set allow_unsigned_metadata".into()) } }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
fn saml_sp_config(st: &S, base: &str, org: &str, cfg: &Row) -> Result<SpConfig, String> {
    let key_pem = oc::decrypt_symmetric(&st.master(), &db::s(cfg,"sp_key_enc")).map_err(|e| e.to_string())?;
    let creds = Credentials {
        signing_key: Some(PrivateKeyPem::new(String::from_utf8_lossy(&key_pem).into_owned())),
        signing_certificate: Some(CertificatePem::new(db::s(cfg,"sp_cert_pem"))),
        ..Credentials::default() };
    SpConfig::builder(EntityId::try_new(saml_sp_entity(base, org)).map_err(|e| e.to_string())?)
        .acs_endpoint(AcsEndpoint::post(saml_acs_url(base, org)).map_err(|e| e.to_string())?)
        .credentials(creds)
        .validation(SpValidationPolicy::strict())
        .build().map_err(|e| e.to_string()) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn get_saml_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid, &uid).await?; st.require_enterprise(edition::Feature::OrgSso)?; st.require_feature(&oid, "saml").await?;
    let base = issuer(&st, &h);
    let Some(cfg) = st.db.one("SELECT * FROM saml_configs WHERE org_id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))? else {
        return Ok(j(json!({
            "configured": false,
            "idp_entity_id": "",
            "metadata_xml": "",
            "sp_metadata_url": saml_sp_entity(&base, &oid),
            "acs_url": saml_acs_url(&base, &oid),
            "allow_unsigned_metadata": false,
            "metadata_trusted_cert_set": false,
            "auto_provision": false,
            "allowed_domains": "",
        }))); };
    Ok(j(json!({
        "configured": true,
        "idp_entity_id": db::s(&cfg,"idp_entity_id"),
        "metadata_xml": db::s(&cfg,"idp_metadata_xml"),
        "sp_metadata_url": saml_sp_entity(&base, &oid),
        "acs_url": saml_acs_url(&base, &oid),
        "allow_unsigned_metadata": db::n(&cfg,"allow_unsigned_metadata") == 1,
        "metadata_trusted_cert_set": !db::s(&cfg,"metadata_trusted_cert").is_empty(),
        "auto_provision": db::n(&cfg,"auto_provision") == 1,
        "allowed_domains": db::s(&cfg,"allowed_domains"),
    }))) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn put_saml_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid, &uid).await?;
    st.require_feature(&oid, "saml").await?;
    st.require_enterprise(edition::Feature::OrgSso)?;
    let idp_entity_id = body.get("idp_entity_id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if idp_entity_id.is_empty() { return Err(bad("idp_entity_id is required")); }
    let mut xml = body.get("metadata_xml").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let metadata_url = body.get("metadata_url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if xml.is_empty() && !metadata_url.is_empty() {
        if !url_ok(&metadata_url) || !egress_allowed(&metadata_url) { return Err(bad("metadata_url must be an http(s) URL outside private networks")); }
        let text = http_client().get(&metadata_url).send().await.map_err(|e| bad(&e.to_string()))?.text().await.map_err(|e| bad(&e.to_string()))?;
        if text.len() > 2_000_000 { return Err(bad("SAML metadata is too large")); }
        xml = text;
    }
    if xml.is_empty() { return Err(bad("metadata_xml or metadata_url is required")); }
    let trusted_cert = body.get("metadata_trusted_cert").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let allow_unsigned = body.get("allow_unsigned_metadata").and_then(|v| v.as_bool()).unwrap_or(false);
    let auto = body.get("auto_provision").and_then(|v| v.as_bool()).unwrap_or(false);
    let domains = body.get("allowed_domains").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !valid_domain_list(&domains) { return Err(bad("allowed_domains must be comma-separated DNS domains")); }
    saml_descriptor(&idp_entity_id, &xml, &trusted_cert, allow_unsigned).map_err(|e| bad(&format!("invalid IdP metadata: {}", e)))?;
    let existing = st.db.one("SELECT sp_key_enc,sp_cert_pem FROM saml_configs WHERE org_id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    let master = st.master();
    let (key_enc, cert_pem) = match existing {
        Some(ref row) => (db::s(row,"sp_key_enc"), db::s(row,"sp_cert_pem")),
        None => {
            let (key_pem, cert_pem) = saml_signing_keypair(&format!("openwarp-saml-{}", oid)).map_err(|e| bad(&e))?;
            (oc::encrypt_symmetric(&master, key_pem.as_bytes()), cert_pem)
        }
    };
    let statements = if existing.is_some() {
        vec![("UPDATE saml_configs SET idp_entity_id=?,idp_metadata_xml=?,allow_unsigned_metadata=?,metadata_trusted_cert=?,auto_provision=?,allowed_domains=? WHERE org_id=?".into(),
            vec![json!(&idp_entity_id), json!(&xml), json!(if allow_unsigned {1} else {0}), json!(&trusted_cert), json!(if auto {1} else {0}), json!(&domains), json!(&oid)])]
    } else {
        vec![("INSERT INTO saml_configs(org_id,idp_entity_id,idp_metadata_xml,sp_key_enc,sp_cert_pem,allow_unsigned_metadata,metadata_trusted_cert,auto_provision,allowed_domains,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)".into(),
            vec![json!(&oid), json!(&idp_entity_id), json!(&xml), json!(&key_enc), json!(&cert_pem), json!(if allow_unsigned {1} else {0}), json!(&trusted_cert), json!(if auto {1} else {0}), json!(&domains), json!(now())])]
    };
    st.audited_batch_master(&statements, &[], [&oid, "", "", &uid, "saml.configure", &idp_entity_id], master).await.map_err(master_write_error)?;
    Ok(j(json!({"ok": true, "sp_metadata_url": saml_sp_entity(&issuer(&st,&h), &oid)}))) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn saml_metadata(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Response {
    if let Err(e)=st.epoch_ok().await { return e.into_response(); }
    if !st.feature_granted(&oid, "saml").await { return err(StatusCode::FORBIDDEN, "SAML sign-in is not enabled for this workspace").into_response(); }
    let cfg = match saml_config_row(&st, &oid).await { Ok(c) => c, Err(e) => return e.into_response() };
    let sp = match saml_sp_config(&st, &issuer(&st,&h), &oid, &cfg).and_then(|c| Saml::sp(c).map_err(|e| e.to_string())) { Ok(s) => s, Err(e) => return bad(&e).into_response() };
    let mut resp = sp.metadata_xml().to_string().into_response();
    resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/samlmetadata+xml"));
    resp }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn saml_start(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Response {
    if let Err(e)=st.epoch_ok().await { return e.into_response(); }
    if let Err(e) = st.require_enterprise(edition::Feature::OrgSso) { return e.into_response(); }
    // This endpoint is reached by a browser navigation, so a workspace without
    // the grant gets the sign-in screen back with a readable reason rather
    // than a JSON error body.
    if !st.feature_granted(&oid, "saml").await { return axum::response::Redirect::temporary("/#error=saml_not_enabled").into_response(); }
    let cfg = match saml_config_row(&st, &oid).await { Ok(c) => c, Err(e) => return e.into_response() };
    let base = issuer(&st, &h);
    let sp = match saml_sp_config(&st, &base, &oid, &cfg).and_then(|c| Saml::sp(c).map_err(|e| e.to_string())) { Ok(s) => s, Err(e) => return bad(&e).into_response() };
    let idp = match saml_descriptor(&db::s(&cfg,"idp_entity_id"), &db::s(&cfg,"idp_metadata_xml"), &db::s(&cfg,"metadata_trusted_cert"), db::n(&cfg,"allow_unsigned_metadata") == 1) { Ok(d) => d, Err(e) => return bad(&e).into_response() };
    let state = oc::random_token("saml");
    let relay = match RelayStateParam::try_from_option(Some(state.clone())) { Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let started = match sp.start_sso(&idp, StartSso::redirect().relay_state(relay)) { Ok(s) => s, Err(e) => return bad(&e.to_string()).into_response() };
    let url = match started.outbound.redirect_url() { Ok(u) => u.to_string(), Err(e) => return bad(&e.to_string()).into_response() };
    let snap = started.pending.snapshot();
    let snapshot = json!({
        "id": snap.id, "peer": snap.peer_entity_id, "expected": snap.expected_binding,
        "acs": snap.acs_url, "acs_binding": snap.acs_binding,
        "issued": snap.issued_at.as_ref().map(|v| v.as_str()), "expires": snap.expires_at.as_ref().map(|v| v.as_str())
    }).to_string();
    let _ = st.db.exec("DELETE FROM saml_pending WHERE created_at<?", &[json!(now() - 600)]).await;
    if let Err(e) = st.db.exec("INSERT INTO saml_pending(state,org_id,snapshot,created_at) VALUES(?,?,?,?)", &[json!(&state), json!(&oid), json!(&snapshot), json!(now())]).await { return bad(&e).into_response(); }
    axum::response::Redirect::temporary(&url).into_response() }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn provision_saml_user(st: &S, org: &str, idp_entity: &str, name_id: &str, email: &str) -> Result<String, (StatusCode, Json<Value>)> {
    if let Some(bound) = st.db.one("SELECT user_id FROM saml_subjects WHERE org_id=? AND idp_entity_id=? AND name_id=?", &[json!(org), json!(idp_entity), json!(name_id)]).await.map_err(|e| bad(&e))? {
        let uid = db::s(&bound, "user_id");
        if !st.principal_active(&uid).await { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        if st.org_role(org, &uid).await.is_none() {
            st.require_org_running(org).await?;
            // A pending invitation admits the account; membership still needs explicit token acceptance.
            let pending = st.db.one("SELECT id FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(email), json!(org), json!(now())]).await.map_err(|e| bad(&e))?;
            if pending.is_none() { return Err(err(StatusCode::FORBIDDEN, "this account is no longer a member of this organisation; ask an administrator to invite you again")); }
        }
        return Ok(uid);
    }
    st.require_org_running(org).await?;
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).await.map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password or ask an admin to link this SAML identity"));
    }
    let cfg = saml_config_row(st, org).await?;
    let pending = st.db.one("SELECT role,token_hash FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(email), json!(org), json!(now())]).await.map_err(|e| bad(&e))?;
    let auto = db::n(&cfg, "auto_provision") == 1;
    let domains = db::s(&cfg, "allowed_domains");
    let domain = email.split('@').nth(1).unwrap_or("");
    let domain_ok = domains.is_empty() || domains.split(',').any(|d| d.trim().eq_ignore_ascii_case(domain));
    if pending.is_none() && !(auto && domain_ok && signups_open(st).await) {
        return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow SAML self-provisioning; ask an administrator to invite you"));
    }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("saml"); let uid = id();
    let pass_hash = oc::hash_password(&pw).map_err(|e| bad(&e))?;
    let wrapped = oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    // Invitation-backed accounts join only through explicit token acceptance.
    let mut statements = vec![
        ("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)".into(),
            vec![json!(&uid), json!(email), json!(pass_hash), json!(kp.public), json!(wrapped), json!(now())]),
        ("INSERT INTO saml_subjects(org_id,idp_entity_id,name_id,user_id,created_at) VALUES(?,?,?,?,?)".into(),
            vec![json!(org), json!(idp_entity), json!(name_id), json!(&uid), json!(now())]),
    ];
    if pending.is_none() { statements.push(("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')".into(), vec![json!(org), json!(&uid)])); }
    st.audited_batch(&statements, &[], [org, "", "", &uid, "auth.saml_provision", &format!("{} {}", email, name_id)]).await.map_err(|e| bad(&e))?;
    claim_instance_owner(st, &uid).await;
    Ok(uid) }
#[cfg(all(feature = "saml", not(target_arch = "wasm32")))]
async fn saml_acs(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> Response {
    if let Err(e)=st.epoch_ok().await { return e.into_response(); }
    if !st.feature_granted(&oid, "saml").await { return err(StatusCode::FORBIDDEN, "SAML sign-in is not enabled for this workspace").into_response(); }
    let pending_row = match st.db.one("SELECT * FROM saml_pending WHERE org_id=? AND state=?", &[json!(&oid), json!(form.get("RelayState").cloned().unwrap_or_default())]).await { Ok(Some(r)) => r, _ => return bad("SAML request is missing, expired, or already used").into_response() };
    if db::n(&pending_row,"created_at") + 600 < now() { return bad("SAML request expired").into_response(); }
    let snapshot: Value = match serde_json::from_str(&db::s(&pending_row,"snapshot")) { Ok(v) => v, Err(_) => return bad("SAML pending request is corrupt").into_response() };
    let cfg = match saml_config_row(&st, &oid).await { Ok(c) => c, Err(e) => return e.into_response() };
    let base = issuer(&st, &h);
    let sp = match saml_sp_config(&st, &base, &oid, &cfg).and_then(|c| Saml::sp(c).map_err(|e| e.to_string())) { Ok(s) => s, Err(e) => return bad(&e).into_response() };
    let idp = match saml_descriptor(&db::s(&cfg,"idp_entity_id"), &db::s(&cfg,"idp_metadata_xml"), &db::s(&cfg,"metadata_trusted_cert"), db::n(&cfg,"allow_unsigned_metadata") == 1) { Ok(d) => d, Err(e) => return bad(&e).into_response() };
    let relay = match RelayStateParam::try_from_option(form.get("RelayState").cloned()) { Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let mut snap = PendingSnapshot::<AuthnRequest>::authn_request(
        snapshot["id"].as_str().unwrap_or("").to_string(), relay,
        snapshot["peer"].as_str().unwrap_or("").to_string(),
        snapshot["expected"].as_str().unwrap_or("post").to_string(),
        snapshot["acs"].as_str().unwrap_or("").to_string(),
        snapshot["acs_binding"].as_str().unwrap_or("post").to_string());
    if let Some(i) = snapshot["issued"].as_str() { if let Ok(v) = SamlInstant::try_new(i) { snap.issued_at = Some(v); } }
    if let Some(e) = snapshot["expires"].as_str() { if let Ok(v) = SamlInstant::try_new(e) { snap.expires_at = Some(v); } }
    let pending = match Pending::<AuthnRequest>::from_snapshot(snap) { Ok(p) => p, Err(e) => return bad(&e.to_string()).into_response() };
    let mut cache = SamlReplayCache { st: st.clone() };
    let ctx = SamlValidationContext::new(crate::clock::system_time(), ReplayPolicy::RequireCache(&mut cache));
    let fields: Vec<FormField> = form.iter().map(|(k,v)| FormField::new(k.clone(), v.clone())).collect();
    let session = match sp.finish_sso(&idp, &pending, BrowserInput::<SsoResponse>::post(fields), ctx) { Ok(s) => s, Err(e) => return bad(&format!("SAML validation failed: {}", e)).into_response() };
    let name_id = session.name_id().value().to_string(); let email = name_id.to_lowercase();
    if !valid_email(&email) { return bad("SAML NameID must be an email address; configure the IdP NameID format").into_response(); }
    let uid = match provision_saml_user(&st, &oid, &db::s(&cfg,"idp_entity_id"), &name_id, &email).await { Ok(u) => u, Err(e) => return e.into_response() };
    let _ = st.db.exec("DELETE FROM saml_pending WHERE state=?", &[json!(form.get("RelayState").cloned().unwrap_or_default())]).await;
    if mfa::required(&st, &uid).await {
        let challenge = match mfa::new_challenge(&st, &uid).await { Ok(c) => c, Err(e) => return e.into_response() };
        return axum::response::Redirect::temporary(&format!("/#mfa={}&org={}", challenge, oid)).into_response(); }
    let token = match make_session(&st, &uid).await { Ok(t) => t, Err(e) => return e.into_response() };
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    (hdr, axum::response::Redirect::to(&format!("/#org={}", oid))).into_response() }
// ---------- LDAP directory sign-in ----------
// The directory validates the password, so this path shares the password
// login's rate limits, MFA challenge and audit trail. It is compiled out when
// the `ldap` feature is off (a Workers/WASM build has no raw TCP sockets).
#[cfg(feature = "ldap")]
async fn ldap_row(st: &S, org: &str) -> Result<Option<Row>, (StatusCode, Json<Value>)> {
    st.db.one("SELECT * FROM ldap_configs WHERE org_id=?", &[json!(org)]).await.map_err(|e| bad(&e)) }
#[cfg(feature = "ldap")]
async fn role_known(st: &S, org: &str, role: &str) -> bool {
    matches!(role, "owner" | "admin" | "developer")
        || st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(org), json!(role)]).await.ok().flatten().is_some() }
#[cfg(feature = "ldap")]
const DIR_UNAVAILABLE: &str = "directory sign-in is unavailable; ask an administrator to check the workspace LDAP configuration";
// Display names and DNs come from the directory; control characters would let
// a directory entry forge lines in plain-text audit consumers.
#[cfg(feature = "ldap")]
fn audit_safe(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).take(200).collect() }
#[cfg(feature = "ldap")]
fn ldap_config_from_row(st: &S, row: &Row) -> Result<ldap::DirectoryConfig, (StatusCode, Json<Value>)> {
    let enc = db::s(row, "bind_password_enc");
    let bind_password = if enc.is_empty() { String::new() } else {
        oc::decrypt_symmetric(&st.master(), &enc).map(|b| String::from_utf8_lossy(&b).into_owned()).map_err(|e| bad(&e))? };
    Ok(ldap::DirectoryConfig {
        url: db::s(row, "url"), bind_dn: db::s(row, "bind_dn"), bind_password,
        base_dn: db::s(row, "base_dn"), user_filter: db::s(row, "user_filter"),
        email_attr: db::s(row, "email_attr"), name_attr: db::s(row, "name_attr"),
        group_attr: db::s(row, "group_attr"), group_roles: db::s(row, "group_roles"),
        ca_cert_pem: db::s(row, "ca_cert_pem"), allowed_domains: db::s(row, "allowed_domains") }) }
#[cfg(feature = "ldap")]
async fn get_ldap_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid, &uid).await?;
    st.require_feature(&oid, "ldap").await?;
    st.require_enterprise(edition::Feature::DirectorySync)?;
    let Some(row) = ldap_row(&st, &oid).await? else { return Ok(j(json!({"configured": false}))) };
    Ok(j(json!({
        "configured": !db::s(&row, "url").is_empty(),
        "url": db::s(&row, "url"), "bind_dn": db::s(&row, "bind_dn"),
        "bind_password_set": !db::s(&row, "bind_password_enc").is_empty(),
        "base_dn": db::s(&row, "base_dn"), "user_filter": db::s(&row, "user_filter"),
        "email_attr": db::s(&row, "email_attr"), "name_attr": db::s(&row, "name_attr"),
        "group_attr": db::s(&row, "group_attr"), "group_roles": db::s(&row, "group_roles"),
        "default_role": db::s(&row, "default_role"),
        "auto_provision": db::n(&row, "auto_provision") == 1,
        "allowed_domains": db::s(&row, "allowed_domains"),
        "ca_cert_pem": db::s(&row, "ca_cert_pem"),
    }))) }
#[cfg(feature = "ldap")]
fn ldap_field(body: &Value, row: Option<&Row>, key: &str) -> String {
    body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .or_else(|| row.map(|r| db::s(r, key))).unwrap_or_default() }
#[cfg(feature = "ldap")]
async fn put_ldap_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid, &uid).await?;
    st.require_feature(&oid, "ldap").await?;
    st.require_enterprise(edition::Feature::DirectorySync)?;
    let existing = ldap_row(&st, &oid).await?;
    let url = ldap_field(&body, existing.as_ref(), "url");
    if !ldap::url_ok(&url) { return Err(bad("LDAP URL must be ldaps:// (TLS is required); ldap:// and STARTTLS are not accepted")); }
    if !egress_allowed(&url) { return Err(bad("LDAP URL resolves to a private or loopback address; set OPENWARP_ALLOW_PRIVATE_EGRESS=1 to allow a self-hosted directory")); }
    let bind_dn = ldap_field(&body, existing.as_ref(), "bind_dn");
    if bind_dn.is_empty() || bind_dn.contains('\0') { return Err(bad("bind_dn is required: LDAP search needs a service account")); }
    let base_dn = ldap_field(&body, existing.as_ref(), "base_dn");
    if base_dn.is_empty() { return Err(bad("base_dn is required")); }
    let user_filter = ldap_field(&body, existing.as_ref(), "user_filter");
    let user_filter = if user_filter.is_empty() { "(uid={username})".to_string() } else { user_filter };
    if !user_filter.contains("{username}") { return Err(bad("user_filter must contain the {username} placeholder")); }
    if user_filter.contains('\0') || user_filter.contains('\n') { return Err(bad("user_filter must be a single LDAP filter")); }
    let email_attr = ldap_field(&body, existing.as_ref(), "email_attr");
    let email_attr = if email_attr.is_empty() { "mail".to_string() } else { email_attr };
    let name_attr = ldap_field(&body, existing.as_ref(), "name_attr");
    let name_attr = if name_attr.is_empty() { "displayName".to_string() } else { name_attr };
    let group_attr = ldap_field(&body, existing.as_ref(), "group_attr");
    let group_attr = if group_attr.is_empty() { "memberOf".to_string() } else { group_attr };
    if !ldap::valid_attr(&email_attr) || !ldap::valid_attr(&name_attr) { return Err(bad("email_attr and name_attr must be LDAP attribute names")); }
    if !group_attr.is_empty() && !ldap::valid_attr(&group_attr) { return Err(bad("group_attr must be an LDAP attribute name")); }
    let group_roles = ldap_field(&body, existing.as_ref(), "group_roles");
    if !ldap::valid_mapping(&group_roles) { return Err(bad("group_roles must be Group=role pairs separated by semicolons")); }
    // A mapping to a role that does not exist yet would pass the permission
    // check below with an empty permission set and start granting privileges
    // the moment an admin creates that role.
    let mut unknown_mapping = false;
    for (_, role) in group_roles.split(';').filter_map(|p| p.rsplit_once('=')) {
        if !role_known(&st, &oid, role.trim()).await { unknown_mapping = true; break; }
    }
    if unknown_mapping {
        return Err(bad("group_roles may only reference roles that exist in this organisation; create the role first")); }
    let default_role = ldap_field(&body, existing.as_ref(), "default_role");
    let default_role = if default_role.is_empty() { "developer".to_string() } else { default_role };
    if !role_known(&st, &oid, &default_role).await { return Err(bad("default_role must be owner, admin, developer or a custom role in this organisation")); }
    // The membership API lets only an owner grant owner or admin; a directory
    // mapping must not become the side door around that rule. Custom roles are
    // checked by effective permissions, because one carrying "*" or
    // "org:admin" is admin by another name.
    let requested = std::iter::once(default_role.clone()).chain(
        group_roles.split(';').filter_map(|p| p.rsplit_once('=')).map(|(_, r)| r.trim().to_string()));
    let mut privileged = false;
    for role in requested {
        if st.role_perms(&oid, &role).await.iter().any(|p| p == "*" || p == "org:admin") { privileged = true; break; }
    }
    if privileged && st.require_org(&oid, &uid).await? != "owner" {
        return Err(err(StatusCode::FORBIDDEN, "only an owner can map a role with admin rights through LDAP")); }
    let allowed_domains = ldap_field(&body, existing.as_ref(), "allowed_domains");
    if !valid_domain_list(&allowed_domains) { return Err(bad("allowed_domains must be comma-separated DNS domains")); }
    let ca_cert_pem = ldap_field(&body, existing.as_ref(), "ca_cert_pem");
    if !ca_cert_pem.is_empty() && native_tls::Certificate::from_pem(ca_cert_pem.as_bytes()).is_err() {
        return Err(bad("ca_cert_pem is not a PEM certificate")); }
    if url.len() > 512 || bind_dn.len() > 512 || base_dn.len() > 512 || user_filter.len() > 512 || group_roles.len() > 1024 || ca_cert_pem.len() > 16384 {
        return Err(bad("LDAP configuration value is too long")); }
    let auto = body.get("auto_provision").and_then(|v| v.as_bool())
        .unwrap_or_else(|| existing.as_ref().map(|r| db::n(r, "auto_provision") == 1).unwrap_or(false));
    let url_changed = existing.as_ref().map(|r| db::s(r, "url") != url).unwrap_or(false);
    let supplied = body.get("bind_password").and_then(|v| v.as_str()).unwrap_or("");
    let stored = existing.as_ref().map(|r| db::s(r, "bind_password_enc")).unwrap_or_default();
    let master = st.master();
    let password_enc = if supplied.is_empty() { stored } else { oc::encrypt_symmetric(&master, supplied.as_bytes()) };
    if password_enc.is_empty() { return Err(bad("bind_password is required: LDAP search needs a service account")); }
    let mut statements: Vec<(String,Vec<Value>)> = if existing.is_some() {
        vec![("UPDATE ldap_configs SET url=?,bind_dn=?,bind_password_enc=?,base_dn=?,user_filter=?,email_attr=?,name_attr=?,group_attr=?,group_roles=?,default_role=?,auto_provision=?,allowed_domains=?,ca_cert_pem=?,updated_at=? WHERE org_id=?".into(),
            vec![json!(&url), json!(&bind_dn), json!(&password_enc), json!(&base_dn), json!(&user_filter), json!(&email_attr), json!(&name_attr), json!(&group_attr), json!(&group_roles), json!(&default_role), json!(if auto {1} else {0}), json!(&allowed_domains), json!(&ca_cert_pem), json!(now()), json!(&oid)])]
    } else {
        vec![("INSERT INTO ldap_configs(org_id,url,bind_dn,bind_password_enc,base_dn,user_filter,email_attr,name_attr,group_attr,group_roles,default_role,auto_provision,allowed_domains,ca_cert_pem,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)".into(),
            vec![json!(&oid), json!(&url), json!(&bind_dn), json!(&password_enc), json!(&base_dn), json!(&user_filter), json!(&email_attr), json!(&name_attr), json!(&group_attr), json!(&group_roles), json!(&default_role), json!(if auto {1} else {0}), json!(&allowed_domains), json!(&ca_cert_pem), json!(now())])]
    };
    // Bindings belong to the directory that was configured when they were
    // created. A new endpoint must not inherit them, or an admin could point
    // the URL at a directory that asserts an existing member's DN.
    if url_changed { statements.push(("DELETE FROM ldap_subjects WHERE org_id=?".into(), vec![json!(&oid)])); }
    st.audited_batch_master(&statements, &[], [&oid, "", "", &uid, "ldap.configure", &format!("{} url_changed={}", url, url_changed)], master).await.map_err(master_write_error)?;
    Ok(j(json!({"ok": true}))) }
#[cfg(feature = "ldap")]
async fn delete_ldap_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid, &uid).await?;
    st.require_feature(&oid, "ldap").await?;
    st.audited_batch(&[
        ("DELETE FROM ldap_configs WHERE org_id=?".into(), vec![json!(&oid)]),
        ("DELETE FROM ldap_subjects WHERE org_id=?".into(), vec![json!(&oid)]),
    ], &[], [&oid, "", "", &uid, "ldap.delete", ""]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"ok": true}))) }
#[cfg(feature = "ldap")]
#[derive(Deserialize)] struct LdapLoginReq { org_id: String, username: String, password: String }
#[cfg(feature = "ldap")]
async fn ldap_login(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<LdapLoginReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    st.epoch_ok().await?;
    st.require_enterprise(edition::Feature::DirectorySync)?;
    let org = r.org_id.trim().to_string();
    if !st.feature_granted(&org, "ldap").await { return Err(err(StatusCode::FORBIDDEN, "Directory sign-in is not enabled for this workspace")); }
    let username = r.username.trim().to_string();
    // Two budgets: one per account and one per address, so spraying many names
    // from one host is limited even when each name is tried only once.
    let ip_key = format!("ldap-ip:{}", addr);
    if !st.rate_ok(&ip_key, 30, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many directory sign-in attempts from this address; try again later")); }
    let key = format!("ldap:{}:{}:{}", addr, org, username.to_lowercase());
    if !st.rate_ok(&key, 5, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed directory sign-in attempts; try again later")); }
    // Count before contacting the directory: a read-then-write check lets
    // concurrent guesses all pass while no failure has been recorded yet.
    st.rate_fail(&key, 900).await; st.rate_fail(&ip_key, 900).await;
    if org.is_empty() { return Err(bad("org_id is required")); }
    let Some(row) = ldap_row(&st, &org).await? else { return Err(bad("LDAP sign-in is not configured for this workspace; ask an administrator to set it up")); };
    let cfg = ldap_config_from_row(&st, &row)?;
    if !ldap::url_ok(&cfg.url) { return Err(bad("the stored LDAP URL is not ldaps://; an administrator must correct the workspace LDAP configuration")); }
    if !egress_allowed(&cfg.url) { return Err(bad("LDAP URL is on a private or loopback address; set OPENWARP_ALLOW_PRIVATE_EGRESS=1 to allow a self-hosted directory")); }
    if username.len() > 256 || r.password.len() > 1024 { return Err(bad("username or password is too long")); }
    let attempt = tokio::time::timeout(std::time::Duration::from_secs(20), ldap::authenticate(&cfg, &username, &r.password)).await;
    let user = match attempt {
        Err(_) => return Err(err(StatusCode::SERVICE_UNAVAILABLE, DIR_UNAVAILABLE)),
        // An ambiguous match reveals directory structure, so it gets the same
        // answer as a wrong password.
        Ok(Err(ldap::DirectoryError::Denied)) | Ok(Err(ldap::DirectoryError::Ambiguous)) => {
            return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
        Ok(Err(ldap::DirectoryError::Unavailable(e))) => {
            eprintln!("LDAP directory error: {}", e);
            return Err(err(StatusCode::SERVICE_UNAVAILABLE, DIR_UNAVAILABLE)); }
        Ok(Ok(u)) => u };
    st.rate_clear(&key).await;
    if !ldap::valid_email(&user.email) { return Err(bad("the directory entry has no usable email attribute; check email_attr")); }
    let mapped = match ldap::mapping_role(&cfg.group_roles, &user.groups) {
        Some(role) if role_known(&st, &org, &role).await => Some(role),
        _ => None,
    };
    let pending = st.db.one("SELECT role,token_hash FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(&user.email), json!(&org), json!(now())]).await.map_err(|e| bad(&e))?;
    let domain = user.email.rsplit_once('@').map(|(_, d)| d).unwrap_or("").to_string();
    let domain_ok = cfg.allowed_domains.is_empty() || cfg.allowed_domains.split(',').any(|d| d.trim().eq_ignore_ascii_case(&domain));
    let bound = st.db.one("SELECT user_id,role FROM ldap_subjects WHERE org_id=? AND dn=?", &[json!(&org), json!(&user.dn)]).await.map_err(|e| bad(&e))?;
    let stored_role = bound.as_ref().map(|b| db::s(b, "role")).unwrap_or_default();
    let uid = if let Some(b) = &bound {
        let uid = db::s(b, "user_id");
        if !st.principal_active(&uid).await { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        uid
    } else {
        st.require_org_running(&org).await?;
        if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&user.email)]).await.map_err(|e| bad(&e))?.is_some() {
            return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password, or ask an organisation admin to link this identity"));
        }
        // Same gate as OIDC: an invitation, or explicitly enabled
        // self-provisioning for an allowed email domain while signups are open.
        if pending.is_none() && !(db::n(&row, "auto_provision") == 1 && domain_ok && signups_open(&st).await) {
            return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow LDAP self-provisioning; ask an administrator to invite you or enable it in organisation settings"));
        }
        let kp = oc::Keypair::generate(); let pw = oc::random_token("ldap"); let nid = id();
        let pass_hash = oc::hash_password(&pw).map_err(|e| bad(&e))?;
        let wrapped = oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
        st.audited_batch(&[
            ("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)".into(),
                vec![json!(&nid), json!(&user.email), json!(pass_hash), json!(kp.public), json!(wrapped), json!(now())]),
            ("INSERT INTO ldap_subjects(org_id,dn,user_id,created_at) VALUES(?,?,?,?)".into(),
                vec![json!(&org), json!(&user.dn), json!(&nid), json!(now())]),
        ], &[], [&org, "", "", &nid, "auth.ldap_provision", &format!("{} {} dn={}", audit_safe(&user.email), audit_safe(&user.name), audit_safe(&user.dn))]).await.map_err(|e| bad(&e))?;
        claim_instance_owner(&st, &nid).await;
        nid };
    let locked = match st.require_org_running(&org).await { Ok(()) => false, Err((StatusCode::FORBIDDEN, _)) => true, Err(e) => return Err(e) };
    let audit_detail = format!("{} {} dn={}", audit_safe(&user.email), audit_safe(&user.name), audit_safe(&user.dn));
    let audit: [&str;6] = [&org, "", "", &uid, "auth.ldap_credentials", &audit_detail];
    if st.org_role(&org, &uid).await.is_none() {
        st.require_org_running(&org).await?;
        // Pending invitations admit an account, never a directory-derived membership.
        if pending.is_none() {
            if bound.is_some() {
                return Err(err(StatusCode::FORBIDDEN, "this account is no longer a member of this organisation; ask an administrator to invite you again"));
            }
            let role = mapped.clone().unwrap_or_else(|| db::s(&row, "default_role"));
            add_provisioned_member(&st, &org, &uid, &role).await?;
            // Only group-mapped roles are directory-derived and subject to later revocation.
            let mapped_role = if mapped.is_some() { role } else { String::new() };
            let _ = st.db.exec("UPDATE ldap_subjects SET role=? WHERE org_id=? AND dn=?", &[json!(&mapped_role), json!(&org), json!(&user.dn)]).await;
        }
    } else if !locked {
        let current = st.org_role(&org, &uid).await.unwrap_or_default();
        if let Some(role) = &mapped {
            // The directory's group mapping stays authoritative, except that it
            // never demotes an owner: a group change must not lock out the only one.
            if &current != role && current != "owner" {
                user_guarded_commit(&st, &[&uid], &[
                    ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(&uid)]),
                    ("UPDATE org_members SET role=? WHERE org_id=? AND user_id=? AND role<>'owner'".into(), vec![json!(role), json!(&org), json!(&uid)]),
                    ("UPDATE ldap_subjects SET role=? WHERE org_id=? AND dn=?".into(), vec![json!(role), json!(&org), json!(&user.dn)]),
                ], &[0, 1], Some(audit)).await?;
            } else if current != "owner" {
                st.audited_batch(&[("UPDATE ldap_subjects SET role=? WHERE org_id=? AND dn=?".into(), vec![json!(role), json!(&org), json!(&user.dn)])], &[], audit).await.map_err(|e| bad(&e))?;
            } else { st.audited_batch(&[], &[], audit).await.map_err(|e| bad(&e))?; }
        } else if !stored_role.is_empty() && current == stored_role && current != "owner" {
            // The user left the mapped group: revoke a directory-granted role,
            // unless a human has changed it since.
            let fallback = db::s(&row, "default_role");
            user_guarded_commit(&st, &[&uid], &[
                ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(&uid)]),
                ("UPDATE org_members SET role=? WHERE org_id=? AND user_id=? AND role=? AND role<>'owner'".into(), vec![json!(&fallback), json!(&org), json!(&uid), json!(&stored_role)]),
                ("UPDATE ldap_subjects SET role='' WHERE org_id=? AND dn=?".into(), vec![json!(&org), json!(&user.dn)]),
            ], &[0, 1], Some(audit)).await?;
        } else { st.audited_batch(&[], &[], audit).await.map_err(|e| bad(&e))?; }
    } else { st.audited_batch(&[], &[], audit).await.map_err(|e| bad(&e))?; }
    if mfa::required(&st, &uid).await {
        st.audit(&org, "", "", &uid, "auth.ldap_mfa_challenge", &audit_safe(&user.email)).await;
        let challenge = mfa::new_challenge(&st, &uid).await?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge,
            "methods": mfa::methods(&st, &uid).await, "email_available": mfa::email_available() && mfa::email_enabled(&st, &uid).await})))); }
    let token = make_session(&st, &uid).await?;
    st.audit(&org, "", "", &uid, "auth.ldap_login", &format!("{} dn={}", audit_safe(&user.email), audit_safe(&user.dn))).await;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    let pubkey = st.db.one("SELECT pubkey FROM users WHERE id=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "pubkey")).unwrap_or_default();
    Ok((hdr, j(json!({"token": token, "user_id": uid, "public_key": pubkey})))) }

// ---------- deployment jurisdiction ----------
// A jurisdiction is a deployment boundary: its own database and its own master
// key. The label comes from deployment configuration, never from a tenant row,
// so it cannot disagree with where the data actually lives.
const REGION_DEFAULT: &str = "global";
fn region_label_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') }
pub fn region() -> String {
    crate::envcfg::var("OPENWARP_REGION").ok().map(|v| v.trim().to_ascii_lowercase()).filter(|v| region_label_ok(v)).unwrap_or_else(|| REGION_DEFAULT.to_string()) }
// `label=origin` entries for the jurisdictions a sign-in can be elected into.
// Empty means this deployment is the only one, so the console states the
// jurisdiction but offers no switch.
// A hand-off target is an origin the browser navigates to, so it is parsed
// rather than pattern-matched: a string test lets `http://localhost:80@host`
// read as loopback while the browser goes to `host` over plain HTTP. The
// published value is the parsed origin, so a spelling like `https:eu.example`
// still reaches the console as a real origin instead of the raw string.
fn canonical_region_origin(origin: &str) -> Result<String, String> {
    let invalid = || format!("OPENWARP_REGIONS origin {:?} must be an origin with no credentials, query or path: https, or http on a loopback host", origin);
    let u = reqwest::Url::parse(origin).map_err(|_| invalid())?;
    if !u.username().is_empty() || u.password().is_some() { return Err(invalid()); }
    if u.query().is_some() || u.fragment().is_some() { return Err(invalid()); }
    if u.path() != "/" && !u.path().is_empty() { return Err(invalid()); }
    let Some(host) = u.host_str() else { return Err(invalid()) };
    let loopback = host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost") || host == "[::1]" || host == "::1";
    match u.scheme() { "https" => (), "http" if loopback => (), _ => return Err(invalid()) }
    Ok(u.origin().ascii_serialization()) }
fn parse_regions(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() { continue; }
        let (label, origin) = entry.split_once('=').ok_or_else(|| format!("OPENWARP_REGIONS entry {:?} must be label=origin", entry))?;
        let label = label.trim().to_ascii_lowercase();
        let origin = canonical_region_origin(origin.trim())?;
        if !region_label_ok(&label) { return Err(format!("OPENWARP_REGIONS label {:?} must be 1-32 characters of a-z, 0-9 or '-'", label)); }
        if out.iter().any(|(l, _)| l == &label) { return Err(format!("OPENWARP_REGIONS lists the jurisdiction {:?} twice", label)); }
        out.push((label, origin)); }
    Ok(out) }
fn region_choices() -> Vec<Value> {
    crate::envcfg::var("OPENWARP_REGIONS").ok().and_then(|raw| parse_regions(&raw).ok()).unwrap_or_default()
        .into_iter().map(|(label, origin)| json!({"label": label, "origin": origin})).collect() }
/// A jurisdiction list that omits this deployment would send a user to a host
/// that cannot authenticate them, so refuse to start rather than mislabel it.
fn validate_regions(here_raw: Option<&str>, list_raw: Option<&str>) -> Result<(), String> {
    let here = match here_raw.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => { let v = v.to_ascii_lowercase();
            if !region_label_ok(&v) { return Err(format!("OPENWARP_REGION {:?} must be 1-32 characters of a-z, 0-9 or '-'", v)); }
            v }
        None => REGION_DEFAULT.to_string() };
    let choices = match list_raw { Some(raw) => parse_regions(raw)?, None => return Ok(()) };
    if choices.is_empty() { return Ok(()); }
    if !choices.iter().any(|(l, _)| l == &here) {
        return Err(format!("OPENWARP_REGIONS does not list this deployment's region {:?}", here)); }
    Ok(()) }
pub fn validate_region_env() -> Result<(), String> {
    let here = crate::envcfg::var("OPENWARP_REGION").ok();
    let list = crate::envcfg::var("OPENWARP_REGIONS").ok();
    validate_regions(here.as_deref(), list.as_deref()) }

// ---------- email, verification and password reset ----------
pub fn production() -> bool {
    crate::envcfg::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) }
// The operator supplies a small HTTP relay that forwards {to,subject,text} to
// their mail provider. Without one, mail is suppressed; outside production the
// rendered message (including its link) is written to the log so a local
// operator can finish signup or recovery.
async fn send_template(to: &str, kind: &str, vars: &[(&str, &str)]) {
    let cfg = mailer::MailConfig::from_env();
    let msg = mailer::render(kind, to, vars);
    if !cfg.enabled() {
        eprintln!("email suppressed (no provider configured): {} -> {}", kind, to);
        if !production() { eprintln!("{}", msg.text); }
        return; }
    if let Err(e) = mailer::send(&cfg, &msg).await { eprintln!("email delivery failed: {}", e); } }
// Security codes need the delivery outcome, so they use the fallible variant.
// Outside production a suppressed message still counts as delivered: the code
// is written to the operator log, which is how the local walkthrough works.
pub(crate) async fn send_email_result(to: &str, subject: &str, text: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let cfg = mailer::MailConfig::from_env();
    if !cfg.enabled() {
        if production() { return Err(err(StatusCode::SERVICE_UNAVAILABLE, "email delivery is not configured on this instance")); }
        eprintln!("email suppressed (no provider configured): {} -> {}\n{}", subject, to, text);
        return Ok(());
    }
    let msg = mailer::MailMessage { to: to.to_string(), subject: subject.to_string(), text: text.to_string(),
        html: format!("<p>{}</p>", esc(text).replace('\n', "<br>")) };
    mailer::send(&cfg, &msg).await.map_err(|_| err(StatusCode::BAD_GATEWAY, "the email relay rejected the message"))
}
async fn test_email(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "instance owner required")); }
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if to.is_empty() { return Err(bad("to is required")); }
    let cfg = mailer::MailConfig::from_env();
    if !cfg.enabled() { return Err(bad("no email provider is configured")); }
    let msg = mailer::render("test", to, &[]);
    mailer::send(&cfg, &msg).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"ok": true, "provider": cfg.provider}))) }
async fn issue_auth_token(st: &S, uid: &str, kind: &str, ttl: i64) -> String {
    let token = oc::random_token(kind);
    let _ = st.db.exec("INSERT INTO auth_tokens(token_hash,user_id,kind,created_at,expires_at) VALUES(?,?,?,?,?)", &[json!(oc::hash_token(&token)), json!(uid), json!(kind), json!(now()), json!(now() + ttl)]).await;
    token }
#[derive(Deserialize)] struct EmailReq { email: String }
#[derive(Deserialize)] struct ResetReq { token: String, password: String, #[serde(default)] recovery_kit: String, #[serde(default)] discard_e2e_key: bool }
async fn verify_email(State(st): State<S>, Query(q): Query<HashMap<String,String>>) -> Response {
    let token = q.get("token").cloned().unwrap_or_default(); let hash = oc::hash_token(token.trim());
    let found = st.db.one("SELECT user_id FROM auth_tokens WHERE token_hash=? AND kind='verify' AND used=0 AND expires_at>?", &[json!(&hash), json!(now())]).await.ok().flatten();
    let (status, title, detail) = match found {
        Some(row) => { let uid = db::s(&row, "user_id");
            match st.audited_batch(&[
                ("UPDATE users SET email_verified=1 WHERE id=?".into(), vec![json!(&uid)]),
                ("UPDATE auth_tokens SET used=1 WHERE token_hash=?".into(), vec![json!(&hash)]),
            ], &[], ["", "", "", &uid, "auth.email_verified", ""]).await {
                Ok(()) => { claim_instance_owner_on_verify(&st, &uid).await; (StatusCode::OK, "Email verified", "You can sign in now.") }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Verification failed", "Try again shortly.") } }
        None => (StatusCode::BAD_REQUEST, "Link not valid", "This verification link is invalid, already used, or expired.") };
    let mut r = Html(format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>OpenWarp</title></head><body style=\"margin:0;background:#08080c;color:#eceaf8;font:15px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;min-height:100vh\"><main style=\"max-width:520px;padding:28px\"><h1 style=\"font-size:20px\">{}</h1><p style=\"color:#9a97b3\">{}</p><p><a style=\"color:#9d8fff\" href=\"/\">Open the console</a></p></main></body></html>", esc(title), esc(detail))).into_response();
    *r.status_mut() = status;
    r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(OAUTH_CSP));
    r }
async fn forgot_password(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Json(r): Json<EmailReq>) -> Res {
    if !auth_enabled(&st, "password").await { return Ok(j(json!({"ok": true, "note": "if that address has an account, a reset link is on its way"}))); }
    let key = format!("forgot:{}", addr);
    if !st.rate_ok(&key, 5, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many reset requests; try again later")); }
    st.rate_fail(&key, 900).await;
    let email = r.email.trim().to_lowercase();
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE email=? AND active=1", &[json!(&email)]).await {
        let uid = db::s(&row, "id"); let token = issue_auth_token(&st, &uid, "reset", 3600).await;
        let link = format!("{}/#reset={}", issuer(&st, &h), token);
        send_template(&email, "reset", &[("link", &link), ("email", &email)]).await;
        st.audit("", "", "", &uid, "auth.password_reset_requested", "").await;
    }
    // Same answer whether or not the address exists.
    Ok(j(json!({"ok": true, "note": "if that address has an account, a reset link is on its way"}))) }
async fn resend_verification(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Json(r): Json<EmailReq>) -> Res {
    let key = format!("verify-resend:{}", addr);
    if !st.rate_ok(&key, 5, 3600).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many verification requests; try again later")); }
    st.rate_fail(&key, 3600).await;
    let email = r.email.trim().to_lowercase();
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE email=? AND active=1 AND email_verified=0", &[json!(&email)]).await {
        let uid = db::s(&row, "id"); let token = issue_auth_token(&st, &uid, "verify", 86400).await;
        let link = format!("{}/api/auth/verify?token={}", issuer(&st, &h), token);
        send_template(&email, "verify", &[("link", &link), ("email", &email)]).await;
    }
    Ok(j(json!({"ok": true}))) }
async fn reset_password(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(r): Json<ResetReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "password").await { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance")); }
    let key = format!("reset:{}", addr);
    if !st.rate_ok(&key, 10, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again later")); }
    if r.password.len() < 8 { return Err(bad("password (>=8 chars) required")); }
    let hash = oc::hash_token(r.token.trim());
    let row = st.db.one("SELECT user_id FROM auth_tokens WHERE token_hash=? AND kind='reset' AND used=0 AND expires_at>?", &[json!(&hash), json!(now())]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("reset link is invalid, already used, or expired"))?;
    let uid = db::s(&row, "user_id");
    let user = st.db.one("SELECT email,pubkey,email_verified,auth_version FROM users WHERE id=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("account not found"))?;
    // A version 1 reset would install a real password hash on a version 2
    // account and reopen the password endpoint; keep the account on v2.
    if db::n(&user, "auth_version") == 2 { return Err(bad("this account uses client-derived sign-in; use the v2 reset endpoint")); }
    st.rate_fail(&key, 900).await;
    let kit = r.recovery_kit.trim().to_string();
    let (pubkey, wrapped, replaced) = if !kit.is_empty() {
        let kp = oc::Keypair::from_secret_b64(&kit).map_err(|_| bad("recovery kit is not a valid key"))?;
        if kp.public != db::s(&user, "pubkey") { return Err(bad("recovery kit does not match this account")); }
        (db::s(&user, "pubkey"), oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?, false)
    } else if r.discard_e2e_key {
        let kp = oc::Keypair::generate();
        (kp.public.clone(), oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?, true)
    } else { return Err(bad("recovery kit required; pass discard_e2e_key=true to replace your key and lose access to end-to-end environments")); };
    let pass = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    st.audited_batch(&[
        ("UPDATE users SET pass_hash=?,pubkey=?,wrapped_privkey=?,email_verified=1 WHERE id=?".into(), vec![json!(pass), json!(pubkey), json!(wrapped), json!(&uid)]),
        ("UPDATE auth_tokens SET used=1 WHERE token_hash=?".into(), vec![json!(&hash)]),
        ("DELETE FROM sessions WHERE user_id=?".into(), vec![json!(&uid)]),
        ("DELETE FROM oauth_tokens WHERE user_id=?".into(), vec![json!(&uid)]),
    ], &[], ["", "", "", &uid, "auth.password_reset", if replaced { "key replaced" } else { "kit supplied" }]).await.map_err(|e| bad(&e))?;
    mfa::note_password_login(&st, &uid).await;
    // A reset link proves the mailbox, not the second factor. Changing the
    // password must not be a way around an enrolled factor.
    if mfa::required(&st, &uid).await {
        let challenge = mfa::new_challenge(&st, &uid).await?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge,
            "methods": mfa::methods(&st, &uid).await, "email_available": mfa::email_available() && mfa::email_enabled(&st, &uid).await,
            "e2e_key_replaced": replaced})))); }
    let session = make_session(&st, &uid).await?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap());
    Ok((hdr, j(json!({"token": session, "user_id": uid, "e2e_key_replaced": replaced})))) }

// ---------- instance settings + Google/GitHub sign-in ----------
async fn signups_open(st: &S) -> bool {
    match crate::envcfg::var("OPENWARP_SIGNUPS") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "closed" | "invite" | "invite_only" | "0" | "false"),
        Err(_) => meta_get(st, "signups_open").await != "0" } }
// The first account ever created owns instance-level policy. The claim is
// written once, so two accounts created in the same second cannot both win.
async fn claim_instance_owner(st: &S, uid: &str) {
    if meta_get(st, "instance_owner").await.is_empty() {
        let _ = user_guarded_batch(st, &[uid], &[
            ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(uid)]),
            ("INSERT INTO meta(k,v) VALUES('instance_owner',?)".into(), vec![json!(uid)]),
        ], &[0, 1]).await;
    } }
// A password account owns the instance only once its address is proven. The
// oldest verified account wins if the original registration was never opened.
async fn claim_instance_owner_on_verify(st: &S, uid: &str) {
    if !meta_get(st, "instance_owner").await.is_empty() { return; }
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE active=1 AND email_verified=1 ORDER BY created_at, id LIMIT 1", &[]).await {
        if db::s(&row, "id") == uid { claim_instance_owner(st, uid).await; } } }
async fn instance_owner(st: &S) -> Option<String> {
    let stored = meta_get(st, "instance_owner").await;
    if !stored.is_empty() { return Some(stored); }
    let uid = st.db.one("SELECT id FROM users WHERE active=1 AND email_verified=1 ORDER BY created_at, id LIMIT 1", &[]).await.ok().flatten().map(|r| db::s(&r, "id"));
    if let Some(u) = &uid { claim_instance_owner(st, u).await; }
    let persisted = meta_get(st, "instance_owner").await;
    if persisted.is_empty() { None } else { Some(persisted) } }
const AUTH_METHODS: &[&str] = &["password", "google", "microsoft", "apple", "github", "okta", "auth0", "gitlab", "atlassian", "slack", "salesforce", "openai", "x", "oidc", "discord", "linkedin", "workos"];
fn auth_method_configured(method: &str) -> bool {
    match method {
        "password" => true,
        _ => social_enabled(method) } }
fn auth_env_lock() -> Option<Vec<String>> {
    crate::envcfg::var("OPENWARP_AUTH_PROVIDERS").ok()
        .map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()) }
// Operators can pin the method list with OPENWARP_AUTH_PROVIDERS. Otherwise the
// instance owner's stored choice wins, defaulting to every configured method.
async fn auth_enabled(st: &S, method: &str) -> bool {
    if !auth_method_configured(method) { return false; }
    if let Some(lock) = auth_env_lock() { return lock.iter().any(|m| m == method); }
    let stored = meta_get(st, "auth_providers").await;
    if stored.is_empty() { return true; }
    serde_json::from_str::<Value>(&stored).ok()
        .and_then(|v| v.get(method).and_then(|b| b.as_bool())).unwrap_or(true) }
async fn auth_settings(st: &S) -> Value {
    let mut out = serde_json::Map::new();
    let mut enabled: Vec<&str> = Vec::new(); let mut configured: Vec<&str> = Vec::new();
    for method in AUTH_METHODS {
        if auth_method_configured(method) { configured.push(*method); }
        let on = auth_enabled(st, method).await;
        if on { enabled.push(*method); }
        out.insert((*method).to_string(), json!(on));
    }
    out.insert("methods".into(), json!(enabled));
    out.insert("configured".into(), json!(configured));
    out.insert("env_locked".into(), json!(auth_env_lock().is_some()));
    Value::Object(out) }
pub fn validate_auth_env() -> Result<(), String> {
    let Some(lock) = auth_env_lock() else { return Ok(()) };
    if lock.is_empty() { return Err("OPENWARP_AUTH_PROVIDERS is set but names no sign-in method".into()); }
    for m in &lock {
        if !AUTH_METHODS.contains(&m.as_str()) { return Err(format!("OPENWARP_AUTH_PROVIDERS contains unknown method {:?}; use {:?}", m, AUTH_METHODS)); }
        if !auth_method_configured(m) { return Err(format!("OPENWARP_AUTH_PROVIDERS enables {:?} but its credentials are not configured", m)); }
    }
    Ok(()) }
async fn set_auth_providers(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can change sign-in methods")); }
    if auth_env_lock().is_some() { return Err(err(StatusCode::CONFLICT, "OPENWARP_AUTH_PROVIDERS controls sign-in methods on this instance")); }
    let mut chosen: Vec<&str> = Vec::new();
    for method in AUTH_METHODS {
        let current = auth_enabled(&st, method).await;
        let value = body.get(*method).and_then(|v| v.as_bool()).unwrap_or(current);
        if value {
            if !auth_method_configured(method) { return Err(bad(&format!("{} sign-in is not configured; set its client credentials first", method))); }
            chosen.push(method);
        }
    }
    if chosen.is_empty() { return Err(bad("at least one sign-in method must stay enabled, or nobody could sign in")); }
    let cfg: serde_json::Map<String, Value> = AUTH_METHODS.iter().map(|m| ((*m).to_string(), json!(chosen.contains(m)))).collect();
    st.audited_batch(&meta_statements("auth_providers",&Value::Object(cfg).to_string()), &[], ["","","",&uid,"instance.auth_providers",&chosen.join(",")]).await.map_err(|e|bad(&e))?;
    Ok(j(auth_settings(&st).await)) }
fn env_nonempty(key: &str) -> String { crate::envcfg::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_default() }
fn social_provider(provider: &str) -> Option<(String, String)> {
    // Any OIDC issuer this instance trusts. The secret is optional because a
    // public client relies on PKCE instead.
    if provider == "oidc" {
        let id = env_nonempty("OPENWARP_OIDC_CLIENT_ID");
        if id.is_empty() || env_nonempty("OPENWARP_OIDC_ISSUER").is_empty() { return None; }
        return Some((id, env_nonempty("OPENWARP_OIDC_CLIENT_SECRET"))); }
    // X also supports a public client, where PKCE replaces the client secret.
    if provider == "x" {
        let id = env_nonempty("OPENWARP_X_CLIENT_ID");
        if id.is_empty() { return None; }
        return Some((id, env_nonempty("OPENWARP_X_CLIENT_SECRET"))); }
    let (id_key, secret_key) = match provider {
        "google" => ("OPENWARP_GOOGLE_CLIENT_ID", "OPENWARP_GOOGLE_CLIENT_SECRET"),
        "github" => ("OPENWARP_GITHUB_CLIENT_ID", "OPENWARP_GITHUB_CLIENT_SECRET"),
        "apple" => ("OPENWARP_APPLE_CLIENT_ID", "OPENWARP_APPLE_CLIENT_SECRET"),
        "openai" => ("OPENWARP_OPENAI_CLIENT_ID", "OPENWARP_OPENAI_CLIENT_SECRET"),
        "microsoft" => ("OPENWARP_MICROSOFT_CLIENT_ID", "OPENWARP_MICROSOFT_CLIENT_SECRET"),
        "okta" => ("OPENWARP_OKTA_CLIENT_ID", "OPENWARP_OKTA_CLIENT_SECRET"),
        "auth0" => ("OPENWARP_AUTH0_CLIENT_ID", "OPENWARP_AUTH0_CLIENT_SECRET"),
        "gitlab" => ("OPENWARP_GITLAB_CLIENT_ID", "OPENWARP_GITLAB_CLIENT_SECRET"),
        "slack" => ("OPENWARP_SLACK_CLIENT_ID", "OPENWARP_SLACK_CLIENT_SECRET"),
        "salesforce" => ("OPENWARP_SALESFORCE_CLIENT_ID", "OPENWARP_SALESFORCE_CLIENT_SECRET"),
        "atlassian" => ("OPENWARP_ATLASSIAN_CLIENT_ID", "OPENWARP_ATLASSIAN_CLIENT_SECRET"),
        _ => return crate::social_extra::credentials(provider) };
    let id = env_nonempty(id_key);
    let secret = env_nonempty(secret_key);
    if id.is_empty() || secret.is_empty() { None } else { Some((id, secret)) } }
// OIDC providers also need an issuer; GitHub, X, Discord and WorkOS use OAuth 2.0.
fn social_enabled(provider: &str) -> bool {
    social_provider(provider).is_some() && (matches!(provider, "github" | "x" | "discord" | "workos") || social_issuer(provider).is_some()) }
fn google_issuer() -> String { crate::envcfg::var("OPENWARP_GOOGLE_ISSUER").unwrap_or_else(|_| "https://accounts.google.com".into()) }
// Apple's client secret is a short-lived JWT the operator generates with their
// Sign in with Apple key; OpenAI issues a regular OAuth client secret.
fn social_issuer(provider: &str) -> Option<String> {
    match provider {
        "google" => Some(google_issuer()),
        "apple" => Some(crate::envcfg::var("OPENWARP_APPLE_ISSUER").unwrap_or_else(|_| "https://appleid.apple.com".into())),
        "openai" => Some(crate::envcfg::var("OPENWARP_OPENAI_ISSUER").unwrap_or_else(|_| "https://auth.openai.com".into())),
        "microsoft" => Some(microsoft_issuer()),
        "okta" => issuer_or("OPENWARP_OKTA_ISSUER", ""),
        "auth0" => issuer_or("OPENWARP_AUTH0_ISSUER", ""),
        "gitlab" => issuer_or("OPENWARP_GITLAB_ISSUER", "https://gitlab.com"),
        "slack" => issuer_or("OPENWARP_SLACK_ISSUER", "https://slack.com"),
        "salesforce" => issuer_or("OPENWARP_SALESFORCE_ISSUER", "https://login.salesforce.com"),
        "atlassian" => issuer_or("OPENWARP_ATLASSIAN_ISSUER", "https://auth.atlassian.com"),
        "oidc" => { let issuer = env_nonempty("OPENWARP_OIDC_ISSUER"); if issuer.is_empty() { None } else { Some(issuer) } },
        _ => crate::social_extra::issuer(provider) } }
fn issuer_or(key: &str, default: &str) -> Option<String> {
    let value = env_nonempty(key);
    if !value.is_empty() { Some(value) } else if !default.is_empty() { Some(default.to_string()) } else { None } }
fn microsoft_issuer() -> String {
    let explicit = env_nonempty("OPENWARP_MICROSOFT_ISSUER");
    if !explicit.is_empty() { return explicit; }
    let tenant = env_nonempty("OPENWARP_MICROSOFT_TENANT");
    let tenant = if tenant.is_empty() { "common".to_string() } else { tenant };
    format!("https://login.microsoftonline.com/{}/v2.0", tenant.trim_matches('/')) }
fn x_web() -> String { issuer_or("OPENWARP_X_WEB", "https://x.com").unwrap_or_else(|| "https://x.com".into()) }
fn x_api() -> String { issuer_or("OPENWARP_X_API", "https://api.x.com").unwrap_or_else(|| "https://api.x.com".into()) }
// Apple rejects scopes outside its advertised set (openid, email, name).
fn social_scope(provider: &str) -> &'static str {
    match provider {
        "apple" => "openid email",
        "x" => "users.read users.email",
        _ => crate::social_extra::scope(provider).unwrap_or("openid email profile") } }
// PKCE is safe wherever the provider supports S256. Some IdPs implement it but
// omit it from discovery, so the known ones are explicit here.
fn social_pkce(provider: &str, disc: &Value) -> bool {
    if matches!(provider, "oidc" | "openai" | "microsoft" | "okta" | "auth0" | "gitlab" | "salesforce" | "atlassian") { return true; }
    disc.get("code_challenge_methods_supported").and_then(|v| v.as_array())
        .map(|a| a.iter().any(|v| v.as_str() == Some("S256"))).unwrap_or(false) }
fn oidc_custom_name() -> String { let name = env_nonempty("OPENWARP_OIDC_NAME"); if name.is_empty() { "SSO".into() } else { name } }
fn oidc_custom_scope() -> String {
    let raw = env_nonempty("OPENWARP_OIDC_SCOPES");
    if raw.is_empty() { return "openid email profile".into(); }
    let mut parts: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();
    if !parts.iter().any(|s| s == "openid") { parts.insert(0, "openid".into()); }
    parts.join(" ") }
fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    oc::b64(&Sha256::digest(verifier.as_bytes())).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string() }
// OIDC says email_verified is a boolean, but Apple has also emitted the string
// form; accept both and reject anything that is not a clear true.
fn claim_bool(v: &Value) -> Option<bool> {
    match v { Value::Bool(b) => Some(*b), Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true), "false" => Some(false), _ => None }, _ => None } }
fn email_verified_claim(claims: &Value) -> Option<bool> { claims.get("email_verified").and_then(claim_bool) }
fn github_web() -> String { crate::envcfg::var("OPENWARP_GITHUB_WEB").unwrap_or_else(|_| "https://github.com".into()) }
fn github_api() -> String { crate::envcfg::var("OPENWARP_GITHUB_API").unwrap_or_else(|_| "https://api.github.com".into()) }
fn social_redirect(st: &S, h: &HeaderMap, provider: &str) -> String { format!("{}/api/auth/social/{}/callback", issuer(st, h), provider) }
// Generic OIDC providers sign with RS*, PS* or ES*; the key type comes from the
// JWKS entry, and the token header must agree with it.
fn jwk_signing_algorithm(jwk: &Value, header: jsonwebtoken::Algorithm) -> Result<jsonwebtoken::Algorithm, String> {
    use jsonwebtoken::Algorithm::*;
    let declared = jwk.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let header_name = serde_json::to_value(header).ok().and_then(|v| v.as_str().map(|s| s.to_string())).unwrap_or_default();
    if !declared.is_empty() && declared != header_name { return Err(format!("id_token alg {} does not match the JWK algorithm {}", header_name, declared)); }
    let name = if declared.is_empty() { header_name.as_str() } else { declared };
    match name {
        "RS256" => Ok(RS256), "RS384" => Ok(RS384), "RS512" => Ok(RS512),
        "PS256" => Ok(PS256), "PS384" => Ok(PS384), "PS512" => Ok(PS512),
        "ES256" => Ok(ES256), "ES384" => Ok(ES384),
        _ => Err(format!("unsupported id_token signature algorithm: {}", name)) } }
fn jwk_decoding_key(jwk: &Value, alg: jsonwebtoken::Algorithm) -> Result<jsonwebtoken::DecodingKey, String> {
    use jsonwebtoken::Algorithm::*;
    match alg {
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => jsonwebtoken::DecodingKey::from_rsa_components(
            jwk.get("n").and_then(|v| v.as_str()).ok_or("the JWK has no RSA modulus")?,
            jwk.get("e").and_then(|v| v.as_str()).ok_or("the JWK has no RSA exponent")?).map_err(|e| e.to_string()),
        ES256 | ES384 => jsonwebtoken::DecodingKey::from_ec_components(
            jwk.get("x").and_then(|v| v.as_str()).ok_or("the JWK has no EC x coordinate")?,
            jwk.get("y").and_then(|v| v.as_str()).ok_or("the JWK has no EC y coordinate")?).map_err(|e| e.to_string()),
        _ => Err(format!("unsupported id_token signature algorithm: {:?}", alg)) } }
fn b64url_json(segment: &str) -> Option<Value> {
    let mut s = segment.replace('-', "+").replace('_', "/");
    while !s.len().is_multiple_of(4) { s.push('='); }
    serde_json::from_slice(&oc::unb64(&s).ok()?).ok() }
// Microsoft publishes a templated issuer for multi-tenant apps. The tid claim
// selects the concrete tenant; the signature and audience are still checked.
fn concrete_issuer(issuer: &str, id_token: &str) -> String {
    if !issuer.contains("{tenantid}") { return issuer.to_string(); }
    let tid = id_token.split('.').nth(1).and_then(b64url_json)
        .and_then(|c| c.get("tid").and_then(|v| v.as_str()).map(str::to_string));
    match tid { Some(t) if !t.is_empty() => issuer.replace("{tenantid}", &t), _ => issuer.to_string() } }
async fn verify_id_token(id_token: &str, issuer: &str, audience: &str, jwks_uri: &str) -> Result<Value, String> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|e| e.to_string())?;
    let kid = header.kid.clone().unwrap_or_default();
    let jwks: Value = http_client().get(jwks_uri).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let keys = jwks.get("keys").and_then(|v| v.as_array()).ok_or("the JWKS has no keys")?;
    // A provider with one signing key may omit kid from the token.
    let jwk = if kid.is_empty() {
        if keys.len() == 1 { &keys[0] } else { return Err("the id_token has no kid and the JWKS has multiple keys".into()); }
    } else { keys.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid)).ok_or("kid not found in the JWKS")? };
    let alg = jwk_signing_algorithm(jwk, header.alg)?;
    let dkey = jwk_decoding_key(jwk, alg)?;
    let expected_issuer = concrete_issuer(issuer, id_token);
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_audience(&[audience]); validation.set_issuer(&[&expected_issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let data = jsonwebtoken::decode::<Value>(id_token, &dkey, &validation).map_err(|e| e.to_string())?;
    let claims = data.claims;
    // OIDC Core 3.1.3.7: multiple audiences require a matching authorised party.
    if claims.get("aud").and_then(|v| v.as_array()).map(|a| a.len() > 1).unwrap_or(false)
        && claims.get("azp").and_then(|v| v.as_str()) != Some(audience) { return Err("the id_token has multiple audiences but no matching azp".into()); }
    Ok(claims) }
fn oidc_token_auth_basic(disc: &Value) -> bool {
    match env_nonempty("OPENWARP_OIDC_TOKEN_AUTH_METHOD").as_str() {
        "client_secret_basic" => true,
        "client_secret_post" => false,
        _ => { let methods: Vec<&str> = disc.get("token_endpoint_auth_methods_supported").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
            methods.contains(&"client_secret_basic") && !methods.contains(&"client_secret_post") } } }
#[allow(clippy::too_many_arguments)] // every argument is a distinct token-exchange value
async fn oidc_identity_from_doc(disc: &Value, issuer: &str, client_id: &str, client_secret: &str, redirect: &str, code: &str, verifier: &str, expected_nonce: &str, custom: bool, provider: &str) -> Result<(String, String), String> {
    let token_ep = disc.get("token_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    let jwks_uri = disc.get("jwks_uri").and_then(|v| v.as_str()).unwrap_or("");
    if !issuer_url_ok(token_ep) || !issuer_url_ok(jwks_uri) { return Err("the OIDC token and JWKS endpoints must be https, or http on a loopback address".into()); }
    if !egress_allowed(token_ep) || !egress_allowed(jwks_uri) { return Err("OIDC endpoints are refused by egress policy".into()); }
    // Validate iss against the issuer the discovery document identifies, not the
    // configured URL: providers commonly differ by a trailing slash.
    let expected_issuer = disc.get("issuer").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or(issuer);
    // The metadata must identify the issuer we configured; a differing value
    // would separate token validation from the binding key. Microsoft's
    // multi-tenant documents publish a {tenantid} template, checked per token.
    if !expected_issuer.contains("{tenantid}") && expected_issuer.trim_end_matches('/') != issuer.trim_end_matches('/') { return Err("the OIDC discovery issuer does not match the configured issuer".into()); }
    let basic = custom && !client_secret.is_empty() && oidc_token_auth_basic(disc);
    let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect)];
    if !basic { form.push(("client_id", client_id)); }
    if !client_secret.is_empty() && !basic { form.push(("client_secret", client_secret)); }
    if !verifier.is_empty() { form.push(("code_verifier", verifier)); }
    let mut req = http_client().post(token_ep);
    if basic { req = req.basic_auth(client_id, Some(client_secret)); }
    let tok: Value = req.form(&form)
        .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = tok.get("error").and_then(|v| v.as_str()) { return Err(format!("the token endpoint rejected the code: {}", err)); }
    let id_token = tok.get("id_token").and_then(|v| v.as_str()).ok_or("the token response has no id_token")?;
    let claims = verify_id_token(id_token, expected_issuer, client_id, jwks_uri).await?;
    if !expected_nonce.is_empty() && claims.get("nonce").and_then(|v| v.as_str()) != Some(expected_nonce) { return Err("id_token nonce does not match this sign-in attempt".into()); }
    if email_verified_claim(&claims) == Some(false) { return Err("the provider reports this email address as unverified".into()); }
    let mut email = claims.get("email").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    // Entra work accounts often omit email and identify the user by UPN.
    if email.is_empty() && provider == "microsoft" {
        email = ["preferred_username", "upn"].iter()
            .find_map(|k| claims.get(*k).and_then(|v| v.as_str())).unwrap_or("").trim().to_lowercase();
        if !email.contains('@') { email.clear(); } }
    let subject = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if email.is_empty() || subject.is_empty() { return Err("the id_token has no email or subject".into()); }
    Ok((subject, email)) }
#[allow(clippy::too_many_arguments)] // mirrors the token-exchange inputs of oidc_identity_from_doc
async fn oidc_social_identity(provider: &str, issuer: &str, client_id: &str, client_secret: &str, redirect: &str, code: &str, verifier: &str, expected_nonce: &str) -> Result<(String, String), String> {
    let disc = oidc_discovery(issuer).await.map_err(|(_, j)| j.to_string())?;
    oidc_identity_from_doc(&disc, issuer, client_id, client_secret, redirect, code, verifier, expected_nonce, false, provider).await }
async fn github_identity(client_id: &str, client_secret: &str, redirect: &str, code: &str) -> Result<(String, String), String> {
    let tok: Value = http_client().post(format!("{}/login/oauth/access_token", github_web()))
        .header("Accept", "application/json").header("User-Agent", "openwarp")
        .form(&[("client_id", client_id), ("client_secret", client_secret), ("code", code), ("redirect_uri", redirect)])
        .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let at = tok.get("access_token").and_then(|v| v.as_str()).ok_or("GitHub token response has no access_token")?;
    let user: Value = http_client().get(format!("{}/user", github_api()))
        .bearer_auth(at).header("Accept", "application/vnd.github+json").header("User-Agent", "openwarp")
        .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let subject = user.get("id").and_then(|v| v.as_i64()).map(|n| n.to_string())
        .or_else(|| user.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())).ok_or("GitHub user has no id")?;
    // Only a verified address may create or match an account.
    let emails: Value = http_client().get(format!("{}/user/emails", github_api()))
        .bearer_auth(at).header("Accept", "application/vnd.github+json").header("User-Agent", "openwarp")
        .send().await.map_err(|e| format!("GitHub email lookup needs the user:email scope: {}", e))?.json().await.map_err(|e| e.to_string())?;
    let verified = emails.as_array().and_then(|arr| {
        arr.iter().find(|e| e.get("primary").and_then(|v| v.as_bool()) == Some(true) && e.get("verified").and_then(|v| v.as_bool()) == Some(true))
            .or_else(|| arr.iter().find(|e| e.get("verified").and_then(|v| v.as_bool()) == Some(true))) });
    let email = verified.and_then(|e| e.get("email").and_then(|v| v.as_str())).unwrap_or("").to_lowercase();
    if email.is_empty() { return Err("GitHub account has no verified email".into()); }
    Ok((subject, email)) }
async fn x_identity(client_id: &str, client_secret: &str, redirect: &str, code: &str, verifier: &str) -> Result<(String, String), String> {
    let token_ep = format!("{}/2/oauth2/token", x_api());
    let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect)];
    if !verifier.is_empty() { form.push(("code_verifier", verifier)); }
    let mut req = http_client().post(&token_ep);
    if client_secret.is_empty() { form.push(("client_id", client_id)); } else { req = req.basic_auth(client_id, Some(client_secret)); }
    let tok: Value = req.form(&form).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = tok.get("error").and_then(|v| v.as_str()) { return Err(format!("the X token endpoint rejected the code: {}", err)); }
    let at = tok.get("access_token").and_then(|v| v.as_str()).ok_or("the X token response has no access_token")?;
    let me: Value = http_client().get(format!("{}/2/users/me?user.fields=confirmed_email", x_api()))
        .bearer_auth(at).header("User-Agent", "openwarp")
        .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let data = me.get("data").ok_or("the X user response has no data")?;
    let subject = data.get("id").and_then(|v| v.as_str()).ok_or("the X user has no id")?.to_string();
    // confirmed_email is present only when the app holds the users.email scope.
    let email = data.get("confirmed_email").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    if email.is_empty() { return Err("X did not return a confirmed email; enable the users.email scope and confirm an email on the account".into()); }
    Ok((subject, email)) }
async fn resolve_social(st: &S, provider: &str, subject: &str, email: &str) -> Result<String, (StatusCode, Json<Value>)> {
    if let Some(bound) = st.db.one("SELECT user_id FROM social_subjects WHERE provider=? AND subject=?", &[json!(provider), json!(subject)]).await.map_err(|e| bad(&e))? {
        let uid = db::s(&bound, "user_id");
        if !st.principal_active(&uid).await { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        return Ok(uid); }
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).await.map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password first")); }
    // A pending invite admits the user even when self-signup is closed.
    let invite = st.db.one("SELECT * FROM invites WHERE email=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(email), json!(now())]).await.map_err(|e| bad(&e))?;
    if let Some(inv) = &invite { st.require_running(&db::s(inv, "org_id")).await?; }
    if invite.is_none() && !signups_open(st).await { return Err(err(StatusCode::FORBIDDEN, "signups are disabled on this instance; ask an administrator to invite you")); }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("social"); let uid = id();
    let pass_hash = oc::hash_password(&pw).map_err(|e| bad(&e))?;
    let wrapped = oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    // The provider asserted a verified address, so this account needs no
    // separate email round-trip.
    // The provider asserted the address, so the account itself needs no email
    // round-trip. A pending invite admits the account only: like OIDC and
    // SAML, membership requires the invitee to accept the token explicitly.
    let statements = vec![
        ("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)".into(), vec![json!(uid), json!(email), json!(pass_hash), json!(kp.public), json!(wrapped), json!(now())]),
        ("INSERT INTO social_subjects(provider,subject,user_id,created_at) VALUES(?,?,?,?)".into(), vec![json!(provider), json!(subject), json!(uid), json!(now())]),
    ];
    st.audited_batch(&statements, &[], ["", "", "", &uid, "auth.social_login", &format!("{} {}", provider, email)]).await.map_err(|e| bad(&e))?;
    claim_instance_owner(st, &uid).await;
    // Without an invite the workspace rules still decide: an invite-only
    // instance leaves the account with none until one is accepted. Runs after
    // the account row exists because the guarded batch locks the user row.
    if invite.is_none() { workspaces::default_workspace(st, &uid, email).await?; }
    Ok(uid) }
async fn auth_providers(State(st): State<S>) -> Res {
    let mut out = auth_settings(&st).await;
    out["ldap"] = json!(cfg!(feature = "ldap"));
    // Whether the binary can do SAML at all. The sign-in button stays visible
    // when this is true, even for a workspace without the grant, so the click
    // can explain itself.
    out["saml"] = json!(cfg!(feature = "saml"));
    out["oidc_name"] = json!(if social_enabled("oidc") { oidc_custom_name() } else { String::new() });
    out["signups"] = json!(if signups_open(&st).await { "open" } else { "invite" });
    out["region"] = json!(region());
    out["regions"] = json!(region_choices());
    out["workspace_creation_open"] = json!(workspaces::creation_open(&st).await?);
    Ok(j(out)) }
// Composed from discovery plus optional explicit endpoints, for IdPs that do not
// publish usable metadata.
async fn custom_oidc_metadata() -> Result<Value, (StatusCode, Json<Value>)> {
    let issuer = env_nonempty("OPENWARP_OIDC_ISSUER");
    let auth_ep = env_nonempty("OPENWARP_OIDC_AUTHORIZATION_ENDPOINT");
    let token_ep = env_nonempty("OPENWARP_OIDC_TOKEN_ENDPOINT");
    let jwks_uri = env_nonempty("OPENWARP_OIDC_JWKS_URI");
    if !issuer_url_ok(&issuer) || !egress_allowed(&issuer) { return Err(bad("OPENWARP_OIDC_ISSUER must be https, or http on a loopback address; private addresses need OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let explicit = !auth_ep.is_empty() && !token_ep.is_empty() && !jwks_uri.is_empty();
    let mut disc = match oidc_discovery(&issuer).await { Ok(d) => d, Err(e) => { if explicit { json!({"issuer": &issuer}) } else { return Err(e); } } };
    if let Some(obj) = disc.as_object_mut() {
        if !auth_ep.is_empty() { obj.insert("authorization_endpoint".into(), json!(auth_ep)); }
        if !token_ep.is_empty() { obj.insert("token_endpoint".into(), json!(token_ep)); }
        if !jwks_uri.is_empty() { obj.insert("jwks_uri".into(), json!(jwks_uri)); }
        obj.entry("issuer").or_insert(json!(&issuer)); }
    Ok(disc) }
fn social_flow_cookie(st: &S, h: &HeaderMap, provider: &str, state: &str, proof: &str) -> HeaderMap {
    let secure = issuer(st, h).starts_with("https://") || crate::envcfg::var("OPENWARP_SECURE_COOKIES").map(|v| v == "1").unwrap_or(false);
    let same_site = if provider == "apple" && secure { "None" } else { "Lax" };
    let cookie = format!("ow_social_{}={}; HttpOnly; Path=/api/auth/social/{}/callback; SameSite={}; Max-Age={}{}",
        sha256_hex(state.as_bytes()), proof, provider, same_site, if proof.is_empty() { 0 } else { 600 }, if secure { "; Secure" } else { "" });
    let mut headers = HeaderMap::new(); headers.insert(axum::http::header::SET_COOKIE, cookie.parse().unwrap()); headers }
async fn social_start(State(st): State<S>, h: HeaderMap, Path(provider): Path<String>) -> Result<(HeaderMap, axum::response::Redirect), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, &provider).await { return Err(err(StatusCode::NOT_FOUND, "this sign-in provider is disabled on this instance")); }
    let (client_id, _) = social_provider(&provider).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
    let redirect = social_redirect(&st, &h, &provider);
    let state = oc::random_token("sst");
    let proof = oc::random_token("browser");
    // Only the browser receives the independent secret; the database key binds it to the public state.
    let bound_state = hmac_hex(proof.as_bytes(), state.as_bytes());
    let headers = social_flow_cookie(&st, &h, &provider, &state, &proof);
    if let Some(url) = crate::social_extra::authorize_url(&provider, &client_id, &redirect, &state).map_err(|e| bad(&e))? {
        st.db.exec("INSERT INTO social_states(state,provider,created_at) VALUES(?,?,?)", &[json!(&bound_state), json!(&provider), json!(now())]).await.map_err(|e| bad(&e))?;
        return Ok((headers, axum::response::Redirect::temporary(&url))); }
    if provider == "github" {
        st.db.exec("INSERT INTO social_states(state,provider,created_at) VALUES(?,?,?)", &[json!(&bound_state), json!(&provider), json!(now())]).await.map_err(|e| bad(&e))?;
        let url = format!("{}/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}", github_web(), urlencode(&client_id), urlencode(&redirect), state);
        return Ok((headers, axum::response::Redirect::temporary(&url))); }
    if provider == "x" {
        let verifier = oc::random_token("pkce");
        st.db.exec("INSERT INTO social_states(state,provider,created_at,code_verifier) VALUES(?,?,?,?)", &[json!(&bound_state), json!(&provider), json!(now()), json!(&verifier)]).await.map_err(|e| bad(&e))?;
        let url = format!("{}/i/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            x_web(), urlencode(&client_id), urlencode(&redirect), urlencode(social_scope("x")), state, pkce_challenge(&verifier));
        return Ok((headers, axum::response::Redirect::temporary(&url))); }
    let disc = if provider == "oidc" { custom_oidc_metadata().await? } else {
        let issuer = social_issuer(&provider).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
        if !issuer_url_ok(&issuer) || !egress_allowed(&issuer) { return Err(bad("the provider issuer must be https, or http on a loopback address")); }
        oidc_discovery(&issuer).await? };
    let auth_ep = disc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    if !url_ok(auth_ep) || !egress_allowed(auth_ep) { return Err(bad("OIDC discovery returned no usable authorization_endpoint")); }
    if provider == "oidc" && !issuer_url_ok(auth_ep) { return Err(bad("OPENWARP_OIDC_AUTHORIZATION_ENDPOINT must be https, or http on a loopback address")); }
    let nonce = oc::random_token("n");
    // PKCE wherever the provider supports it; Apple and Slack do not advertise S256.
    let verifier = if social_pkce(&provider, &disc) { oc::random_token("pkce") } else { String::new() };
    st.db.exec("INSERT INTO social_states(state,provider,created_at,nonce,code_verifier) VALUES(?,?,?,?,?)", &[json!(&bound_state), json!(&provider), json!(now()), json!(&nonce), json!(&verifier)]).await.map_err(|e| bad(&e))?;
    let scope = if provider == "oidc" { oidc_custom_scope() } else { social_scope(&provider).to_string() };
    let mut url = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}", auth_ep, urlencode(&client_id), urlencode(&redirect), urlencode(&scope), state, nonce);
    if provider == "apple" { url.push_str("&response_mode=form_post"); }
    if !verifier.is_empty() { url.push_str(&format!("&code_challenge={}&code_challenge_method=S256", pkce_challenge(&verifier))); }
    Ok((headers, axum::response::Redirect::temporary(&url))) }
async fn social_callback(State(st): State<S>, h: HeaderMap, Path(provider): Path<String>, Query(q): Query<HashMap<String,String>>, form: Result<axum::extract::Form<HashMap<String,String>>, axum::extract::rejection::FormRejection>) -> Result<(HeaderMap, axum::response::Redirect), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, &provider).await { return Err(err(StatusCode::NOT_FOUND, "this sign-in provider is disabled on this instance")); }
    let (client_id, client_secret) = social_provider(&provider).filter(|_| social_enabled(&provider)).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
    // Apple answers with a form POST; every other provider uses the query string.
    let params = if q.contains_key("code") || q.contains_key("state") { q } else { form.ok().map(|axum::extract::Form(f)| f).unwrap_or_default() };
    let code = params.get("code").cloned().unwrap_or_default(); let state = params.get("state").cloned().unwrap_or_default();
    let proof = cookie_val(&h, &format!("ow_social_{}", sha256_hex(state.as_bytes())));
    if state.is_empty() || proof.is_empty() { return Err(bad("invalid or expired state")); }
    let bound_state = hmac_hex(proof.as_bytes(), state.as_bytes());
    let row = st.db.one("SELECT provider,created_at,nonce,code_verifier FROM social_states WHERE state=?", &[json!(&bound_state)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    if db::s(&row, "provider") != provider || db::n(&row, "created_at") + 600 < now() { return Err(bad("invalid or expired state")); }
    if code.is_empty() { return Err(bad("missing authorization code")); }
    st.db.batch_checked(&[("DELETE FROM social_states WHERE state=?".into(), vec![json!(&bound_state)])], &[0]).await
        .map_err(|e| if e.contains("version conflict") { bad("invalid or expired state") } else { bad(&e) })?;
    let headers = social_flow_cookie(&st, &h, &provider, &state, "");
    let redirect = social_redirect(&st, &h, &provider);
    let (subject, email) = if let Some(identity) = crate::social_extra::identity(&provider, &client_id, &client_secret, &redirect, &code).await.map_err(|e| bad(&e))? {
        identity
    } else if provider == "github" {
        github_identity(&client_id, &client_secret, &redirect, &code).await.map_err(|e| bad(&e))?
    } else if provider == "x" {
        x_identity(&client_id, &client_secret, &redirect, &code, &db::s(&row, "code_verifier")).await.map_err(|e| bad(&e))?
    } else if provider == "oidc" {
        let disc = custom_oidc_metadata().await?;
        let issuer = env_nonempty("OPENWARP_OIDC_ISSUER");
        let nonce = db::s(&row, "nonce"); let verifier = db::s(&row, "code_verifier");
        oidc_identity_from_doc(&disc, &issuer, &client_id, &client_secret, &redirect, &code, &verifier, &nonce, true, "oidc").await.map_err(|e| bad(&e))?
    } else {
        let issuer = social_issuer(&provider).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
        let nonce = db::s(&row, "nonce"); let verifier = db::s(&row, "code_verifier");
        oidc_social_identity(&provider, &issuer, &client_id, &client_secret, &redirect, &code, &verifier, &nonce).await.map_err(|e| bad(&e))? };
    // Bind a custom-OIDC identity to its issuer so a changed issuer cannot
    // inherit the bindings of the previous one.
    let bound_provider = if provider == "oidc" { format!("oidc:{}", env_nonempty("OPENWARP_OIDC_ISSUER")) } else { provider.clone() };
    let uid = resolve_social(&st, &bound_provider, &subject, &email).await?;
    // The provider proved the address, not possession of the account's second
    // factor, so MFA still applies to social sign-in.
    if mfa::required(&st, &uid).await {
        let challenge = mfa::new_challenge(&st, &uid).await?;
        return Ok((headers, axum::response::Redirect::temporary(&format!("/#mfa={}", challenge)))); }
    let token = make_session(&st, &uid).await?;
    Ok((headers, axum::response::Redirect::temporary(&format!("/#token={}", token)))) }
async fn instance_info(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h).await?;
    let mut out = auth_settings(&st).await;
    out["signups_open"] = json!(signups_open(&st).await);
    out["workspace_creation_open"] = json!(workspaces::creation_open(&st).await?);
    out["workspace_creation_env_locked"] = json!(crate::envcfg::var("OPENWARP_WORKSPACE_CREATION").is_ok());
    out["signups_env_locked"] = json!(crate::envcfg::var("OPENWARP_SIGNUPS").is_ok());
    out["instance_owner"] = json!(instance_owner(&st).await.as_deref() == Some(uid.as_str()));
    out["mfa_email"] = json!(mfa::email_available());
    out["google"] = json!(social_enabled("google"));
    out["github"] = json!(social_enabled("github"));
    out["apple"] = json!(social_enabled("apple"));
    out["openai"] = json!(social_enabled("openai"));
    out["microsoft"] = json!(social_enabled("microsoft"));
    out["okta"] = json!(social_enabled("okta"));
    out["auth0"] = json!(social_enabled("auth0"));
    out["gitlab"] = json!(social_enabled("gitlab"));
    out["slack"] = json!(social_enabled("slack"));
    out["salesforce"] = json!(social_enabled("salesforce"));
    out["atlassian"] = json!(social_enabled("atlassian"));
    out["x"] = json!(social_enabled("x"));
    out["discord"] = json!(social_enabled("discord"));
    out["linkedin"] = json!(social_enabled("linkedin"));
    out["workos"] = json!(social_enabled("workos"));
    out["oidc"] = json!(social_enabled("oidc"));
    out["features"] = json!(crate::features::compiled_names());
    Ok(j(out)) }
async fn edition_info(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h).await?;
    let mut status = st.edition().status();
    // The customer and expiry are commercial details; other members only need
    // to know which plan is active.
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) {
        if let Some(map) = status.as_object_mut() { map.remove("customer"); map.remove("expires_at"); } }
    Ok(j(status)) }
/// Instance-owner view: which build features exist and which workspace holds
/// a grant. The console renders its feature matrix from this.
async fn list_feature_grants(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can inspect feature grants")); }
    let rows = st.db.query("SELECT o.id AS org_id, o.name AS name, COALESCE(g.features,'') AS features FROM orgs o LEFT JOIN feature_grants g ON g.org_id=o.id ORDER BY o.name", &[]).await.map_err(|e| bad(&e))?;
    let mut grants = Vec::new();
    for r in &rows {
        let raw = db::s(r, "features");
        let names: Vec<&str> = raw.split_whitespace().collect();
        grants.push(json!({"org_id": db::s(r, "org_id"), "name": db::s(r, "name"), "features": crate::features::normalize(names)}));
    }
    Ok(j(json!({"compiled": crate::features::compiled_names(), "grants": grants}))) }
async fn put_feature_grants(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can change feature grants")); }
    let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if org.is_empty() { return Err(bad("org is required")); }
    st.db.one("SELECT id FROM orgs WHERE id=?", &[json!(&org)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "workspace not found"))?;
    let list = body.get("features").and_then(|v| v.as_array()).ok_or_else(|| bad("features must be an array"))?;
    let mut names = Vec::new();
    for v in list { names.push(v.as_str().ok_or_else(|| bad("features must contain strings"))?.to_string()); }
    st.set_feature_grants(&org, &names, &uid).await?;
    let saved = st.feature_grants(&org).await;
    st.audit(&org, "", "", &uid, "instance.features", &saved.join(" ")).await;
    Ok(j(json!({"org_id": org, "features": saved}))) }
/// Workspace view for the console: what this workspace may use, so settings
/// cards for ungranted surfaces stay hidden.
async fn org_features(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?;
    st.require_org(&oid, &uid).await?;
    Ok(j(json!({"compiled": crate::features::compiled_names(), "granted": st.feature_grants(&oid).await}))) }
async fn set_signups(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can change signup policy")); }
    if crate::envcfg::var("OPENWARP_SIGNUPS").is_ok() { return Err(err(StatusCode::CONFLICT, "OPENWARP_SIGNUPS controls signups on this instance")); }
    let open = body.get("open").and_then(|v| v.as_bool()).ok_or_else(|| bad("open must be a boolean"))?;
    st.audited_batch(&meta_statements("signups_open",if open {"1"} else {"0"}), &[], ["","","",&uid,"instance.signups",if open {"open"} else {"invite"}]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"signups_open": open}))) }
async fn set_instance_owner(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can transfer instance ownership")); }
    let target = if let Some(id) = body.get("user_id").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) { id.to_string() } else {
        let email = body.get("email").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
        if email.is_empty() { return Err(bad("user_id or email required")); }
        st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"id")).ok_or_else(|| err(StatusCode::NOT_FOUND, "account not found"))?
    };
    if target == uid { return Err(bad("choose another account")); }
    let row = st.db.one("SELECT active,email_verified FROM users WHERE id=?", &[json!(&target)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "account not found"))?;
    if db::n(&row,"active") == 0 || db::n(&row,"email_verified") == 0 { return Err(err(StatusCode::CONFLICT, "the new instance owner needs an active, verified account")); }
    user_guarded_commit(&st, &[&uid, &target], &[
        ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(&target)]),
        ("UPDATE meta SET v=? WHERE k='instance_owner' AND v=?".into(), vec![json!(&target), json!(&uid)]),
    ], &[0, 1], Some(["","","",&uid,"instance.owner",&target])).await?;
    Ok(j(json!({"ok":true, "instance_owner":target}))) }
async fn rewrap_env_keys(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can rewrap environment keys")); }
    let kms = st.kms().ok_or_else(|| bad("no KMS is configured; environment keys are wrapped by the instance master"))?;
    let rows = st.db.query("SELECT id,env_key_wrapped FROM envs WHERE env_key_wrapped<>''", &[]).await.map_err(|e| bad(&e))?;
    let mut rewrapped = 0;
    let mut stmts: Vec<(String, Vec<Value>)> = Vec::new();
    let mut checked=Vec::new();
    if let Some(root)=st.db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.map_err(|e| bad(&e))? {
        let previous=db::s(&root,"v"); let master=st.master();
        let raw=kms.unwrap(&previous,"master").await.map_err(|e| bad(&e))?;
        if raw.as_slice()!=master { return Err(bad("stored KMS root differs from the current root")); }
        let wrapped=kms.wrap(&master,"master").await.map_err(|e| bad(&e))?;
        if kms.unwrap(&wrapped,"master").await.map_err(|e| bad(&e))?.as_slice()!=master { return Err(bad("KMS root roundtrip returned a different key")); }
        checked.push(stmts.len());
        stmts.push(("UPDATE meta SET v=? WHERE k='kms_root' AND v=?".into(),vec![json!(wrapped),json!(previous)]));
    }
    for r in &rows {
        let eid = db::s(r, "id");
        let previous=db::s(r,"env_key_wrapped"); let context=format!("env:{}",eid);
        // Decode without env_key's lazy migration so a failed preparation writes nothing.
        let raw=if previous.starts_with("owkms:") { kms.unwrap(&previous,&context).await.map_err(|e| bad(&e))? }
            else { oc::decrypt_symmetric(&st.master(),&previous).map_err(|e| bad(&e))? };
        let key: [u8;32]=raw.try_into().map_err(|_| bad("bad env key"))?;
        let wrapped = kms.wrap(&key, &context).await.map_err(|e| bad(&format!("KMS could not wrap {}: {}", eid, e)))?;
        if kms.unwrap(&wrapped,&context).await.map_err(|e| bad(&e))?.as_slice()!=key { return Err(bad("KMS environment key roundtrip returned a different key")); }
        checked.push(stmts.len());
        stmts.push(("UPDATE envs SET env_key_wrapped=? WHERE id=? AND env_key_wrapped=?".into(), vec![json!(wrapped), json!(&eid), json!(previous)]));
        rewrapped += 1;
    }
    st.audited_batch(&stmts, &checked, ["","","",&uid,"instance.rewrap_keys",&format!("{} environments, key {}",rewrapped,kms.key_id())]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"rewrapped": rewrapped, "key_id": kms.key_id()}))) }
async fn encrypt_metadata(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can migrate secret metadata")); }
    // Only managed environments have a server-side key; never touch E2E or
    // delegated rows, whose client-owned metadata cannot be rewritten here.
    let envs = st.db.query("SELECT id FROM envs WHERE env_key_wrapped<>'' AND mode='sse'", &[]).await.map_err(|e| bad(&e))?;
    let mut updated = 0; let mut statements: Vec<(String,Vec<Value>)> = Vec::new();
    for e in &envs {
        let eid = db::s(e, "id");
        let key = match st.env_key(&eid).await { Ok(k) => k, Err(_) => continue };
        let rows = st.db.query("SELECT id,path,tags,path_enc,tags_enc,key_enc FROM secrets WHERE env_id=?", &[json!(&eid)]).await.map_err(|e| bad(&e))?;
        for r in &rows {
            let sid = db::s(r, "id");
            let path = if db::s(r, "path_enc").is_empty() { db::s(r, "path") }
                else { oc::decrypt_symmetric_compat(&key, &secret_aad(&eid, &sid, "path"), &db::s(r, "path_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|_| db::s(r, "path")) };
            let path = if path.is_empty() { "/".to_string() } else { path };
            let tags = if db::s(r, "tags_enc").is_empty() { db::s(r, "tags") }
                else { oc::decrypt_symmetric_compat(&key, &secret_aad(&eid, &sid, "tags"), &db::s(r, "tags_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|_| db::s(r, "tags")) };
            let Ok(kname) = oc::decrypt_symmetric_compat(&key, &secret_aad(&eid, &sid, "key"), &db::s(r, "key_enc")) else { continue };
            let kname = String::from_utf8_lossy(&kname).into_owned();
            if kname.is_empty() { continue; }
            let kh = key_index(&key, &path, &kname);
            let path_enc = oc::encrypt_symmetric_aad(&key, &secret_aad(&eid, &sid, "path"), path.as_bytes());
            let tags_enc = oc::encrypt_symmetric_aad(&key, &secret_aad(&eid, &sid, "tags"), tags.as_bytes());
            statements.push(("UPDATE secrets SET path='',path_enc=?,tags='',tags_enc=?,key_hash=?,key_index=? WHERE id=?".into(),
                vec![json!(path_enc), json!(tags_enc), json!(&kh), json!(&kh), json!(&sid)]));
            updated += 1;
        }
    }
    st.audited_batch(&statements, &[], ["", "", "", &uid, "instance.encrypt_metadata", &format!("{} secrets", updated)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"updated": updated}))) }
// Complete inventory shared by rotation and first-boot master identity validation.
async fn master_updates(db: &Db, old: &[u8; 32], new: &[u8; 32]) -> Result<Vec<(String, Vec<Value>)>, String> {
    let mut updates = Vec::new();
    for (table, id_col, col, predicate) in [
        ("envs", "id", "env_key_wrapped", "env_key_wrapped<>''"),
        ("meta", "k", "v", "k LIKE 'oidc_client_secret:%' OR k LIKE 'totp_secret:%' OR k LIKE 'totp_pending:%'"),
        ("pki_cas", "id", "key_enc", "key_enc<>''"),
        ("log_streams", "id", "secret", "secret<>''"),
        ("saml_configs", "org_id", "sp_key_enc", "sp_key_enc<>''"),
        ("rotation_hooks", "org_id", "secret_enc", "secret_enc<>''"),
        ("ldap_configs", "org_id", "bind_password_enc", "bind_password_enc<>''"),
        ("ai_settings", "org_id", "key_enc", "key_enc<>''"),
        ("users", "id", "auth_key_enc", "auth_key_enc<>''"),
    ] {
        let rows = db.query(&format!("SELECT {},{} FROM {} WHERE {}", id_col, col, table, predicate), &[]).await?;
        for row in rows {
            let id = db::s(&row, id_col); let value = db::s(&row, col);
            if value.is_empty() || (table == "envs" && value.starts_with("owkms:")) { continue; }
            let plain = match table {
                "users" => oc::decrypt_symmetric_aad(old, &auth_key_aad(&id), &value),
                "ai_settings" => oc::decrypt_symmetric_aad(old, &crate::ai::key_aad(&id), &value),
                _ => oc::decrypt_symmetric(old, &value),
            }.map_err(|_| format!("{}.{} for {} cannot be decrypted with the current master key; refusing transition", table, col, id))?;
            let encrypted = match table {
                "users" => oc::encrypt_symmetric_aad(new, &auth_key_aad(&id), &plain),
                "ai_settings" => oc::encrypt_symmetric_aad(new, &crate::ai::key_aad(&id), &plain),
                _ => oc::encrypt_symmetric(new, &plain),
            };
            updates.push((format!("UPDATE {} SET {}=? WHERE {}=?", table, col, id_col), vec![json!(encrypted), json!(id)]));
        }
    }
    Ok(updates)
}

pub async fn verify_master(db: &Db, key: &[u8; 32]) -> Result<(), String> {
    if let Some(row) = db.one("SELECT v FROM meta WHERE k='master_key_check'", &[]).await? {
        let plain = oc::decrypt_symmetric(key, &db::s(&row, "v")).map_err(|_| "configured master key does not match the database; restore the current key".to_string())?;
        if plain != b"openwarp-master-key-v1" { return Err("invalid persisted master key verifier".into()); }
    } else {
        master_updates(db, key, key).await?;
    }
    Ok(())
}
// Custody transitions delete or mint root material, and a persisted verifier
// only proves agreement with whoever wrote it: the full inventory must also
// decrypt under the root before custody moves.
async fn verify_master_full(db: &Db, key: &[u8; 32]) -> Result<(), String> {
    verify_master(db, key).await?;
    master_updates(db, key, key).await?;
    Ok(())
}
/// Adopt the root another boot persisted first. The candidate this boot minted
/// is discarded only after the winner proves itself against the inventory.
async fn adopt_kms_root(db: &Db, kms: &kms::Kms, supplied: Option<[u8; 32]>) -> Result<[u8; 32], String> {
    let row = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await?.ok_or("the concurrent KMS root is missing")?;
    let raw = kms.unwrap(&db::s(&row, "v"), "master").await.map_err(|e| format!("KMS could not unwrap the master root: {}", e))?;
    let winner: [u8; 32] = raw.try_into().map_err(|_| "KMS master root is not 32 bytes".to_string())?;
    if let Some(binding) = supplied { if binding != winner { return Err("OPENWARP_MASTER_KEY does not match the stored master root".into()); } }
    verify_master_full(db, &winner).await?;
    Ok(winner)
}
// Mint the boot verifier by CAS: a loser revalidates the authoritative row and
// refuses when another boot established a different root.
async fn persist_verifier(db: &Db, key: &[u8; 32]) -> Result<(), String> {
    if db.insert_if_absent("master_key_check", &oc::encrypt_symmetric(key, b"openwarp-master-key-v1")).await? { return Ok(()); }
    let row = db.one("SELECT v FROM meta WHERE k='master_key_check'", &[]).await?.ok_or("the concurrent master verifier is missing")?;
    let plain = oc::decrypt_symmetric(key, &db::s(&row, "v")).map_err(|_| "another boot established a different master root".to_string())?;
    if plain != b"openwarp-master-key-v1" { return Err("invalid persisted master key verifier".into()); }
    Ok(())
}

pub async fn load_master(db: &Db, kms: Option<&kms::Kms>) -> Result<[u8; 32], String> {
    let supplied = crate::envcfg::var("OPENWARP_MASTER_KEY").ok().map(|v| {
        oc::unb64(&v).map_err(|_| "OPENWARP_MASTER_KEY is not valid base64".to_string())?
            .try_into().map_err(|_| "OPENWARP_MASTER_KEY must decode to exactly 32 bytes".to_string())
    }).transpose()?;
    // A present-but-unreadable master row must stop the boot. Minting a new
    // root here would make every record under the old key undecryptable and
    // delete the only copy of the old root.
    let local: Option<[u8; 32]> = match db.one("SELECT v FROM meta WHERE k='master'", &[]).await? {
        Some(r) => Some(oc::unb64(&db::s(&r, "v")).map_err(|_| "the stored master root is not valid base64; refusing to generate a replacement".to_string())?
            .try_into().map_err(|_| "the stored master root is not 32 bytes; refusing to generate a replacement".to_string())?),
        None => None,
    };
    if let (Some(binding), Some(existing)) = (supplied, local) { if binding != existing { return Err("OPENWARP_MASTER_KEY does not match the stored master root".into()); } }
    if let Some(kms) = kms {
        let stored = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await?;
        let master = if let Some(r) = &stored {
            let raw = kms.unwrap(&db::s(r, "v"), "master").await.map_err(|e| format!("KMS could not unwrap the master root: {}", e))?;
            let master: [u8; 32] = raw.try_into().map_err(|_| "KMS master root is not 32 bytes".to_string())?;
            if let Some(binding) = supplied { if binding != master { return Err("OPENWARP_MASTER_KEY does not match the stored master root".into()); } }
            // Prove this root against the persisted inventory before the
            // duplicate plaintext row is deleted below.
            verify_master_full(db, &master).await?;
            master
        } else {
            let k = local.or(supplied).unwrap_or_else(oc::random_key);
            let wrapped = kms.wrap(&k, "master").await?;
            // A wrapped root that does not unwrap back to the same bytes would
            // strand every future boot, so it is proven before being persisted.
            let verified = kms.unwrap(&wrapped, "master").await.map_err(|e| format!("KMS root roundtrip failed: {}", e))?;
            if verified.as_slice() != k { return Err("KMS root roundtrip returned a different key; refusing to persist it".into()); }
            // The candidate must decrypt the existing inventory before a new
            // kms_root is persisted, or a refusal would leave the write behind.
            // A concurrent first boot can persist its root between the read
            // above and this preflight, so a failed candidate adopts that
            // winner instead of rejecting this boot.
            let candidate = verify_master_full(db, &k).await;
            match candidate {
                Ok(()) => {
                    // The insert is atomic and portable across SQLite, PostgreSQL and
                    // MySQL. A losing concurrent first boot adopts the stored winner
                    // before writing anything encrypted by this process.
                    if db.insert_if_absent("kms_root", &wrapped).await? { k } else { adopt_kms_root(db, kms, supplied).await? }
                }
                Err(candidate_error) => {
                    if db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await?.is_some() {
                        adopt_kms_root(db, kms, supplied).await?
                    } else { return Err(candidate_error); }
                }
            }
        };
        // A plaintext master that differs from the effective wrapped root is a
        // mixed-root database. Deleting either copy would lose key material, so
        // startup stops and both rows stay for operator recovery.
        if let Some(local) = local { if local != master { return Err("meta.master and meta.kms_root hold different roots; refusing to delete either. Restore the matching root or database backup.".into()); } }
        // Every refusal above precedes the first mutation, and the effective
        // root is fully verified by then on all three arms. The verifier mint
        // precedes the delete so a losing CAS against a different root still
        // leaves the plaintext recovery row in place.
        persist_verifier(db, &master).await?;
        db.exec("DELETE FROM meta WHERE k='master'", &[]).await?;
        Ok(master)
    } else {
        if supplied.is_none() && crate::production() { return Err("OPENWARP_MASTER_KEY or OPENWARP_KMS_URL is required in production. Preserve the original root for an existing database; a generated development key must be supplied externally or adopted by a KMS.".into()); }
        // Without the bridge the wrapped root cannot be compared with the
        // plaintext row, so their coexistence is ambiguous custody.
        let wrapped_present = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await?.is_some();
        if let Some(local) = local {
            if wrapped_present { return Err("meta.master and meta.kms_root are both present and no KMS is configured; refusing ambiguous root custody. Restore the KMS bridge or remove the stale row.".into()); }
            verify_master(db, &local).await?;
            persist_verifier(db, &local).await?;
            return Ok(local);
        }
        // A database booted with a KMS has no plaintext master row: the root lives
        // in meta.kms_root. Generating one here would silently make every owkms:
        // environment key and every account key unreadable.
        if wrapped_present {
            let key = supplied.ok_or("this database's master root is wrapped by a KMS, but OPENWARP_KMS_URL is not configured. Restore the KMS bridge, or set OPENWARP_MASTER_KEY to the original root.")?;
            // The wrapped root is unreadable without the bridge, so the supplied
            // root is only accepted against identity evidence that already
            // exists; no verifier is minted from an unproven fallback.
            let row = db.one("SELECT v FROM meta WHERE k='master_key_check'", &[]).await?.ok_or("no master key verifier is persisted to prove OPENWARP_MASTER_KEY against the KMS-wrapped root; restore the KMS bridge")?;
            let plain = oc::decrypt_symmetric(&key, &db::s(&row, "v")).map_err(|_| "OPENWARP_MASTER_KEY does not match the persisted master key verifier".to_string())?;
            if plain != b"openwarp-master-key-v1" { return Err("invalid persisted master key verifier".into()); }
            master_updates(db, &key, &key).await?;
            return Ok(key);
        }
        let k = match supplied {
            Some(k) => { verify_master(db, &k).await?; k }
            None => {
                let k = oc::random_key();
                // Prove a generated root against any orphaned inventory before
                // the plaintext master row is written.
                verify_master(db, &k).await?;
                db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&k))]).await?;
                eprintln!("warning: OPENWARP_MASTER_KEY is not set; a generated key was stored in the database. Set OPENWARP_MASTER_KEY before production use.");
                k
            }
        };
        persist_verifier(db, &k).await?;
        Ok(k)
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn rotate_master(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let lifecycle_guard=st.lifecycle.clone().write_owned().await;
    let uid = st.token_user(&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can rotate the master key")); }
    let new_key = body.get("new_key").and_then(|v| v.as_str()).unwrap_or("");
    let new: [u8; 32] = oc::unb64(new_key).map_err(|_| bad("new_key must be base64"))?.try_into().map_err(|_| bad("new_key must decode to exactly 32 bytes"))?;
    let rotation_permit = st.key_lifecycle.clone().write_owned().await;
    if st.kms().is_some() || st.db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT,"master rotation is unavailable while KMS auto-unseal is configured")); }
    if !matches!(&*st.db,Db::Sqlite(_)) { return Err(err(StatusCode::CONFLICT,"online master rotation requires single-process SQLite; PostgreSQL and MySQL require offline coordinated rotation")); }
    let transit_guard=st.transit_gate.clone().lock_owned().await;
    let transit_lifecycle=st.transit_lifecycle.clone().write_owned().await;
    // Serialize personal credential snapshots and writes with this replica's rotation.
    let credential_guard = st.secret_health_credentials.clone().lock_owned().await;
    let _ai_guard = st.ai_credentials.lock().await;
    let old = st.master();
    let ai_updates = crate::ai::rewrap(&st, &old, &new).await?;
    #[cfg(feature = "transit")]
    let transit_root = transit::root(&st, &old).await?;
    if old == new { return Err(bad("new_key is the current key")); }
    verify_master(&st.db, &old).await.map_err(|e| bad(&e))?;
    // The fence advances first in the same transaction, then every encrypted
    // row is snapshotted, rewrapped and audited. Any decrypt or write failure
    // rolls back the whole rotation, including the epoch advance.

    // Database fencing serializes key writes; publish only after commit without
    // holding the standard master lock while database drivers need the runtime.
    let st2 = st.clone(); let handle=tokio::runtime::Handle::current();
    let updates = tokio::task::spawn_blocking(move || {
        let _credential_guard = credential_guard;
        let _lifecycle_guard=lifecycle_guard;
        let _transit_guard=transit_guard;
        let _transit_lifecycle=transit_lifecycle;
        let _rotation_permit = rotation_permit;
        if st2.master() != old {return Err(err(StatusCode::CONFLICT,"master key changed during preflight; retry"));}
        let result = handle.block_on(st2.db.webhook_atomic(move |tx| {
            let epoch=webhooks::epoch_advance(tx,&old,&new)?;
            #[cfg(feature = "transit")]
            transit::rotation_tx(tx,&old,&new,&transit_root)?;
            transit_compat::rewrap_master_tx(tx,&old,&new)?;
            tx.exec("DELETE FROM email_codes",&[])?;
            // Captured incoming payloads are transient debug data sealed with
            // the old master; rotation erases them rather than rewrapping.
            tx.exec("UPDATE webhook_receipts SET body_enc=''",&[])?;
            for (sql,params) in &ai_updates { if tx.exec(sql,params)? != 1 { return Err("AI credential changed during rotation".into()); } }
            for table in ["webhook_subscriptions","incoming_webhooks"] {
                for row in tx.query(&format!("SELECT id,secret_enc FROM {}",table),&[])? {
                    let wid=db::s(&row,"id"); let aad=format!("webhook:{}",wid);
                    let plain=oc::decrypt_symmetric_aad(&old,aad.as_bytes(),&db::s(&row,"secret_enc")).map_err(|_|"webhook key cannot be decrypted; refusing master rotation")?;
                    tx.exec(&format!("UPDATE {} SET secret_enc=? WHERE id=?",table),&[json!(oc::encrypt_symmetric_aad(&new,aad.as_bytes(),&plain)),json!(wid)])?;
                }
            }
            for row in tx.query("SELECT id,sign_key_enc FROM webhook_subscriptions WHERE sign_key_enc<>''",&[])? {
                let wid=db::s(&row,"id"); let aad=format!("webhook-sign:{}",wid);
                let plain=oc::decrypt_symmetric_aad(&old,aad.as_bytes(),&db::s(&row,"sign_key_enc")).map_err(|_|"a webhook signing key cannot be decrypted; refusing master rotation")?;
                tx.exec("UPDATE webhook_subscriptions SET sign_key_enc=? WHERE id=?",&[json!(oc::encrypt_symmetric_aad(&new,aad.as_bytes(),&plain)),json!(wid)])?;
            }
            let mut counts=(0usize,0usize,0usize,0usize,0usize,0usize); let mut auth_count=0usize; let mut ldap_count=0usize;
            for row in tx.query("SELECT id,env_key_wrapped FROM envs",&[])? {
                let id=db::s(&row,"id"); let wrapped=db::s(&row,"env_key_wrapped");
                if wrapped.starts_with("owkms:") || wrapped.is_empty() { continue; }
                let plain=oc::decrypt_symmetric(&old,&wrapped).map_err(|_|"existing environment keys cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE envs SET env_key_wrapped=? WHERE id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(id)])?; counts.0+=1;
            }
            for row in tx.query("SELECT k,v FROM meta WHERE k LIKE 'oidc_client_secret:%' OR k LIKE 'totp_secret:%' OR k LIKE 'totp_pending:%' OR k LIKE 'hibp_api_key:%' OR k LIKE 'enzoic_credentials:%'",&[])? {
                let k=db::s(&row,"k"); let value=db::s(&row,"v"); if value.is_empty() {continue;}
                let plain=oc::decrypt_symmetric(&old,&value).map_err(|_|format!("stored secret {} cannot be decrypted with the current master key; refusing rotation",k))?;
                tx.exec("UPDATE meta SET v=? WHERE k=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(k)])?; counts.1+=1;
            }
            for row in tx.query("SELECT id,auth_key_enc FROM users WHERE auth_key_enc<>''",&[])? {
                let id=db::s(&row,"id"); let plain=oc::decrypt_symmetric_aad(&old,&auth_key_aad(&id),&db::s(&row,"auth_key_enc")).map_err(|_|"an account auth key cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE users SET auth_key_enc=? WHERE id=?",&[json!(oc::encrypt_symmetric_aad(&new,&auth_key_aad(&id),&plain)),json!(id)])?; auth_count+=1;
            }
            for row in tx.query("SELECT org_id,bind_password_enc FROM ldap_configs WHERE bind_password_enc<>''",&[])? {
                let org=db::s(&row,"org_id"); let plain=oc::decrypt_symmetric(&old,&db::s(&row,"bind_password_enc")).map_err(|_|"an LDAP bind password cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE ldap_configs SET bind_password_enc=? WHERE org_id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(org)])?; ldap_count+=1;
            }
            for row in tx.query("SELECT id,hook_secret_enc FROM pki_cas WHERE hook_secret_enc<>''",&[])? {
                let cid=db::s(&row,"id"); let plain=oc::decrypt_symmetric(&old,&db::s(&row,"hook_secret_enc")).map_err(|_|"a CA hook secret cannot be decrypted; refusing master rotation")?;
                if tx.exec("UPDATE pki_cas SET hook_secret_enc=? WHERE id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(cid)])? != 1 { return Err("CA hook changed during rotation".into()); }
            }
            for row in tx.query("SELECT id,key_enc FROM pki_cas",&[])? {
                let id=db::s(&row,"id"); let plain=oc::decrypt_symmetric(&old,&db::s(&row,"key_enc")).map_err(|_|"a CA private key cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE pki_cas SET key_enc=? WHERE id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(id)])?; counts.2+=1;
            }
            for row in tx.query("SELECT id,secret FROM log_streams",&[])? {
                let id=db::s(&row,"id"); let value=db::s(&row,"secret"); if value.is_empty() {continue;}
                let plain=oc::decrypt_symmetric(&old,&value).map_err(|_|"a log stream secret cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE log_streams SET secret=? WHERE id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(id)])?; counts.3+=1;
            }
            for row in tx.query("SELECT org_id,sp_key_enc FROM saml_configs",&[])? {
                let org=db::s(&row,"org_id"); let plain=oc::decrypt_symmetric(&old,&db::s(&row,"sp_key_enc")).map_err(|_|"a SAML signing key cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE saml_configs SET sp_key_enc=? WHERE org_id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(org)])?; counts.4+=1;
            }
            for row in tx.query("SELECT org_id,secret_enc FROM rotation_hooks WHERE secret_enc<>''",&[])? {
                let org=db::s(&row,"org_id"); let plain=oc::decrypt_symmetric(&old,&db::s(&row,"secret_enc")).map_err(|_|"a rotation hook secret cannot be decrypted with the current master key; refusing rotation")?;
                tx.exec("UPDATE rotation_hooks SET secret_enc=? WHERE org_id=?",&[json!(oc::encrypt_symmetric(&new,&plain)),json!(org)])?; counts.5+=1;
            }
            if tx.one("SELECT v FROM meta WHERE k='master'",&[])?.is_some() {tx.exec("UPDATE meta SET v=? WHERE k='master'",&[json!(oc::b64(&new))])?;}
            // The boot verifier proves the configured key on the next start, so
            // it moves with the records in the same transaction.
            tx.exec("UPDATE meta SET v=? WHERE k='master_key_check'",&[json!(oc::encrypt_symmetric(&new, b"openwarp-master-key-v1"))])?;
            let detail=format!("envs={} meta={} cas={} streams={} saml={} hooks={} auth={} ldap={} epoch={}",counts.0,counts.1,counts.2,counts.3,counts.4,counts.5,auth_count,ldap_count,epoch);
            AuditEvent::new(["", "", "", &uid, "instance.master_rotate", &detail]).append(tx)?;
            Ok(counts)
        })).map_err(|e| if e==webhooks::EPOCH_STALE {webhooks::epoch_stale()} else {err(StatusCode::CONFLICT,&e)});
        if result.is_ok() { *st2.master.write().unwrap_or_else(|e| e.into_inner()) = new; }
        result
    }).await.map_err(|e| bad(&e.to_string()))?;
    let counts = updates?;
    st.drain_outbox().await;
    // Fingerprints are keyed by the master key and salted by workspace, so the
    // old ones are invalid. Clear them and rebuild the index off the request.
    let _ = st.db.exec("UPDATE secrets SET value_fp=''", &[]).await;
    let _ = st.db.exec("DELETE FROM meta WHERE k='migration:value_fp'", &[]).await;
    { let st2 = st.clone(); tokio::spawn(async move { backfill_value_fingerprints(&st2).await; }); }
    Ok(j(json!({"ok": true, "rotated": {"envs": counts.0, "meta": counts.1, "cas": counts.2, "streams": counts.3, "saml": counts.4, "hooks": counts.5}, "note": "If OPENWARP_MASTER_KEY is set in the environment, update it and restart with the new value."}))) }

// The Workers build has no blocking runtime, rusqlite, or OCSP/CRL signing;
// these instance and PKI routes answer 501 there.
#[cfg(target_arch = "wasm32")]
async fn rotate_master(State(_): State<S>) -> Res { Err(err(StatusCode::NOT_IMPLEMENTED, "master key rotation requires the native server")) }
#[cfg(target_arch = "wasm32")]
async fn ocsp_respond() -> Response { err(StatusCode::NOT_IMPLEMENTED, "OCSP requires the native server").into_response() }
#[cfg(target_arch = "wasm32")]
async fn ca_crl() -> Response { err(StatusCode::NOT_IMPLEMENTED, "CRL generation requires the native server").into_response() }

// ---------- SCIM groups + user lifecycle ----------
#[cfg(feature = "scim")]
async fn scim_group_json(st: &S, row: &Row) -> Value { let tid = db::s(row,"id");
    let members = st.db.query("SELECT user_id FROM team_members WHERE team_id=?", &[json!(tid)]).await.unwrap_or_default();
    json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": tid, "displayName": db::s(row,"name"), "members": members.iter().map(|m| json!({"value": db::s(m,"user_id"), "$ref": format!("/scim/v2/Users/{}", db::s(m,"user_id"))})).collect::<Vec<_>>()}) }
#[cfg(feature = "scim")]
async fn scim_replace_members(st: &S, org: &str, tid: &str, body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    st.db.exec("DELETE FROM team_members WHERE team_id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?;
    for m in body.get("members").and_then(|v| v.as_array()).cloned().unwrap_or_default() { if let Some(uid) = m.get("value").and_then(|v| v.as_str()) { if scim_member(st, org, uid).await { let _ = st.db.exec("INSERT INTO team_members(team_id,user_id) VALUES(?,?)", &[json!(tid), json!(uid)]).await; } } } Ok(()) }
#[cfg(feature = "scim")]
async fn scim_create_group(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res {
    let org = scim_org(&st, &h, &q).await?;
    let name = body.get("displayName").and_then(|v| v.as_str()).unwrap_or(""); if name.is_empty() { return Err(bad("displayName required")); }
    let tid = id(); st.db.exec("INSERT INTO teams(id,org_id,name) VALUES(?,?,?)", &[json!(tid), json!(org), json!(name)]).await.map_err(|e| bad(&e))?;
    scim_replace_members(&st, &org, &tid, &body).await?; let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.unwrap(); Ok(j(scim_group_json(&st,&row).await)) }
#[cfg(feature = "scim")]
async fn scim_list_groups(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q).await?;
    let rows = st.db.query("SELECT * FROM teams WHERE org_id=? ORDER BY name", &[json!(org)]).await.map_err(|e| bad(&e))?;
    let (start, count) = scim_page(&q); let filter = scim_eq_filter(&q);
    let mut all: Vec<Value> = Vec::with_capacity(rows.len());
    for r in &rows { all.push(scim_group_json(&st, r).await); }
    if let Some(name) = filter { all.retain(|g| g["displayName"].as_str().map(|d| d.eq_ignore_ascii_case(&name)).unwrap_or(false)); }
    let total = all.len(); let page: Vec<Value> = all.into_iter().skip(start - 1).take(count).collect();
    let page_len = page.len();
    Ok(j(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": page, "totalResults": total, "startIndex": start, "itemsPerPage": page_len}))) }
#[cfg(feature = "scim")]
async fn scim_get_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q).await?;
    let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&row,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    Ok(j(scim_group_json(&st,&row).await)) }
#[cfg(feature = "scim")]
async fn scim_put_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q).await?;
    let existing = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&existing,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    if let Some(name) = body.get("displayName").and_then(|v| v.as_str()) { st.db.exec("UPDATE teams SET name=? WHERE id=?", &[json!(name), json!(tid)]).await.map_err(|e| bad(&e))?; }
    scim_replace_members(&st, &org, &tid, &body).await?; let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?; Ok(j(scim_group_json(&st,&row).await)) }
#[cfg(feature = "scim")]
async fn scim_patch_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q).await?;
    let existing = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&existing,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    for op in body.get("Operations").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let path = op.get("path").and_then(|v| v.as_str()).unwrap_or(""); let val = op.get("value").cloned().unwrap_or(json!({}));
        if path == "displayName" { if let Some(n) = val.as_str() { st.db.exec("UPDATE teams SET name=? WHERE id=?", &[json!(n), json!(tid)]).await.map_err(|e| bad(&e))?; } }
        else if path.starts_with("members") { scim_replace_members(&st, &org, &tid, &json!({"members": val})).await?; } }
    let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?; Ok(j(scim_group_json(&st,&row).await)) }
#[cfg(feature = "scim")]
async fn scim_delete_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q).await?;
    let existing = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&existing,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    st.db.exec("DELETE FROM team_members WHERE team_id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?; st.db.exec("DELETE FROM teams WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?; Ok(j(json!({"deleted": tid}))) }
#[cfg(feature = "scim")]
async fn scim_put_user(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q).await?; let caller = st.token_user(&h).await?; let uid = tid;
    if !scim_member(&st, &org, &uid).await { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    if let Some(email) = body.get("userName").and_then(|v| v.as_str()) {
        let current = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "email")).unwrap_or_default();
        if !email.eq_ignore_ascii_case(&current) {
            let orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).await.map_err(|e| bad(&e))?;
            for o in &orgs { let r = st.org_role(&db::s(o, "org_id"), &caller).await.unwrap_or_default(); if r != "owner" && r != "admin" { return Err(err(StatusCode::FORBIDDEN, "changing an account email requires admin rights in every organisation the user belongs to")); } }
            st.db.exec("UPDATE users SET email=? WHERE id=?", &[json!(email.to_lowercase()), json!(uid)]).await.map_err(|e| bad(&e))?; } }
    if let Some(active) = body.get("active").and_then(|v| v.as_bool()) { if !active { scim_deactivate(&st, &org, &uid, &caller).await?; } }
    Ok(j(json!({"id": uid, "active": body.get("active").and_then(|v| v.as_bool()).unwrap_or(true)}))) }
#[cfg(feature = "scim")]
async fn scim_patch_user(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q).await?; let caller = st.token_user(&h).await?; let uid = tid;
    if !scim_member(&st, &org, &uid).await { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    for op in body.get("Operations").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        if op.get("path").and_then(|v| v.as_str()) == Some("active") { if let Some(a) = op.get("value").and_then(|v| v.as_bool()) { if !a { scim_deactivate(&st, &org, &uid, &caller).await?; } } } }
    Ok(j(json!({"id": uid}))) }
#[cfg(feature = "scim")]
async fn scim_delete_user(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q).await?; let caller = st.token_user(&h).await?;
    if !scim_member(&st, &org, &tid).await { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    scim_deactivate(&st, &org, &tid, &caller).await?; Ok(j(json!({"id": tid, "active": false}))) }
#[cfg(feature = "scim")]
async fn scim_deactivate(st: &S, org: &str, uid: &str, caller: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let target_role = st.org_role(org, uid).await.unwrap_or_default();
    if target_role == "owner" { let caller_role = st.org_role(org, caller).await.unwrap_or_default(); if caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can remove an owner")); } }
    let deleted = st.db.exec("DELETE FROM org_members WHERE org_id=? AND user_id=? AND (role<>'owner' OR (SELECT COUNT(*) FROM org_members WHERE org_id=? AND role='owner')>1)", &[json!(org), json!(uid), json!(org)]).await.map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(bad("cannot remove the last owner")); }
    st.db.exec("DELETE FROM team_members WHERE user_id=? AND team_id IN (SELECT id FROM teams WHERE org_id=?)", &[json!(uid), json!(org)]).await.map_err(|e| bad(&e))?;
    if let Ok(rows) = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).await { if rows.is_empty() {
        let _ = st.db.exec("DELETE FROM sessions WHERE user_id=?", &[json!(uid)]).await;
        let _ = st.db.exec("DELETE FROM oauth_tokens WHERE user_id=?", &[json!(uid)]).await;
        let _ = st.db.exec("UPDATE users SET active=0 WHERE id=?", &[json!(uid)]).await; } }
    Ok(()) }


// ---------- customer-run sync runners (delegated environments) ----------
#[derive(Deserialize)] struct RunnerReq { name: String, public_key: String }
async fn runner_auth(st: &S, h: &HeaderMap) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let token = bearer_token(h);
    if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "runner token required")); }
    let row = st.db.one("SELECT id,org_id FROM runners WHERE token_hash=?", &[json!(oc::hash_token(&token))]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid runner token"))?;
    st.require_running(&db::s(&row, "org_id")).await?;
    Ok((db::s(&row, "id"), db::s(&row, "org_id"))) }
async fn runner_for_env(st: &S, eid: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let env = st.db.one("SELECT runner_id,mode FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
    if db::s(&env, "mode") != "delegated" { return Err(bad("environment is not delegated")); }
    let rid = db::s(&env, "runner_id");
    let runner = st.db.one("SELECT pubkey FROM runners WHERE id=?", &[json!(&rid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("runner not found"))?;
    Ok((rid, db::s(&runner, "pubkey"))) }
async fn seal_to_runner(st: &S, eid: &str, iid: &str, config: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    let (rid, pubkey) = runner_for_env(st, eid).await?;
    // The sealed box has no AAD, so bind the payload to its integration inside
    // the plaintext and make the runner verify it before using the config.
    let envelope = json!({"context": format!("ow-integration|{}|{}", eid, iid), "config": config}).to_string();
    let sealed = oc::encrypt_to(&pubkey, envelope.as_bytes()).map_err(|e| bad(&e))?;
    Ok(format!("owrunner:{}:{}", rid, sealed)) }
async fn enqueue_sync(st: &S, eid: &str, iid: &str, job_kind: &str) -> Result<(), (StatusCode, Json<Value>)> {
    st.require_env_running(eid).await?;
    let (rid, _) = runner_for_env(st, eid).await?;
    if st.db.one("SELECT id FROM sync_jobs WHERE integration_id=? AND status IN ('pending','claimed') AND kind=?", &[json!(iid), json!(job_kind)]).await.map_err(|e| bad(&e))?.is_some() { return Ok(()); }
    st.db.exec("INSERT INTO sync_jobs(id,env_id,integration_id,runner_id,kind,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(id()), json!(eid), json!(iid), json!(rid), json!(job_kind), json!(now())]).await.map_err(|e| bad(&e))?;
    Ok(()) }
async fn create_runner(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<RunnerReq>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new(); st.check_admin(&oid, &uid).await?;
    let name = r.name.trim();
    if name.is_empty() { return Err(bad("runner name required")); }
    let raw = oc::unb64(&r.public_key).map_err(|_| bad("public_key must be base64 X25519"))?;
    if raw.len() != 32 { return Err(bad("public_key must decode to 32 bytes")); }
    let rid = id(); let token = oc::random_token("run");
    statements.push((("INSERT INTO runners(id,org_id,name,pubkey,token_hash,created_at) VALUES(?,?,?,?,?,?)").to_string(), ([json!(&rid), json!(&oid), json!(name), json!(&r.public_key), json!(oc::hash_token(&token)), json!(now())]).to_vec()));
    st.audited_batch(&statements, &[], [&oid, "", "", &uid, "runner.create", name]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"id": rid, "name": name, "public_key": r.public_key, "token": token, "note": "token shown once; store it with the runner"}))) }
async fn list_runners(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid, &uid).await?;
    let rows = st.db.query("SELECT id,name,pubkey,created_at FROM runners WHERE org_id=?", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_runner(State(st): State<S>, h: HeaderMap, Path((oid, rid)): Path<(String, String)>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid, &uid).await?;
    if st.db.one("SELECT id FROM envs WHERE runner_id=? AND mode='delegated' LIMIT 1", &[json!(&rid)]).await.map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "this runner still owns a delegated environment; remove or migrate those environments first")); }
    st.audited_batch(&[
        ("DELETE FROM runners WHERE id=? AND org_id=?".into(), vec![json!(&rid), json!(&oid)]),
        ("DELETE FROM runner_env_keys WHERE runner_id=?".into(), vec![json!(&rid)]),
        ("DELETE FROM sync_jobs WHERE runner_id=?".into(), vec![json!(&rid)]),
    ], &[0], [&oid, "", "", &uid, "runner.delete", &rid]).await.map_err(|e| if e.contains("version conflict") {err(StatusCode::NOT_FOUND, "runner not found")} else {bad(&e)})?;
    Ok(j(json!({"deleted": rid}))) }
async fn runner_jobs(State(st): State<S>, h: HeaderMap) -> Res {
    let (rid, _) = runner_auth(&st, &h).await?;
    // A runner that crashes after claiming a job must not strand it forever.
    let stale = now() - 600;
    let rows = st.db.query("SELECT sync_jobs.* FROM sync_jobs JOIN envs e ON e.id=sync_jobs.env_id JOIN apps a ON a.id=e.app_id JOIN orgs o ON o.id=a.org_id WHERE sync_jobs.runner_id=? AND (status='pending' OR (status='claimed' AND claimed_at<?)) AND a.emergency_locked=0 AND o.emergency_locked=0 ORDER BY sync_jobs.created_at LIMIT 10", &[json!(&rid), json!(stale)]).await.map_err(|e| bad(&e))?;
    let mut jobs = Vec::new();
    for job in &rows {
        let jid = db::s(job, "id"); let claim = oc::random_token("job"); let claimed_at = now();
        if st.db.exec("UPDATE sync_jobs SET status='claimed',claimed_at=?,claim_id=? WHERE id=? AND (status='pending' OR (status='claimed' AND claimed_at<?)) AND EXISTS (SELECT 1 FROM envs e JOIN apps a ON a.id=e.app_id JOIN orgs o ON o.id=a.org_id WHERE e.id=sync_jobs.env_id AND o.emergency_locked=0 AND a.emergency_locked=0)", &[json!(claimed_at), json!(&claim), json!(&jid), json!(stale)]).await.unwrap_or(0) == 0 { continue; }
        let eid = db::s(job, "env_id"); let iid = db::s(job, "integration_id");
        let fail = async |msg: &str| { let _ = st.db.exec("UPDATE sync_jobs SET status='failed',detail=? WHERE id=? AND claim_id=?", &[json!(msg), json!(&jid), json!(&claim)]).await; };
        let env = match st.db.one("SELECT runner_id FROM envs WHERE id=?", &[json!(&eid)]).await { Ok(Some(e)) => e, _ => { fail("environment no longer exists").await; continue; } };
        if db::s(&env, "runner_id") != rid { fail("runner does not own this environment").await; continue; }
        let wrapped = match st.db.one("SELECT wrapped_key FROM runner_env_keys WHERE runner_id=? AND env_id=?", &[json!(&rid), json!(&eid)]).await { Ok(Some(w)) => db::s(&w, "wrapped_key"), _ => { fail("no wrapped environment key for this runner").await; continue; } };
        let integ = match st.db.one("SELECT kind,config_enc FROM integrations WHERE id=?", &[json!(&iid)]).await { Ok(Some(i)) => i, _ => { fail("integration no longer exists").await; continue; } };
        // Sealed values are never readable, so a runner job must never carry them.
        let secrets = st.db.query("SELECT key_enc,value_enc,key_hash,path FROM secrets WHERE env_id=? AND deleted=0 AND secret_type<>'sealed'", &[json!(&eid)]).await.map_err(|e| bad(&e))?;
        let prev = st.db.query("SELECT remote_name FROM integration_sync_state WHERE integration_id=?", &[json!(&iid)]).await.unwrap_or_default();
        if st.require_env_running(&eid).await.is_err() { continue; }
        if st.db.one("SELECT id FROM sync_jobs WHERE id=? AND status='claimed' AND claim_id=?", &[json!(&jid), json!(&claim)]).await.map_err(|e| bad(&e))?.is_none() { continue; }
        jobs.push(json!({
            "id": jid, "claim": claim, "env_id": eid, "integration_id": iid, "job_kind": db::s(job, "kind"),
            "kind": db::s(&integ, "kind"), "config_enc": db::s(&integ, "config_enc"), "wrapped_key": wrapped,
            "secrets": secrets.iter().map(db::obj).collect::<Vec<_>>(),
            "previous": prev.iter().map(|r| db::s(r, "remote_name")).collect::<Vec<_>>(),
        }));
    }
    runner_auth(&st, &h).await?;
    Ok(j(json!({"jobs": jobs}))) }
#[derive(Deserialize)] struct ManagedSecret { name: String, #[serde(default)] value_hash: String }
#[derive(Deserialize)] struct JobResultReq { ok: bool, #[serde(default)] detail: String, #[serde(default)] managed: Vec<ManagedSecret>, #[serde(default)] claim: String }
async fn runner_job_result(State(st): State<S>, h: HeaderMap, Path(jid): Path<String>, Json(r): Json<JobResultReq>) -> Res {
    let (rid, _) = runner_auth(&st, &h).await?;
    let job = st.db.one("SELECT * FROM sync_jobs WHERE id=? AND runner_id=?", &[json!(&jid), json!(&rid)]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "job not found"))?;
    st.require_env_running(&db::s(&job, "env_id")).await?;
    if db::s(&job, "status") != "claimed" { return Err(err(StatusCode::CONFLICT, "job is not claimed by this runner")); }
    // The claim id is the fencing token: a job reclaimed after the stale window
    // rejects the old runner's late result.
    let eid = db::s(&job, "env_id"); let iid = db::s(&job, "integration_id");
    let (org, app) = st.env_org_app(&eid).await?;
    let mut statements = vec![("UPDATE sync_jobs SET status=?,detail=? WHERE id=? AND runner_id=? AND status='claimed' AND claim_id=? AND EXISTS (SELECT 1 FROM envs e JOIN apps a ON a.id=e.app_id JOIN orgs o ON o.id=a.org_id WHERE e.id=sync_jobs.env_id AND o.emergency_locked=0 AND a.emergency_locked=0)".into(),
        vec![json!(if r.ok { "done" } else { "failed" }), json!(&r.detail), json!(&jid), json!(&rid), json!(&r.claim)])];
    let require_one = vec![0];
    if r.ok && db::s(&job, "kind") == "sync" && !r.managed.is_empty() {
        statements.push(("DELETE FROM integration_sync_state WHERE integration_id=?".into(), vec![json!(&iid)]));
        for m in &r.managed { statements.push(("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)".into(), vec![json!(&iid), json!(&m.name), json!(&m.value_hash)])); }
    }
    st.audited_batch(&statements, &require_one, [&org, &app, &eid, "runner", if r.ok { "integration.sync" } else { "integration.sync_failed" }, &format!("{} {}", iid, r.detail)]).await.map_err(|e| if e.contains("version conflict") {err(StatusCode::CONFLICT, "this claim was superseded; refresh the job queue")} else {bad(&e)})?;
    Ok(j(json!({"status": if r.ok { "done" } else { "failed" }}))) }

// ---------- machine identities + Universal Auth (Infisical-inspired) ----------
async fn create_identity(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let caller_role = st.require_org(&oid, &uid).await?; st.check_admin(&oid, &uid).await?;
    let want = if r.role.trim().is_empty() { "developer".to_string() } else { r.role.trim().to_string() };
    if want == "owner" { return Err(bad("machine identities cannot hold the owner role")); }
    if want != "developer" && want != "admin" && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(oid), json!(&want)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    // A machine identity is a durable principal, so an admin must not mint one
    // with a role that is admin-equivalent under another name. The role must
    // exist first: permissions are immutable, so this read cannot go stale.
    if st.role_privileged(&oid, &want).await && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can create an identity with admin rights")); }
    let iid = id(); let client_id = oc::random_token("cid"); let client_secret = oc::random_token("csec");
    statements.push((("INSERT INTO identities(id,org_id,name,role,created_at) VALUES(?,?,?,?,?)").to_string(), ([json!(iid), json!(oid), json!(r.name), json!(want), json!(now())]).to_vec()));
    statements.push((("INSERT INTO identity_credentials(id,identity_id,client_id,secret_hash,created_at) VALUES(?,?,?,?,?)").to_string(), ([json!(id()), json!(iid), json!(client_id), json!(oc::hash_token(&client_secret)), json!(now())]).to_vec()));
    st.audited_batch(&statements, &[], [&oid,"","",&uid,"identity.create",&r.name]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"id": iid, "client_id": client_id, "client_secret": client_secret, "note": "client_secret shown once; POST /api/v1/machine/auth/universal/login {client_id, client_secret} for a 1h access token"}))) }
async fn list_identities(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.check_admin(&oid, &uid).await?;
    let rows = st.db.query("SELECT i.id,i.org_id,i.name,i.role,i.created_at,c.client_id FROM identities i LEFT JOIN identity_credentials c ON c.identity_id=i.id WHERE i.org_id=?", &[json!(oid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_identity(State(st): State<S>, h: HeaderMap, Path((oid, iid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    st.check_admin(&oid, &uid).await?;
    if st.db.one("SELECT id FROM identities WHERE id=? AND org_id=?", &[json!(&iid), json!(&oid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "identity not found")); }
    statements.push(("DELETE FROM workload_bindings WHERE identity_id=?".into(), vec![json!(&iid)]));
    statements.push((("DELETE FROM identity_credentials WHERE identity_id=?").to_string(), ([json!(&iid)]).to_vec()));
    statements.push((("DELETE FROM tokens WHERE created_by=?").to_string(), ([json!(&iid)]).to_vec()));
    statements.push((("DELETE FROM identities WHERE id=?").to_string(), ([json!(&iid)]).to_vec()));
    st.audited_batch(&statements, &[], [&oid,"","",&uid,"identity.delete",&iid]).await.map_err(|e|bad(&e))?; Ok(j(json!({"deleted": iid}))) }
async fn rotate_identity(State(st): State<S>, h: HeaderMap, Path((oid, iid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid, &uid).await?;
    if st.db.one("SELECT id FROM identities WHERE id=? AND org_id=?", &[json!(&iid), json!(&oid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "identity not found")); }
    let secret = oc::random_token("csec");
    let existing = st.db.one("SELECT client_id FROM identity_credentials WHERE identity_id=?", &[json!(&iid)]).await.map_err(|e| bad(&e))?;
    let client_id = existing.as_ref().map(|r| db::s(r,"client_id")).unwrap_or_else(|| oc::random_token("cid"));
    let statements = if existing.is_some() {
        vec![("UPDATE identity_credentials SET secret_hash=? WHERE identity_id=?".into(), vec![json!(oc::hash_token(&secret)), json!(&iid)])]
    } else {
        vec![("INSERT INTO identity_credentials(id,identity_id,client_id,secret_hash,created_at) VALUES(?,?,?,?,?)".into(), vec![json!(id()), json!(&iid), json!(&client_id), json!(oc::hash_token(&secret)), json!(now())])]
    };
    let require_one: Vec<usize> = if existing.is_some() { vec![0] } else { Vec::new() };
    st.audited_batch(&statements, &require_one, [&oid,"","",&uid,"identity.rotate",&iid]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"id": iid, "client_id": client_id, "client_secret": secret, "note": "client_secret shown once"}))) }
async fn universal_login(State(st): State<S>, Json(body): Json<Value>) -> Res {
    let cid = body.get("client_id").and_then(|v| v.as_str()).unwrap_or(""); let secret = body.get("client_secret").and_then(|v| v.as_str()).unwrap_or("");
    let cred = st.db.one("SELECT identity_id FROM identity_credentials WHERE client_id=? AND secret_hash=?", &[json!(cid), json!(oc::hash_token(secret))]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid client credentials"))?;
    let iid = db::s(&cred, "identity_id");
    let identity = st.db.one("SELECT org_id FROM identities WHERE id=?", &[json!(&iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "identity not found"))?;
    st.require_running(&db::s(&identity, "org_id")).await?;
    let token = oc::random_token("owm");
    st.db.exec("INSERT INTO tokens(id,org_id,name,token_hash,kind,expires_at,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)", &[json!(id()), json!(""), json!("machine"), json!(oc::hash_token(&token)), json!("machine"), json!(now()+3600), json!(now()), json!(iid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"accessToken": token, "expiresIn": 3600, "tokenType": "Bearer", "identity_id": iid}))) }

// ---------- approval workflow: secret change proposals ----------
async fn create_proposal(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h).await?; let mut statements = Vec::new(); let (org, app) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "proposals:write").await?;
    let key = st.env_key(&eid).await?; let payload = serde_json::to_string(&r.secrets.iter().map(|s| json!({"key":s.key,"value":s.value,"path":s.path,"comment":s.comment,"tags":s.tags,"type":s.secret_type})).collect::<Vec<_>>()).unwrap();
    let pid = id();
    statements.push((("INSERT INTO proposals(id,env_id,author,payload_enc,created_at) VALUES(?,?,?,?,?)").to_string(), ([json!(pid), json!(eid), json!(uid), json!(oc::encrypt_symmetric_aad(&key, &proposal_aad(&eid, &pid, "payload"), payload.as_bytes())), json!(now())]).to_vec()));
    st.audited_batch(&statements, &[], [&org,&app,&eid,&uid,"proposal.create",&pid]).await.map_err(|e|bad(&e))?; Ok(j(json!({"id": pid, "status": "pending"}))) }
async fn list_proposals(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid, &uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let rows = st.db.query("SELECT id,env_id,author,status,created_at,decided_by FROM proposals WHERE env_id=? ORDER BY created_at DESC", &[json!(eid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn decide_proposal(State(st): State<S>, h: HeaderMap, Path((pid, action)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM proposals WHERE id=?", &[json!(pid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"proposal not found"))?;
    if db::s(&row,"status") != "pending" { return Err(bad("proposal already decided")); }
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid, &uid).await?;
    st.check_admin(&org, &uid).await.map_err(|_| err(StatusCode::FORBIDDEN, "proposals need approval by an admin (not the author)"))?;
    if action == "approve" {
        let key = st.env_key(&eid).await?; let master = st.master(); let plain = oc::decrypt_symmetric_compat(&key, &proposal_aad(&eid, &pid, "payload"), &db::s(&row,"payload_enc")).map_err(|e| bad(&e))?;
        let items: Vec<Value> = serde_json::from_slice(&plain).unwrap_or_default(); let mut count = 0;
        let mut statements: Vec<(String,Vec<Value>)> = Vec::new(); let mut require_one: Vec<usize> = Vec::new();
        for it in &items { let s = SecretIn{ key: it["key"].as_str().unwrap_or("").into(), value: it["value"].as_str().unwrap_or("").into(), path: it["path"].as_str().unwrap_or("/").into(), comment: it["comment"].as_str().unwrap_or("").into(), tags: it["tags"].as_str().unwrap_or("").into(), secret_type: it["type"].as_str().unwrap_or("secret").into(), expected_version: None };
            if !s.key.is_empty() { require_one.push(statements.len()); statements.push(("UPDATE envs SET id=id WHERE id=?".into(), vec![json!(&eid)]));
                require_one.push(statements.len()); statements.extend(secret_statements(&st, &eid, &org, &key, &uid, &s, &master).await?); count += 1; } }
        statements.push(("UPDATE proposals SET status='approved',decided_by=? WHERE id=?".into(), vec![json!(uid), json!(pid)]));
        st.audited_batch_master(&statements, &require_one, [&org,&app,&eid,&uid,"proposal.approve",&format!("{} applied {} secrets",pid,count)], master).await.map_err(secret_batch_error)?; let sync_errors = trigger_sync(&st,&eid,&uid).await;
        Ok(j(json!({"status":"approved","applied":count,"sync_errors":sync_errors})))
    } else if action == "reject" {
        st.audited_batch(&[("UPDATE proposals SET status='rejected',decided_by=? WHERE id=?".into(), vec![json!(uid), json!(pid)])], &[], [&org,&app,&eid,&uid,"proposal.reject",&pid]).await.map_err(|e| bad(&e))?; Ok(j(json!({"status":"rejected"})))
    } else { Err(bad("action must be approve or reject")) } }

// ---------- access requests ----------
async fn request_access(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let (org, _) = st.env_org_app(&eid).await?; st.require_org(&org, &uid).await?;
    let rid = id(); st.db.exec("INSERT INTO access_requests(id,env_id,user_id,reason,created_at) VALUES(?,?,?,?,?)", &[json!(rid), json!(eid), json!(uid), json!(body.get("reason").and_then(|v| v.as_str()).unwrap_or("")), json!(now())]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "status": "pending"}))) }
async fn list_access_requests(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.require_env(&eid, &uid).await?;
    let rows = st.db.query("SELECT * FROM access_requests WHERE env_id=? ORDER BY created_at DESC", &[json!(eid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn decide_access(State(st): State<S>, h: HeaderMap, Path((rid, action)): Path<(String, String)>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM access_requests WHERE id=?", &[json!(rid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"request not found"))?;
    if db::s(&row,"status") != "pending" { return Err(bad("already decided")); }
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid, &uid).await?;
    st.check_admin(&org, &uid).await?;
    if action == "approve" { let target = db::s(&row,"user_id"); st.audited_batch(&[("DELETE FROM env_members WHERE env_id=? AND user_id=?".into(), vec![json!(&eid),json!(&target)]),("INSERT INTO env_members(env_id,user_id) VALUES(?,?)".into(), vec![json!(&eid),json!(&target)]),("UPDATE access_requests SET status='approved',decided_by=? WHERE id=?".into(), vec![json!(uid),json!(rid)])], &[2], [&org,&app,&eid,&uid,"access.approve",&target]).await.map_err(|e| bad(&e))?;
        Ok(j(json!({"status":"approved"})))
    } else { st.db.exec("UPDATE access_requests SET status='rejected',decided_by=? WHERE id=?", &[json!(uid), json!(rid)]).await.map_err(|e| bad(&e))?; Ok(j(json!({"status":"rejected"}))) } }

// ---------- dynamic Postgres secrets + PKI ----------
async fn reserve_lease(st: &S, org: &str, eid: &str, lid: &str, name: &str, config: &str, expires_at: i64) -> Result<(), (StatusCode, Json<Value>)> {
    st.db.batch_checked(&[
        ("UPDATE orgs SET name=name WHERE id=?".into(), vec![json!(org)]),
        ("INSERT INTO leases(id,env_id,name,value_enc,config_enc,expires_at,created_at) SELECT ?,e.id,?,'',?,?,? FROM envs e JOIN apps a ON a.id=e.app_id WHERE e.id=? AND a.org_id=?".into(), vec![json!(lid), json!(name), json!(config), json!(expires_at), json!(now()), json!(eid), json!(org)]),
    ], &[0, 1]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT, "workspace or environment was deleted before lease issuance") } else { bad(&e) })
}
async fn complete_lease(st: &S, lid: &str, value: &str, username: &str, config: &str) -> Result<(), (StatusCode, Json<Value>)> {
    st.db.batch_checked(&[("UPDATE leases SET value_enc=?,username=?,config_enc=? WHERE id=? AND value_enc='' AND revoked=0".into(), vec![json!(value), json!(username), json!(config), json!(lid)])], &[0]).await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("lease {} issued but persistence failed; pending reservation retained, operator reconciliation required", lid)))
}
async fn create_lease_v2(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "leases:write").await?;
    let key = st.env_key(&eid).await?; let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("lease").to_string();
    let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600).clamp(60, 30 * 86400); let lid = id();
    let typ = body.get("type").and_then(|v| v.as_str()).unwrap_or("generic");
    let pending = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), json!({"type":"pending", "request":body}).to_string().as_bytes());
    if typ == "postgres" {
        let conn = body.get("config").and_then(|c| c.get("connection")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if conn.is_empty() { return Err(bad("postgres dynamic secret requires config.connection")); }
        if db_target_allowed(&conn).map_err(|e| bad(&e))? != "postgres" { return Err(bad("postgres dynamic secret requires a postgres:// connection")); }
        let username = format!("dyn_{}", oc::random_token("").chars().take(12).collect::<String>().to_lowercase());
        let password = oc::random_token("dyn");
        reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
        if let Err(e) = crate::pglease::create_role(&conn, &username, &password, now() + ttl).await {
            if crate::pglease::drop_role(&conn, &username).await.is_err() { return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("lease {} issuance and Postgres cleanup failed; pending reservation retained, operator reconciliation required", lid))); }
            st.db.batch_checked(&[("DELETE FROM leases WHERE id=? AND value_enc='' AND revoked=0".into(), vec![json!(&lid)])], &[0]).await
                .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("lease {} cleanup succeeded but its pending record could not be retired", lid)))?;
            return Err(bad(&e)); }
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), json!({"connection":conn,"type":"postgres"}).to_string().as_bytes());
        complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), password.as_bytes()), &username, &config_enc).await?;
        return Ok(j(json!({"id": lid, "username": username, "password": password, "expires_at": now()+ttl, "type":"postgres"}))); }
    if typ == "mysql" {
        let config = body.get("config").cloned().unwrap_or(json!({}));
        let conn = config.get("connection").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if conn.is_empty() { return Err(bad("mysql dynamic secret requires config.connection")); }
        if db_target_allowed(&conn).map_err(|e| bad(&e))? != "mysql" { return Err(bad("mysql dynamic secret requires a mysql:// or mariadb:// connection")); }
        let grants: Vec<String> = config.get("grants").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
        if grants.is_empty() || grants.len() > 8 { return Err(bad("mysql dynamic secret requires config.grants, 1 to 8 entries like \"SELECT ON app.*\"")); }
        let username = format!("dyn_{}", oc::random_token("").chars().filter(|c| c.is_ascii_alphanumeric()).take(12).collect::<String>().to_lowercase());
        let password = oc::random_token("dyn");
        for grant in &grants { crate::mysqllease::grant_sql(grant, &username).map_err(|e| bad(&e))?; }
        reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
        if let Err(e) = crate::mysqllease::create_account(&conn, &username, &password, &grants).await {
            // A half-granted account must not outlive the failed request.
            if crate::mysqllease::drop_account(&conn, &username).await.is_err() { return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("lease {} issuance and MySQL cleanup failed; pending reservation retained, operator reconciliation required", lid))); }
            st.db.batch_checked(&[("DELETE FROM leases WHERE id=? AND value_enc='' AND revoked=0".into(), vec![json!(&lid)])], &[0]).await
                .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("lease {} cleanup succeeded but its pending record could not be retired", lid)))?;
            return Err(bad(&e)); }
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), json!({"connection":conn,"type":"mysql","grants":grants}).to_string().as_bytes());
        complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), password.as_bytes()), &username, &config_enc).await?;
        return Ok(j(json!({"id": lid, "username": username, "password": password, "expires_at": now()+ttl, "type":"mysql"}))); }
    if typ == "aws_iam" {
        let config = body.get("config").cloned().unwrap_or(json!({}));
        reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
        let creds = integrations::sts_assume_role(&config).await.map_err(|e| bad(&e))?;
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), json!({"type":"aws_iam"}).to_string().as_bytes());
        complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), creds.to_string().as_bytes()), "", &config_enc).await?;
        return Ok(j(json!({"id": lid, "credentials": creds, "expires_at": now()+ttl, "type":"aws_iam"})));
    }
    if typ == "planetscale" {
        let config = body.get("config").cloned().unwrap_or(json!({}));
        reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
        let issued = integrations::planetscale_create_password(&config, &name, ttl).await.map_err(|e| bad(&e))?;
        let password = issued["password"].as_str().unwrap_or(""); let remote_id = issued["id"].as_str().unwrap_or("");
        let stored = json!({"type": "planetscale", "base_url": issued["base"], "remote_id": remote_id, "engine": issued["engine"],
            "organization": config.get("organization").and_then(|v| v.as_str()).unwrap_or(""),
            "db": config.get("database").and_then(|v| v.as_str()).unwrap_or(""),
            "branch": config.get("branch").and_then(|v| v.as_str()).unwrap_or(""),
            "parent": config.get("service_token").and_then(|v| v.as_str()).unwrap_or(""),
            "parent_id": config.get("service_token_id").and_then(|v| v.as_str()).unwrap_or("")});
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), stored.to_string().as_bytes());
        complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), password.as_bytes()), issued["username"].as_str().unwrap_or(""), &config_enc).await?;
        return Ok(j(json!({"id": lid, "username": issued["username"], "password": password, "host": issued["host"], "database": issued["database"], "remote_id": remote_id, "expires_at": now()+ttl, "type": "planetscale"})));
    }
    if typ == "instabox" {
        let config = body.get("config").cloned().unwrap_or(json!({}));
        reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
        let issued = integrations::instabox_create_ssh_token(&config, &name, ttl).await.map_err(|e| bad(&e))?;
        let token = issued["token"].as_str().unwrap_or(""); let remote_id = issued["id"].as_str().unwrap_or("");
        let stored = json!({"type": "instabox", "base_url": issued["base"], "remote_id": remote_id,
            "machine_id": config.get("machine_id").and_then(|v| v.as_str()).unwrap_or(""),
            "parent": config.get("api_key").and_then(|v| v.as_str()).unwrap_or("")});
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), stored.to_string().as_bytes());
        complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), token.as_bytes()), "", &config_enc).await?;
        return Ok(j(json!({"id": lid, "value": token, "host": issued["host"], "port": issued["port"], "command": issued["command"], "remote_id": remote_id, "expires_at": now()+ttl, "type": "instabox"})));
    }
	    if matches!(typ, "openrouter" | "resend" | "openai" | "huggingface" | "fireworks" | "mistral" | "perplexity" | "xai" | "gemini" | "cloudflare" | "deepgram" | "elevenlabs" | "deepinfra" | "baseten" | "fal" | "speechmatics" | "chutes") {
        let config = body.get("config").cloned().unwrap_or(json!({}));
        reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
		        let issued = match typ {
	            "openrouter" => integrations::openrouter_create_key(&config, &name, ttl).await,
	            "resend" => integrations::resend_create_key(&config, &name).await,
	            "huggingface" => integrations::huggingface_create_token(&config, &name).await,
	            "fireworks" => inference_leases::fireworks_create_key(&config, &name, ttl).await,
	            "mistral" => inference_leases::mistral_create_key(&config, &name, ttl).await,
	            "perplexity" => inference_leases::perplexity_create_key(&config, &name).await,
	            "xai" => inference_leases::xai_create_key(&config, &name).await,
	            "gemini" => inference_leases::gemini_create_key(&config, &name).await,
	            "cloudflare" => inference_leases::cloudflare_create_token(&config, &name, ttl).await,
	            "deepgram" => inference_leases::deepgram_create_key(&config, &name, ttl).await,
	            "elevenlabs" => inference_leases::elevenlabs_create_key(&config, &name).await,
	            "deepinfra" => inference_leases::deepinfra_create_key(&config, &name).await,
	            "baseten" => inference_leases::baseten_create_key(&config, &name, ttl).await,
	            "fal" => inference_leases::fal_create_key(&config, &name).await,
		            "speechmatics" => inference_leases::speechmatics_create_key(&config, &name, ttl).await,
		            "chutes" => inference_leases::chutes_create_key(&config, &name).await,
		            _ => integrations::openai_create_key(&config, &name, ttl).await,
	        }.map_err(|e| bad(&e))?;
	        let (secret, remote_id, base_url) = match typ {
	            "openrouter" => (issued["key"].as_str().unwrap_or("").to_string(), issued["hash"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://openrouter.ai/api/v1")),
	            "resend" => (issued["token"].as_str().unwrap_or("").to_string(), issued["id"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://api.resend.com")),
	            "huggingface" => (issued["token"].as_str().unwrap_or("").to_string(), issued["id"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://huggingface.co")),
	            "perplexity" => (issued["token"].as_str().unwrap_or("").to_string(), issued["token"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://api.perplexity.ai")),
	            "deepinfra" => (issued["token"].as_str().unwrap_or("").to_string(), issued["id"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://api.deepinfra.com")),
	            "cloudflare" => (issued["token"].as_str().unwrap_or("").to_string(), issued["id"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://api.cloudflare.com/client/v4")),
	            "gemini" => (issued["key"].as_str().unwrap_or("").to_string(), issued["name"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://apikeys.googleapis.com")),
		            "fireworks" | "mistral" | "xai" | "deepgram" | "elevenlabs" | "baseten" | "fal" | "speechmatics" | "chutes" => (issued["key"].as_str().unwrap_or("").to_string(), issued["id"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or(match typ { "fireworks" => "https://api.fireworks.ai", "mistral" => "https://api.mistral.ai", "xai" => "https://management-api.x.ai", "deepgram" => "https://api.deepgram.com", "baseten" => "https://api.baseten.co", "fal" => "https://api.fal.ai", "speechmatics" => "https://mp.speechmatics.com", "chutes" => "https://api.chutes.ai", _ => "https://api.elevenlabs.io" })),
	            _ => (issued["value"].as_str().unwrap_or("").to_string(), issued["id"].as_str().unwrap_or("").to_string(), config.get("base_url").and_then(|v| v.as_str()).unwrap_or("https://api.openai.com/v1")),
	        };
        // The parent credential is encrypted for the revoke call only. The response carries the child secret.
        let mut stored = json!({"type": typ, "base_url": base_url, "remote_id": remote_id});
	        let parent = match typ {
	            "openrouter" | "xai" | "speechmatics" => config.get(if typ == "speechmatics" { "management_token" } else { "management_key" }),
	            "huggingface" => config.get("token"),
	            "openai" | "mistral" => config.get("admin_key"),
	            "gemini" => config.get("access_token"),
	            "cloudflare" => config.get("api_token"),
	            _ => config.get("api_key"),
	        }.and_then(|v| v.as_str()).unwrap_or("");
	        stored["parent"] = json!(parent);
	        if typ == "openai" { stored["project_id"] = json!(config.get("project_id").and_then(|v| v.as_str()).unwrap_or("")); }
	        if typ == "huggingface" { stored["org"] = json!(config.get("org").and_then(|v| v.as_str()).unwrap_or("")); stored["service_account_id"] = json!(config.get("service_account_id").and_then(|v| v.as_str()).unwrap_or("")); }
	        if typ == "fireworks" { stored["account_id"] = json!(config.get("account_id").and_then(|v| v.as_str()).unwrap_or("")); stored["user_id"] = json!(config.get("user_id").and_then(|v| v.as_str()).unwrap_or("")); }
	        if matches!(typ, "deepgram" | "gemini") { stored["project_id"] = json!(config.get(if typ == "deepgram" { "project_id" } else { "project" }).and_then(|v| v.as_str()).unwrap_or("")); }
	        if typ == "elevenlabs" { stored["service_account_id"] = json!(config.get("service_account_id").and_then(|v| v.as_str()).unwrap_or("")); }
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), stored.to_string().as_bytes());
        complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), secret.as_bytes()), "", &config_enc).await?;
        return Ok(j(json!({"id": lid, "value": secret, "remote_id": remote_id, "expires_at": now()+ttl, "type": typ})));
    }
    let value = oc::random_token("dyn");
    reserve_lease(&st, &org, &eid, &lid, &name, &pending, now()+ttl).await?;
    complete_lease(&st, &lid, &oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), value.as_bytes()), "", "").await?;
    Ok(j(json!({"id": lid, "value": value, "expires_at": now()+ttl}))) }
async fn revoke_lease_remote_inner(st: &S, lid: &str, audit: Option<[&str;6]>) -> Result<(), (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM leases WHERE id=?", &[json!(lid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    let eid = db::s(&row,"env_id"); let key = st.env_key(&eid).await?;
    if db::s(&row,"value_enc").is_empty() { return Err(err(StatusCode::CONFLICT, "lease issuance is unresolved; operator reconciliation required before revocation")); }
    if !db::s(&row,"config_enc").is_empty() { let plain = oc::decrypt_symmetric_compat(&key, &lease_aad(&eid, lid, "config"), &db::s(&row,"config_enc")).map_err(|_| bad("lease config could not be decrypted"))?; let cfg: Value = serde_json::from_slice(&plain).map_err(|_| bad("invalid lease config"))?;
        match cfg.get("type").and_then(|v| v.as_str()) {
            Some("postgres") => { let conn = cfg.get("connection").and_then(|v| v.as_str()).unwrap_or("").to_string(); let username = db::s(&row,"username");
                crate::pglease::drop_role(&conn, &username).await.map_err(|_| bad("Postgres lease revocation failed"))?; }
            Some("mysql") => { let conn = cfg.get("connection").and_then(|v| v.as_str()).unwrap_or("").to_string(); let username = db::s(&row,"username");
                crate::mysqllease::drop_account(&conn, &username).await.map_err(|_| bad("MySQL lease revocation failed"))?; }
            Some("planetscale") => { let remote = cfg.get("remote_id").and_then(|v| v.as_str()).unwrap_or("");
                integrations::planetscale_revoke_password(&cfg, remote).await.map_err(|e| bad(&e))?; }
            Some("instabox") => { let remote = cfg.get("remote_id").and_then(|v| v.as_str()).unwrap_or("");
                let machine = cfg.get("machine_id").and_then(|v| v.as_str()).unwrap_or("");
                integrations::instabox_revoke_ssh_token(&cfg, machine, remote).await.map_err(|e| bad(&e))?; }
            Some(kind @ ("openrouter" | "resend" | "openai" | "huggingface" | "fireworks" | "mistral" | "perplexity" | "xai" | "gemini" | "cloudflare" | "deepgram" | "elevenlabs" | "deepinfra" | "baseten" | "fal" | "speechmatics" | "chutes")) => {
                let base = cfg.get("base_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let parent = cfg.get("parent").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let remote = cfg.get("remote_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
	                let project = cfg.get("project_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
	                let hf_org = cfg.get("org").and_then(|v| v.as_str()).unwrap_or("").to_string();
	                let service_account = cfg.get("service_account_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
	                let account_id = cfg.get("account_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
	                let user_id = cfg.get("user_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let kind = kind.to_string();
                // A failed remote delete must not mark the local lease revoked.
	                let remote_result = match kind.as_str() {
	                    "openrouter" => integrations::openrouter_revoke_key(&base, &parent, &remote).await,
	                    "resend" => integrations::resend_revoke_key(&base, &parent, &remote).await,
	                    "huggingface" => integrations::huggingface_revoke_token(&base, &parent, &hf_org, &service_account, &remote).await,
	                    "fireworks" => inference_leases::fireworks_revoke_key(&base, &parent, &account_id, &user_id, &remote).await,
	                    "mistral" => inference_leases::mistral_revoke_key(&base, &parent, &remote).await,
	                    "perplexity" => inference_leases::perplexity_revoke_key(&base, &parent, &remote).await,
	                    "xai" => inference_leases::xai_revoke_key(&base, &parent, &remote).await,
	                    "gemini" => inference_leases::gemini_revoke_key(&base, &parent, &remote).await,
	                    "cloudflare" => inference_leases::cloudflare_revoke_token(&base, &parent, &remote).await,
	                    "deepgram" => inference_leases::deepgram_revoke_key(&base, &parent, &project, &remote).await,
	                    "elevenlabs" => inference_leases::elevenlabs_revoke_key(&base, &parent, &service_account, &remote).await,
	                    "deepinfra" => inference_leases::deepinfra_revoke_key(&base, &parent, &remote).await,
	                    "baseten" => inference_leases::baseten_revoke_key(&base, &parent, &remote).await,
	                    "fal" => inference_leases::fal_revoke_key(&base, &parent, &remote).await,
		                    "speechmatics" => inference_leases::speechmatics_revoke_key(&base, &parent, &remote).await,
		                    "chutes" => inference_leases::chutes_revoke_key(&base, &parent, &remote).await,
		                    _ => integrations::openai_revoke_key(&base, &parent, &project, &remote).await,
	                };
                remote_result.map_err(|e| bad(&e))?;
            }
            _ => {}
        } }
    if let Some(fields)=audit { st.audited_batch(&[("UPDATE leases SET revoked=1 WHERE id=?".into(), vec![json!(lid)])], &[], fields).await.map_err(|e| bad(&e))?; }
    else { st.db.exec("UPDATE leases SET revoked=1 WHERE id=?", &[json!(lid)]).await.map_err(|e| bad(&e))?; }
    Ok(()) }
async fn revoke_lease_remote(st: &S, lid: &str) -> Result<(), (StatusCode, Json<Value>)> { revoke_lease_remote_inner(st, lid, None).await }
async fn revoke_lease_remote_audited(st: &S, lid: &str, audit: [&str;6]) -> Result<(), (StatusCode, Json<Value>)> { revoke_lease_remote_inner(st, lid, Some(audit)).await }
async fn revoke_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM leases WHERE id=?", &[json!(&lid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "leases:write").await?;
    revoke_lease_remote_audited(&st, &lid, [&org, &app, &eid, &uid, "lease.revoke", &lid]).await?;
    Ok(j(json!({"revoked": lid}))) }
async fn lookup_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM leases WHERE id=?", &[json!(&lid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    let eid = db::s(&row,"env_id"); st.check_scope(&h, &eid).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let kind = st.env_key(&eid).await.ok()
        .and_then(|key| oc::decrypt_symmetric_compat(&key, &lease_aad(&eid, &lid, "config"), &db::s(&row,"config_enc")).ok())
        .and_then(|plain| serde_json::from_slice::<Value>(&plain).ok())
        .and_then(|cfg| cfg.get("type").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| "generic".to_string());
    let expires_at = db::n(&row,"expires_at"); let revoked = db::n(&row,"revoked") != 0;
    Ok(j(json!({"id": db::s(&row,"id"), "name": db::s(&row,"name"), "env_id": eid, "type": kind,
        "username": db::s(&row,"username"), "created_at": db::n(&row,"created_at"), "expires_at": expires_at,
        "revoked": revoked, "renewable": !revoked && expires_at > now()}))) }

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "pki")]
fn ca_params(cn: &str, is_ca: bool) -> rcgen::CertificateParams {
    let mut p = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2050, 1, 1);
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    if is_ca { p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained); p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign]; }
    else { p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature]; p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth, rcgen::ExtendedKeyUsagePurpose::ClientAuth]; }
    p }
// Device certificates keep the private key on the device: enrollment takes a
// CSR, so the server never returns or stores the device key.
#[cfg(feature = "pki")]
const DEVICE_SELECT: &str = "SELECT d.*,c.id AS cert_id,c.serial AS cert_serial,c.expires_at AS cert_expires_at,c.revoked AS cert_revoked,c.revoked_at AS cert_revoked_at FROM pki_devices d LEFT JOIN pki_certs c ON c.id=d.active_cert_id";
#[cfg(feature = "pki")]
fn valid_device_name(name: &str) -> bool { !name.is_empty() && name.len() <= 64 && !name.starts_with(['.', '-']) && !name.ends_with(['.', '-']) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')) }
#[cfg(feature = "pki")]
fn valid_dns_san(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    !s.is_empty() && s.len() <= 253 && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) }
#[cfg(feature = "pki")]
fn device_sans(body: &Value) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let Some(arr) = body.get("sans") else { return Ok(Vec::new()); };
    let arr = arr.as_array().ok_or_else(|| bad("sans must be an array of DNS names or IP addresses"))?;
    if arr.len() > 32 { return Err(bad("at most 32 SANs are allowed")); }
    let mut out: Vec<String> = Vec::new();
    for raw in arr.iter().filter_map(|v| v.as_str()) {
        let s = raw.trim();
        let value = if let Ok(ip) = s.parse::<std::net::IpAddr>() { ip.to_string() }
            else if valid_dns_san(s) { s.trim_end_matches('.').to_string() }
            else { return Err(bad(&format!("invalid SAN {:?}: must be a DNS name or IP address", raw))); };
        if !out.iter().any(|x| x.eq_ignore_ascii_case(&value)) { out.push(value); } }
    Ok(out) }
#[cfg(feature = "pki")]
fn device_json(r: &Row) -> Value {
    let active = if db::s(r, "cert_id").is_empty() { Value::Null } else {
        json!({"id": db::s(r,"cert_id"), "serial": db::s(r,"cert_serial"), "expires_at": db::n(r,"cert_expires_at"), "revoked": db::n(r,"cert_revoked") == 1, "revoked_at": db::n(r,"cert_revoked_at")}) };
    json!({"id": db::s(r,"id"), "org_id": db::s(r,"org_id"), "ca_id": db::s(r,"ca_id"), "app_id": db::s(r,"app_id"), "env_id": db::s(r,"env_id"), "group_id": db::s(r,"group_id"), "name": db::s(r,"name"), "model": db::s(r,"model"), "hardware_serial": db::s(r,"hardware_serial"), "tags": db::s(r,"tags"), "sans": db::s(r,"sans").split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>(), "cert_days": db::n(r,"cert_days"), "attested": db::n(r,"attested") == 1, "active_cert_id": db::s(r,"active_cert_id"), "created_at": db::n(r,"created_at"), "updated_at": db::n(r,"updated_at"), "active_cert": active}) }
#[cfg(feature = "pki")]
fn group_json(r: &Row) -> Value {
    json!({"id": db::s(r,"id"), "org_id": db::s(r,"org_id"), "ca_id": db::s(r,"ca_id"), "name": db::s(r,"name"), "env_id": db::s(r,"env_id"), "sans": db::s(r,"sans").split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>(), "cert_days": db::n(r,"cert_days"), "tags": db::s(r,"tags"), "device_count": db::n(r,"device_count"), "created_at": db::n(r,"created_at"), "updated_at": db::n(r,"updated_at")}) }
#[cfg(feature = "pki")]
fn csv_field(v: &str) -> String {
    let formula = v.chars().next().map(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r')).unwrap_or(false);
    let safe = if formula { format!("'{}", v) } else { v.to_string() };
    if safe.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) { format!("\"{}\"", safe.replace('"', "\"\"")) } else { safe } }
#[cfg(feature = "pki")]
async fn pki_env_access(st: &S, row: &Row, uid: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let env = db::s(row,"env_id"); if !env.is_empty() { st.require_env(&env,uid).await?; } Ok(())
}
#[cfg(feature = "pki")]
async fn load_device_opt(st: &S, did: &str) -> Result<Option<Row>, (StatusCode, Json<Value>)> {
    st.db.one(&format!("{} WHERE d.id=?", DEVICE_SELECT), &[json!(did)]).await.map_err(|e| bad(&e)) }
#[cfg(feature = "pki")]
async fn load_device(st: &S, did: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    load_device_opt(st, did).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "device not found")) }
#[cfg(feature = "pki")]
async fn resolve_device_scope(st: &S, org: &str, uid: &str, app_id: String, env_id: String) -> Result<(String, String), (StatusCode, Json<Value>)> {
    if !env_id.is_empty() {
        let (eorg, eapp) = st.env_org_app(&env_id).await.map_err(|_| err(StatusCode::NOT_FOUND, "environment not found"))?;
        if eorg != org { return Err(err(StatusCode::NOT_FOUND, "environment not found")); }
        st.require_env(&env_id,uid).await?;
        if !app_id.is_empty() && app_id != eapp { return Err(bad("environment does not belong to the app")); }
        Ok((eapp, env_id))
    } else if !app_id.is_empty() {
        let row = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(&app_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "app not found"))?;
        if db::s(&row, "org_id") != org { return Err(err(StatusCode::NOT_FOUND, "app not found")); }
        Ok((app_id, env_id))
    } else { Ok((app_id, env_id)) } }
#[cfg(feature = "pki")]
fn body_str(body: &Value, key: &str) -> Option<String> { body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()) }
#[cfg(feature = "pki")]
fn device_conflict(e: String) -> (StatusCode, Json<Value>) { let l = e.to_lowercase(); if l.contains("unique") || l.contains("duplicate") { err(StatusCode::CONFLICT, "a device with this name already exists for the CA") } else { bad(&e) } }
#[cfg(feature = "pki")]
fn group_conflict(e: String) -> (StatusCode, Json<Value>) { let l = e.to_lowercase(); if l.contains("unique") || l.contains("duplicate") { err(StatusCode::CONFLICT, "a group with this name already exists for the CA") } else { bad(&e) } }
#[cfg(feature = "pki")]
async fn insert_device(st: &S, org: &str, uid: &str, caid: &str, body: &Value, scoped: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    let name = body_str(body, "name").unwrap_or_default();
    if !valid_device_name(&name) { return Err(bad("name must be 1-64 characters of A-Z, a-z, 0-9, dot, underscore, colon or hyphen")); }
    let group_id = body_str(body, "group_id").unwrap_or_default();
    let group = if group_id.is_empty() { None } else {
        Some(st.db.one("SELECT * FROM pki_groups WHERE id=? AND ca_id=? AND org_id=?", &[json!(&group_id), json!(caid), json!(org)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "group not found"))?) };
    let g = |key: &str| group.as_ref().map(|r| db::s(r, key)).unwrap_or_default();
    let mut env_id = body_str(body, "env_id").unwrap_or_else(|| g("env_id"));
    if !scoped.is_empty() {
        if env_id.is_empty() { env_id = scoped.to_string(); }
        else if env_id != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); } }
    if !g("env_id").is_empty() && env_id != g("env_id") { return Err(bad("device environment must match the group environment")); }
    let sans = if body.get("sans").is_some() { device_sans(body)?.join(",") } else { g("sans") };
    let group_days = group.as_ref().map(|r| db::n(r, "cert_days")).unwrap_or(0);
    let cert_days = body.get("cert_days").and_then(|v| v.as_i64()).unwrap_or(if group_days > 0 { group_days } else { 90 }).clamp(1, 365);
    let tags = body_str(body, "tags").unwrap_or_else(|| g("tags"));
    let (app_id, env_id) = resolve_device_scope(st, org, uid, body_str(body, "app_id").unwrap_or_default(), env_id).await?;
    let did = id(); let t = now();
    let insert_sql = "INSERT INTO pki_devices(id,org_id,ca_id,app_id,env_id,name,model,hardware_serial,tags,sans,cert_days,active_cert_id,enroll_epoch,deleting,created_at,updated_at,group_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,'',0,0,?,?,?)";
    let params = vec![json!(&did), json!(org), json!(caid), json!(&app_id), json!(&env_id), json!(&name), json!(body_str(body,"model").unwrap_or_default()), json!(body_str(body,"hardware_serial").unwrap_or_default()), json!(&tags), json!(&sans), json!(cert_days), json!(t), json!(t), json!(&group_id)];
    if group_id.is_empty() {
        st.db.exec(insert_sql, &params).await.map_err(device_conflict)?;
    } else {
        st.db.tx_locked("SELECT env_id FROM pki_groups WHERE id=?", &[json!(&group_id)], |r| db::s(r,"env_id").is_empty() || db::s(r,"env_id") == env_id, &[(insert_sql, params)], &[(0, 1)]).await
            .map_err(|e| if e == "lock condition failed" { err(StatusCode::CONFLICT, "group changed or was removed; retry") } else { device_conflict(e) })?; }
    st.db.one(&format!("{} WHERE d.id=?", DEVICE_SELECT), &[json!(&did)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("device not found")) }
#[cfg(feature = "pki")]
async fn insert_enrollment(st: &S, did: &str, row: &Row, ttl: i64, revoke_previous: bool, uid: &str) -> Result<(String, i64, String), (StatusCode, Json<Value>)> {
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(db::s(row,"ca_id"))]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "CA not found"))?;
    if ca_revoked(st,&ca).await { return Err(bad("CA is revoked")); }
    let t = now(); let expires = t + ttl.clamp(300, 604800);
    let code = oc::random_token("owdev"); let eid = id(); let nonce = hex_encode(&oc::random_key()[..16]);
    let _ = st.db.exec("DELETE FROM pki_enrollments WHERE device_id=? AND (used_at>0 OR expires_at<?)", &[json!(did), json!(t)]).await;
    st.db.exec("INSERT INTO pki_enrollments(id,device_id,token_hash,expires_at,used_at,created_by,created_at,enroll_epoch,revoke_previous,nonce) VALUES(?,?,?,?,0,?,?,?,?,?)",
        &[json!(&eid), json!(did), json!(oc::hash_token(&code)), json!(expires), json!(uid), json!(t), json!(db::n(row,"enroll_epoch")), json!(if revoke_previous {1} else {0}), json!(&nonce)]).await.map_err(|e| bad(&e))?;
    Ok((code, expires, nonce)) }
#[cfg(feature = "pki")]
async fn create_ca(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid,&uid).await?; st.require_feature(&oid,"pki").await?;
    let name = body_str(&body,"name").unwrap_or_else(|| "OpenWarp CA".to_string());
    let parent_id = body_str(&body,"parent_id").unwrap_or_default();
    let parent = if parent_id.is_empty() { None } else {
        let p = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=? AND org_id=?", &[json!(&parent_id), json!(&oid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "parent CA not found"))?;
        if db::s(&p,"ca_kind") != "root" { return Err(bad("only a root CA can sign an intermediate")); }
        if db::n(&p,"revoked") == 1 { return Err(bad("parent CA is revoked")); }
        Some(p) };
    let issued = if let Some(p) = &parent {
        let key = oc::decrypt_symmetric(&st.master(), &db::s(p,"key_enc")).map_err(|e| bad(&e))?;
        crate::pki::create_intermediate(&name,&db::s(p,"cert_pem"),&String::from_utf8_lossy(&key))
    } else { crate::pki::create_ca(&name) }.map_err(|e| bad(&e))?;
    let kind = if parent.is_some() { "intermediate" } else { "root" };
    let master=st.master(); let cid = id(); let insert_sql = "INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,serial,created_at,parent_id,ca_kind,kind) VALUES(?,?,?,?,?,?,?,?,?,'x509')";
    let params = vec![json!(&cid), json!(&oid), json!(&name), json!(&issued.certificate_pem), json!(oc::encrypt_symmetric(&master, issued.private_key_pem.as_bytes())), json!(&issued.serial_hex), json!(now()), json!(&parent_id), json!(kind)];
    if parent_id.is_empty() {
        st.epoch_write(&[(insert_sql.into(), params)], &[0], master).await.map_err(master_write_error)?;
    } else {
        st.db.tx_locked("SELECT revoked FROM pki_cas WHERE id=?", &[json!(&parent_id)], |r| db::n(r,"revoked") == 0, &[(insert_sql, params)], &[(0, 1)]).await
            .map_err(|e| if e == "lock condition failed" { bad("parent CA is revoked or missing") } else { bad(&e) })?; }
    Ok(j(json!({"id": cid, "certificate": issued.certificate_pem, "kind": kind, "parent_id": parent_id}))) }
#[cfg(feature = "pki")]
async fn ca_chain(st: &S, ca: &Row) -> Vec<String> {
    let mut out = vec![db::s(ca,"cert_pem")]; let mut parent_id = db::s(ca,"parent_id");
    for _ in 0..3 {
        if parent_id.is_empty() { break; }
        let Some(p) = st.db.one("SELECT cert_pem,parent_id FROM pki_cas WHERE id=?", &[json!(&parent_id)]).await.ok().flatten() else { break; };
        out.push(db::s(&p,"cert_pem")); parent_id = db::s(&p,"parent_id"); }
    out }
#[cfg(feature = "pki")]
async fn ca_revoked(st: &S, ca: &Row) -> bool {
    if !ca_live(ca) { return true; }
    let parent_id = db::s(ca,"parent_id");
    if parent_id.is_empty() { return db::s(ca,"ca_kind") != "root"; }
    if db::s(ca,"ca_kind") != "intermediate" { return true; }
    match st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=? AND org_id=?", &[json!(&parent_id), json!(db::s(ca,"org_id"))]).await {
        Ok(Some(p)) => !ca_live(&p) || db::s(&p,"ca_kind") != "root" || !db::s(&p,"parent_id").is_empty(),
        _ => true } }
#[cfg(feature = "pki")]
fn ca_live(ca: &Row) -> bool {
    if db::n(ca,"revoked") != 0 || db::s(ca,"kind") != "x509" { return false; }
    crate::pki::certificate_live(&db::s(ca,"cert_pem")) }
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "pki")]
fn load_issuer(st: &S, ca: &Row) -> Result<(rcgen::Certificate, rcgen::KeyPair), (StatusCode, Json<Value>)> {
    if db::s(ca,"kind") != "x509" { return Err(bad("not an X.509 CA")); }
    let pem = oc::decrypt_symmetric(&st.master(), &db::s(ca,"key_enc")).map_err(|e| bad(&e))?;
    let kp = rcgen::KeyPair::from_pem(&String::from_utf8_lossy(&pem)).map_err(|e| bad(&e.to_string()))?;
    let mut params = ca_params(&db::s(ca,"name"), true);
    if let Some(serial) = hex_decode(&db::s(ca,"serial")) { params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial)); }
    let cert = params.self_signed(&kp).map_err(|e| bad(&e.to_string()))?;
    Ok((cert, kp)) }
#[cfg(feature = "pki")]
#[cfg(feature = "pki")]
async fn issue_cert(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    st.check_admin(&db::s(&ca,"org_id"), &uid).await?;
    st.require_feature(&db::s(&ca,"org_id"), "pki").await?;
    if db::s(&ca,"kind") != "x509" { return Err(bad("CA is not an X.509 CA")); }
    if ca_revoked(&st,&ca).await { return Err(bad("CA is revoked")); }
    if db::n(&ca,"attest_required") == 1 || !db::s(&ca,"hook_url").is_empty() { return Err(err(StatusCode::FORBIDDEN,"CA policy requires CSR issuance")); }
    let device_id = body_str(&body, "device_id").unwrap_or_default();
    let mut issue_app = String::new();
    let (cn, sans, days, epoch) = if device_id.is_empty() {
        st.require_org_running(&db::s(&ca,"org_id")).await?;
        let cn = body_str(&body, "cn").unwrap_or_else(|| "service".to_string());
        let sans = body.get("sans").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(",")).unwrap_or_default();
        (cn, sans, body.get("days").and_then(|v| v.as_i64()).unwrap_or(365).clamp(1, 3650), 0)
    } else {
        let dev = st.db.one("SELECT * FROM pki_devices WHERE id=? AND ca_id=?", &[json!(&device_id), json!(caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"device not found"))?;
        pki_env_access(&st,&dev,&uid).await?;
        if db::n(&dev,"deleting") == 1 { return Err(err(StatusCode::NOT_FOUND,"device not found")); }
        st.require_running(&db::s(&dev,"org_id")).await?;
        issue_app = db::s(&dev,"app_id");
        if !issue_app.is_empty() { st.require_app_running(&issue_app).await?; }
        (db::s(&dev,"name"), db::s(&dev,"sans"), body.get("days").and_then(|v| v.as_i64()).unwrap_or(db::n(&dev,"cert_days")).clamp(1, 365), db::n(&dev,"enroll_epoch")) };
    let key = oc::decrypt_symmetric(&st.master(), &db::s(&ca,"key_enc")).map_err(|e| bad(&e))?;
    let names: Vec<String> = sans.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
    let issued = if device_id.is_empty() { crate::pki::issue(&db::s(&ca,"cert_pem"),&String::from_utf8_lossy(&key),&cn,&names,days) }
        else { crate::pki::issue_device(&db::s(&ca,"cert_pem"),&String::from_utf8_lossy(&key),&cn,&names,days,None) }.map_err(|e| bad(&e))?;
    let cert_id = id(); let serial = issued.serial_hex.clone(); let t = now(); let expires = crate::pki::certificate_expiry(&issued.certificate_pem).map_err(|e| bad(&e))?;
    let mut stmts: Vec<(&str, Vec<Value>)> = vec![
        ("INSERT INTO pki_certs(id,ca_id,cn,cert_pem,serial,expires_at,created_at,device_id,revoked_at,issued_via) VALUES(?,?,?,?,?,?,?,?,0,'server')", vec![json!(&cert_id), json!(&caid), json!(&cn), json!(&issued.certificate_pem), json!(&serial), json!(expires), json!(t), json!(&device_id)]),
    ];
    let mut expect = vec![(0usize, 1u64)];
    if !device_id.is_empty() {
        stmts.push(("UPDATE pki_devices SET active_cert_id=?,updated_at=?,enroll_epoch=enroll_epoch+1 WHERE id=? AND enroll_epoch=? AND deleting=0", vec![json!(&cert_id), json!(t), json!(&device_id), json!(epoch)]));
        expect.push((1, 1)); }
    // Lock the issuing CA, workspace and project rows: a concurrent revoke or
    // lockdown either commits first (the lock check fails) or waits and sweeps
    // this certificate afterwards.
    let lock = pki_issuer_lock(&issue_app); let lock_params = pki_issuer_params(&issue_app, &caid);
    match st.db.tx_locked(&lock, &lock_params, |r| issuer_unchanged(r,&ca), &stmts, &expect).await {
        Ok(_) => {}
        Err(e) if e == "lock condition failed" => return Err(err(StatusCode::CONFLICT, "CA was revoked; retry")),
        Err(e) if e.contains("affected 0 rows") => return Err(err(StatusCode::CONFLICT, "device changed while issuing; retry")),
        Err(e) => return Err(bad(&e)) }
    if !device_id.is_empty() { st.audit(&db::s(&ca,"org_id"), "", "", &uid, "pki.issue.device", &format!("{} {}", device_id, serial)).await; }
    Ok(j(json!({"id": cert_id, "certificate": issued.certificate_pem, "private_key": issued.private_key_pem, "ca_certificate": db::s(&ca,"cert_pem"), "ca_chain": ca_chain(&st,&ca).await, "device_id": device_id, "expires_at": expires}))) }
#[cfg(feature = "pki")]
async fn ocsp_respond(State(st): State<S>, PeerAddr(addr): PeerAddr, Path(caid): Path<String>, body: Bytes) -> Response {
    if let Err(e)=st.epoch_ok().await { return e.into_response(); }
    // Unauthenticated by design and one signing operation per call, so it
    // carries its own budget. The limit sits far above what a caching client
    // needs; a caller that trips it is not a client checking its own
    // certificates. A 429 is a soft-fail signal for revocation, which is why
    // the budget is generous rather than tight.
    let budget = oc::hash_token(&format!("ocsp:{}", addr));
    if st.db.rate_increment(&budget, now(), 60).await.is_ok_and(|count| count > 600) {
        return err(StatusCode::TOO_MANY_REQUESTS, "too many certificate status requests; retry shortly").into_response(); }
    let ca = match st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await { Ok(Some(c)) => c, _ => return err(StatusCode::NOT_FOUND, "CA not found").into_response() };
    let cert_der = match keystore_ocsp::pem::decode("CERTIFICATE", &db::s(&ca,"cert_pem")) { Ok(d) => d, Err(e) => return bad(&e.to_string()).into_response() };
    let key_pem = match oc::decrypt_symmetric(&st.master(), &db::s(&ca,"key_enc")) { Ok(k) => k, Err(e) => return bad(&e).into_response() };
    let key_text = String::from_utf8_lossy(&key_pem);
    let label = if key_text.contains("BEGIN EC PRIVATE KEY") { "EC PRIVATE KEY" } else { "PRIVATE KEY" };
    let key_der = match keystore_ocsp::pem::decode(label, &key_text) { Ok(d) => d, Err(e) => return bad(&e.to_string()).into_response() };
    let request = match keystore_ocsp::OcspRequest::from_der(&body) { Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let responder = match keystore_ocsp::Responder::new(&cert_der, &key_der, keystore_pki::SignatureAlgorithm::Sha256WithEcdsa) {
        Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    // The responder callback is synchronous, so load the CA's revocation
    // table once instead of doing a database lookup per certificate.
    let certs = st.db.query("SELECT serial,revoked,revoked_at FROM pki_certs WHERE ca_id=?", &[json!(&caid)]).await.unwrap_or_default();
    let status: HashMap<String, (bool, i64)> = certs.iter().map(|r| (db::s(r, "serial").to_lowercase(), (db::n(r, "revoked") == 1, db::n(r, "revoked_at")))).collect();
    let response = match responder.respond_at(&request, |cert_id| {
        let serial = cert_id.serial_hex().to_lowercase();
        match status.get(&serial) {
            Some((true, at)) => keystore_ocsp::CertStatus::Revoked { revocation_time: if *at > 0 { *at } else { now() }, reason: None },
            Some((false, _)) => keystore_ocsp::CertStatus::Good,
            None => keystore_ocsp::CertStatus::Unknown,
        }
    }, crate::clock::system_time()) { Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let mut resp = response.to_der().into_response();
    resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/ocsp-response"));
    resp }
#[cfg(feature = "pki")]
#[cfg(feature = "pki")]
async fn list_certs(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT org_id,kind FROM pki_cas WHERE id=?", &[json!(caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); let role = st.require_org(&org,&uid).await?; st.check_perm(&org,&uid,"pki:read").await?;
    if db::s(&ca,"kind") != "x509" { return Err(bad("CA is not an X.509 CA")); }
    // A deleted device keeps its certificate rows for audit. An org admin may
    // still see that history; anyone narrower sees only certificates whose
    // device (and therefore environment) is still present and accessible.
    let admin = st.role_privileged(&org, &role).await;
    st.require_feature(&db::s(&ca,"org_id"), "pki").await?;
    let rows = st.db.query("SELECT id,ca_id,cn,serial,revoked,revoked_at,expires_at,created_at,device_id,issued_via FROM pki_certs WHERE ca_id=?", &[json!(caid)]).await.map_err(|e| bad(&e))?;
    let mut visible=Vec::new(); for row in rows { let did=db::s(&row,"device_id"); if !did.is_empty() {
        match load_device_opt(&st,&did).await? {
            Some(device) => { if pki_env_access(&st,&device,&uid).await.is_err() { continue; } }
            None => { if !admin { continue; } } }
    } visible.push(db::obj(&row)); }
    Ok(j(json!(visible))) }
#[cfg(feature = "pki")]
#[cfg(feature = "pki")]
async fn revoke_cert(State(st): State<S>, h: HeaderMap, Path(cid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT ca_id,device_id FROM pki_certs WHERE id=?", &[json!(cid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"cert not found"))?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=? AND kind='x509'", &[json!(db::s(&row,"ca_id"))]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?; st.check_perm(&db::s(&ca,"org_id"),&uid,"pki:write").await?;
    let device = db::s(&row,"device_id"); if device.is_empty() { st.check_admin(&db::s(&ca,"org_id"),&uid).await?; } else { pki_env_access(&st,&load_device(&st,&device).await?,&uid).await?; }
    let t = now(); st.db.exec("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE id=? AND revoked=0", &[json!(t), json!(cid)]).await.map_err(|e| bad(&e))?;
    let did = db::s(&row,"device_id");
    if !did.is_empty() { let _ = st.db.exec("UPDATE pki_devices SET active_cert_id='',updated_at=? WHERE id=? AND active_cert_id=?", &[json!(t), json!(&did), json!(cid)]).await; }
    Ok(j(json!({"revoked": cid}))) }
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "pki")]
#[cfg(feature = "pki")]
async fn ca_crl(State(st): State<S>, Path(caid): Path<String>) -> Response {
    if let Err(e)=st.epoch_ok().await { return e.into_response(); }
    // A CRL is a signed public artifact; brokers fetch it without a credential.
    let ca = match st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(&caid)]).await { Ok(Some(c)) => c, _ => return err(StatusCode::NOT_FOUND, "CA not found").into_response() };
    if db::s(&ca,"kind") != "x509" { return bad("CA is not an X.509 CA").into_response(); }
    let (issuer_cert, issuer_kp) = match load_issuer(&st, &ca) { Ok(x) => x, Err(e) => return e.into_response() };
    let rows = match st.db.query("SELECT serial,revoked,revoked_at FROM pki_certs WHERE ca_id=?", &[json!(&caid)]).await { Ok(r) => r, Err(e) => return bad(&e).into_response() };
    let mut revoked = Vec::new();
    for r in &rows { if db::n(r,"revoked") == 1 { if let Some(serial) = hex_decode(&db::s(r,"serial")) {
        let at = db::n(r,"revoked_at");
        let revocation_time = if at > 0 { time::OffsetDateTime::from_unix_timestamp(at).unwrap_or_else(|_| time::OffsetDateTime::now_utc()) } else { time::OffsetDateTime::now_utc() };
        revoked.push(rcgen::RevokedCertParams { serial_number: rcgen::SerialNumber::from_slice(&serial), revocation_time, reason_code: None, invalidity_date: None }); } } }
    // Revoked immediate children are listed in the root's CRL so a broker can
    // distrust one environment or factory without replacing the root.
    if let Ok(children) = st.db.query("SELECT serial,revoked_at FROM pki_cas WHERE parent_id=? AND revoked=1", &[json!(&caid)]).await {
        for r in &children { if let Some(serial) = hex_decode(&db::s(r,"serial")) {
            let at = db::n(r,"revoked_at");
            let revocation_time = if at > 0 { time::OffsetDateTime::from_unix_timestamp(at).unwrap_or_else(|_| time::OffsetDateTime::now_utc()) } else { time::OffsetDateTime::now_utc() };
            revoked.push(rcgen::RevokedCertParams { serial_number: rcgen::SerialNumber::from_slice(&serial), revocation_time, reason_code: None, invalidity_date: None }); } } }
    let params = rcgen::CertificateRevocationListParams {
        this_update: time::OffsetDateTime::now_utc(),
        next_update: time::OffsetDateTime::now_utc() + time::Duration::days(7),
        crl_number: rcgen::SerialNumber::from_slice(&oc::random_key()[..8]),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    match params.signed_by(&issuer_cert, &issuer_kp) {
        Ok(crl) => match crl.pem() {
            Ok(pem) => { let mut resp = pem.into_response(); resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/pkix-crl")); resp }
            Err(e) => bad(&e.to_string()).into_response(),
        },
        Err(e) => bad(&e.to_string()).into_response(),
    } }
#[cfg(feature = "pki")]
async fn list_cas(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    st.require_org(&oid,&uid).await?; st.check_perm(&oid,&uid,"pki:read").await?;
    let rows = st.db.query("SELECT id,name,cert_pem,serial,created_at,parent_id,ca_kind,revoked,revoked_at,hook_url,attest_issuer,attest_required FROM pki_cas WHERE org_id=? AND kind='x509' ORDER BY created_at", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "certificate": db::s(r,"cert_pem"), "serial": db::s(r,"serial"), "created_at": db::n(r,"created_at"), "parent_id": db::s(r,"parent_id"), "kind": db::s(r,"ca_kind"), "revoked": db::n(r,"revoked") == 1, "revoked_at": db::n(r,"revoked_at"), "hook_set": !db::s(r,"hook_url").is_empty(), "attest_issuer": db::s(r,"attest_issuer"), "attest_required": db::n(r,"attest_required") == 1})).collect::<Vec<_>>()))) }
#[cfg(feature = "pki")]
async fn create_device(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let scoped = env_scope_of(&st, &h).await?;
    let row = insert_device(&st, &org, &uid, &caid, &body, &scoped).await?;
    st.audit(&org,&db::s(&row,"app_id"),&db::s(&row,"env_id"),&uid,"pki.device.create",&format!("{} ({})", db::s(&row,"name"), db::s(&row,"id"))).await;
    Ok(j(device_json(&row))) }
#[cfg(feature = "pki")]
async fn list_devices(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.require_org(&org,&uid).await?; st.check_perm(&org,&uid,"pki:read").await?;
    let scoped = env_scope_of(&st, &h).await?;
    let rows = if scoped.is_empty() {
        st.db.query(&format!("{} WHERE d.ca_id=? ORDER BY d.name", DEVICE_SELECT), &[json!(&caid)]).await
    } else {
        st.db.query(&format!("{} WHERE d.ca_id=? AND d.env_id=? ORDER BY d.name", DEVICE_SELECT), &[json!(&caid), json!(&scoped)]).await
    }.map_err(|e| bad(&e))?;
    let mut visible = Vec::new(); for row in rows { if pki_env_access(&st,&row,&uid).await.is_ok() { visible.push(row); } } let rows = visible;
    Ok(j(json!(rows.iter().map(device_json).collect::<Vec<_>>()))) }
#[cfg(feature = "pki")]
async fn get_device(State(st): State<S>, h: HeaderMap, Path(did): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = load_device(&st,&did).await?; pki_env_access(&st,&row,&uid).await?; let org = db::s(&row,"org_id"); st.require_org(&org,&uid).await?; st.check_perm(&org,&uid,"pki:read").await?;
    let certs = st.db.query("SELECT id,cn,serial,revoked,revoked_at,expires_at,created_at,issued_via FROM pki_certs WHERE device_id=? ORDER BY created_at DESC", &[json!(&did)]).await.map_err(|e| bad(&e))?;
    let mut out = device_json(&row); out["certs"] = json!(certs.iter().map(db::obj).collect::<Vec<_>>()); Ok(j(out)) }
#[cfg(feature = "pki")]
async fn update_device(State(st): State<S>, h: HeaderMap, Path(did): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let row = load_device(&st,&did).await?; pki_env_access(&st,&row,&uid).await?; let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let scoped = env_scope_of(&st, &h).await?;
    if !scoped.is_empty() {
        if db::s(&row,"env_id") != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); }
        if body.get("env_id").is_some() && body_str(&body,"env_id").unwrap_or_default() != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); } }
    let name = body_str(&body,"name").unwrap_or_else(|| db::s(&row,"name"));
    if !valid_device_name(&name) { return Err(bad("name must be 1-64 characters of A-Z, a-z, 0-9, dot, underscore, colon or hyphen")); }
    let app_in = if scoped.is_empty() { body_str(&body,"app_id").unwrap_or_else(|| db::s(&row,"app_id")) } else { String::new() };
    let env_in = if scoped.is_empty() { body_str(&body,"env_id").unwrap_or_else(|| db::s(&row,"env_id")) } else { scoped };
    if !db::s(&row,"group_id").is_empty() {
        if let Ok(Some(grp)) = st.db.one("SELECT env_id FROM pki_groups WHERE id=?", &[json!(db::s(&row,"group_id"))]).await {
            let genv = db::s(&grp,"env_id"); if !genv.is_empty() && env_in != genv { return Err(bad("device environment must match the group environment")); } } }
    let (app_id, env_id) = resolve_device_scope(&st,&org,&uid,app_in,env_in).await?;
    let sans = if body.get("sans").is_some() { device_sans(&body)?.join(",") } else { db::s(&row,"sans") };
    let cert_days = body.get("cert_days").and_then(|v| v.as_i64()).unwrap_or(db::n(&row,"cert_days")).clamp(1,365);
    let update_sql = "UPDATE pki_devices SET name=?,app_id=?,env_id=?,model=?,hardware_serial=?,tags=?,sans=?,cert_days=?,updated_at=?,enroll_epoch=enroll_epoch+1 WHERE id=? AND deleting=0";
    let params = vec![json!(&name), json!(&app_id), json!(&env_id), json!(body_str(&body,"model").unwrap_or_else(|| db::s(&row,"model"))), json!(body_str(&body,"hardware_serial").unwrap_or_else(|| db::s(&row,"hardware_serial"))), json!(body_str(&body,"tags").unwrap_or_else(|| db::s(&row,"tags"))), json!(&sans), json!(cert_days), json!(now()), json!(&did)];
    if db::s(&row,"group_id").is_empty() {
        let n = st.db.exec(update_sql, &params).await.map_err(device_conflict)?;
        if n != 1 { return Err(err(StatusCode::NOT_FOUND, "device not found")); }
    } else {
        st.db.tx_locked("SELECT env_id FROM pki_groups WHERE id=?", &[json!(db::s(&row,"group_id"))], |r| db::s(r,"env_id").is_empty() || db::s(r,"env_id") == env_id, &[(update_sql, params)], &[(0, 1)]).await
            .map_err(|e| if e == "lock condition failed" { err(StatusCode::CONFLICT, "group changed or was removed; retry") } else { device_conflict(e) })?; }
    st.audit(&org,&app_id,&env_id,&uid,"pki.device.update",&format!("{} ({})", name, did)).await;
    let fresh = load_device(&st,&did).await?; Ok(j(device_json(&fresh))) }
#[cfg(feature = "pki")]
async fn revoke_device(State(st): State<S>, h: HeaderMap, Path(did): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = load_device(&st,&did).await?; pki_env_access(&st,&row,&uid).await?; let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let t = now();
    // Invalidate codes and the epoch, then sweep the certificates, atomically.
    let counts = st.db.tx(&[
        ("DELETE FROM pki_enrollments WHERE device_id=?", vec![json!(&did)]),
        ("UPDATE pki_devices SET active_cert_id='',updated_at=?,enroll_epoch=enroll_epoch+1 WHERE id=?", vec![json!(t), json!(&did)]),
        ("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE device_id=? AND revoked=0", vec![json!(t), json!(&did)]),
    ]).await.map_err(|e| bad(&e))?;
    let n = counts.get(2).copied().unwrap_or(0);
    st.audit(&org,&db::s(&row,"app_id"),&db::s(&row,"env_id"),&uid,"pki.device.revoke",&format!("{} ({})", db::s(&row,"name"), did)).await;
    Ok(j(json!({"revoked": n}))) }
#[cfg(feature = "pki")]
async fn delete_device(State(st): State<S>, h: HeaderMap, Path(did): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = load_device(&st,&did).await?; pki_env_access(&st,&row,&uid).await?; let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let t = now();
    // Tombstone, sweep and removal in one transaction: no interleaving can
    // attach a certificate, and a failure leaves the device intact.
    let counts = st.db.tx(&[
        ("UPDATE pki_devices SET deleting=1,active_cert_id='',updated_at=?,enroll_epoch=enroll_epoch+1 WHERE id=?", vec![json!(t), json!(&did)]),
        ("DELETE FROM pki_enrollments WHERE device_id=?", vec![json!(&did)]),
        ("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE device_id=? AND revoked=0", vec![json!(t), json!(&did)]),
        ("DELETE FROM pki_devices WHERE id=?", vec![json!(&did)]),
    ]).await.map_err(|e| bad(&e))?;
    let revoked = counts.get(2).copied().unwrap_or(0);
    st.audit(&org,&db::s(&row,"app_id"),&db::s(&row,"env_id"),&uid,"pki.device.delete",&format!("{} ({})", db::s(&row,"name"), did)).await;
    Ok(j(json!({"deleted": true, "revoked": revoked}))) }
#[cfg(feature = "pki")]
async fn create_enrollment(State(st): State<S>, h: HeaderMap, Path(did): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let row = load_device(&st,&did).await?; pki_env_access(&st,&row,&uid).await?; let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    if db::n(&row,"deleting") == 1 { return Err(err(StatusCode::NOT_FOUND, "device not found")); }
    let ttl = body.get("ttl_seconds").and_then(|v| v.as_i64()).unwrap_or(3600);
    let revoke_previous = body.get("revoke_previous").and_then(|v| v.as_bool()).unwrap_or(false);
    let (code, expires, nonce) = insert_enrollment(&st,&did,&row,ttl,revoke_previous,&uid).await?;
    st.audit(&org,&db::s(&row,"app_id"),&db::s(&row,"env_id"),&uid,"pki.device.enrollment",&format!("{} ({}) expires {}", db::s(&row,"name"), did, expires)).await;
    Ok(j(json!({"code": code, "expires_at": expires, "nonce": nonce, "revoke_previous": revoke_previous}))) }
#[cfg(feature = "pki")]
async fn renew_device(State(st): State<S>, h: HeaderMap, Path(did): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let row = load_device(&st,&did).await?; pki_env_access(&st,&row,&uid).await?; let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    if db::n(&row,"deleting") == 1 { return Err(err(StatusCode::NOT_FOUND, "device not found")); }
    let ttl = body.get("ttl_seconds").and_then(|v| v.as_i64()).unwrap_or(3600);
    let (code, expires, nonce) = insert_enrollment(&st,&did,&row,ttl,true,&uid).await?;
    st.audit(&org,&db::s(&row,"app_id"),&db::s(&row,"env_id"),&uid,"pki.device.renew",&format!("{} ({}) expires {}", db::s(&row,"name"), did, expires)).await;
    Ok(j(json!({"code": code, "expires_at": expires, "nonce": nonce, "revoke_previous": true}))) }
// The lock row carries the workspace and (when the device has a project) the
// project lockdown flags. FOR UPDATE on these joins serialises issuance with
// an emergency transition, so a lockdown committed during the enrollment hook
// cannot be followed by a certificate.
#[cfg(feature = "pki")]
const PKI_ISSUER_LOCK: &str = "SELECT c.*,p.revoked AS parent_revoked,p.cert_pem AS parent_cert,p.parent_id AS ancestor_id,p.org_id AS parent_org,p.ca_kind AS parent_kind,o.emergency_locked AS org_locked FROM pki_cas c JOIN pki_cas p ON p.id=CASE WHEN c.parent_id='' THEN c.id ELSE c.parent_id END JOIN orgs o ON o.id=c.org_id WHERE c.id=? AND c.kind='x509' AND p.kind='x509'";
#[cfg(feature = "pki")]
fn pki_issuer_lock(app_id: &str) -> String {
    if app_id.is_empty() { return PKI_ISSUER_LOCK.to_string(); }
    PKI_ISSUER_LOCK.replace(",o.emergency_locked AS org_locked FROM", ",o.emergency_locked AS org_locked,a.emergency_locked AS app_locked FROM")
        .replace(" JOIN orgs o ON o.id=c.org_id WHERE", " JOIN orgs o ON o.id=c.org_id JOIN apps a ON a.id=? AND a.org_id=c.org_id WHERE") }
#[cfg(feature = "pki")]
fn pki_issuer_params(app_id: &str, caid: &str) -> Vec<Value> {
    if app_id.is_empty() { vec![json!(caid)] } else { vec![json!(app_id), json!(caid)] } }
#[cfg(feature = "pki")]
fn issuer_unchanged(r: &Row, ca: &Row) -> bool {
    db::n(r,"org_locked") == 0 && db::n(r,"app_locked") == 0
        && ca_live(r) && db::n(r,"parent_revoked") == 0 && db::s(r,"ancestor_id").is_empty() && db::s(r,"parent_kind") == "root" && db::s(r,"parent_org") == db::s(r,"org_id")
        && crate::pki::certificate_live(&db::s(r,"parent_cert"))
        && ["parent_id","ca_kind","kind","cert_pem","hook_url","hook_secret_enc","attest_mode","attest_issuer","attest_key_pem","attest_alg"].iter().all(|k| db::s(r,k) == db::s(ca,k)) && db::n(r,"attest_required") == db::n(ca,"attest_required") }
#[cfg(feature = "pki")]
fn device_attestation(ca: &Row, dev: &Row, nonce: &str, csr: &str, body: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    let required = db::n(ca,"attest_required") == 1;
    if db::s(ca,"attest_mode") == "tpm2" {
        let Some(evidence) = body.get("tpm_evidence") else { return if required { Err(err(StatusCode::FORBIDDEN,"TPM evidence is required")) } else { Ok(String::new()) }; };
        let pin = db::s(dev,"tpm_ak_public"); let policy = db::s(dev,"tpm_pcr_digest");
        if pin.is_empty() || policy.is_empty() { return Err(err(StatusCode::FORBIDDEN,"device TPM is not provisioned")); }
        let der = keystore_ocsp::pem::decode("CERTIFICATE REQUEST", csr).map_err(|e| bad(&e.to_string()))?;
        let request = keystore_pki::pkcs10::parse(&der).map_err(|e| bad(&e.to_string()))?;
        request.verify().map_err(|e| bad(&e.to_string()))?;
        return tpm_attestation::verify(evidence,&pin,&request.spki,nonce,&policy).map(|v| v.to_string()).map_err(|e| err(StatusCode::FORBIDDEN,&e)); }
    let token = body.get("attestation").and_then(Value::as_str).unwrap_or("");
    if token.is_empty() { return if required { Err(err(StatusCode::FORBIDDEN,"attestation is required for this CA")) } else { Ok(String::new()) }; }
    if db::s(ca,"attest_key_pem").is_empty() { return Err(bad("attestation is not configured for this CA")); }
    verify_attestation(ca,&db::s(dev,"id"),nonce,csr,token).map(|v| v.to_string()) }
#[cfg(feature = "pki")]
async fn get_device_tpm(State(st): State<S>, h: HeaderMap, Path(did): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; let dev = load_device(&st,&did).await?; pki_env_access(&st,&dev,&uid).await?;
    if !matches!(st.require_org(&db::s(&dev,"org_id"),&uid).await?.as_str(),"owner"|"admin") { return Err(err(StatusCode::FORBIDDEN,"workspace owner or admin required")); }
    st.check_admin(&db::s(&dev,"org_id"),&uid).await?; st.check_perm(&db::s(&dev,"org_id"),&uid,"pki:write").await?;
    Ok(j(json!({"ak_public":db::s(&dev,"tpm_ak_public"),"pcr_digest":db::s(&dev,"tpm_pcr_digest")}))) }
#[cfg(feature = "pki")]
async fn put_device_tpm(State(st): State<S>, h: HeaderMap, Path(did): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let dev = load_device(&st,&did).await?; pki_env_access(&st,&dev,&uid).await?; let org = db::s(&dev,"org_id");
    if !matches!(st.require_org(&org,&uid).await?.as_str(),"owner"|"admin") { return Err(err(StatusCode::FORBIDDEN,"workspace owner or admin required")); }
    st.check_admin(&org,&uid).await?; st.check_perm(&org,&uid,"pki:write").await?;
    let pin = body.get("ak_public").and_then(Value::as_str).unwrap_or("");
    let policy = body.get("pcr_digest").and_then(Value::as_str).unwrap_or("");
    tpm_attestation::validate_ak(pin).map_err(|e| bad(&e))?;
    if policy.len()!=64 || !policy.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(bad("pcr_digest must be 64 hex characters")); }
    st.db.exec("UPDATE pki_devices SET tpm_ak_public=?,tpm_pcr_digest=?,enroll_epoch=enroll_epoch+1,updated_at=? WHERE id=? AND deleting=0", &[json!(pin),json!(policy),json!(now()),json!(&did)]).await.map_err(|e| bad(&e))?;
    st.audit(&org,"","",&uid,"pki.device.tpm",&did).await;
    Ok(j(json!({"ak_public":pin,"pcr_digest":policy}))) }
#[cfg(feature = "pki")]
async fn enroll_device(State(st): State<S>, Json(body): Json<Value>) -> Res {
    let code = body_str(&body,"code").unwrap_or_default(); let csr_pem = body.get("csr").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if code.is_empty() || code.len() > 256 { return Err(err(StatusCode::UNAUTHORIZED, "invalid or expired enrollment code")); }
    if csr_pem.is_empty() || csr_pem.len() > 16384 { return Err(bad("csr is required (PEM, max 16 KiB)")); }
    crate::pki::csr_public_key(&csr_pem).map_err(|e| bad(&format!("invalid CSR: {}", e)))?;
    let hash = oc::hash_token(&code);
    let row = st.db.one("SELECT e.id AS enrollment_id,e.used_at,e.expires_at AS enrollment_expires_at,e.enroll_epoch AS code_epoch,e.revoke_previous AS code_revoke_previous,e.nonce AS code_nonce,d.* FROM pki_enrollments e JOIN pki_devices d ON d.id=e.device_id WHERE e.token_hash=?", &[json!(hash)]).await.map_err(|e| bad(&e))?
        .filter(|r| db::n(r,"used_at") == 0 && db::n(r,"enrollment_expires_at") > now() && db::n(r,"code_epoch") == db::n(r,"enroll_epoch") && db::n(r,"deleting") == 0)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid or expired enrollment code"))?;
    // Public enrollment is resolved from the code, not the URL, so the
    // emergency middleware cannot see its workspace. Refuse before any
    // attestation, hook or certificate work when either scope is locked.
    let org = db::s(&row,"org_id"); let app = db::s(&row,"app_id");
    st.require_running(&org).await?;
    if !app.is_empty() { st.require_app_running(&app).await?; }
    let did = db::s(&row,"id"); let ca_id = db::s(&row,"ca_id"); let old_cert = db::s(&row,"active_cert_id");
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&ca_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    if ca_revoked(&st,&ca).await { return Err(bad("CA is revoked")); }
    let attestation_summary = device_attestation(&ca,&row,&db::s(&row,"code_nonce"),&csr_pem,&body)?;
    enrollment_hook_ok(&st,&ca,&row,&db::s(&row,"enrollment_id"),&csr_pem).await?;
    let days = db::n(&row,"cert_days").clamp(1,365);
    let key = oc::decrypt_symmetric(&st.master(),&db::s(&ca,"key_enc")).map_err(|e| bad(&e))?;
    let names = db::s(&row,"sans").split(',').filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>();
    let issued = crate::pki::issue_device(&db::s(&ca,"cert_pem"),&String::from_utf8_lossy(&key),&db::s(&row,"name"),&names,days,Some(&csr_pem)).map_err(|e| bad(&e))?;
    let t = now(); let cert_id = id(); let serial = issued.serial_hex.clone(); let expires = crate::pki::certificate_expiry(&issued.certificate_pem).map_err(|e| bad(&e))?;
    let mut stmts: Vec<(&str, Vec<Value>)> = vec![
        ("UPDATE pki_enrollments SET used_at=? WHERE id=? AND used_at=0 AND expires_at>OW_NOW()", vec![json!(t), json!(db::s(&row,"enrollment_id"))]),
        ("INSERT INTO pki_certs(id,ca_id,cn,cert_pem,serial,expires_at,created_at,device_id,revoked_at,issued_via) VALUES(?,?,?,?,?,?,?,?,0,'csr')", vec![json!(&cert_id), json!(&ca_id), json!(db::s(&row,"name")), json!(&issued.certificate_pem), json!(&serial), json!(expires), json!(t), json!(&did)]),
        // Attaching the certificate is the commit point: a device revoked or
        // deleted after the row was read bumps enroll_epoch, so this matches nothing.
        ("UPDATE pki_devices SET active_cert_id=?,updated_at=?,enroll_epoch=enroll_epoch+1,attested=?,attestation=? WHERE id=? AND enroll_epoch=? AND deleting=0 AND active_cert_id=?", vec![json!(&cert_id), json!(t), json!(if attestation_summary.is_empty() {0} else {1}), json!(&attestation_summary), json!(&did), json!(db::n(&row,"enroll_epoch")), json!(&old_cert)]),
    ];
    if db::n(&row,"code_revoke_previous") == 1 && !old_cert.is_empty() {
        stmts.push(("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE id=? AND revoked=0", vec![json!(t), json!(&old_cert)])); }
    let lock = pki_issuer_lock(&app); let lock_params = pki_issuer_params(&app, &ca_id);
    match st.db.tx_locked(&lock, &lock_params, |r| issuer_unchanged(r,&ca), &stmts, &[(0, 1), (1, 1), (2, 1)]).await {
        Ok(_) => {}
        Err(e) if e == "lock condition failed" => return Err(err(StatusCode::FORBIDDEN, "enrollment is blocked by an active emergency lockdown")),
        Err(e) if e.contains("affected 0 rows") => return Err(err(StatusCode::UNAUTHORIZED, "invalid or expired enrollment code")),
        Err(e) => return Err(bad(&e)),
    }
    st.audit(&db::s(&row,"org_id"),&db::s(&row,"app_id"),&db::s(&row,"env_id"),&format!("device:{}", did),"pki.enroll",&format!("cert {} serial {} attested {}", cert_id, serial, !attestation_summary.is_empty())).await;
    let chain = ca_chain(&st,&ca).await;
    Ok(j(json!({"device_id": did, "name": db::s(&row,"name"), "serial": serial, "certificate": issued.certificate_pem, "ca_certificate": db::s(&ca,"cert_pem"), "ca_chain": chain, "attested": !attestation_summary.is_empty(), "expires_at": expires}))) }


#[cfg(feature = "pki")]
async fn renewal_leaf(st: &S, dev: &Row) -> Result<Row, (StatusCode, Json<Value>)> {
    if db::n(dev,"deleting") != 0 { return Err(bad("device is unavailable")); }
    let cert = st.db.one("SELECT * FROM pki_certs WHERE id=? AND device_id=? AND ca_id=? AND revoked=0 AND expires_at>?", &[json!(db::s(dev,"active_cert_id")),json!(db::s(dev,"id")),json!(db::s(dev,"ca_id")),json!(now())]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("active certificate is not live"))?;
    if !crate::pki::certificate_live(&db::s(&cert,"cert_pem")) { return Err(bad("active certificate is not live")); } Ok(cert) }
#[cfg(feature = "pki")]
async fn renewal_challenge(State(st): State<S>, Json(body): Json<Value>) -> Res {
    let did = body_str(&body,"device_id").unwrap_or_default();
    let csr = body.get("csr").and_then(Value::as_str).unwrap_or("");
    if did.is_empty() || did.len()>128 || csr.is_empty() || csr.len()>16384 { return Err(bad("device_id and CSR (max 16 KiB) are required")); }
    crate::pki::csr_public_key(csr).map_err(|e| bad(&e.to_string()))?;
    let dev = load_device(&st,&did).await?;
    // The public renewal route cannot be resolved by the emergency middleware.
    st.require_running(&db::s(&dev,"org_id")).await?;
    if !db::s(&dev,"app_id").is_empty() { st.require_app_running(&db::s(&dev,"app_id")).await?; }
    let cert = renewal_leaf(&st,&dev).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(db::s(&dev,"ca_id"))]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("CA missing"))?;
    if ca_revoked(&st,&ca).await { return Err(bad("CA is unavailable")); }
    // Only valid device/CSR requests consume the bounded challenge budget.
    for (key,max) in [(format!("pki-renew-org:{}",db::s(&dev,"org_id")),1000),(format!("pki-renew:{}",did),20)] {
        let key=AppState::rate_key(&key); let t=now();
        #[cfg(not(target_arch = "wasm32"))]
        let insert=if st.db.backend()==db::Backend::Mysql { "INSERT IGNORE INTO rate_limits(key,window_start,count) VALUES(?,?,0)" } else { "INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,0) ON CONFLICT(key) DO NOTHING" };
        #[cfg(target_arch = "wasm32")]
        let insert="INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,0) ON CONFLICT(key) DO NOTHING";
        st.db.exec(insert,&[json!(&key),json!(t)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE,"renewal rate limit unavailable"))?;
        let reservation=st.db.tx_locked("SELECT count,window_start FROM rate_limits WHERE key=?",&[json!(&key)],|r| db::n(r,"window_start")<=t-300 || db::n(r,"count")<max,&[("UPDATE rate_limits SET count=CASE WHEN window_start<=? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<=? THEN ? ELSE window_start END WHERE key=?",vec![json!(t-300),json!(t-300),json!(t),json!(&key)])],&[(0,1)]).await;
        match reservation { Ok(_) => {}, Err(e) if e=="lock condition failed" => return Err(err(StatusCode::TOO_MANY_REQUESTS,"renewal challenge rate exceeded")), Err(_) => return Err(err(StatusCode::SERVICE_UNAVAILABLE,"renewal rate limit unavailable")) }
    }
    let cid = id(); let expires = now()+300; use sha2::Digest;
    let challenge = json!({"purpose":"OpenWarp/PKI/renew/v1","destination":format!("{}#{}",st.pub_url,hmac_hex(&st.master(),b"OpenWarp/PKI/renew/destination")),"challenge_id":cid,"device_id":did,"cert_id":db::s(&cert,"id"),"csr_sha256":format!("{:x}",sha2::Sha256::digest(csr.as_bytes())),"nonce":hex_encode(&oc::random_key()),"expires_at":expires}).to_string();
    st.db.exec("DELETE FROM pki_renew_challenges WHERE used_at>0 OR expires_at<=?", &[json!(now())]).await.map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO pki_renew_challenges(id,device_id,cert_id,csr,challenge,expires_at,used_at) VALUES(?,?,?,?,?,?,0)", &[json!(&cid),json!(&did),json!(db::s(&cert,"id")),json!(csr),json!(&challenge),json!(expires)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"challenge_id":cid,"challenge":challenge,"expires_at":expires}))) }
#[cfg(feature = "pki")]
async fn self_renew_device(State(st): State<S>, Json(body): Json<Value>) -> Res {
    let cid = body_str(&body,"challenge_id").unwrap_or_default(); let signature = body.get("signature").and_then(Value::as_str).unwrap_or("");
    if cid.len()>128 || signature.len()>8192 { return Err(bad("invalid renewal proof")); }
    let c = st.db.one("SELECT * FROM pki_renew_challenges WHERE id=? AND used_at=0 AND expires_at>?", &[json!(&cid),json!(now())]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired renewal challenge"))?;
    let did = db::s(&c,"device_id"); let dev = load_device(&st,&did).await?;
    // Public renewal cannot be resolved by the path middleware either.
    let org = db::s(&dev,"org_id"); let app = db::s(&dev,"app_id");
    st.require_running(&org).await?;
    if !app.is_empty() { st.require_app_running(&app).await?; }
    let old = renewal_leaf(&st,&dev).await?;
    let old_id = db::s(&old,"id"); if old_id!=db::s(&c,"cert_id") { return Err(bad("active certificate changed")); }
    let der = keystore_ocsp::pem::decode("CERTIFICATE",&db::s(&old,"cert_pem")).map_err(|e| bad(&e.to_string()))?;
    let cert = keystore_pki::parse_certificate(&der).map_err(|e| bad(&e.to_string()))?;
    let key = keystore_pki::parse_public_key(&cert.spki).map_err(|e| bad(&e.to_string()))?;
    let alg = match &key { keystore_pki::PublicKey::EcP256(_) => keystore_pki::SignatureAlgorithm::Sha256WithEcdsa, keystore_pki::PublicKey::EcP384(_) => keystore_pki::SignatureAlgorithm::Sha384WithEcdsa, keystore_pki::PublicKey::Ed25519(_) => keystore_pki::SignatureAlgorithm::Ed25519, keystore_pki::PublicKey::Rsa(_) => keystore_pki::SignatureAlgorithm::Sha256WithRsa, _ => return Err(bad("unsupported renewal key")) };
    use base64ct::{Base64, Encoding};
    let sig = Base64::decode_vec(signature).map_err(|_| bad("invalid signature base64"))?;
    keystore_pki::verify(alg,&key,db::s(&c,"challenge").as_bytes(),&sig).map_err(|_| err(StatusCode::FORBIDDEN,"invalid renewal signature"))?;
    let ca_id = db::s(&dev,"ca_id"); let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&ca_id)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("CA missing"))?;
    if ca_revoked(&st,&ca).await { return Err(bad("CA is unavailable")); }
    let csr_pem = db::s(&c,"csr");
    let summary = device_attestation(&ca,&dev,&cid,&csr_pem,&body)?;
    enrollment_hook_ok(&st,&ca,&dev,&cid,&csr_pem).await?;
    let days = db::n(&dev,"cert_days").clamp(1,365);
    let key = oc::decrypt_symmetric(&st.master(),&db::s(&ca,"key_enc")).map_err(|e| bad(&e))?;
    let names = db::s(&dev,"sans").split(',').filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>();
    let issued = crate::pki::issue_device(&db::s(&ca,"cert_pem"),&String::from_utf8_lossy(&key),&db::s(&dev,"name"),&names,days,Some(&csr_pem)).map_err(|e| bad(&e))?;
    let serial = issued.serial_hex.clone(); let cert_id = id(); let t = now(); let expires=crate::pki::certificate_expiry(&issued.certificate_pem).map_err(|e| bad(&e))?;
    let stmts = [
        ("UPDATE pki_renew_challenges SET used_at=? WHERE id=? AND used_at=0 AND expires_at>OW_NOW()",vec![json!(t),json!(&cid)]),
        ("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE id=? AND device_id=? AND ca_id=? AND revoked=0 AND expires_at>OW_NOW()",vec![json!(t),json!(&old_id),json!(&did),json!(&ca_id)]),
        ("INSERT INTO pki_certs(id,ca_id,cn,cert_pem,serial,expires_at,created_at,device_id,revoked_at,issued_via) VALUES(?,?,?,?,?,?,?,?,0,'csr')",vec![json!(&cert_id),json!(&ca_id),json!(db::s(&dev,"name")),json!(&issued.certificate_pem),json!(&serial),json!(expires),json!(t),json!(&did)]),
        ("UPDATE pki_devices SET active_cert_id=?,updated_at=?,enroll_epoch=enroll_epoch+1,attested=?,attestation=? WHERE id=? AND enroll_epoch=? AND active_cert_id=? AND deleting=0 AND ?>OW_NOW() AND EXISTS (SELECT 1 FROM pki_renew_challenges WHERE id=? AND expires_at>OW_NOW())",vec![json!(&cert_id),json!(t),json!(if summary.is_empty(){0}else{1}),json!(&summary),json!(&did),json!(db::n(&dev,"enroll_epoch")),json!(&old_id),json!(db::n(&old,"expires_at")),json!(&cid)]) ];
    // Acquire every authorization row before checking database time, so a wait
    // on the device or old certificate cannot carry an expired proof past validation.
    let renewal_lock=pki_issuer_lock(&app).replace(" WHERE c.id=?", " JOIN pki_devices d ON d.ca_id=c.id JOIN pki_certs old ON old.id=d.active_cert_id WHERE c.id=? AND d.id=? AND old.id=?");
    let mut lock_params = pki_issuer_params(&app, &ca_id); lock_params.push(json!(&did)); lock_params.push(json!(&old_id));
    st.db.tx_locked(&renewal_lock,&lock_params,|r| issuer_unchanged(r,&ca),&stmts,&[(0,1),(1,1),(2,1),(3,1)]).await.map_err(|e| err(StatusCode::CONFLICT,&format!("renewal did not commit: {}",e)))?;
    st.audit(&db::s(&dev,"org_id"),&db::s(&dev,"app_id"),&db::s(&dev,"env_id"),&format!("device:{}",did),"pki.renew",&serial).await;
    Ok(j(json!({"device_id":did,"serial":serial,"certificate":issued.certificate_pem,"ca_certificate":db::s(&ca,"cert_pem"),"ca_chain":ca_chain(&st,&ca).await,"attested":!summary.is_empty(),"expires_at":expires}))) }
#[cfg(feature = "pki")]
async fn expiring_certs(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h).await?;
    st.require_org(&oid,&uid).await?; st.check_perm(&oid,&uid,"pki:read").await?;
    let days = q.get("days").and_then(|s| s.parse::<i64>().ok()).unwrap_or(30).clamp(1, 365);
    let scoped = env_scope_of(&st, &h).await?; let window = days.max(30); let cutoff = now() + window*86400;
    let rows = if scoped.is_empty() {
        st.db.query("SELECT c.id AS cert_id,c.serial,c.expires_at,c.device_id,d.name,d.env_id,d.group_id,d.attested FROM pki_certs c JOIN pki_devices d ON d.id=c.device_id WHERE d.org_id=? AND c.revoked=0 AND c.expires_at<=? ORDER BY c.expires_at", &[json!(&oid), json!(cutoff)]).await
    } else {
        st.db.query("SELECT c.id AS cert_id,c.serial,c.expires_at,c.device_id,d.name,d.env_id,d.group_id,d.attested FROM pki_certs c JOIN pki_devices d ON d.id=c.device_id WHERE d.org_id=? AND d.env_id=? AND c.revoked=0 AND c.expires_at<=? ORDER BY c.expires_at", &[json!(&oid), json!(&scoped), json!(cutoff)]).await
    }.map_err(|e| bad(&e))?;
    let mut visible = Vec::new(); for row in rows { if pki_env_access(&st,&row,&uid).await.is_ok() { visible.push(row); } } let rows = visible;
    let t = now(); let mut items = Vec::new(); let (mut c7, mut c14, mut c30) = (0, 0, 0);
    for r in &rows { let expires = db::n(r,"expires_at"); let left = ((expires - t).max(0) + 86399) / 86400;
        if expires <= t + 7*86400 { c7 += 1; }
        if expires <= t + 14*86400 { c14 += 1; }
        if expires <= t + 30*86400 { c30 += 1; }
        if expires <= t + days*86400 { items.push(json!({"certificate_id": db::s(r,"cert_id"), "serial": db::s(r,"serial"), "expires_at": expires, "days_left": left, "device_id": db::s(r,"device_id"), "name": db::s(r,"name"), "env_id": db::s(r,"env_id"), "group_id": db::s(r,"group_id"), "attested": db::n(r,"attested") == 1})); } }
    Ok(j(json!({"days": days, "counts": {"7": c7, "14": c14, "30": c30}, "certificates": items}))) }
#[cfg(feature = "pki")]
async fn import_devices(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let list = body.get("devices").and_then(|v| v.as_array()).ok_or_else(|| bad("devices must be an array"))?;
    if list.len() > 1000 { return Err(bad("at most 1000 devices per import")); }
    let mint = body.get("mint_codes").and_then(|v| v.as_bool()).unwrap_or(false);
    let ttl = body.get("ttl_seconds").and_then(|v| v.as_i64()).unwrap_or(3600);
    let scoped = env_scope_of(&st, &h).await?; let mut results = Vec::new(); let (mut created, mut failed) = (0, 0);
    for item in list {
        match insert_device(&st,&org,&uid,&caid,item,&scoped).await {
            Ok(row) => { created += 1; let did = db::s(&row,"id");
                let mut out = json!({"name": db::s(&row,"name"), "id": did});
                if mint { match insert_enrollment(&st,&db::s(&row,"id"),&row,ttl,false,&uid).await {
                    Ok((code, expires, nonce)) => { out["code"] = json!(code); out["expires_at"] = json!(expires); out["nonce"] = json!(nonce); }
                    Err(e) => { out["error"] = e.1.0.get("error").cloned().unwrap_or(json!("enrollment failed")); } } }
                results.push(out); }
            Err(e) => { failed += 1; results.push(json!({"name": item.get("name").cloned().unwrap_or(Value::Null), "error": e.1.0.get("error").cloned().unwrap_or(json!("failed"))})); } } }
    st.audit(&org,"","",&uid,"pki.device.import",&format!("created={} failed={}", created, failed)).await;
    Ok(j(json!({"created": created, "failed": failed, "results": results}))) }
#[cfg(feature = "pki")]
async fn bulk_codes(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let ids = body.get("device_ids").and_then(|v| v.as_array()).ok_or_else(|| bad("device_ids must be an array"))?;
    if ids.len() > 500 { return Err(bad("at most 500 devices per request")); }
    let ttl = body.get("ttl_seconds").and_then(|v| v.as_i64()).unwrap_or(3600);
    let scoped = env_scope_of(&st, &h).await?; let mut results = Vec::new();
    for id in ids.iter().filter_map(|v| v.as_str()) {
        match st.db.one("SELECT * FROM pki_devices WHERE id=? AND ca_id=?", &[json!(id), json!(&caid)]).await.map_err(|e| bad(&e))? {
            Some(row) if db::n(&row,"deleting") == 0 && (scoped.is_empty() || db::s(&row,"env_id") == scoped) => {
                if pki_env_access(&st,&row,&uid).await.is_err() { results.push(json!({"id": id, "error": "device not found"})); continue; }
                match insert_enrollment(&st,id,&row,ttl,false,&uid).await {
                    Ok((code, expires, nonce)) => results.push(json!({"id": id, "name": db::s(&row,"name"), "code": code, "expires_at": expires, "nonce": nonce})),
                    Err(e) => results.push(json!({"id": id, "error": e.1.0.get("error").cloned().unwrap_or(json!("enrollment failed"))})) } }
            _ => results.push(json!({"id": id, "error": "device not found"})) } }
    st.audit(&org,"","",&uid,"pki.device.codes",&format!("requested={} issued={}", ids.len(), results.iter().filter(|r| r.get("code").is_some()).count())).await;
    Ok(j(json!({"codes": results}))) }
#[cfg(feature = "pki")]
async fn export_devices(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Response { let uid = match st.token_user(&h).await { Ok(u) => u, Err(e) => return e.into_response() };
    let ca = match st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(&caid)]).await { Ok(Some(c)) => c, _ => return err(StatusCode::NOT_FOUND, "CA not found").into_response() };
    let org = db::s(&ca,"org_id");
    if let Err(e) = st.require_org(&org,&uid).await { return e.into_response(); }
    if let Err(e) = st.check_perm(&org,&uid,"pki:read").await { return e.into_response(); }
    let scoped = match env_scope_of(&st, &h).await { Ok(s) => s, Err(e) => return e.into_response() };
    let rows = if scoped.is_empty() {
        st.db.query("SELECT d.name,d.model,d.hardware_serial,d.tags,d.env_id,d.group_id,d.sans,d.cert_days,c.serial AS cert_serial,c.expires_at,c.revoked,d.attested FROM pki_devices d LEFT JOIN pki_certs c ON c.id=d.active_cert_id WHERE d.ca_id=? ORDER BY d.name", &[json!(&caid)]).await
    } else {
        st.db.query("SELECT d.name,d.model,d.hardware_serial,d.tags,d.env_id,d.group_id,d.sans,d.cert_days,c.serial AS cert_serial,c.expires_at,c.revoked,d.attested FROM pki_devices d LEFT JOIN pki_certs c ON c.id=d.active_cert_id WHERE d.ca_id=? AND d.env_id=? ORDER BY d.name", &[json!(&caid), json!(&scoped)]).await
    };
    let rows = match rows { Ok(r) => r, Err(e) => return bad(&e).into_response() };
    let mut visible = Vec::new(); for row in rows { if pki_env_access(&st,&row,&uid).await.is_ok() { visible.push(row); } } let rows = visible;
    let mut csv = String::from("name,model,hardware_serial,tags,env_id,group_id,sans,cert_days,serial,expires_at,revoked,attested\n");
    for r in &rows { let fields = [db::s(r,"name"), db::s(r,"model"), db::s(r,"hardware_serial"), db::s(r,"tags"), db::s(r,"env_id"), db::s(r,"group_id"), db::s(r,"sans"), db::n(r,"cert_days").to_string(), db::s(r,"cert_serial"), db::n(r,"expires_at").to_string(), (db::n(r,"revoked") == 1).to_string(), (db::n(r,"attested") == 1).to_string()];
        csv.push_str(&fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",")); csv.push('\n'); }
    let mut resp = csv.into_response(); resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("text/csv; charset=utf-8"));
    resp.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, axum::http::HeaderValue::from_static("attachment; filename=\"openwarp-devices.csv\""));
    resp }
#[cfg(feature = "pki")]
async fn create_group(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let name = body_str(&body,"name").unwrap_or_default();
    if !valid_device_name(&name) { return Err(bad("name must be 1-64 characters of A-Z, a-z, 0-9, dot, underscore, colon or hyphen")); }
    let mut env_id = body_str(&body,"env_id").unwrap_or_default();
    let scoped = env_scope_of(&st, &h).await?;
    if !scoped.is_empty() { if env_id.is_empty() { env_id = scoped; } else if env_id != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); } }
    if !env_id.is_empty() { let (eorg, _) = st.env_org_app(&env_id).await.map_err(|_| err(StatusCode::NOT_FOUND, "environment not found"))?; if eorg != org { return Err(err(StatusCode::NOT_FOUND, "environment not found")); } st.require_env(&env_id,&uid).await?; }
    let sans = device_sans(&body)?.join(",");
    let cert_days = body.get("cert_days").and_then(|v| v.as_i64()).unwrap_or(90).clamp(1,365);
    let gid = id(); let t = now();
    st.db.exec("INSERT INTO pki_groups(id,org_id,ca_id,name,env_id,sans,cert_days,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        &[json!(&gid), json!(&org), json!(&caid), json!(&name), json!(&env_id), json!(&sans), json!(cert_days), json!(body_str(&body,"tags").unwrap_or_default()), json!(t), json!(t)]).await
        .map_err(group_conflict)?;
    st.audit(&org,"",&env_id,&uid,"pki.group.create",&format!("{} ({})", name, gid)).await;
    let row = st.db.one("SELECT g.*,(SELECT COUNT(*) FROM pki_devices d WHERE d.group_id=g.id) AS device_count FROM pki_groups g WHERE g.id=?", &[json!(&gid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("group not found"))?;
    Ok(j(group_json(&row))) }
#[cfg(feature = "pki")]
async fn list_groups(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.require_org(&org,&uid).await?; st.check_perm(&org,&uid,"pki:read").await?;
    let scoped = env_scope_of(&st, &h).await?;
    let rows = if scoped.is_empty() {
        st.db.query("SELECT g.*,(SELECT COUNT(*) FROM pki_devices d WHERE d.group_id=g.id) AS device_count FROM pki_groups g WHERE g.ca_id=? ORDER BY g.name", &[json!(&caid)]).await
    } else {
        st.db.query("SELECT g.*,(SELECT COUNT(*) FROM pki_devices d WHERE d.group_id=g.id) AS device_count FROM pki_groups g WHERE g.ca_id=? AND g.env_id=? ORDER BY g.name", &[json!(&caid), json!(&scoped)]).await
    }.map_err(|e| bad(&e))?;
    let mut visible = Vec::new();
    for mut row in rows {
        if pki_env_access(&st,&row,&uid).await.is_err() { continue; }
        let devices=st.db.query("SELECT env_id FROM pki_devices WHERE group_id=?",&[json!(db::s(&row,"id"))]).await.map_err(|e| bad(&e))?;
        let mut count=0; for device in &devices { if pki_env_access(&st,device,&uid).await.is_ok() { count+=1; } }
        row.insert("device_count".to_string(),json!(count)); visible.push(row);
    }
    Ok(j(json!(visible.iter().map(group_json).collect::<Vec<_>>()))) }
#[cfg(feature = "pki")]
async fn update_group(State(st): State<S>, h: HeaderMap, Path(gid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM pki_groups WHERE id=?", &[json!(&gid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    pki_env_access(&st,&row,&uid).await?;
    let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let scoped = env_scope_of(&st, &h).await?;
    if !scoped.is_empty() && db::s(&row,"env_id") != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); }
    let name = body_str(&body,"name").unwrap_or_else(|| db::s(&row,"name"));
    if !valid_device_name(&name) { return Err(bad("name must be 1-64 characters of A-Z, a-z, 0-9, dot, underscore, colon or hyphen")); }
    let env_id = if scoped.is_empty() { body_str(&body,"env_id").unwrap_or_else(|| db::s(&row,"env_id")) } else { scoped.clone() };
    if !env_id.is_empty() { let (eorg, _) = st.env_org_app(&env_id).await.map_err(|_| err(StatusCode::NOT_FOUND, "environment not found"))?; if eorg != org { return Err(err(StatusCode::NOT_FOUND, "environment not found")); } st.require_env(&env_id,&uid).await?; }
    let sans = if body.get("sans").is_some() { device_sans(&body)?.join(",") } else { db::s(&row,"sans") };
    let cert_days = body.get("cert_days").and_then(|v| v.as_i64()).unwrap_or(db::n(&row,"cert_days")).clamp(1,365);
    let update_sql = "UPDATE pki_groups SET name=?,env_id=?,sans=?,cert_days=?,tags=?,updated_at=? WHERE id=? AND NOT EXISTS (SELECT 1 FROM pki_devices WHERE group_id=? AND env_id<>?)";
    let params = vec![json!(&name), json!(&env_id), json!(&sans), json!(cert_days), json!(body_str(&body,"tags").unwrap_or_else(|| db::s(&row,"tags"))), json!(now()), json!(&gid), json!(&gid), json!(&env_id)];
    let scope_check = scoped.clone();
    st.db.tx_locked("SELECT env_id FROM pki_groups WHERE id=?", &[json!(&gid)], |r| scope_check.is_empty() || db::s(r,"env_id") == scope_check, &[(update_sql, params)], &[(0, 1)]).await
        .map_err(|e| if e.contains("affected 0 rows") { bad("move or detach the group's devices before changing its environment") } else if e == "lock condition failed" { err(StatusCode::CONFLICT, "group changed or was removed; retry") } else { group_conflict(e) })?;
    st.audit(&org,"",&env_id,&uid,"pki.group.update",&format!("{} ({})", name, gid)).await;
    let fresh = st.db.one("SELECT g.*,(SELECT COUNT(*) FROM pki_devices d WHERE d.group_id=g.id) AS device_count FROM pki_groups g WHERE g.id=?", &[json!(&gid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("group not found"))?;
    Ok(j(group_json(&fresh))) }
#[cfg(feature = "pki")]
async fn delete_group(State(st): State<S>, h: HeaderMap, Path(gid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM pki_groups WHERE id=?", &[json!(&gid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    pki_env_access(&st,&row,&uid).await?;
    let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let scoped = env_scope_of(&st, &h).await?;
    if !scoped.is_empty() && db::s(&row,"env_id") != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); }
    let members=st.db.query("SELECT id,env_id FROM pki_devices WHERE group_id=?",&[json!(&gid)]).await.map_err(|e| bad(&e))?;
    for member in &members { pki_env_access(&st,member,&uid).await?; }
    // Only detach members whose exact device and environment were authorised.
    let mut stmts:Vec<(&str,Vec<Value>)>=members.iter().map(|m| ("UPDATE pki_devices SET group_id='' WHERE id=? AND group_id=? AND env_id=?",vec![json!(db::s(m,"id")),json!(&gid),json!(db::s(m,"env_id"))])).collect();
    let mut expected:Vec<(usize,u64)>=(0..stmts.len()).map(|i|(i,1)).collect();
    let delete_index=stmts.len();stmts.push(("DELETE FROM pki_groups WHERE id=? AND NOT EXISTS (SELECT 1 FROM pki_devices WHERE group_id=?)",vec![json!(&gid),json!(&gid)]));expected.push((delete_index,1));
    st.db.tx_locked("SELECT env_id FROM pki_groups WHERE id=?", &[json!(&gid)], |r| scoped.is_empty() || db::s(r,"env_id") == scoped, &stmts, &expected).await
        .map_err(|e| if e == "lock condition failed" || e.contains("affected 0 rows") { err(StatusCode::CONFLICT,"group membership changed; retry") } else { bad(&e) })?;
    st.audit(&org,"",&db::s(&row,"env_id"),&uid,"pki.group.delete",&format!("{} ({})", db::s(&row,"name"), gid)).await;
    Ok(j(json!({"deleted": true, "detached": members.len()}))) }
#[cfg(feature = "pki")]
async fn revoke_group(State(st): State<S>, h: HeaderMap, Path(gid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT * FROM pki_groups WHERE id=?", &[json!(&gid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    pki_env_access(&st,&row,&uid).await?;
    let org = db::s(&row,"org_id"); st.check_perm(&org,&uid,"pki:write").await?;
    let scoped = env_scope_of(&st, &h).await?;
    if !scoped.is_empty() && db::s(&row,"env_id") != scoped { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); }
    let members=st.db.query("SELECT id,env_id FROM pki_devices WHERE group_id=?",&[json!(&gid)]).await.map_err(|e| bad(&e))?;
    for member in &members { pki_env_access(&st,member,&uid).await?; }
    let t = now();
    // No group-wide sweep: a concurrently added or moved device was not part
    // of the authorised snapshot, so only mutate exact checked id/env pairs.
    let mut stmts:Vec<(&str,Vec<Value>)>=Vec::new();
    let mut expected:Vec<(usize,u64)>=Vec::new();
    for member in &members {
        let id=db::s(member,"id");let env=db::s(member,"env_id");
        expected.push((stmts.len(),1));
        stmts.push(("UPDATE pki_devices SET active_cert_id='',updated_at=?,enroll_epoch=enroll_epoch+1 WHERE id=? AND group_id=? AND env_id=?",vec![json!(t),json!(&id),json!(&gid),json!(&env)]));
        stmts.push(("DELETE FROM pki_enrollments WHERE device_id=?",vec![json!(&id)]));
        stmts.push(("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE device_id=? AND revoked=0",vec![json!(t),json!(&id)]));
    }
    let counts=st.db.tx_locked("SELECT env_id FROM pki_groups WHERE id=?",&[json!(&gid)],|r| scoped.is_empty() || db::s(r,"env_id")==scoped,&stmts,&expected).await
        .map_err(|e| if e=="lock condition failed" || e.contains("affected 0 rows") { err(StatusCode::CONFLICT,"group membership changed; retry") } else { bad(&e) })?;
    let revoked:u64=counts.iter().skip(2).step_by(3).sum();
    st.audit(&org,"",&db::s(&row,"env_id"),&uid,"pki.group.revoke",&format!("{} ({})", db::s(&row,"name"), gid)).await;
    Ok(j(json!({"devices": members.len(), "revoked": revoked}))) }


#[cfg(feature = "pki")]
async fn revoke_ca(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_admin(&org,&uid).await?;
    let t = now();
    // Lock the CA row first, then take the fresh statement snapshot that sees
    // any intermediate created between the caller's read and this transaction.
    let counts = st.db.tx_locked("SELECT revoked FROM pki_cas WHERE id=?", &[json!(&caid)], |_| true, &[
        ("UPDATE pki_cas SET revoked=1,revoked_at=? WHERE (id=? OR parent_id=?) AND revoked=0", vec![json!(t), json!(&caid), json!(&caid)]),
        ("UPDATE pki_devices SET active_cert_id='',updated_at=?,enroll_epoch=enroll_epoch+1 WHERE ca_id=? OR ca_id IN (SELECT id FROM pki_cas WHERE parent_id=?)", vec![json!(t), json!(&caid), json!(&caid)]),
        ("DELETE FROM pki_enrollments WHERE device_id IN (SELECT id FROM pki_devices WHERE ca_id=? OR ca_id IN (SELECT id FROM pki_cas WHERE parent_id=?))", vec![json!(&caid), json!(&caid)]),
        ("UPDATE pki_certs SET revoked=1,revoked_at=? WHERE (ca_id=? OR ca_id IN (SELECT id FROM pki_cas WHERE parent_id=?)) AND revoked=0", vec![json!(t), json!(&caid), json!(&caid)]),
    ], &[]).await.map_err(|e| if e == "lock condition failed" { err(StatusCode::NOT_FOUND, "CA not found") } else { bad(&e) })?;
    st.audit(&org,"","",&uid,"pki.ca.revoke",&format!("{} ({}) cas={} certs={}", db::s(&ca,"name"), caid, counts.first().copied().unwrap_or(0), counts.get(3).copied().unwrap_or(0))).await;
    Ok(j(json!({"revoked": true, "cas": counts.first().copied().unwrap_or(0), "certificates": counts.get(3).copied().unwrap_or(0)}))) }
#[cfg(feature = "pki")]
async fn get_ca_hook(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    st.check_admin(&db::s(&ca,"org_id"),&uid).await?;
    Ok(j(json!({"url": db::s(&ca,"hook_url"), "secret_set": !db::s(&ca,"hook_secret_enc").is_empty()}))) }
#[cfg(feature = "pki")]
async fn put_ca_hook(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_admin(&org,&uid).await?;
    let url = body_str(&body,"url").unwrap_or_default();
    if !url.is_empty() && (!url_ok(&url) || !egress_allowed(&url)) { return Err(bad("hook url must be http(s) and outside private networks unless OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let secret_enc = if let Some(s) = body.get("secret").and_then(|v| v.as_str()) { if s.is_empty() { String::new() } else { oc::encrypt_symmetric(&st.master(), s.as_bytes()) } } else { db::s(&ca,"hook_secret_enc") };
    st.db.exec("UPDATE pki_cas SET hook_url=?,hook_secret_enc=? WHERE id=?", &[json!(&url), json!(&secret_enc), json!(&caid)]).await.map_err(|e| bad(&e))?;
    st.audit(&org,"","",&uid,"pki.ca.hook",&format!("{} ({})", db::s(&ca,"name"), caid)).await;
    Ok(j(json!({"url": url, "secret_set": !secret_enc.is_empty()}))) }
#[cfg(feature = "pki")]
async fn enrollment_hook_ok(st: &S, ca: &Row, dev: &Row, enrollment_id: &str, csr_pem: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let url = db::s(ca,"hook_url"); if url.is_empty() { return Ok(()); }
    if !url_ok(&url) || !egress_allowed(&url) { return Err(err(StatusCode::BAD_GATEWAY, "enrollment policy hook is blocked by the egress policy")); }
    // A DNS name can resolve into a private network even though the URL has no
    // IP literal. Resolve in production, refuse private answers, and pin the
    // checked address for the request so a rebinding answer cannot swap it.
    #[cfg(not(target_arch = "wasm32"))]
    let mut pinned: Option<(String, std::net::SocketAddr)> = None;
    #[cfg(not(target_arch = "wasm32"))]
    if !crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false) && crate::envcfg::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) {
        if let Ok(parsed) = reqwest::Url::parse(&url) { if let Some(host) = parsed.host_str() {
            if host.parse::<std::net::IpAddr>().is_err() {
                let port = parsed.port_or_known_default().unwrap_or(443);
                let addrs = match tokio::net::lookup_host((host, port)).await {
                    Ok(addrs) => addrs.collect::<Vec<_>>(),
                    Err(_) => return Err(err(StatusCode::BAD_GATEWAY, "enrollment hook host did not resolve")) };
                if addrs.iter().any(|a| !egress_allowed(&format!("http://{}/",a.ip()))) { return Err(err(StatusCode::BAD_GATEWAY, "enrollment hook resolves to a private address")); }
                if let Some(addr) = addrs.first() { pinned = Some((host.to_string(), *addr)); } } } } }
    let secret = { let enc = db::s(ca,"hook_secret_enc"); if enc.is_empty() { String::new() } else { oc::decrypt_symmetric(&st.master(), &enc).map(|b| String::from_utf8_lossy(&b).into_owned()).map_err(|e| bad(&e))? } };
    use sha2::Digest; let csr_sha256 = format!("{:x}", sha2::Sha256::digest(csr_pem.as_bytes()));
    let sans_raw = db::s(dev,"sans"); let sans: Vec<&str> = sans_raw.split(',').filter(|s| !s.is_empty()).collect();
    let ts = now().to_string();
    let payload = json!({"event": "pki.enroll", "enrollment_id": enrollment_id, "device": {"id": db::s(dev,"id"), "name": db::s(dev,"name"), "env_id": db::s(dev,"env_id"), "model": db::s(dev,"model"), "tags": db::s(dev,"tags"), "sans": sans}, "ca": {"id": db::s(ca,"id"), "name": db::s(ca,"name")}, "csr_sha256": csr_sha256}).to_string();
    #[cfg(not(target_arch = "wasm32"))]
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).redirect(reqwest::redirect::Policy::none());
    #[cfg(not(target_arch = "wasm32"))]
    if let Some((host, addr)) = pinned { builder = builder.resolve(&host, addr); }
    #[cfg(not(target_arch = "wasm32"))]
    let client = builder.build().map_err(|e| bad(&e.to_string()))?;
    #[cfg(target_arch = "wasm32")]
    let client = http_client();
    let mut req = client.post(&url).header("content-type", "application/json").body(payload.clone());
    if !secret.is_empty() { let sig = hmac_hex(secret.as_bytes(), format!("{}.{}", ts, payload).as_bytes()); req = req.header("X-OpenWarp-Timestamp", ts.clone()).header("X-OpenWarp-Signature", format!("t={},v1={}", ts, sig)); }
    let bytes = crate::http::provider_post_bounded(req, 16 * 1024).await
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "enrollment policy hook failed"))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::BAD_GATEWAY, "invalid enrollment policy response"))?;
    if v.get("allow").and_then(|x| x.as_bool()) == Some(true) { Ok(()) }
    else { Err(err(StatusCode::FORBIDDEN, "enrollment denied by policy")) }
}
#[derive(serde::Deserialize, serde::Serialize)]
#[cfg(feature = "pki")]
struct AttestClaims { iss: String, aud: String, sub: String, exp: i64, #[serde(default)] iat: i64, nonce: String, csr_sha256: String, #[serde(default)] hardware_backed: bool, #[serde(default)] key_id: String }
#[cfg(feature = "pki")]
fn attest_key(ca: &Row) -> Result<jsonwebtoken::DecodingKey, (StatusCode, Json<Value>)> {
    let pem = db::s(ca,"attest_key_pem"); let alg = db::s(ca,"attest_alg");
    let key = if alg == "RS256" { jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()) } else { jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()) };
    key.map_err(|e| bad(&format!("attestation public key is invalid: {}", e))) }
#[cfg(feature = "pki")]
fn verify_attestation(ca: &Row, dev_id: &str, nonce: &str, csr_pem: &str, token: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let alg = if db::s(ca,"attest_alg") == "RS256" { jsonwebtoken::Algorithm::RS256 } else { jsonwebtoken::Algorithm::ES256 };
    let key = attest_key(ca)?;
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_audience(&["openwarp-pki"]);
    let issuer = db::s(ca,"attest_issuer"); validation.set_issuer(&[issuer.as_str()]);
    validation.required_spec_claims = ["exp","iss","aud","sub"].iter().map(|s| s.to_string()).collect();
    let data = jsonwebtoken::decode::<AttestClaims>(token, &key, &validation).map_err(|e| err(StatusCode::FORBIDDEN, &format!("attestation rejected: {}", e)))?;
    let claims = data.claims;
    if claims.sub != dev_id { return Err(err(StatusCode::FORBIDDEN, "attestation subject does not match the device")); }
    if claims.nonce != nonce { return Err(err(StatusCode::FORBIDDEN, "attestation nonce does not match the enrollment challenge")); }
    use sha2::Digest; let digest = format!("{:x}", sha2::Sha256::digest(csr_pem.as_bytes()));
    if claims.csr_sha256.to_lowercase() != digest { return Err(err(StatusCode::FORBIDDEN, "attestation does not bind the submitted CSR")); }
    if !claims.hardware_backed { return Err(err(StatusCode::FORBIDDEN, "attestation does not assert a hardware-backed key")); }
    Ok(json!({"issuer": claims.iss, "subject": claims.sub, "key_id": claims.key_id, "iat": claims.iat, "hardware_backed": true})) }
#[cfg(feature = "pki")]
async fn get_ca_attestation(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    st.check_admin(&db::s(&ca,"org_id"),&uid).await?;
    Ok(j(json!({"mode": db::s(&ca,"attest_mode"), "issuer": db::s(&ca,"attest_issuer"), "algorithm": db::s(&ca,"attest_alg"), "required": db::n(&ca,"attest_required") == 1, "key_set": !db::s(&ca,"attest_key_pem").is_empty()}))) }
#[cfg(feature = "pki")]
async fn put_ca_attestation(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE kind='x509' AND id=?", &[json!(&caid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    let org = db::s(&ca,"org_id"); st.check_admin(&org,&uid).await?;
    let issuer = body_str(&body,"issuer").unwrap_or_default();
    let alg = body_str(&body,"algorithm").unwrap_or_else(|| "ES256".to_string());
    if !matches!(alg.as_str(), "ES256" | "RS256") { return Err(bad("algorithm must be ES256 or RS256")); }
    let key = match body.get("public_key_pem").and_then(|v| v.as_str()) { Some(k) => k.to_string(), None => db::s(&ca,"attest_key_pem") };
    if !key.is_empty() {
        let parsed = if alg == "RS256" { jsonwebtoken::DecodingKey::from_rsa_pem(key.as_bytes()) } else { jsonwebtoken::DecodingKey::from_ec_pem(key.as_bytes()) };
        parsed.map_err(|e| bad(&format!("public key is invalid: {}", e)))?; }
    let required = body.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
    let mode = body_str(&body,"mode").unwrap_or_else(|| db::s(&ca,"attest_mode"));
    if !matches!(mode.as_str(),"jwt"|"tpm2") { return Err(bad("mode must be jwt or tpm2")); }
    if required && mode == "jwt" && (issuer.is_empty() || key.is_empty()) { return Err(bad("required attestation needs an issuer and a public key")); }
    st.db.exec("UPDATE pki_cas SET attest_issuer=?,attest_key_pem=?,attest_alg=?,attest_required=?,attest_mode=? WHERE id=?", &[json!(&issuer), json!(&key), json!(&alg), json!(if required {1} else {0}),json!(&mode), json!(&caid)]).await.map_err(|e| bad(&e))?;
    st.audit(&org,"","",&uid,"pki.ca.attestation",&format!("{} ({}) required={}", db::s(&ca,"name"), caid, required)).await;
    Ok(j(json!({"mode":mode,"issuer": issuer, "algorithm": alg, "required": required, "key_set": !key.is_empty()}))) }


#[cfg(feature = "pki")]
async fn notify_pki_expiry(st: &S, org: &str) -> Result<(u64,u64), (StatusCode, Json<Value>)> {
    let t = now(); let day = t/86400;
    let rows = st.db.query("SELECT c.expires_at,d.env_id FROM pki_certs c JOIN pki_devices d ON d.id=c.device_id WHERE d.org_id=? AND c.revoked=0 AND c.expires_at<=?", &[json!(org),json!(t+30*86400)]).await.map_err(|e| bad(&e))?;
    if rows.is_empty() { return Ok((0,0)); }
    let members = st.db.query("SELECT u.id,u.email FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? AND m.role IN ('owner','admin') AND u.active=1 AND u.email_verified=1", &[json!(org)]).await.map_err(|e| bad(&e))?;
    let org_row = st.db.one("SELECT name FROM orgs WHERE id=?", &[json!(org)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("workspace missing"))?;
    let cfg = mailer::MailConfig::from_env(); let (mut sent,mut failed) = (0,0);
    for member in members { let uid = db::s(&member,"id");
        if st.check_perm(org,&uid,"pki:read").await.is_err() { continue; }
        let (mut c7,mut c14,mut c30) = (0,0,0);
        for row in &rows { let env = db::s(row,"env_id"); if !env.is_empty() && st.require_env(&env,&uid).await.is_err() { continue; }
            let e = db::n(row,"expires_at");
            if e<=t+7*86400 { c7+=1; }
            if e<=t+14*86400 { c14+=1; }
            c30+=1; }
        if c30==0 { continue; }
        let insert = "INSERT INTO pki_expiry_deliveries(org_id,user_id,day,status) VALUES(?,?,?,'pending') ON CONFLICT(org_id,user_id,day) DO NOTHING";
        #[cfg(not(target_arch = "wasm32"))]
        let insert = if st.db.backend() == db::Backend::Mysql { "INSERT INTO pki_expiry_deliveries(org_id,user_id,day,status) VALUES(?,?,?,'pending') ON DUPLICATE KEY UPDATE org_id=VALUES(org_id)" } else { insert };
        st.db.exec(insert, &[json!(org),json!(&uid),json!(day)]).await.map_err(|e| bad(&e))?;
        let row = st.db.one("SELECT status FROM pki_expiry_deliveries WHERE org_id=? AND user_id=? AND day=?", &[json!(org),json!(&uid),json!(day)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("delivery claim missing"))?;
        let status = db::s(&row,"status");
        if status=="sent" || status.strip_prefix("sending:").and_then(|s| s.split(':').next()).and_then(|s| s.parse::<i64>().ok()).map(|ts| ts>t-300).unwrap_or(false) { continue; }
        let claim = format!("sending:{}:{}",t,id());
        if st.db.exec("UPDATE pki_expiry_deliveries SET status=? WHERE org_id=? AND user_id=? AND day=? AND status=?", &[json!(&claim),json!(org),json!(&uid),json!(day),json!(&status)]).await.map_err(|e| bad(&e))? != 1 { continue; }
        let msg = mailer::render("pki-expiry",&db::s(&member,"email"),&[("org",&db::s(&org_row,"name")),("count7",&c7.to_string()),("count14",&c14.to_string()),("count30",&c30.to_string())]);
        let delivered = cfg.enabled() && mailer::send(&cfg,&msg).await.is_ok();
        st.db.exec("UPDATE pki_expiry_deliveries SET status=? WHERE org_id=? AND user_id=? AND day=? AND status=?", &[json!(if delivered {"sent"}else{"failed"}),json!(org),json!(&uid),json!(day),json!(&claim)]).await.map_err(|e| bad(&e))?;
        if delivered { sent+=1; } else { failed+=1; } }
    Ok((sent,failed)) }
#[cfg(feature = "pki")]
async fn manual_pki_expiry(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?;
    if !matches!(st.require_org(&oid,&uid).await?.as_str(),"owner"|"admin") { return Err(err(StatusCode::FORBIDDEN,"workspace owner or admin required")); }
    st.check_admin(&oid,&uid).await?; st.check_perm(&oid,&uid,"pki:write").await?; st.check_perm(&oid,&uid,"pki:read").await?;
    let (sent,failed) = notify_pki_expiry(&st,&oid).await?;
    Ok(j(json!({"sent":sent,"failed":failed}))) }
#[cfg(feature = "pki")]
pub async fn pki_expiry_alerts(st: &S) {
    let day = now() / 86400;
    let orgs = st.db.query("SELECT id FROM orgs", &[]).await.unwrap_or_default();
    for o in &orgs { let org = db::s(o,"id");
        if let Err(e) = notify_pki_expiry(st,&org).await { eprintln!("PKI expiry notification failed: {:?}",e.0); }
        let key = format!("pki_expiry_alert:{}", org);
        if meta_get(st, &key).await.parse::<i64>().unwrap_or(0) >= day { continue; }
        let rows = st.db.query("SELECT c.expires_at FROM pki_certs c JOIN pki_devices d ON d.id=c.device_id WHERE d.org_id=? AND c.revoked=0 AND c.expires_at<=?", &[json!(&org), json!(now()+30*86400)]).await.unwrap_or_default();
        if rows.is_empty() { meta_set(st, &key, &day.to_string()).await; continue; }
        let t = now(); let (mut c7, mut c14, mut c30) = (0, 0, 0);
        for r in &rows { let e = db::n(r,"expires_at");
            if e <= t+7*86400 { c7 += 1; }
            if e <= t+14*86400 { c14 += 1; }
            c30 += 1; }
        st.audit(&org, "", "", "system", "pki.expiry", &format!("7d={} 14d={} 30d={}", c7, c14, c30)).await;
        meta_set(st, &key, &day.to_string()).await; } }


async fn emergency_session(st: &S, h: &HeaderMap) -> Result<String, (StatusCode, Json<Value>)> {
    if h.contains_key("authorization") { return Err(err(StatusCode::FORBIDDEN, "a browser cookie session is required")); }
    let token = cookie_val(h, "ow_session");
    if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "a browser cookie session is required")); }
    let uid = st.token_user(h).await?;
    if st.db.one("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND created_at>?", &[json!(oc::hash_token(&token)), json!(&uid), json!(now()-7*86400)]).await.map_err(|e| bad(&e))?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "a browser cookie session is required")); }
    Ok(uid) }
async fn emergency_owner(st: &S, h: &HeaderMap, org: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let uid = emergency_session(st, h).await?;
    if st.org_role(org, &uid).await.as_deref() != Some("owner") { return Err(err(StatusCode::FORBIDDEN, "an owner session is required")); } Ok(uid) }
async fn get_emergency(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = emergency_session(&st, &h).await?; st.require_org(&oid, &uid).await?;
    Ok(j(json!({"locked": st.emergency_locked(&oid).await?}))) }
async fn get_app_emergency(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res {
    let uid = emergency_session(&st, &h).await?; let (org, direct, workspace) = st.app_emergency(&aid).await?; st.require_org(&org, &uid).await?;
    Ok(j(json!({"locked": direct || workspace, "direct_locked": direct, "workspace_locked": workspace}))) }
async fn put_app_emergency(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<EmergencyReq>) -> Res {
    let (org, _, _) = st.app_emergency(&aid).await?; let uid = emergency_owner(&st, &h, &org).await?;
    emergency_transition(&st, &org, Some(&aid), r.locked, [&org, &aid, "", &uid, if r.locked { "app.emergency.lock" } else { "app.emergency.restore" }, ""]).await?;
    get_app_emergency(State(st), h, Path(aid)).await }
#[derive(Deserialize)] struct EmergencyReq { locked: bool }
async fn put_emergency(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<EmergencyReq>) -> Res {
    let uid = emergency_owner(&st, &h, &oid).await?;
    emergency_transition(&st, &oid, None, r.locked, [&oid, "", "", &uid, if r.locked { "org.emergency.lock" } else { "org.emergency.restore" }, ""]).await?;
    Ok(j(json!({"locked": r.locked}))) }
async fn emergency_transition(st: &S, oid: &str, app: Option<&str>, locked: bool, audit: [&str;6]) -> Result<(), (StatusCode, Json<Value>)> {
    let mut statements = vec![(format!("UPDATE {} SET emergency_locked=? WHERE id=?", if app.is_some() { "apps" } else { "orgs" }), vec![json!(if locked { 1 } else { 0 }), json!(app.unwrap_or(oid))])];
    if locked {
        // Credentials are account-wide. Preserve real workspace owners, not admin-equivalent roles.
        for table in ["sessions", "oauth_tokens", "oauth_codes", "mfa_challenges", "mfa_passkey_states", "auth_challenges", "step_up_challenges", "step_up_grants"] {
            statements.push((format!("DELETE FROM {} WHERE user_id IN (SELECT user_id FROM org_members WHERE org_id=? AND role<>'owner')", table), vec![json!(&oid)])); }
        for table in ["oidc_states", "saml_pending"] { statements.push((format!("DELETE FROM {} WHERE org_id=?", table), vec![json!(&oid)])); }
        // Reset only the halted target's claims, fencing late results after restoration.
        statements.push((format!("UPDATE sync_jobs SET status='pending',claim_id='',claimed_at=0 WHERE status='claimed' AND env_id IN (SELECT e.id FROM envs e JOIN apps a ON a.id=e.app_id WHERE {}=?)", if app.is_some() { "a.id" } else { "a.org_id" }), vec![json!(app.unwrap_or(oid))]));
    }
    st.audited_batch(&statements, &[], audit).await.map_err(|e| bad(&e))?;
    Ok(()) }
async fn unscoped_emergency_locked(st: &S, uid: &str) -> Result<bool, (StatusCode, Json<Value>)> {
    Ok(st.db.one("SELECT o.id FROM orgs o WHERE (EXISTS (SELECT 1 FROM org_members m WHERE m.org_id=o.id AND m.user_id=?) OR EXISTS (SELECT 1 FROM identities i WHERE i.org_id=o.id AND i.id=?)) AND (o.emergency_locked<>0 OR EXISTS (SELECT 1 FROM apps a WHERE a.org_id=o.id AND a.emergency_locked<>0))", &[json!(uid), json!(uid)]).await.map_err(|e| bad(&e))?.is_some()) }
async fn secret_health_running(st: &S, uid: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if unscoped_emergency_locked(st, uid).await? { return Err(err(StatusCode::LOCKED, "cannot run unscoped secret health checks during workspace emergency lockdown")); } Ok(()) }
async fn emergency_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let canonical = match canonical_policy_path(req.uri().path()) { Ok(v)=>v, Err(_)=>return bad("invalid path encoding").into_response() };
    let path = canonical.as_str();
    if matches!(path, "/api/instance/rewrap" | "/api/instance/encrypt-metadata" | "/api/instance/rotate-master") {
        match st.db.one("SELECT id FROM orgs WHERE emergency_locked<>0 UNION ALL SELECT id FROM apps WHERE emergency_locked<>0 LIMIT 1", &[]).await {
            Ok(None) => {}, Ok(Some(_)) => return err(StatusCode::FORBIDDEN, "workspace emergency lockdown blocks instance-wide key changes").into_response(), Err(e) => return bad(&e).into_response(), }
    }
    let parts: Vec<&str> = path.split('/').collect();
    let sso = parts.len() == 6 && parts[1] == "api" && parts[2] == "auth" && ((parts[3] == "oidc" && parts[5] == "start" && req.method() == axum::http::Method::GET) || (parts[3] == "saml" && ((matches!(parts[5], "metadata" | "start") && req.method() == axum::http::Method::GET) || (parts[5] == "acs" && req.method() == axum::http::Method::POST))));
    if sso { return next.run(req).await; }
    let org = match emergency_request_org(&st, path, req.uri().query().unwrap_or("")).await { Ok(o) => o, Err(e) => return e.into_response() };
    if let Some(org) = org {
        let app = match emergency_request_app(&st, path).await { Ok(a) => a, Err(e) => return e.into_response() };
        let blocked = if let Some(app) = &app { st.require_app_running(app).await } else { st.require_org_running(&org).await };
        let discovery = path == format!("/api/orgs/{}/apps", org) && req.method() == axum::http::Method::GET && matches!(st.emergency_locked(&org).await, Ok(false));
        if let Err(e) = blocked { if discovery { return next.run(req).await; }
            if e.0 != StatusCode::FORBIDDEN { return e.into_response(); }
            let org_tail = path.strip_prefix(&format!("/api/orgs/{}/", org)).unwrap_or("");
            let app_tail = app.as_ref().and_then(|a| path.strip_prefix(&format!("/api/apps/{}/", a))).unwrap_or("");
            let emergency = org_tail == "emergency" || app_tail == "emergency";
            let metadata = req.method() == axum::http::Method::GET && (matches!(org_tail, "emergency" | "apps" | "settings" | "audit" | "members" | "roles") || matches!(app_tail, "emergency" | "envs" | "settings"));
            if !(metadata || (emergency && req.method() == axum::http::Method::PUT)) { return e.into_response(); }
            if let Err(e) = emergency_session(&st, req.headers()).await { return e.into_response(); }
        }
    } else if req.method() == axum::http::Method::POST && matches!(path, "/api/lockbox" | "/api/me/secret-health/email" | "/api/me/secret-health/enzoic/password" | "/api/me/secret-health/enzoic/accounts" | "/api/me/secret-health/enzoic/credentials" | "/api/me/secret-health/leakcheck") {
        if let Ok(uid) = st.token_user(req.headers()).await {
            if path == "/api/lockbox" {
                match unscoped_emergency_locked(&st, &uid).await {
                    Ok(false) => {}, Ok(true) => return err(StatusCode::FORBIDDEN, "cannot create unscoped shares during workspace emergency lockdown").into_response(), Err(e) => return e.into_response(), }
            } else if let Err(e) = secret_health_running(&st, &uid).await { return e.into_response(); }
        }
    }
    next.run(req).await }
async fn emergency_request_app(st: &S, path: &str) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 3 || parts[0] != "api" { return Ok(None); }
    // Device and group routes are keyed by their own rows, not by a CA id.
    if parts[1] == "pki" && parts.len() > 3 {
        let sql = match parts[2] {
            "devices" => "SELECT COALESCE(NULLIF(d.app_id,''),e.app_id) AS app_id FROM pki_devices d LEFT JOIN envs e ON e.id=d.env_id WHERE d.id=?",
            "groups" => "SELECT e.app_id AS app_id FROM pki_groups g JOIN envs e ON e.id=g.env_id WHERE g.id=?",
            _ => return Ok(None),
        };
        return Ok(st.db.one(sql, &[json!(parts[3])]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"app_id")).filter(|a| !a.is_empty()));
    }
    let sql = match parts[1] {
        "apps" => return Ok(Some(parts[2].to_string())),
        "envs" => "SELECT app_id FROM envs WHERE id=?",
        "secrets" => "SELECT e.app_id FROM secrets s JOIN envs e ON e.id=s.env_id WHERE s.id=?",
        "integrations" => "SELECT e.app_id FROM integrations s JOIN envs e ON e.id=s.env_id WHERE s.id=?",
        "leases" => "SELECT e.app_id FROM leases s JOIN envs e ON e.id=s.env_id WHERE s.id=?",
        "rotations" => "SELECT e.app_id FROM rotation_schedules s JOIN envs e ON e.id=s.env_id WHERE s.id=?",
        "proposals" => "SELECT e.app_id FROM proposals s JOIN envs e ON e.id=s.env_id WHERE s.id=?",
        "access-requests" => "SELECT e.app_id FROM access_requests s JOIN envs e ON e.id=s.env_id WHERE s.id=?",
        "webhooks" => "SELECT app_id FROM webhook_subscriptions WHERE id=?",
        "incoming-webhooks" => "SELECT e.app_id FROM incoming_webhooks w JOIN envs e ON e.id=w.env_id WHERE w.id=?",
        "webhook-deliveries" => "SELECT s.app_id FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.webhook_id WHERE d.id=?",
        "tokens" => "SELECT app_id FROM tokens WHERE id=?",
        _ => return Ok(None),
    };
    Ok(st.db.one(sql, &[json!(parts[2])]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "app_id")).filter(|a| !a.is_empty())) }
async fn emergency_request_org(st: &S, path: &str, query: &str) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.first() == Some(&"scim") { let uri = format!("/?{}", query).parse::<axum::http::Uri>().map_err(|_| bad("invalid query"))?; return Ok(Query::<HashMap<String,String>>::try_from_uri(&uri).map_err(|_| bad("invalid query"))?.0.remove("org_id")); }
    if parts.len() >= 5 && parts[0] == "api" && parts[1] == "auth" && matches!(parts[2], "oidc" | "saml") { return Ok(Some(parts[3].to_string())); }
    if parts.len() < 3 || parts[0] != "api" { return Ok(None); }
    let key = parts[2];
    let sql = match parts[1] {
        "orgs" => return Ok(Some(key.to_string())),
        "webhooks" => "SELECT org_id FROM webhook_subscriptions WHERE id=?",
        "incoming-webhooks" => "SELECT org_id FROM incoming_webhooks WHERE id=?",
        "webhook-deliveries" => "SELECT s.org_id FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.webhook_id WHERE d.id=?",
        "apps" => "SELECT org_id FROM apps WHERE id=?",
        "envs" => "SELECT a.org_id FROM envs e JOIN apps a ON a.id=e.app_id WHERE e.id=?",
        "secrets" => "SELECT a.org_id FROM secrets s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id WHERE s.id=?",
        "integrations" => "SELECT a.org_id FROM integrations s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id WHERE s.id=?",
        "leases" => "SELECT a.org_id FROM leases s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id WHERE s.id=?",
        "rotations" => "SELECT a.org_id FROM rotation_schedules s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id WHERE s.id=?",
        "proposals" => "SELECT a.org_id FROM proposals s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id WHERE s.id=?",
        "access-requests" => "SELECT a.org_id FROM access_requests s JOIN envs e ON e.id=s.env_id JOIN apps a ON a.id=e.app_id WHERE s.id=?",
        "tokens" => "SELECT COALESCE(NULLIF(t.org_id,''),i.org_id) AS org_id FROM tokens t LEFT JOIN identities i ON i.id=t.created_by WHERE t.id=?",
        "pki" | "ssh" if parts.len() > 3 => {
            // Devices and groups are looked up in their own tables; reading the
            // request id from pki_certs would miss them and skip lockdown.
            let sql = match (parts[1], parts[2]) {
                (_, "cas") => "SELECT org_id FROM pki_cas WHERE id=?",
                ("ssh", _) => "SELECT c.org_id FROM ssh_certs s JOIN pki_cas c ON c.id=s.ca_id WHERE s.id=?",
                ("pki", "devices") => "SELECT org_id FROM pki_devices WHERE id=?",
                ("pki", "groups") => "SELECT org_id FROM pki_groups WHERE id=?",
                _ => "SELECT c.org_id FROM pki_certs s JOIN pki_cas c ON c.id=s.ca_id WHERE s.id=?",
            };
            return Ok(st.db.one(sql, &[json!(parts[3])]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "org_id"))); },
        _ => return Ok(None),
    };
    Ok(st.db.one(sql, &[json!(key)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r, "org_id")).filter(|o| !o.is_empty())) }

// ---------- IP allowlist enforcement (T01) ----------
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let ip = ip.trim(); let cidr = cidr.trim(); if cidr.is_empty() { return false; }
    let addr = match ip.parse::<std::net::IpAddr>() { Ok(a) => a, Err(_) => return false };
    if let Ok(net) = cidr.parse::<ipnet::IpNet>() { return net.contains(&addr); }
    match cidr.parse::<std::net::IpAddr>() { Ok(a) => a == addr, Err(_) => false } }
async fn request_org(st: &S, path: &str, query: &str) -> Option<String> {

    let seg = |prefix: &str| path.strip_prefix(prefix).and_then(|r| r.split('/').next()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    if let Some(oid) = seg("/api/orgs/") { return Some(oid); }
    for (prefix, table) in [("/api/webhooks/", "webhook_subscriptions"), ("/api/incoming-webhooks/", "incoming_webhooks")] {
        if let Some(wid) = seg(prefix) { return st.db.one(&format!("SELECT org_id FROM {} WHERE id=?", table), &[json!(wid)]).await.ok().flatten().map(|r| db::s(&r, "org_id")); }
    }
    if let Some(did) = seg("/api/webhook-deliveries/") { return st.db.one("SELECT s.org_id AS org_id FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.webhook_id WHERE d.id=?", &[json!(did)]).await.ok().flatten().map(|r| db::s(&r,"org_id")); }
    if let Some(pid) = seg("/api/change-requests/") { return st.db.one("SELECT org_id FROM change_requests WHERE id=?", &[json!(pid)]).await.ok().flatten().map(|r| db::s(&r, "org_id")); }
    if let Some(aid) = seg("/api/apps/") { return st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.ok().flatten().map(|r| db::s(&r, "org_id")); }
    if let Some(eid) = seg("/api/envs/") { return st.env_org_app(&eid).await.ok().map(|(o, _)| o); }
    for (prefix, table) in [("/api/secrets/", "secrets"), ("/api/leases/", "leases"), ("/api/integrations/", "integrations"), ("/api/rotations/", "rotation_schedules")] {
        if let Some(id) = seg(prefix) {
            if let Ok(Some(r)) = st.db.one(&format!("SELECT env_id FROM {} WHERE id=?", table), &[json!(id)]).await {
                return st.env_org_app(&db::s(&r, "env_id")).await.ok().map(|(o, _)| o);
            }
        }
    }
    if let Some(caid) = seg("/api/pki/cas/") { return st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(caid)]).await.ok().flatten().map(|r| db::s(&r, "org_id")); }
    if let Some(did) = seg("/api/pki/devices/") { return st.db.one("SELECT org_id FROM pki_devices WHERE id=?", &[json!(did)]).await.ok().flatten().map(|r| db::s(&r,"org_id")); }
    if let Some(gid) = seg("/api/pki/groups/") { return st.db.one("SELECT org_id FROM pki_groups WHERE id=?", &[json!(gid)]).await.ok().flatten().map(|r| db::s(&r,"org_id")); }
    if let Some(caid) = seg("/api/ssh/cas/") { return st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(caid)]).await.ok().flatten().map(|r| db::s(&r, "org_id")); }
    if let Some(cid) = seg("/api/ssh/certs/") {
        if let Ok(Some(r)) = st.db.one("SELECT ca_id FROM ssh_certs WHERE id=?", &[json!(cid)]).await {
            return st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(db::s(&r, "ca_id"))]).await.ok().flatten().map(|r| db::s(&r, "org_id"));
        }
    }
    if let Some(cid) = seg("/api/pki/certs/") {
        if let Ok(Some(r)) = st.db.one("SELECT ca_id FROM pki_certs WHERE id=?", &[json!(cid)]).await {
            return st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(db::s(&r, "ca_id"))]).await.ok().flatten().map(|r| db::s(&r, "org_id"));
        }
    }
    if path.starts_with("/scim/") { return query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == "org_id").map(|(_, v)| v.to_string()); }
    None }
fn canonical_policy_path(path: &str) -> Result<String, ()> {
    let mut out=Vec::new();
    for component in path.split('/') { let mut bytes=Vec::new(); let raw=component.as_bytes(); let mut i=0;
        while i<raw.len() { if raw[i]==b'%' { if i+2>=raw.len() {return Err(());} let part=std::str::from_utf8(&raw[i+1..i+3]).map_err(|_|())?; bytes.push(u8::from_str_radix(part,16).map_err(|_|())?); i+=3; } else {bytes.push(raw[i]);i+=1;} }
        if bytes==b"." || bytes==b".." || bytes.iter().any(|b|matches!(b,b'/'|b'\\'|b'%'|0..=31|127)) {return Err(());} out.push(String::from_utf8(bytes).map_err(|_|())?);
    } Ok(out.join("/"))
}
fn administrative_transport(path: &str, _method: &axum::http::Method) -> bool {
    // Webhook transport administration only; every other admin surface keeps
    // its own permission path (role grants, enterprise gates, feature grants).
    path.starts_with("/api/webhooks/") || path.starts_with("/api/webhook-deliveries/") || path.ends_with("/webhooks") && path.starts_with("/api/orgs/")
}
async fn ip_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let raw_path = req.uri().path().to_string();
    // Percent-encoded API paths are rejected outright before any decoding so
    // route matching, scoping and policy all see one canonical spelling.
    if raw_path.starts_with("/api/") && raw_path.contains('%') { return bad("percent-encoded API paths are not supported").into_response(); }
    let path = match canonical_policy_path(&raw_path) {Ok(v)=>v,Err(_)=>return bad("invalid path encoding").into_response()};
    let protected = path.starts_with("/api/") || path == "/mcp" || path.starts_with("/scim/");
    if !protected || path.starts_with("/api/auth/login") || path.starts_with("/api/auth/register") || path.starts_with("/api/auth/oidc/") || path.starts_with("/api/v1/machine") { return next.run(req).await; }
    let headers = req.headers().clone(); let uid = match st.token_user(&headers).await { Ok(u) => u, Err(_) => return next.run(req).await };
    let trust_proxy = crate::envcfg::var("OPENWARP_TRUST_PROXY").map(|v| v == "1").unwrap_or(false);
    let conn_ip = req.extensions().get::<PeerAddr>().map(|c| c.0.to_string());
    // X-Forwarded-For is only honoured from a proxy the operator named, so
    // exposing the port directly cannot spoof allowlists or rate-limit keys.
    let proxy_ok = conn_ip.as_deref().map(|ip| {
        crate::envcfg::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1/32,::1".into())
            .split(',').any(|c| ip_in_cidr(ip, c)) }).unwrap_or(false);
    let forwarded = if trust_proxy && proxy_ok { headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(|s| s.split(',').next().unwrap_or("").trim().to_string()) } else { None };
    let client_ip = forwarded.or(conn_ip).unwrap_or_default();
    let query = req.uri().query().unwrap_or("").to_string();
    let allowed = if client_ip.is_empty() { false } else { match request_org(&st, &path, &query).await {
        Some(oid) => { let list = st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?", &[json!(oid)]).await.ok().flatten().map(|r| db::s(&r, "ip_allowlist")).unwrap_or_default();
            list.trim().is_empty() || list.split(',').any(|c| ip_in_cidr(&client_ip, c)) }
        None => { let mut lists: Vec<String> = st.db.query("SELECT o.ip_allowlist AS ip_allowlist FROM orgs o JOIN org_members m ON m.org_id=o.id WHERE m.user_id=?", &[json!(uid)]).await.unwrap_or_default().iter().map(|r| db::s(r, "ip_allowlist")).filter(|s| !s.trim().is_empty()).collect();
            if lists.is_empty() { lists = st.db.query("SELECT o.ip_allowlist AS ip_allowlist FROM orgs o JOIN identities i ON i.org_id=o.id WHERE i.id=?", &[json!(uid)]).await.unwrap_or_default().iter().map(|r| db::s(r, "ip_allowlist")).filter(|s| !s.trim().is_empty()).collect(); }
            lists.is_empty() || lists.iter().all(|l| l.split(',').any(|c| ip_in_cidr(&client_ip, c))) } } };
    if !allowed { return (StatusCode::FORBIDDEN, Json(json!({"error": format!("source IP {} not in organisation allowlist", client_ip)}))).into_response(); }
    next.run(req).await }

// API and MCP audiences are separate; administration needs org:admin, not
// secret consent. Empty PAT scopes retain their legacy full-access meaning.
async fn oauth_scope_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let path = match canonical_policy_path(req.uri().path()) {Ok(v)=>v,Err(_)=>return bad("invalid path encoding").into_response()};
    #[cfg(feature = "workload-identity")]
    if let Err(e) = workload::restrict(&st, req.headers(), &path, req.method().as_str()).await { return e.into_response(); }
    #[cfg(feature = "transit")]
    match transit::scope(&st, req.headers(), &path, req.method().as_str()).await {
        Ok(true) => {
            let hash = oc::hash_token(&bearer_token(req.headers()));
            if let Ok(Some(row)) = st.db.one("SELECT resource FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(hash), json!(now())]).await {
                if db::s(&row,"resource") != if req.extensions().get::<McpDispatch>().is_some() { format!("{}/mcp",issuer(&st,req.headers())) } else {issuer(&st, req.headers())} { return (StatusCode::FORBIDDEN, Json(json!({"error":"OAuth token audience does not match this API; sign in again"}))).into_response(); }
            }
            return next.run(req).await;
        },
        Err(e) => return e.into_response(),
        Ok(false) => (),
    }
    // SCIM is governed too: an environment-scoped credential must not be able to
    // deprovision users just because the route lives outside /api.
    if !(path.starts_with("/api/") || path.starts_with("/scim/")) || path == "/api/auth/logout" { return next.run(req).await; }
    let token = bearer_token(req.headers());
    if token.is_empty() { return next.run(req).await; }
    // The MCP management dispatch re-binds the caller's own audience; plain
    // REST requests fall through to the standard scope and audience checks so
    // their status codes stay unchanged.
    if let Some((_, _, audience)) = oauth_access(&st, req.headers()).await {
        if req.extensions().get::<McpDispatch>().is_some() {
            if administrative_transport(&path, req.method()) && webhooks::transport_admin(&st, req.headers()).await.is_err() { return err(StatusCode::FORBIDDEN, "org:admin transport scope required").into_response(); }
            if audience != format!("{}/mcp", issuer(&st, req.headers())) { return err(StatusCode::UNAUTHORIZED, "token audience does not match endpoint").into_response(); }
        }
    }
    let hash = oc::hash_token(&token);
    let oauth = match st.db.one("SELECT scope,resource FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(&hash),json!(now())]).await { Ok(r)=>r,Err(_)=>return err(StatusCode::SERVICE_UNAVAILABLE,"credential scopes unavailable").into_response() };
    let service = match st.db.one("SELECT scopes,env_id FROM tokens WHERE token_hash=?", &[json!(&hash)]).await { Ok(r)=>r,Err(_)=>return err(StatusCode::SERVICE_UNAVAILABLE,"credential scopes unavailable").into_response() };
    let read = matches!(req.method(), &axum::http::Method::GET | &axum::http::Method::HEAD | &axum::http::Method::OPTIONS);
    let delegated_pki = path.starts_with("/api/pki/devices/") || path.starts_with("/api/pki/groups/") || path.starts_with("/api/pki/certs/") || (path.starts_with("/api/pki/cas/") && (path.contains("/devices") || path.ends_with("/groups") || (read && path.ends_with("/certs")))) || (path.starts_with("/api/orgs/") && (path.ends_with("/pki/expiring") || (read && path.ends_with("/pki/cas"))));
    let need = if delegated_pki { if read && !path.ends_with("/tpm") { "pki:read" } else { "pki:write" } } else if path.contains("/transit-compat/keys") { match path.rsplit('/').next().unwrap_or("") { "encrypt" => "transit:encrypt", "decrypt" | "rewrap" => "transit:decrypt", _ => "transit:manage" } } else if administrative_transport(&path, req.method()) || admin_scope_path(req.method(), &path) { "org:admin" } else if read { "secrets:read" } else { "secrets:write" };
    let rewrap = path.ends_with("/rewrap") && path.contains("/transit-compat/keys/");
    if let Some(row) = oauth {        if db::s(&row,"resource") != if req.extensions().get::<McpDispatch>().is_some() { format!("{}/mcp",issuer(&st,req.headers())) } else {issuer(&st, req.headers())} { return (StatusCode::FORBIDDEN, Json(json!({"error":"OAuth token audience does not match this API; sign in again"}))).into_response(); }
        let scope = db::s(&row, "scope");
        if !scope_has(&scope, need) || (rewrap && !scope_has(&scope,"transit:encrypt")) { return (StatusCode::FORBIDDEN, Json(json!({"error": format!("OAuth token lacks scope {}", need)}))).into_response(); }
    } else if let Some(row) = service.as_ref() {
        let scope = db::s(row, "scopes");
        if !scope.is_empty() && (!scope_has(&scope, need) || (rewrap && !scope_has(&scope,"transit:encrypt"))) { return (StatusCode::FORBIDDEN, Json(json!({"error": format!("token lacks scope {}", need)}))).into_response(); }
    }
    let pki = path.starts_with("/api/pki/") || (path.starts_with("/api/orgs/") && path.contains("/pki/"));
    if pki && delegated_pki {
        let need = if read && !path.ends_with("/tpm") { "pki:read" } else { "pki:write" };
        let scopes = if let Ok(Some(r)) = st.db.one("SELECT scope FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(&hash),json!(now())]).await { Some(db::s(&r,"scope")) }
            else { st.db.one("SELECT scopes FROM tokens WHERE token_hash=?", &[json!(&hash)]).await.ok().flatten().map(|r| db::s(&r,"scopes")).filter(|s| !s.is_empty()) };
        if scopes.as_ref().map(|s| !scope_has(s,need)).unwrap_or(false) { return err(StatusCode::FORBIDDEN,&format!("token lacks scope {}",need)).into_response(); }
    }
    let scoped = match env_scope_of(&st, req.headers()).await { Ok(s)=>s, Err(_)=>return err(StatusCode::SERVICE_UNAVAILABLE,"credential scope unavailable").into_response() };    if !scoped.is_empty() && !scope_path_ok(&st, &scoped, &path).await { return (StatusCode::FORBIDDEN, Json(json!({"error": "this token is scoped to a different environment"}))).into_response(); }
    next.run(req).await }
fn scope_has(scope: &str, need: &str) -> bool { scope.split_whitespace().any(|s| s == "*" || s == need) }
fn admin_scope_path(method: &axum::http::Method, path: &str) -> bool {
    if path.starts_with("/scim/") || path.starts_with("/api/pki/") { return true; }
    if let Some(rest) = path.strip_prefix("/api/ssh/cas/") {
        let (_, tail) = rest.split_once('/').unwrap_or((rest, ""));
        return tail != "sign" && tail != "sign-host";
    }
    if path.starts_with("/api/ssh/certs/") { return true; }
    if path == "/api/instance" || path.starts_with("/api/instance/") { return method != axum::http::Method::GET; }
    if path == "/api/orgs" { return method == axum::http::Method::POST; }
    if let Some(rest) = path.strip_prefix("/api/orgs/") {
        let (_, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if tail.is_empty() { return method != axum::http::Method::GET; }
        let sub = tail.split('/').next().unwrap_or("");
        return matches!(sub, "members" | "invites" | "roles" | "teams" | "settings" | "saml" | "ldap" | "log-streams" | "rotation-hook" | "pki" | "ssh" | "identities" | "runners" | "audit" | "leave" | "transfer");
    }
    if let Some(rest) = path.strip_prefix("/api/apps/") {
        let (_, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if tail.is_empty() { return matches!(*method, axum::http::Method::PATCH | axum::http::Method::DELETE); }
        if tail == "settings" { return method != axum::http::Method::GET; }
        if tail == "tokens" { return method == axum::http::Method::POST; }
    }
    if let Some(rest) = path.strip_prefix("/api/envs/") {
        let (_, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if tail.is_empty() { return method == axum::http::Method::DELETE; }
        return tail == "policy" || tail.starts_with("path-policy/") || tail == "team-grants" || tail.starts_with("team-grants/");
    }
    path.starts_with("/api/tokens/") }
async fn scope_path_ok(st: &S, scope: &str, path: &str) -> bool {
    if path == "/api/me" || path == "/api/auth/logout" || path == "/api/capabilities" { return true; }
    if let Some(rest) = path.strip_prefix("/api/incoming-webhooks/") { return st.db.one("SELECT env_id FROM incoming_webhooks WHERE id=?", &[json!(rest.split('/').next().unwrap_or(""))]).await.ok().flatten().map(|r| db::s(&r,"env_id") == scope).unwrap_or(false); }
    if let Some(rest) = path.strip_prefix("/api/envs/") {
        let (eid, tail) = rest.split_once('/').unwrap_or((rest, ""));
        return eid == scope && !tail.is_empty();
    }
    if let Some(rest) = path.strip_prefix("/api/pki/devices/") {
        let did = rest.split('/').next().unwrap_or("");
        return st.db.one("SELECT env_id FROM pki_devices WHERE id=?", &[json!(did)]).await.ok().flatten().map(|r| db::s(&r, "env_id") == scope).unwrap_or(false);
    }
    if let Some(rest) = path.strip_prefix("/api/pki/cas/") {
        let (_, tail) = rest.split_once('/').unwrap_or((rest, ""));
        return tail == "devices" || tail.starts_with("devices/") || tail == "groups" || tail.starts_with("groups/");
    }
    if let Some(rest) = path.strip_prefix("/api/pki/groups/") {
        let gid = rest.split('/').next().unwrap_or("");
        return st.db.one("SELECT env_id FROM pki_groups WHERE id=?", &[json!(gid)]).await.ok().flatten().map(|r| db::s(&r, "env_id") == scope).unwrap_or(false);
    }
    if path.starts_with("/api/orgs/") && path.ends_with("/pki/expiring") { return true; }
    if let Some(rest) = path.strip_prefix("/api/pki/certs/") {
        let cid = rest.split('/').next().unwrap_or("");
        if let Ok(Some(r)) = st.db.one("SELECT device_id FROM pki_certs WHERE id=?", &[json!(cid)]).await {
            let did = db::s(&r, "device_id");
            if !did.is_empty() { return st.db.one("SELECT env_id FROM pki_devices WHERE id=?", &[json!(&did)]).await.ok().flatten().map(|r| db::s(&r, "env_id") == scope).unwrap_or(false); }
        }
        return false;
    }
    let target = path.strip_prefix("/api/secrets/").map(|r| ("secrets", r))
        .or_else(|| path.strip_prefix("/api/leases/").map(|r| ("leases", r)))
        .or_else(|| path.strip_prefix("/api/integrations/").map(|r| ("integrations", r)))
        .or_else(|| path.strip_prefix("/api/rotations/").map(|r| ("rotation_schedules", r)));
    match target {
        Some((table, rest)) => { let id = rest.split('/').next().unwrap_or(""); st.db.one(&format!("SELECT env_id FROM {} WHERE id=?", table), &[json!(id)]).await.ok().flatten().map(|r| db::s(&r, "env_id") == scope).unwrap_or(false) }
        None => false,
    } }

// ---------- logout / token management (T04) ----------
async fn logout(State(st): State<S>, h: HeaderMap) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let mut token = auth.strip_prefix("Bearer ").unwrap_or("").to_string();
    if token.is_empty() { token = cookie_val(&h, "ow_session"); }
    let hash = oc::hash_token(&token); let _ = st.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(hash)]).await;
    // An OAuth access or refresh token is a credential too: revoke its whole pair.
    if let Ok(Some(row)) = st.db.one("SELECT pair_id FROM oauth_tokens WHERE token_hash=?", &[json!(&hash)]).await {
        let pair = db::s(&row, "pair_id");
        if pair.is_empty() { let _ = st.db.exec("DELETE FROM oauth_tokens WHERE token_hash=?", &[json!(&hash)]).await; }
        else { let _ = st.db.exec("DELETE FROM oauth_tokens WHERE pair_id=?", &[json!(&pair)]).await; } }
    #[cfg(all(feature = "redis-cache", not(target_arch = "wasm32")))] st.cache_revoke(&hash);
    let mut headers=HeaderMap::new();
    headers.insert(axum::http::header::SET_COOKIE, session_cookie("").replace("Max-Age=604800", "Max-Age=0").parse().unwrap());
    Ok((headers, j(json!({"ok": true})))) }
async fn list_tokens(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let rows = st.db.query("SELECT id,app_id,env_id,name,kind,expires_at,scopes,last_used_at,created_at,created_by FROM tokens WHERE app_id=?", &[json!(aid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn revoke_token(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT created_by,org_id FROM tokens WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"token not found"))?;
    if db::s(&row,"created_by") != uid && st.org_role(&db::s(&row,"org_id"),&uid).await.as_deref() != Some("owner") && st.org_role(&db::s(&row,"org_id"),&uid).await.as_deref() != Some("admin") { return Err(err(StatusCode::FORBIDDEN,"token owner or org admin required")); }
    st.db.exec("DELETE FROM tokens WHERE id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?; Ok(j(json!({"revoked": tid}))) }


// ---------- custom RBAC roles (T07) ----------
async fn create_role(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid,&uid).await?;
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(""); if name.is_empty() || ["owner","admin","developer"].contains(&name) { return Err(bad("role name required and cannot shadow managed roles")); }
    let perms = body.get("permissions").cloned().unwrap_or(json!([]));
    let rid = id(); st.db.exec("INSERT INTO roles(id,org_id,name,permissions) VALUES(?,?,?,?)", &[json!(rid), json!(oid), json!(name), json!(perms.to_string())]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "name": name, "permissions": perms}))) }
async fn list_roles(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.require_org(&oid,&uid).await?;
    let rows = st.db.query("SELECT id,name,permissions FROM roles WHERE org_id=?", &[json!(oid)]).await.map_err(|e| bad(&e))?;
    let mut out: Vec<Value> = rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "permissions": serde_json::from_str::<Value>(&db::s(r,"permissions")).unwrap_or(json!([]))})).collect();
    // Report the managed roles' real breadth so the console does not imply that
    // a developer can administer the organisation.
    out.push(json!({"name": "owner", "permissions": ["*"], "managed": true}));
    out.push(json!({"name": "admin", "permissions": ["*"], "managed": true}));
    out.push(json!({"name": "developer", "permissions": DEVELOPER_PERMS, "managed": true}));
    Ok(j(json!(out))) }

// ---------- TOTP MFA + recovery codes (T08) ----------
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
fn b32encode(data: &[u8]) -> String { let mut out = String::new(); let mut buf: u64 = 0; let mut bits = 0; for b in data { buf = (buf << 8) | *b as u64; bits += 8; while bits >= 5 { out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char); bits -= 5; } } if bits > 0 { out.push(B32[((buf << (5 - bits)) & 31) as usize] as char); } out }
fn b32decode(s: &str) -> Vec<u8> { let mut out = Vec::new(); let mut buf: u64 = 0; let mut bits = 0; for c in s.to_uppercase().chars() { if let Some(v) = B32.iter().position(|&x| x as char == c) { buf = (buf << 5) | v as u64; bits += 5; if bits >= 8 { out.push((buf >> (bits - 8)) as u8); bits -= 8; } } } out }
pub(crate) fn totp_code(secret: &[u8], counter: u64) -> String { use sha1::Sha1; use hmac::{Hmac, Mac}; type H = Hmac<Sha1>;
    let mut m = H::new_from_slice(secret).unwrap(); m.update(&counter.to_be_bytes()); let hash = m.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize; let code = ((hash[off] as u32 & 0x7f) << 24) | ((hash[off+1] as u32) << 16) | ((hash[off+2] as u32) << 8) | hash[off+3] as u32; format!("{:06}", code % 1_000_000) }
async fn otp_ok(st: &S, uid: &str, code: &str) -> Result<bool,String> {
    if let Err(e)=st.epoch_ok().await { return Err(epoch_failure_msg(e)); }
    if meta_get(st, &format!("totp_enabled:{}", uid)).await != "1" { return Ok(true); }
    if code.is_empty() { return Ok(false); }
    Ok(mfa::totp_ok(st, uid, code).await? || mfa::recovery_ok(st, uid, code).await?)
}

pub(crate) async fn meta_set(st: &S, k: &str, v: &str) { if st.db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(k), json!(v)]).await.is_err() { let _ = st.db.exec("UPDATE meta SET v=? WHERE k=?", &[json!(v), json!(k)]).await; } }
async fn totp_setup(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    // Adding a factor to an account that already has one needs the password.
    mfa::reauth_add(&st, &uid, &body).await?;
    let provided = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let secret_bytes: Vec<u8> = if provided.is_empty() { oc::random_key()[..20].to_vec() } else { let d = b32decode(provided); if d.len() < 10 { return Err(bad("provided TOTP secret must be base32, at least 10 bytes")); } d };
    let secret_b32 = b32encode(&secret_bytes);
    // Keep the new secret pending until a code proves it. A re-enrolment must
    // not disable the factor that is already protecting the account.
    let master = st.master();
    let pending_enc = oc::encrypt_symmetric(&master, &secret_bytes);
    st.epoch_write(&meta_statements(&format!("totp_pending:{}", uid), &pending_enc), &[], master).await.map_err(|e| if e==webhooks::EPOCH_STALE {webhooks::epoch_stale()} else {err(StatusCode::SERVICE_UNAVAILABLE,&e)})?;
    let codes = if mfa::recovery_count(&st, &uid).await == 0 { mfa::issue_recovery_codes(&st, &uid).await } else { Vec::new() };
    let email = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).await.map(|r| r.map(|x| db::s(&x,"email")).unwrap_or_default()).unwrap_or_default();
    Ok(j(json!({"secret": secret_b32, "otpauth_url": format!("otpauth://totp/OpenWarp:{}?secret={}&issuer=OpenWarp", email, secret_b32), "recovery_codes": codes, "note": "call POST /api/me/totp/verify {code} with a current TOTP code to enable"}))) }
async fn totp_verify(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    match mfa::confirm_totp(&st, &uid, code).await {
        Ok(true) => {},
        Ok(false) => return Err(err(StatusCode::UNAUTHORIZED, "invalid TOTP code")),
        Err(e) => return Err(mfa_failure(e)),
    }
    Ok(j(json!({"enabled": true}))) }
async fn mfa_login(State(st): State<S>, PeerAddr(addr): PeerAddr, Json(body): Json<Value>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    st.epoch_ok().await?;
    let token = body.get("mfa_token").and_then(|v| v.as_str()).unwrap_or(""); let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let uid = mfa::challenge_user(&st, token).await.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid or expired MFA challenge"))?;
    // The password was already accepted upstream, so this step guards the second
    // factor itself: cap guesses per address and account.
    let key = format!("mfa:{}:{}", addr, uid);
    if !st.rate_ok(&key, 5, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later")); }
    match mfa::second_factor_ok(&st, &uid, code).await {
        Ok(true) => {},
        Ok(false) => { st.rate_fail(&key, 900).await; return Err(err(StatusCode::UNAUTHORIZED, "invalid MFA code")); },
        Err(e) => return Err(mfa_failure(e)),
    }
    st.rate_clear(&key).await;
    if !mfa::consume_challenge(&st, token).await { return Err(err(StatusCode::UNAUTHORIZED, "invalid or expired MFA challenge")); }
    st.audit("", "", "", &uid, "auth.mfa", "").await;
    let session = make_session(&st, &uid).await?; let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap()); Ok((hdr, j(json!({"token": session, "user_id": uid})))) }


// ---------- log streams (T10) ----------
async fn create_stream(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    st.check_admin(&oid,&uid).await?; st.require_enterprise(edition::Feature::AuditStreaming)?;
    let url = body.get("url").and_then(|v|v.as_str()).unwrap_or("");
    if !url_ok(url) || !egress_allowed(url) { return Err(bad("log stream url must be http(s) and outside private networks unless OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let secret = body.get("secret").and_then(|v|v.as_str()).unwrap_or("");
    let master = st.master();
    let secret_enc = if secret.is_empty() { String::new() } else { oc::encrypt_symmetric(&master, secret.as_bytes()) };
    let sid = id();
    st.epoch_write(&[("INSERT INTO log_streams(id,org_id,name,url,secret,created_at) VALUES(?,?,?,?,?,?)".into(), vec![json!(sid), json!(oid), json!(body.get("name").and_then(|v|v.as_str()).unwrap_or("stream")), json!(url), json!(secret_enc), json!(now())])], &[], master).await.map_err(|e| if e==webhooks::EPOCH_STALE {webhooks::epoch_stale()} else {bad(&e)})?;
    Ok(j(json!({"id": sid}))) }
async fn list_streams(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let rows = st.db.query("SELECT id,org_id,name,url,created_at FROM log_streams WHERE org_id=?", &[json!(oid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn list_deliveries(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let rows = st.db.query("SELECT d.id,d.stream_id,s.name AS stream_name,s.url AS stream_url,d.event,d.status,d.attempts,d.created_at FROM log_deliveries d JOIN log_streams s ON s.id=d.stream_id WHERE s.org_id=? ORDER BY d.created_at DESC LIMIT 200", &[json!(oid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }

// ---------- lease renew + rotation schedules (T09) ----------
async fn renew_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id,revoked FROM leases WHERE id=?", &[json!(lid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    if db::n(&row,"revoked") == 1 { return Err(bad("lease revoked")); }
    let (org, _) = st.require_env(&db::s(&row,"env_id"), &uid).await?; st.check_perm(&org, &uid, "leases:write").await?;
    let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600).clamp(60, 30 * 86400);
    st.db.exec("UPDATE leases SET expires_at=? WHERE id=?", &[json!(now()+ttl), json!(lid)]).await.map_err(|e| bad(&e))?; Ok(j(json!({"id": lid, "expires_at": now()+ttl}))) }
fn password_target(stype: &str) -> bool { matches!(stype, "" | "secret" | "config") }
// Record the failure without claiming a candidate was retained when the schedule
// never created one (for example, rejected target type or transport).
pub(crate) async fn audit_rotation_failure(st: &S, eid: &str, rid: &str, key_name: &str) {
    if let Ok((org, app)) = st.env_org_app(eid).await {
        let pending = st.db.one("SELECT pending_enc FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.ok().flatten().map(|r| db::s(&r, "pending_enc")).unwrap_or_default();
        let action = if pending.is_empty() { "rotation.failed" } else { "rotation.failed_pending_retained" };
        st.audit(&org, &app, eid, "rotation-scheduler", action, key_name).await; }
}
async fn create_rotation(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org,&uid,"rotations:write").await?;
    let key_name = body.get("key").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let interval = body.get("interval_secs").and_then(|v| v.as_i64()).unwrap_or(86400);
    if !valid_secret_key(&key_name) || interval < 60 { return Err(bad("key ([A-Za-z0-9_.-]{1,128}) and interval_secs (>=60) required")); }
    if !valid_path(path) { return Err(bad("path is invalid")); }
    let config = body.get("config").cloned().unwrap_or(json!({}));
    integrations::validate_rotation_config(&config).map_err(|e| bad(&e))?;
    let config_enc = if config.as_object().map(|o| o.is_empty()).unwrap_or(true) { String::new() }
        else { let key = st.env_key(&eid).await?; oc::encrypt_symmetric(&key, config.to_string().as_bytes()) };
    let kind = integrations::rotation_kind(&config);
    if kind == "postgres-static" {
        let mode=st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"mode")).unwrap_or_default();
        if mode!="sse" { return Err(bad("postgres-static rotation requires SSE")); }
        let key=st.env_key(&eid).await?; let index=key_index(&key,path,&key_name); let legacy=oc::hash_token(&format!("{}:{}",path,key_name));
        let target=st.db.one("SELECT secret_type FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid),json!(index),json!(legacy)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("postgres-static requires an existing target secret"))?;
        if !password_target(&db::s(&target,"secret_type")) { return Err(bad("postgres-static target must be an unsealed secret or config value, not an SSH key or sealed value")); }
    }
    let static_target = if kind == "postgres-static" { json!(crate::pglease::static_target(config["connection"].as_str().unwrap_or(""),config["username"].as_str().unwrap_or("")).map_err(|e| bad(&e))?) } else { Value::Null };
    let rid = id(); st.db.exec("INSERT INTO rotation_schedules(id,env_id,key_name,path,interval_secs,next_run,config_enc,created_at,static_target) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(rid), json!(eid), json!(key_name), json!(path), json!(interval), json!(now()+interval), json!(&config_enc), json!(now()), static_target]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "next_run": now()+interval, "provider_rotation": !config_enc.is_empty(), "kind": kind}))) }
async fn list_rotations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h).await?; let (org, _) = st.require_env(&eid,&uid).await?; st.check_perm(&org, &uid, "secrets:read").await?;
    let rows = st.db.query("SELECT id,env_id,key_name,path,interval_secs,next_run,enabled,created_at, CASE WHEN config_enc='' THEN 0 ELSE 1 END AS provider_rotation FROM rotation_schedules WHERE env_id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_rotation(State(st): State<S>, h: HeaderMap, Path(rid): Path<String>) -> Res { let uid = st.token_user(&h).await?;
    let row = st.db.one("SELECT env_id FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"schedule not found"))?;
    let (org, _) = st.require_env(&db::s(&row,"env_id"),&uid).await?; st.check_perm(&org, &uid, "rotations:write").await?;
    if !st.db.rotation_batch("SELECT id FROM rotation_schedules WHERE id=? AND (pending_enc<>'' OR execution_token<>'')", &[json!(rid)], &[("DELETE FROM rotation_schedules WHERE id=?".into(),vec![json!(rid)])]).await.map_err(|e| bad(&e))? { return Err(err(StatusCode::CONFLICT,"rotation pending or executing; reconcile before deletion")); } Ok(j(json!({"deleted": rid}))) }
pub async fn try_leader(st: &S, name: &str, owner: &str, ttl: i64) -> bool {
    let current = now(); let expires = current + ttl;
    if st.db.exec("UPDATE instance_leases SET owner=?,expires_at=? WHERE name=? AND (owner=? OR expires_at<?)", &[json!(owner), json!(expires), json!(name), json!(owner), json!(current)]).await.unwrap_or(0) > 0 { return true; }
    st.db.exec("INSERT INTO instance_leases(name,owner,expires_at) VALUES(?,?,?)", &[json!(name), json!(owner), json!(expires)]).await.is_ok() }
pub async fn process_maintenance(st: &S) {
    #[cfg(not(target_arch="wasm32"))] let _guard=st.lifecycle.read().await;
    process_rotations_inner(st).await;
    // Legacy delivery history is retained without unsigned dispatch.
    reap_expired_leases(st).await;
    crate::ai::maintenance(st).await;
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn process_webhooks(st: &S) { if st.epoch_ok().await.is_err() { return; } webhooks::process(st).await; }

// Expiry revokes the remote credential, the way a Vault/OpenBao lease does.
// A failed remote delete leaves the lease active and is retried after a minute.
async fn reap_expired_leases(st: &S) {
    if st.epoch_ok().await.is_err() { return; }
    // Skip halted scopes in the query itself: a per-row skip after LIMIT lets
    // expired leases in a locked project occupy the page and starve siblings.
    let rows = st.db.query("SELECT l.* FROM leases l JOIN envs e ON e.id=l.env_id JOIN apps a ON a.id=e.app_id JOIN orgs o ON o.id=a.org_id WHERE l.revoked=0 AND l.expires_at<=? AND l.attempted_at<=? AND a.emergency_locked=0 AND o.emergency_locked=0 ORDER BY l.expires_at LIMIT 50", &[json!(now()), json!(now() - 60)]).await.unwrap_or_default();
    for row in &rows {
        if st.require_env_running(&db::s(row, "env_id")).await.is_err() { continue; }
        let lid = db::s(row, "id"); let eid = db::s(row, "env_id"); let name = db::s(row, "name");
        let claimed = st.db.exec("UPDATE leases SET attempted_at=? WHERE id=? AND revoked=0 AND expires_at=? AND attempted_at=?", &[json!(now()), json!(&lid), json!(db::n(row, "expires_at")), json!(db::n(row, "attempted_at"))]).await.unwrap_or(0);
        if claimed == 0 { continue; }
        let org_app = st.env_org_app(&eid).await.ok();
        let result = if let Some((org, app)) = &org_app { revoke_lease_remote_audited(st, &lid, [org, app, &eid, "lease-scheduler", "lease.expire", &name]).await }
            else { revoke_lease_remote(st, &lid).await };
        match result {
            Ok(()) => {
                if org_app.is_none() { let _ = st.db.exec("UPDATE leases SET revoked=1 WHERE id=?", &[json!(&lid)]).await; }
            }
            Err(_) => {
                // A concurrent manual revoke may have completed first; its own
                // response already reported the outcome.
                if st.db.one("SELECT revoked FROM leases WHERE id=?", &[json!(&lid)]).await.ok().flatten().map(|r| db::n(&r, "revoked") == 1).unwrap_or(false) { continue; }
                let reason = "remote revocation failed";
                if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org, &app, &eid, "lease-scheduler", "lease.expire_failed", &format!("{}: {}", name, reason)).await; }
            }
        }
    }
}

pub async fn process_rotations(st: &S) { #[cfg(not(target_arch="wasm32"))] let _guard=st.lifecycle.read().await; process_rotations_inner(st).await; }
async fn process_rotations_inner(st: &S) {
    if st.epoch_ok().await.is_err() { return; }
    #[cfg(feature = "pki")]
    if try_leader(st,"pki-expiry",&st.instance_id,3600).await { pki_expiry_alerts(st).await; }    let _ = st.db.exec("DELETE FROM instance_leases WHERE expires_at<?", &[json!(now() - 3600)]).await;
    let _ = st.db.exec("DELETE FROM saml_pending WHERE created_at<?", &[json!(now() - 600)]).await;
    let _ = st.db.exec("DELETE FROM saml_replay WHERE expires_at<?", &[json!(now() - 3600)]).await;
    let _ = st.db.exec("DELETE FROM rate_limits WHERE window_start<?", &[json!(now() - 86400)]).await;
    let _ = st.db.exec("DELETE FROM live_events WHERE created_at<?", &[json!(now() - 3600)]).await;
    let _ = st.db.exec("DELETE FROM wrap_tokens WHERE expires_at<?", &[json!(now() - 3600)]).await;
    let due = st.db.query("SELECT * FROM rotation_schedules WHERE enabled=1 AND next_run<=?", &[json!(now())]).await.unwrap_or_default();
    for r in &due {
        let id = db::s(r,"id"); let eid = db::s(r,"env_id"); let key_name = db::s(r,"key_name");
        if st.require_env_running(&eid).await.is_err() { continue; }
        let interval = db::n(r,"interval_secs").max(60); let old_next = db::n(r,"next_run");
        if !db::s(r,"static_target").is_empty() { static_rotation::execute(st,r).await; continue; }
        // Claim the slot atomically so two replicas cannot rotate the same key twice.
        let claimed = st.db.exec("UPDATE rotation_schedules SET next_run=? WHERE id=? AND next_run=?", &[json!(now()+interval), json!(&id), json!(old_next)]).await.unwrap_or(0);
        if claimed == 0 { continue; }
        let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).await.ok().flatten().map(|x| db::s(&x,"mode")).unwrap_or_default();
        if mode == "e2e" || mode == "delegated" { continue; }
        let (org, _) = st.env_org_app(&eid).await.unwrap_or_default();
        let path = { let p = db::s(r,"path"); if p.is_empty() { "/".to_string() } else { p } };
        let Ok(index_key) = st.env_key(&eid).await else { continue };
        let khash = key_index(&index_key, &path, &key_name.to_uppercase());
        let legacy = oc::hash_token(&format!("{}:{}", path, key_name.to_uppercase()));
        let existing = st.db.one("SELECT secret_type FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(&eid), json!(&khash), json!(&legacy)]).await.ok().flatten();
        let stype = match existing {
            Some(row) if db::s(&row,"secret_type") == "sealed" => {
                if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.skipped_sealed",&key_name).await; }
                continue;
            }
            Some(row) => { let t = db::s(&row,"secret_type"); if t.is_empty() { "secret".to_string() } else { t } }
            None => {
                if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.missing",&key_name).await; }
                continue;
            }
        };
        if let Ok(key) = st.env_key(&eid).await {
            let config_enc = db::s(r, "config_enc");
            let rotated = if config_enc.is_empty() { None } else {
                let config = oc::decrypt_symmetric(&key, &config_enc).ok()
                    .and_then(|plain| serde_json::from_slice::<Value>(&plain).ok());
                let Some(config) = config else {
                    if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.config_invalid",&key_name).await; }
                    continue;
                };
                if config["kind"] == "postgres-static" {
                    if static_rotation::rotate(st,r,&config,&key,&org,&stype).await.is_err() { audit_rotation_failure(st,&eid,&id,&key_name).await; }
                    continue;
                }
                match integrations::rotate_value(&config, &key_name, &path).await {
                    Ok(Some(value)) => Some(value),
                    Ok(None) => {
                        if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.adapter_missing",&key_name).await; }
                        continue;
                    }
                    Err(_) => {
                        if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.failed",&key_name).await; }
                        continue;
                    }
                }
            };
            let new_val = rotated.as_ref().map(|v| v.value.clone()).unwrap_or_else(|| oc::random_token("rot"));
            let s = SecretIn{ key: key_name.clone(), value: new_val.clone(), path: path.clone(), comment: "scheduled rotation".into(), tags: "".into(), secret_type: stype, expected_version: None };
            let master = st.master();
            let mut statements = vec![("UPDATE envs SET id=id WHERE id=?".into(), vec![json!(&eid)])];
            let stored = match secret_statements(st, &eid, &org, &key, "rotation-scheduler", &s, &master).await {
                Ok(more) => { statements.extend(more);
                    if let Ok((org_now, app_now)) = st.env_org_app(&eid).await { st.audited_batch_master(&statements, &[0,1], [&org_now,&app_now,&eid,"rotation-scheduler","secret.rotate",&key_name], master).await.is_ok() }
                    else { st.epoch_write(&statements, &[0,1], master).await.is_ok() } }
                Err(_) => false,
            };
            if stored {
                if let Ok((org_now, app_now)) = st.env_org_app(&eid).await {
                    if let Some(err) = fire_rotation_hook(st, &org_now, &eid, &key_name, &new_val).await {
                        st.audit(&org_now,&app_now,&eid,"rotation-scheduler","rotation_hook_failed",&err).await;
                    }
                }
                let _ = trigger_sync_internal(st, &eid).await;
                if let Some(rotated) = rotated {
                    let next_enc = oc::encrypt_symmetric(&key, rotated.config.to_string().as_bytes());
                    if st.db.exec("UPDATE rotation_schedules SET config_enc=? WHERE id=?", &[json!(next_enc), json!(&id)]).await.is_err() {
                        if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.config_update_failed",&key_name).await; }
                    }
                    if let Some(cleanup) = rotated.cleanup {
                        if integrations::finalize_rotation(&cleanup).await.is_err() {
                            if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.cleanup_failed",&key_name).await; }
                        }
                    }
                }
            } else {
                if let Some(rotated) = rotated {
                    if let Some(rollback) = rotated.rollback { let _ = integrations::finalize_rotation(&rollback).await; }
                }
                if let Ok((org, app)) = st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.store_failed",&key_name).await; }
            }
        }
    } }


// ---------- OAuth 2.1 authorization server (shared by CLI login + MCP) ----------
pub(crate) fn b64url(data: &[u8]) -> String { use base64ct::{Base64UrlUnpadded, Encoding}; Base64UrlUnpadded::encode_string(data) }
fn secret_health_origin(st: &S, h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    if h.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site") || h.get("origin").map(|v| !v.to_str().map(|o| origin_matches(st, h, o)).unwrap_or(false)).unwrap_or(false) { return Err(err(StatusCode::FORBIDDEN, "same-origin request required")); }
    Ok(()) }
async fn secret_health_session(st: &S, h: &HeaderMap) -> Result<String, (StatusCode, Json<Value>)> {
    let uid = st.token_user(h).await?;
    let row = st.db.one("SELECT user_id,created_at FROM sessions WHERE token_hash=?", &[json!(oc::hash_token(&secret_health_token(h)))]).await.map_err(|e| bad(&e))?;
    if !row.map(|r| db::s(&r, "user_id") == uid && db::n(&r, "created_at") + 7 * 86400 >= now()).unwrap_or(false) { return Err(err(StatusCode::UNAUTHORIZED, "session required")); }
    Ok(uid) }
fn secret_health_token(h: &HeaderMap) -> String {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let bearer = auth.strip_prefix("Bearer ").unwrap_or("");
    if bearer.is_empty() { cookie_val(h, "ow_session") } else { bearer.to_string() } }
// Mutex, database and quota waits sit between entry authentication and each
// provider dispatch or settings write; a session revoked in that window must
// not finish the queued work, so the original session is revalidated in place.
async fn secret_health_revalidate(st: &S, h: &HeaderMap, uid: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if secret_health_session(st, h).await?.as_str() != uid { return Err(err(StatusCode::UNAUTHORIZED, "session changed; sign in again")); }
    Ok(()) }
#[cfg(not(target_arch = "wasm32"))]
async fn secret_health_quota(st: &S, key: &str, seconds: i64) -> Result<u64, (StatusCode, Json<Value>)> {
    let insert = if st.db.backend() == db::Backend::Mysql {
        "INSERT INTO rate_limits(key,window_start,count) VALUES(?,0,0) ON DUPLICATE KEY UPDATE count=count"
    } else { "INSERT INTO rate_limits(key,window_start,count) VALUES(?,0,0) ON CONFLICT(key) DO NOTHING" };
    st.db.exec(insert, &[json!(key)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "quota unavailable"))?;
    let timestamp = now();
    st.db.exec("UPDATE rate_limits SET window_start=?,count=1 WHERE key=? AND window_start<=?", &[json!(timestamp), json!(key), json!(timestamp-seconds)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "quota unavailable"))
}
async fn secret_health_store(st: &S, uid: &str, token: &str, name: &str, encrypted: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let sql = "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v";
    #[cfg(not(target_arch = "wasm32"))]
    let sql = if st.db.backend() == db::Backend::Mysql { "INSERT INTO meta(k,v) VALUES(?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)" } else { sql };
    secret_health_write(st, uid, token, &[(sql.into(), vec![json!(name), json!(encrypted)])]).await }
async fn secret_health_delete(st: &S, uid: &str, token: &str, name: &str) -> Result<(), (StatusCode, Json<Value>)> {
    secret_health_write(st, uid, token, &[("DELETE FROM meta WHERE k=?".into(), vec![json!(name)])]).await }
// The session predicate runs inside the same transaction as the write, so a
// revocation landing after the pre-write revalidation still refuses the write.
// Expiry uses the database clock, evaluated after the transaction is acquired;
// the entry and revalidation checks use the crate clock, so a session can fail
// here milliseconds before the crate clock would expire it. Fail-closed.
async fn secret_health_write(st: &S, uid: &str, token: &str, statements: &[(String, Vec<Value>)]) -> Result<(), (StatusCode, Json<Value>)> {
    #[cfg(target_arch = "wasm32")]
    let now_sql = "CAST(strftime('%s','now') AS INTEGER)";
    #[cfg(not(target_arch = "wasm32"))]
    let now_sql = match st.db.backend() {
        db::Backend::Sqlite => "CAST(strftime('%s','now') AS INTEGER)",
        db::Backend::Postgres => "EXTRACT(EPOCH FROM clock_timestamp())::bigint",
        db::Backend::Mysql => "UNIX_TIMESTAMP()",
    };
    let session_guard = format!("UPDATE sessions SET created_at=created_at WHERE token_hash=? AND user_id=? AND created_at + {} >= {}", 7 * 86400, now_sql);
    let mut batch: Vec<(String, Vec<Value>)> = vec![
        ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(), vec![json!(uid)]),
        (session_guard, vec![json!(oc::hash_token(token)), json!(uid)]),
    ];
    batch.extend_from_slice(statements);
    st.db.batch_checked(&batch, &[0, 1]).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::UNAUTHORIZED, "session revoked; sign in again") } else { bad(&e) }) }
async fn secret_health_settings(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    #[cfg(not(target_arch = "wasm32"))]
    let _credential_guard = st.secret_health_credentials.lock().await;
    secret_health_revalidate(&st, &h, &uid).await?;
    let row = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("hibp_api_key:{}", uid))]).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    Ok(j(json!({"api_key_set":row.map(|r| !db::s(&r,"v").is_empty()).unwrap_or(false)}))) }
async fn secret_health_save(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    secret_health_origin(&st, &h)?;
    let key = body.get("api_key").ok_or_else(|| bad("api_key required"))?;
    let name = format!("hibp_api_key:{}", uid);
    #[cfg(not(target_arch = "wasm32"))]
    let _credential_guard = st.secret_health_credentials.lock().await;
    secret_health_revalidate(&st, &h, &uid).await?;
    let token = secret_health_token(&h);
    if key.is_null() {
        secret_health_delete(&st, &uid, &token, &name).await?;
    } else {
        let key = key.as_str().filter(|k| k.len() == 32 && k.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(|| bad("api_key must be 32 hexadecimal characters"))?;
        let encrypted = oc::encrypt_symmetric(&st.master(), key.as_bytes());
        secret_health_store(&st, &uid, &token, &name, &encrypted).await?;
    }
    Ok(j(json!({"api_key_set":!key.is_null()}))) }
async fn secret_health_email(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    secret_health_running(&st, &uid).await?;
    secret_health_origin(&st, &h)?;
    if body.get("consent").and_then(Value::as_bool) != Some(true) { return Err(bad("explicit consent required")); }
    let email = body.get("email").and_then(Value::as_str).unwrap_or("");
    let parts: Vec<&str> = email.split('@').collect();
    if email.len() > 254 || parts.len() != 2 || parts[0].is_empty() || !parts[1].contains('.') || parts[1].starts_with('.') || parts[1].ends_with('.') || email.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) { return Err(bad("valid email required")); }
    #[cfg(not(target_arch = "wasm32"))]
    let credential_guard = st.secret_health_credentials.lock().await;
    secret_health_revalidate(&st, &h, &uid).await?;
    let row = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("hibp_api_key:{}", uid))]).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?.ok_or_else(|| bad("configure your own HIBP API key first"))?;
    let key = oc::decrypt_symmetric(&st.master(), &db::s(&row,"v")).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    #[cfg(not(target_arch = "wasm32"))]
    drop(credential_guard);
    #[cfg(target_arch = "wasm32")]
    { let _ = key; Err(err(StatusCode::NOT_IMPLEMENTED, "email checks require the native server's redirect-safe transport")) }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Consume quota atomically before outbound work, including provider failures.
        let quota = secret_health_quota(&st, &format!("hibp:{}",uid), 60).await?;
        if quota != 1 { return Err(err(StatusCode::TOO_MANY_REQUESTS, "wait one minute between email checks")); }
        let client = crate::http::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "email check unavailable"))?;
        let address: String = email.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) }).collect();
        let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true", address);
        secret_health_running(&st, &uid).await?;
        secret_health_revalidate(&st, &h, &uid).await?;
        let response = client.get(url).header("hibp-api-key", String::from_utf8(key).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?).header("user-agent", "OpenWarp-secret-health").send().await;
        let Ok(mut response) = response else { return Err(err(StatusCode::BAD_GATEWAY, "email check unavailable")); };
        match response.status().as_u16() {
            404 => return Ok(j(json!({"status":"not_found","breaches":[]}))),
            401 => return Err(err(StatusCode::BAD_GATEWAY, "HIBP API key rejected (401)")),
            403 => return Err(err(StatusCode::BAD_GATEWAY, "HIBP access forbidden (403); check your subscription")),
            429 => return Err(err(StatusCode::TOO_MANY_REQUESTS, "HIBP rate limit reached")),
            200 => (),
            _ => return Err(err(StatusCode::BAD_GATEWAY, "email check unavailable")),
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| err(StatusCode::BAD_GATEWAY, "email check unavailable"))? {
            if bytes.len() + chunk.len() > 65536 { return Err(err(StatusCode::BAD_GATEWAY, "email check unavailable")); }
            bytes.extend_from_slice(&chunk);
        }
        let data: Value = serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::BAD_GATEWAY, "email check unavailable"))?;
        let rows = data.as_array().filter(|r| r.len() <= 1000).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "email check unavailable"))?;
        let mut names = Vec::new();
        for row in rows { let name = row.get("Name").and_then(Value::as_str).filter(|n| !n.is_empty() && n.len() <= 128 && n.chars().all(|c| c.is_alphanumeric() || " ._()-".contains(c))).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "email check unavailable"))?; names.push(name); }
        Ok(j(json!({"status":if names.is_empty(){"not_found"}else{"found"},"breaches":names})))
    } }
async fn leakcheck_email(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    secret_health_running(&st, &uid).await?;
    secret_health_origin(&st, &h)?;
    if body.get("consent").and_then(Value::as_bool) != Some(true) { return Err(bad("explicit consent required")); }
    if body.as_object().map(|o| o.len() != 2).unwrap_or(true) { return Err(bad("only email_hash and consent are accepted")); }
    let prefix = body.get("email_hash").and_then(Value::as_str).filter(|s| s.len() == 24 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).ok_or_else(|| bad("email_hash must be 24 lowercase hexadecimal characters"))?;
    #[cfg(target_arch = "wasm32")]
    { let _ = (uid, prefix); Err(err(StatusCode::NOT_IMPLEMENTED, "LeakCheck checks require the native server's redirect-safe transport")) }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Two whole-second ticks ensure at least one second between shared-egress attempts.
        for (key, seconds) in [(format!("leakcheck:{}", uid), 60), ("leakcheck:instance".to_string(), 2)] {
            let quota = secret_health_quota(&st, &key, seconds).await?;
            if quota != 1 { return Err(err(StatusCode::TOO_MANY_REQUESTS, "LeakCheck quota reached; wait before retrying")); }
        }
        let client = crate::http::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "LeakCheck check unavailable"))?;
        secret_health_running(&st, &uid).await?;
        secret_health_revalidate(&st, &h, &uid).await?;
        let response = client.get(format!("https://leakcheck.io/api/public?check={}", prefix)).send().await;
        let Ok(mut response) = response else { return Err(err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable")); };
        if response.status().as_u16() == 429 { return Err(err(StatusCode::TOO_MANY_REQUESTS, "LeakCheck rate limit reached")); }
        if response.status().as_u16() != 200 { return Err(err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable")); }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable"))? {
            if bytes.len() + chunk.len() > 65536 { return Err(err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable")); }
            bytes.extend_from_slice(&chunk);
        }
        let data: Value = serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable"))?;
        if data.get("success").and_then(Value::as_bool) != Some(true) { return Err(err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable")); }
        let found = data.get("found").and_then(Value::as_u64).filter(|n| *n <= 9007199254740991).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable"))?;
        let rows = data.get("sources").and_then(Value::as_array).filter(|r| r.len() <= 1000).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable"))?;
        if (found > 0) == rows.is_empty() { return Err(err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable")); }
        let mut names = Vec::new();
        for row in rows {
            let name = row.get("name").and_then(Value::as_str).filter(|s| !s.trim().is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable"))?;
            let _date = row.get("date").and_then(Value::as_str).filter(|s| s.len() <= 32 && !s.chars().any(char::is_control)).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "LeakCheck check unavailable"))?;
            names.push(name);
        }
        Ok(j(json!({"status":if found > 0 {"found"} else {"not_found"},"breaches":names})))
    } }
async fn enzoic_settings(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    #[cfg(not(target_arch = "wasm32"))]
    let _credential_guard = st.secret_health_credentials.lock().await;
    secret_health_revalidate(&st, &h, &uid).await?;
    let row = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("enzoic_credentials:{}", uid))]).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    Ok(j(json!({"configured":row.map(|r| !db::s(&r,"v").is_empty()).unwrap_or(false)}))) }
async fn enzoic_save(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    secret_health_origin(&st, &h)?;
    let key = body.get("api_key").ok_or_else(|| bad("api_key required"))?;
    let secret = body.get("api_secret").ok_or_else(|| bad("api_secret required"))?;
    let name = format!("enzoic_credentials:{}", uid);
    #[cfg(not(target_arch = "wasm32"))]
    let _credential_guard = st.secret_health_credentials.lock().await;
    secret_health_revalidate(&st, &h, &uid).await?;
    let token = secret_health_token(&h);
    if key.is_null() && secret.is_null() {
        secret_health_delete(&st, &uid, &token, &name).await?;
    } else {
        let valid = |v: &Value| v.as_str().filter(|s| !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic() && b != b':')).map(str::to_string);
        let key = valid(key).ok_or_else(|| bad("api_key must be 1-256 visible ASCII characters without a colon"))?;
        let secret = valid(secret).ok_or_else(|| bad("api_secret must be 1-256 visible ASCII characters without a colon"))?;
        let encrypted = oc::encrypt_symmetric(&st.master(), json!({"api_key":key,"api_secret":secret}).to_string().as_bytes());
        secret_health_store(&st, &uid, &token, &name, &encrypted).await?;
    }
    Ok(j(json!({"configured":!key.is_null()}))) }
async fn enzoic_password(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    secret_health_running(&st, &uid).await?;
    secret_health_origin(&st, &h)?;
    if body.get("consent").and_then(Value::as_bool) != Some(true) { return Err(bad("explicit consent required")); }
    if body.as_object().map(|o| o.len() != 2).unwrap_or(true) { return Err(bad("only prefix and consent are accepted")); }
    let prefix = body.get("prefix").and_then(Value::as_str).filter(|s| s.len() == 10 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).ok_or_else(|| bad("prefix must be ten lowercase hexadecimal characters"))?;
    #[cfg(not(target_arch = "wasm32"))]
    let credential_guard = st.secret_health_credentials.lock().await;
    secret_health_revalidate(&st, &h, &uid).await?;
    let row = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("enzoic_credentials:{}", uid))]).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?.ok_or_else(|| bad("configure your own Enzoic credentials first"))?;
    let decrypted = oc::decrypt_symmetric(&st.master(), &db::s(&row,"v")).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    #[cfg(not(target_arch = "wasm32"))]
    drop(credential_guard);
    let credentials: Value = serde_json::from_slice(&decrypted).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    let key = credentials.get("api_key").and_then(Value::as_str).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    let secret = credentials.get("api_secret").and_then(Value::as_str).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
    #[cfg(target_arch = "wasm32")]
    { let _ = (prefix, key, secret); Err(err(StatusCode::NOT_IMPLEMENTED, "Enzoic checks require the native server's redirect-safe transport")) }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Failed provider calls also spend the user's atomic quota slot.
        let quota = secret_health_quota(&st, &format!("enzoic:{}",uid), 60).await?;
        if quota != 1 { return Err(err(StatusCode::TOO_MANY_REQUESTS, "wait one minute between Enzoic checks")); }
        let client = crate::http::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "Enzoic check unavailable"))?;
        secret_health_running(&st, &uid).await?;
        secret_health_revalidate(&st, &h, &uid).await?;
        let response = client.post("https://api.enzoic.com/v1/passwords").basic_auth(key, Some(secret)).json(&json!({"partialSHA256":prefix})).send().await;
        let Ok(mut response) = response else { return Err(err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable")); };
        match response.status().as_u16() {
            404 => return Ok(j(json!({"candidates":[]}))),
            401 => return Err(err(StatusCode::BAD_GATEWAY, "Enzoic credentials rejected (401)")),
            403 => return Err(err(StatusCode::BAD_GATEWAY, "Enzoic access forbidden (403); check your subscription or quota")),
            429 => return Err(err(StatusCode::TOO_MANY_REQUESTS, "Enzoic rate limit reached")),
            200 => (),
            _ => return Err(err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable")),
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable"))? {
            if bytes.len() + chunk.len() > 1024 * 1024 { return Err(err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable")); }
            bytes.extend_from_slice(&chunk);
        }
        let data: Value = serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable"))?;
        let rows = data.get("candidates").and_then(Value::as_array).filter(|r| r.len() <= 1000).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable"))?;
        let mut candidates = Vec::new();
        for row in rows {
            let hash = row.get("sha256").and_then(Value::as_str).filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable"))?;
            let exposed = row.get("revealedInExposure").and_then(Value::as_bool).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable"))?;
            let count = row.get("exposureCount").and_then(Value::as_u64).filter(|n| *n <= 9007199254740991).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Enzoic check unavailable"))?;
            candidates.push(json!({"sha256":hash,"revealedInExposure":exposed,"exposureCount":count}));
        }
        Ok(j(json!({"candidates":candidates})))
    } }
#[cfg(not(target_arch = "wasm32"))]
fn enzoic_plain_salt(value: &Value) -> bool {
    value.as_str().map(|s| s.len() <= 1024 && !["$argon2", "base64:", "hex:"].iter().any(|p| s.to_ascii_lowercase().starts_with(p))).unwrap_or(false)
}
#[cfg(not(target_arch = "wasm32"))]
fn enzoic_plain_encoding(value: Option<&Value>) -> bool { value.is_none() || value.and_then(Value::as_str) == Some("plain") }
#[cfg(not(target_arch = "wasm32"))]
fn enzoic_pair_response(data: &Value, accounts: bool) -> Result<Value, (StatusCode, Json<Value>)> {
    let unavailable = || err(StatusCode::BAD_GATEWAY, "Enzoic credential-pair check unavailable");
    if accounts {
        let salt = data.get("salt").filter(|v| enzoic_plain_salt(v)).ok_or_else(unavailable)?;
        if !enzoic_plain_encoding(data.get("saltEncoding")) { return Err(unavailable()); }
        let rows = data.get("passwordHashesRequired").and_then(Value::as_array).filter(|r| !r.is_empty() && r.len() <= 32).ok_or_else(unavailable)?;
        let mut requirements = Vec::new();
        for row in rows {
            let kind = row.get("hashType").and_then(Value::as_u64).filter(|k| matches!(*k, 1|2|3|13|14|19|25|27|32|35|37|40)).ok_or_else(unavailable)?;
            if !enzoic_plain_encoding(row.get("saltEncoding")) { return Err(unavailable()); }
            let mut spec = json!({"hashType":kind});
            if let Some(s) = row.get("salt") { if !enzoic_plain_salt(s) { return Err(unavailable()); } spec["salt"] = s.clone(); }
            if matches!(kind, 13|19|25|32|37|40) && spec.get("salt").and_then(Value::as_str).map(str::is_empty).unwrap_or(true) { return Err(unavailable()); }
            requirements.push(spec);
        }
        Ok(json!({"found":true,"salt":salt,"passwordHashesRequired":requirements}))
    } else {
        let rows = data.get("candidateHashes").and_then(Value::as_array).filter(|r| r.len() <= 1000).ok_or_else(unavailable)?;
        let mut hashes = Vec::new();
        for row in rows { let hash = row.as_str().filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(unavailable)?; hashes.push(hash.to_ascii_lowercase()); }
        Ok(json!({"candidateHashes":hashes}))
    }
}
async fn enzoic_accounts(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { enzoic_pair_relay(st, h, body, true).await }
async fn enzoic_credentials(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { enzoic_pair_relay(st, h, body, false).await }
async fn enzoic_pair_relay(st: S, h: HeaderMap, body: Value, accounts: bool) -> Res {
    let uid = secret_health_session(&st, &h).await?;
    secret_health_running(&st, &uid).await?;
    secret_health_origin(&st, &h)?;
    if body.get("consent").and_then(Value::as_bool) != Some(true) { return Err(bad("explicit consent required")); }
    if body.as_object().map(|o| o.len() != 2).unwrap_or(true) { return Err(bad("only the stage hash field and consent are accepted")); }
    let lower_hex = |s: &str, length| s.len() == length && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut query = Vec::new();
    if accounts {
        let hash = body.get("username_hash").and_then(Value::as_str).filter(|s| lower_hex(s, 64)).ok_or_else(|| bad("username_hash must be 64 lowercase hexadecimal characters"))?;
        query.push(("username", hash));
    } else {
        let hashes = body.get("partial_hashes").and_then(Value::as_array).filter(|r| !r.is_empty() && r.len() <= 32).ok_or_else(|| bad("partial_hashes must contain 1-32 prefixes"))?;
        for hash in hashes { query.push(("partialHashes", hash.as_str().filter(|s| lower_hex(s, 10)).ok_or_else(|| bad("partial_hashes must contain ten-character lowercase hexadecimal prefixes"))?)); }
    }
    #[cfg(target_arch = "wasm32")]
    { let _ = (uid, query); Err(err(StatusCode::NOT_IMPLEMENTED, "Enzoic checks require the native server's redirect-safe transport")) }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let credential_guard = st.secret_health_credentials.lock().await;
        secret_health_revalidate(&st, &h, &uid).await?;
        let row = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("enzoic_credentials:{}", uid))]).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?.ok_or_else(|| bad("configure your own Enzoic credentials first"))?;
        let decrypted = oc::decrypt_symmetric(&st.master(), &db::s(&row,"v")).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
        drop(credential_guard);
        let credentials: Value = serde_json::from_slice(&decrypted).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
        let key = credentials.get("api_key").and_then(Value::as_str).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
        let secret = credentials.get("api_secret").and_then(Value::as_str).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "settings unavailable"))?;
        let stage = if accounts { "accounts" } else { "credentials" };
        // Separate atomic stage slots let a permitted account lookup finish its second request.
        if secret_health_quota(&st, &format!("enzoic:{}:{}", stage, uid), 60).await? != 1 { return Err(err(StatusCode::TOO_MANY_REQUESTS, "wait one minute between Enzoic requests for this stage")); }
        let unavailable = || err(StatusCode::BAD_GATEWAY, "Enzoic credential-pair check unavailable");
        let client = crate::http::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| unavailable())?;
        let target = if accounts { "https://api.enzoic.com/v1/accounts" } else { "https://api.enzoic.com/v1/credentials" };
        secret_health_running(&st, &uid).await?;
        secret_health_revalidate(&st, &h, &uid).await?;
        let mut response = client.get(target).query(&query).basic_auth(key, Some(secret)).send().await.map_err(|_| unavailable())?;
        match response.status().as_u16() {
            404 => return Ok(j(if accounts { json!({"found":false}) } else { json!({"candidateHashes":[]}) })),
            429 => return Err(err(StatusCode::TOO_MANY_REQUESTS, "Enzoic rate limit reached")),
            200 => (),
            _ => return Err(unavailable()),
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if bytes.len() + chunk.len() > 1024 * 1024 { return Err(unavailable()); }
            bytes.extend_from_slice(&chunk);
        }
        let data: Value = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        Ok(j(enzoic_pair_response(&data, accounts)?))
    }
}
#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "secret_health_rotation_tests.rs"]
mod secret_health_rotation_tests;

async fn oauth_user(st: &S, h: &HeaderMap) -> Option<String> {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let bearer = auth.strip_prefix("Bearer ").unwrap_or("").to_string();
    let cookie = cookie_val(h, "ow_session");
    for tok in [bearer, cookie] { if tok.is_empty() { continue; }
        if let Ok(Some(r)) = st.db.one("SELECT user_id,created_at FROM sessions WHERE token_hash=?", &[json!(oc::hash_token(&tok))]).await { if db::n(&r,"created_at") + 7*86400 >= now() { return Some(db::s(&r,"user_id")); } } }
    None }
pub async fn oauth_access(st: &S, h: &HeaderMap) -> Option<(String, String, String)> {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""); let tok = auth.strip_prefix("Bearer ").unwrap_or("");
    if tok.is_empty() { return None; }
    st.db.one("SELECT user_id,scope,resource FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(oc::hash_token(tok)), json!(now())]).await.ok().flatten().map(|r| (db::s(&r,"user_id"), db::s(&r,"scope"), db::s(&r,"resource"))) }
async fn prm(State(st): State<S>, h: HeaderMap) -> impl IntoResponse { let iss = issuer(&st, &h);
    Json(json!({"resource": format!("{}/mcp", iss), "authorization_servers": [iss], "scopes_supported": ["secrets:read","secrets:write","mcp","org:admin"], "bearer_methods_supported": ["header"]})) }
async fn asm(State(st): State<S>, h: HeaderMap) -> impl IntoResponse { let iss = issuer(&st, &h);
    Json(json!({"issuer": iss, "authorization_endpoint": format!("{}/oauth/authorize", iss), "token_endpoint": format!("{}/oauth/token", iss), "registration_endpoint": format!("{}/oauth/register", iss), "revocation_endpoint": format!("{}/oauth/revoke", iss), "response_types_supported": ["code"], "grant_types_supported": ["authorization_code","refresh_token"], "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["client_secret_post","none"], "scopes_supported": KNOWN_SCOPES, "revocation_endpoint_auth_methods_supported": ["client_secret_post","none"]})) }async fn oauth_register(State(st): State<S>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let redirects = body.get("redirect_uris").cloned().unwrap_or(json!([]));
    if !redirects.as_array().map(|a| !a.is_empty()).unwrap_or(false) { return (StatusCode::BAD_REQUEST, Json(json!({"error":"redirect_uris required"}))); }
    let auth_method = body.get("token_endpoint_auth_method").and_then(|v| v.as_str()).unwrap_or("client_secret_post");
    let client_id = oc::random_token("client"); let secret = if auth_method == "none" { String::new() } else { oc::random_token("secret") };
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("secrets:read");
    match st.db.exec("INSERT INTO oauth_clients(client_id,client_secret_hash,name,redirect_uris,scopes,created_at) VALUES(?,?,?,?,?,?)", &[json!(client_id), json!(if secret.is_empty(){String::new()}else{oc::hash_token(&secret)}), json!(body.get("client_name").and_then(|v| v.as_str()).unwrap_or("client")), json!(redirects.to_string()), json!(scope), json!(now())]).await {
        Ok(_) => { let mut out = json!({"client_id": client_id, "redirect_uris": redirects, "scope": scope, "token_endpoint_auth_method": auth_method}); if !secret.is_empty() { out["client_secret"] = json!(secret); } (StatusCode::CREATED, Json(out)) }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))) } }
const KNOWN_SCOPES: &[&str] = &["secrets:read", "secrets:write", "org:admin", "mcp", "transit:manage", "transit:encrypt", "transit:decrypt", "transit:rewrap", "pki:read", "pki:write"];async fn authorize_params_ok(st: &S, q: &HashMap<String, String>, iss: &str) -> Result<(String, String, String), String> {
    let client_id = q.get("client_id").cloned().unwrap_or_default(); let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let client = st.db.one("SELECT redirect_uris,scopes FROM oauth_clients WHERE client_id=?", &[json!(client_id)]).await.ok().flatten().ok_or("unknown client_id")?;
    let uris: Vec<String> = serde_json::from_str(&db::s(&client, "redirect_uris")).unwrap_or_default();
    if !uris.iter().any(|u| u == &redirect) { return Err("redirect_uri does not exactly match a registered URI".into()); }
    if q.get("response_type").map(|s| s.as_str()) != Some("code") { return Err("response_type must be code".into()); }
    if let Some(resource) = q.get("resource").filter(|r| !r.trim().is_empty()) {
        if resource != iss && resource != &format!("{}/mcp", iss) { return Err("resource must be the API issuer or its /mcp endpoint".into()); }
    }
    if q.get("code_challenge_method").map(|s| s.as_str()) != Some("S256") || q.get("code_challenge").map(|s| s.is_empty()).unwrap_or(true) { return Err("PKCE with S256 is required".into()); }
    let scope = q.get("scope").cloned().unwrap_or_else(|| "secrets:read".into());
    let registered_scopes = db::s(&client, "scopes");
    let registered: Vec<&str> = registered_scopes.split_whitespace().collect();
    for s in scope.split_whitespace() {
        if !KNOWN_SCOPES.contains(&s) { return Err(format!("unknown scope {}", s)); }
        if !registered.iter().any(|r| *r == "*" || *r == s) { return Err(format!("scope {} was not registered for this client", s)); }
    }
    if scope.split_whitespace().next().is_none() { return Err("at least one scope is required".into()); }
    Ok((client_id, redirect, scope)) }
async fn oauth_authorize(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Response {
    if let Err(e) = authorize_params_ok(&st, &q, &issuer(&st, &h)).await { return html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>OAuth error</h1><p>{}</p></body></html>", esc(&e))); }
    let hidden = hidden_fields(&q);
    let client = esc(q.get("client_id").map(|s| s.as_str()).unwrap_or(""));
    let scope = esc(q.get("scope").map(|s| s.as_str()).unwrap_or(""));
    if oauth_user(&st, &h).await.is_some() {
        return html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Authorize application</h1><p>Client: {}<br>Scopes: {}</p><form method=post action=\"/oauth/authorize/decision\">{}<button name=approve value=1 style=\"padding:10px 20px\">Approve</button> <button name=approve value=0 style=\"padding:10px 20px\">Deny</button></form></body></html>", client, scope, hidden));
    }
    html_csp_with(OAUTH_AUTH_CSP, format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Sign in to OpenWarp</h1><form id=\"oauthlogin\" method=post action=\"/oauth/authorize/decision\">{}<input name=email type=email placeholder=email required style=\"padding:8px\"><br><input name=password type=password placeholder=password required style=\"padding:8px\"><br><button name=approve value=1 style=\"padding:10px 20px;margin-top:8px\">Sign in and approve</button></form>{}</body></html>", hidden, OAUTH_AUTH_JS))
}
fn consent_mfa_page(form: &HashMap<String, String>, token: &str) -> String {
    format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Two-factor required</h1><p>Enter the code from your authenticator app or a recovery code.</p><form method=post action=\"/oauth/authorize/decision\">{}<input type=hidden name=\"mfa_token\" value=\"{}\"><input name=otp placeholder=\"authenticator code\" autocomplete=one-time-code required><br><button name=approve value=1 style=\"padding:10px 20px;margin-top:8px\">Continue</button></form></body></html>", hidden_fields(form), esc(token))
}
async fn oauth_decision(State(st): State<S>, h: HeaderMap, PeerAddr(addr): PeerAddr, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> Response {
    if let Err(e)=st.epoch_ok().await { return e.into_response(); }
    let (client_id, redirect, scope) = match authorize_params_ok(&st, &form, &issuer(&st, &h)).await { Ok(x) => x, Err(e) => return (StatusCode::BAD_REQUEST, e).into_response() };
    let form_token = form.get("mfa_token").cloned().unwrap_or_default();
    let uid = if !form_token.is_empty() {
        let uid = match mfa::challenge_user(&st, &form_token).await { Some(u) => u, None => return (StatusCode::UNAUTHORIZED, "this two-factor challenge expired; sign in again").into_response() };
        let key = format!("otp:{}:{}", addr, uid);
        if !st.rate_ok(&key, 5, 900).await { return (StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later").into_response(); }
        match mfa::second_factor_ok(&st, &uid, form.get("otp").map(|s| s.as_str()).unwrap_or("")).await {
            Ok(true) => {},
            Ok(false) => { st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, html_csp(consent_mfa_page(&form, &form_token))).into_response(); },
            Err(e) => return mfa_failure(e).into_response(),
        }
        st.rate_clear(&key).await;
        if !mfa::consume_challenge(&st, &form_token).await { return (StatusCode::UNAUTHORIZED, "this two-factor challenge expired; sign in again").into_response(); }
        uid }
    else if let Some(u) = oauth_user(&st, &h).await {
        // A session already passed the sign-in checks, but consent is a
        // privileged action; require the second factor again.
        if mfa::required(&st, &u).await {
            let token = match mfa::new_challenge(&st, &u).await { Ok(t) => t, Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "could not start two-factor verification").into_response() };
            return (StatusCode::UNAUTHORIZED, html_csp(consent_mfa_page(&form, &token))).into_response(); }
        u }
    else if !form.get("proof").cloned().unwrap_or_default().is_empty() {
        let email = form.get("email").cloned().unwrap_or_default().trim().to_lowercase();
        let cid = form.get("challenge_id").cloned().unwrap_or_default();
        let proof = form.get("proof").cloned().unwrap_or_default();
        let key = format!("oauth:{}:{}", addr, email);
        if !st.rate_ok(&key, 5, 900).await { return (StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later").into_response(); }
        let row = match st.db.one("SELECT c.user_id AS user_id,c.challenge AS challenge,c.created_at AS created_at,u.email AS email,u.auth_version AS auth_version,u.active AS active,u.email_verified AS email_verified,u.auth_key_enc AS auth_key_enc,u.kdf_salt AS kdf_salt,u.kdf_iterations AS kdf_iterations,u.kdf_algo AS kdf_algo FROM auth_challenges c JOIN users u ON u.id=c.user_id WHERE c.id_hash=?", &[json!(oc::hash_token(&cid))]).await {
            Ok(Some(r)) => r, _ => { st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); } };
        if db::n(&row, "created_at") + 120 < now() || db::s(&row, "email") != email || db::n(&row, "auth_version") != 2
            || !valid_kdf(&db::s(&row,"kdf_salt"), db::n(&row,"kdf_iterations"), &db::s(&row,"kdf_algo")) {
            st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); }
        let uid = db::s(&row, "user_id");
        let auth_key = match oc::decrypt_symmetric_aad(&st.master(), &auth_key_aad(&uid), &db::s(&row, "auth_key_enc")) {
            Ok(k) => k,
            Err(_) => {
                if st.epoch_ok().await.is_err() { return webhooks::epoch_stale().into_response(); }
                return (StatusCode::SERVICE_UNAVAILABLE, "authentication key is unavailable").into_response();
            } };
        if !verify_proof(&auth_key, &db::s(&row, "challenge"), &cid, &proof) {
            st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); }
        let consumed = st.db.exec("DELETE FROM auth_challenges WHERE id_hash=?", &[json!(oc::hash_token(&cid))]).await.unwrap_or(0);
        if consumed == 0 { st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); }
        st.rate_clear(&key).await;
        if db::n(&row, "active") == 0 { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
        if db::n(&row, "email_verified") == 0 { return (StatusCode::FORBIDDEN, "verify your email address before signing in").into_response(); }
        if mfa::required(&st, &uid).await {
            let token = match mfa::new_challenge(&st, &uid).await { Ok(t) => t, Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "could not start two-factor verification").into_response() };
            return (StatusCode::UNAUTHORIZED, html_csp(consent_mfa_page(&form, &token))).into_response(); }
        uid }
    else {
        if !auth_enabled(&st, "password").await { return (StatusCode::FORBIDDEN, "password sign-in is disabled on this instance").into_response(); }
        let email = form.get("email").cloned().unwrap_or_default(); let password = form.get("password").cloned().unwrap_or_default();
        let key = format!("oauth:{}:{}", addr, email.to_lowercase());
        if !st.rate_ok(&key, 5, 900).await { return (StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later").into_response(); }
        let row = match st.db.one("SELECT id,pass_hash,active,email_verified FROM users WHERE email=?", &[json!(email.to_lowercase())]).await { Ok(Some(r)) => r, _ => { st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); } };
        if db::n(&row, "active") == 0 { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
        if db::n(&row, "email_verified") == 0 { return (StatusCode::FORBIDDEN, "verify your email address before authorizing an application").into_response(); }
        if !oc::verify_password(&password, &db::s(&row, "pass_hash")) { st.rate_fail(&key, 900).await; return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); }
        st.rate_clear(&key).await;
        let uid = db::s(&row, "id");
        mfa::note_password_login(&st, &uid).await;
        if mfa::required(&st, &uid).await {
            let otp = form.get("otp").cloned().unwrap_or_default();
            if !otp.is_empty() {
                let otp_key = format!("otp:{}:{}", addr, uid);
                if !st.rate_ok(&otp_key, 5, 900).await { return (StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later").into_response(); }
                match mfa::second_factor_ok(&st, &uid, &otp).await {
                    Ok(true) => {},
                    Ok(false) => { st.rate_fail(&otp_key, 900).await;
                        let token = match mfa::new_challenge(&st, &uid).await { Ok(t) => t, Err(e) => return e.into_response() };
                        return (StatusCode::UNAUTHORIZED, html_csp(consent_mfa_page(&form, &token))).into_response(); },
                    Err(e) => return mfa_failure(e).into_response(),
                }
                st.rate_clear(&otp_key).await;
            } else {
                let token = match mfa::new_challenge(&st, &uid).await { Ok(t) => t, Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "could not start two-factor verification").into_response() };
                return (StatusCode::UNAUTHORIZED, html_csp(consent_mfa_page(&form, &token))).into_response(); }
        }
        uid };
    let account = match st.db.one("SELECT active,email_verified FROM users WHERE id=?", &[json!(&uid)]).await { Ok(Some(row)) => row, _ => return (StatusCode::UNAUTHORIZED, "invalid account").into_response() };
    if db::n(&account,"active") == 0 { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
    if db::n(&account,"email_verified") == 0 { return (StatusCode::FORBIDDEN, "verify your email address before authorizing an application").into_response(); }
    let state = form.get("state").cloned().unwrap_or_default();
    if form.get("approve").map(|s| s.as_str()) != Some("1") { return axum::response::Redirect::to(&format!("{}?error=access_denied&state={}", redirect, urlencode(&state))).into_response(); }
    let code = oc::random_token("code"); let resource = form.get("resource").cloned().filter(|r| !r.trim().is_empty()).unwrap_or_else(|| issuer(&st, &h));
    if st.db.exec("INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(oc::hash_token(&code)), json!(client_id), json!(uid), json!(redirect), json!(form.get("code_challenge").cloned().unwrap_or_default()), json!(scope), json!(resource), json!(now()+300)]).await.is_err() { return (StatusCode::INTERNAL_SERVER_ERROR, "could not create code").into_response(); }
    axum::response::Redirect::to(&format!("{}?code={}&state={}", redirect, code, urlencode(&state))).into_response() }
async fn issue_oauth_tokens(st: &S, client_id: &str, uid: &str, scope: &str, resource: &str, pair: &str) -> Value {
    let access = oc::random_token("oat"); let refresh = oc::random_token("ort"); let pair = if pair.is_empty() { id() } else { pair.to_string() };
    let _ = st.db.exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,kind,pair_id,expires_at,created_at) VALUES(?,?,?,?,?,'access',?,?,?)", &[json!(oc::hash_token(&access)), json!(client_id), json!(uid), json!(scope), json!(resource), json!(pair), json!(now()+3600), json!(now())]).await;
    let _ = st.db.exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,kind,pair_id,expires_at,created_at) VALUES(?,?,?,?,?,'refresh',?,?,?)", &[json!(oc::hash_token(&refresh)), json!(client_id), json!(uid), json!(scope), json!(resource), json!(pair), json!(now()+30*86400), json!(now())]).await;
    json!({"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh, "scope": scope}) }
async fn oauth_token(State(st): State<S>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> (StatusCode, Json<Value>) {
    let grant = form.get("grant_type").map(|s| s.as_str()).unwrap_or("");
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    let client = match st.db.one("SELECT client_secret_hash FROM oauth_clients WHERE client_id=?", &[json!(client_id)]).await { Ok(Some(r)) => r, _ => return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid_client"}))) };
    let stored_secret = db::s(&client, "client_secret_hash");
    if !stored_secret.is_empty() { let provided = form.get("client_secret").cloned().unwrap_or_default(); if oc::hash_token(&provided) != stored_secret { return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid_client"}))); } }
    if grant == "authorization_code" {
        let code = form.get("code").cloned().unwrap_or_default();
        let row = match st.db.one("SELECT * FROM oauth_codes WHERE code_hash=? AND expires_at>?", &[json!(oc::hash_token(&code)), json!(now())]).await { Ok(Some(r)) => r, _ => return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))) };
        if db::s(&row, "client_id") != client_id || db::s(&row, "redirect_uri") != form.get("redirect_uri").cloned().unwrap_or_default() { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        if verifier.is_empty() { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
        use sha2::{Digest, Sha256}; let computed = b64url(&Sha256::digest(verifier.as_bytes()));
        if computed != db::s(&row, "code_challenge") { return (StatusCode::BAD_REQUEST, Json(json!({"error":"PKCE verification failed"}))); }
        if let Ok(Some(u)) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(db::s(&row, "user_id"))]).await { if db::n(&u, "active") == 0 { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); } }
        let _ = st.db.exec("DELETE FROM oauth_codes WHERE code_hash=?", &[json!(oc::hash_token(&code))]).await;
        (StatusCode::OK, Json(issue_oauth_tokens(&st, &client_id, &db::s(&row,"user_id"), &db::s(&row,"scope"), &db::s(&row,"resource"), "").await))
    } else if grant == "refresh_token" {
        let rt = form.get("refresh_token").cloned().unwrap_or_default();
        let row = match st.db.one("SELECT * FROM oauth_tokens WHERE token_hash=? AND kind='refresh' AND expires_at>?", &[json!(oc::hash_token(&rt)), json!(now())]).await { Ok(Some(r)) => r, _ => return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))) };
        if db::s(&row, "client_id") != client_id { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
        if let Ok(Some(u)) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(db::s(&row, "user_id"))]).await { if db::n(&u, "active") == 0 { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); } }
        let _ = st.db.exec("DELETE FROM oauth_tokens WHERE pair_id=?", &[json!(db::s(&row,"pair_id"))]).await;
        (StatusCode::OK, Json(issue_oauth_tokens(&st, &client_id, &db::s(&row,"user_id"), &db::s(&row,"scope"), &db::s(&row,"resource"), &db::s(&row,"pair_id")).await))
    } else { (StatusCode::BAD_REQUEST, Json(json!({"error":"unsupported_grant_type"}))) } }
async fn oauth_revoke(State(st): State<S>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> StatusCode {
    let tok = form.get("token").cloned().unwrap_or_default(); let _ = st.db.exec("DELETE FROM oauth_tokens WHERE token_hash=?", &[json!(oc::hash_token(&tok))]).await; StatusCode::OK }


// ---------- MCP server (Streamable HTTP, OAuth protected) ----------
fn mcp_tools() -> Value { json!([
 {"name":"api_routes","description":"Discover API routes and methods","inputSchema":{"type":"object","additionalProperties":false}},
 {"name":"api_request","description":"Call a same-origin API route with the original credential and policy checks","inputSchema":{"type":"object","properties":{"method":{"type":"string"},"path":{"type":"string"},"body":{},"step_up":{"type":"string"}},"required":["method","path"],"additionalProperties":false}},
 {"name":"list_envs","description":"List environments the caller can access","inputSchema":{"type":"object","properties":{"app_id":{"type":"string"}}}},
 {"name":"list_secrets","description":"List secrets (names and values) in an environment","inputSchema":{"type":"object","properties":{"env_id":{"type":"string"}},"required":["env_id"]}},
 {"name":"get_secret","description":"Get one secret value by key","inputSchema":{"type":"object","properties":{"env_id":{"type":"string"},"key":{"type":"string"}},"required":["env_id","key"]}},
 {"name":"search_secrets","description":"Search secret keys across accessible apps","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}},
 {"name":"set_secret","description":"Create or update a secret (requires secrets:write scope)","inputSchema":{"type":"object","properties":{"env_id":{"type":"string"},"key":{"type":"string"},"value":{"type":"string"},"path":{"type":"string"}},"required":["env_id","key","value"]}},
 {"name":"delete_secret","description":"Delete a secret by key (requires secrets:write scope)","inputSchema":{"type":"object","properties":{"env_id":{"type":"string"},"key":{"type":"string"}},"required":["env_id","key"]}},
 {"name":"create_lease","description":"Create a short-lived dynamic secret lease (requires secrets:write scope)","inputSchema":{"type":"object","properties":{"env_id":{"type":"string"},"name":{"type":"string"}},"required":["env_id"]}},
 {"name":"sync_integration","description":"Trigger a configured sync integration (requires secrets:write scope)","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string"}},"required":["integration_id"]}}
]) }
fn rpc_result(id: &Value, result: Value) -> Value { json!({"jsonrpc":"2.0","id":id,"result":result}) }
fn rpc_error(id: &Value, code: i64, msg: &str) -> Value { json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}}) }
#[allow(clippy::result_large_err)]
async fn mcp_auth(st: &S, h: &HeaderMap) -> Result<(String, String), (StatusCode, HeaderMap, Json<Value>)> {
    let iss = issuer(st, h);
    let mut hdr = HeaderMap::new(); hdr.insert("www-authenticate", format!("Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"", iss).parse().unwrap());
    if let Some(origin) = h.get("origin").and_then(|v| v.to_str().ok()) {
        if !origin_matches(st, h, origin) { return Err((StatusCode::FORBIDDEN, hdr, Json(json!({"error":"Origin does not match Host"})))); } }
    if let Some((uid, scope, audience)) = oauth_access(st, h).await {
        if audience != format!("{}/mcp", iss) { return Err((StatusCode::UNAUTHORIZED, hdr, Json(json!({"error":"token audience does not match this MCP endpoint"})))); }
        return Ok((uid, scope)); }
    if let Ok(uid) = st.token_user(h).await {
        match st.db.one("SELECT scopes FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(h)))]).await {
            Ok(Some(r)) if !db::s(&r,"scopes").is_empty() => return Ok((uid,db::s(&r,"scopes"))),
            Ok(_) => return Ok((uid,"secrets:read secrets:write".into())),
            Err(_) => return Err((StatusCode::FORBIDDEN,hdr,Json(json!({"error":"credential scopes unavailable"})))),
        }
    }
    Err((StatusCode::UNAUTHORIZED, hdr, Json(json!({"error":"unauthorized; OAuth access token required, see /.well-known/oauth-protected-resource"})))) }
async fn mcp_post(State(st): State<S>, peer: PeerAddr, h: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    let (uid, scope) = match mcp_auth(&st, &h).await { Ok(x) => x, Err(e) => return e.into_response() };
    let id = body.get("id").cloned().unwrap_or(Value::Null); let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(json!({}));
    if id.is_null() { return StatusCode::ACCEPTED.into_response(); }
    let write_tool = ["set_secret","delete_secret","create_lease","sync_integration"].contains(&method) || (method == "tools/call" && ["set_secret","delete_secret","create_lease","sync_integration"].contains(&params.get("name").and_then(|v| v.as_str()).unwrap_or("")));
    if write_tool && !scope.split_whitespace().any(|s| s == "secrets:write" || s == "*") { return Json(rpc_error(&id, -32001, "insufficient scope: secrets:write required")).into_response(); }
    let read_tool = method == "tools/call" && ["list_envs", "list_secrets", "get_secret", "search_secrets", "delete_secret"].contains(&params.get("name").and_then(|v| v.as_str()).unwrap_or(""));
    if (matches!(method, "resources/list" | "resources/read") || read_tool) && !scope_has(&scope, "secrets:read") {
        return Json(rpc_error(&id, -32001, "insufficient scope: secrets:read required")).into_response(); }
    let result: Result<Value, String> = match method {
        "initialize" => Ok(json!({"protocolVersion": params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("2025-06-18"), "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "openwarp", "version": env!("CARGO_PKG_VERSION")}})),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": mcp_tools()})),
        "prompts/list" => Ok(json!({"prompts": []})),
        "resources/list" => mcp_resources(&st, &uid, &h).await,
        "resources/read" => mcp_resource_read(&st, &uid, &h, &params).await,
        "tools/call" if params["name"] == "api_request" => api_request(&st, &h, peer, &params["arguments"]).await,
        "tools/call" if params["name"] == "api_routes" => Ok(management_result(route_catalog(), false)),
        "tools/call" => mcp_call(&st, &uid, &h, &params).await,
        _ => Err(format!("method not found: {}", method)),
    };
    match result { Ok(r) => Json(rpc_result(&id, r)).into_response(), Err(e) => Json(rpc_error(&id, -32000, &e)).into_response() } }
async fn mcp_get() -> impl IntoResponse { (StatusCode::METHOD_NOT_ALLOWED, Json(json!({"error":"stateless MCP server: POST JSON-RPC to /mcp"}))) }
// The socket stays on the replica that accepted it. That replica's single poll
// reads the shared table and fans matching events out, so a write on any
// replica shows up here within a second. Frames carry audit fields only.
#[derive(Clone, serde::Serialize, Deserialize)]
pub(crate) struct LiveAdmission {
    pub uid: String,
    pub credential_hash: String,
    /// The credential arrived in the session cookie, so the per-event identity
    /// check must keep requiring an account session.
    pub via_cookie: bool,
    pub cursor: i64,
    pub peer: String,
}
impl AppState {
    pub(crate) async fn live_identity(&self, admission: &LiveAdmission) -> Result<String, (StatusCode, Json<Value>)> {
        let uid = self.token_user_by_hash(&admission.credential_hash, admission.via_cookie).await?;
        if uid != admission.uid { return Err(err(StatusCode::UNAUTHORIZED, "live credential changed")); }
        if let Some(row) = self.db.one("SELECT scope FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(admission.credential_hash), json!(now())]).await.map_err(|e| bad(&e))? {
            if !db::s(&row, "scope").split_whitespace().any(|s| s == "*" || s == "secrets:read") { return Err(err(StatusCode::FORBIDDEN, "OAuth token lacks secrets:read")); }
        } else if let Some(row) = self.db.one("SELECT scopes FROM tokens WHERE token_hash=?", &[json!(admission.credential_hash)]).await.map_err(|e| bad(&e))? {
            let scopes = db::s(&row, "scopes");
            if !scopes.is_empty() && !scopes.split_whitespace().any(|s| s == "*" || s == "secrets:read") { return Err(err(StatusCode::FORBIDDEN, "token lacks secrets:read")); }
        }
        Ok(uid)
    }
    pub(crate) async fn live_authorize(&self, admission: &LiveAdmission, event: &Value) -> bool {
        let Ok(uid) = self.live_identity(admission).await else { return false };
        let org = event.get("org").and_then(Value::as_str).unwrap_or("");
        if self.require_org(org, &uid).await.is_err() || self.check_perm(org, &uid, "secrets:read").await.is_err() { return false; }
        let Ok(Some(row)) = self.db.one("SELECT ip_allowlist FROM orgs WHERE id=?", &[json!(org)]).await else { return false };
        let list = db::s(&row, "ip_allowlist");
        if !list.trim().is_empty() && !list.split(',').any(|c| ip_in_cidr(&admission.peer, c)) { return false; }
        let env = event.get("env").and_then(Value::as_str).unwrap_or("");
        if self.check_scope_by_hash(&admission.credential_hash, env).await.is_err() { return false; }
        env.is_empty() || self.require_env(env, &uid).await.is_ok()
    }
    pub(crate) async fn live_replay(&self, cursor: i64) -> Result<Vec<Value>, String> {
        let rows = self.db.query("SELECT id,org_id,app_id,env_id,action,detail,created_at FROM live_events WHERE id>? AND created_at>=? ORDER BY id LIMIT 500", &[json!(cursor), json!(now() - 3600)]).await?;
        Ok(rows.iter().map(|r| json!({"type":"event","id":db::n(r,"id"),"org":db::s(r,"org_id"),"app":db::s(r,"app_id"),"env":db::s(r,"env_id"),"action":db::s(r,"action"),"detail":db::s(r,"detail"),"ts":db::n(r,"created_at")})).collect())
    }
}
async fn live_admission(st: &S, h: &HeaderMap, q: &HashMap<String,String>, peer: PeerAddr) -> Result<LiveAdmission, (StatusCode, Json<Value>)> {
    let uid = st.token_user(h).await?;
    st.check_scope(h, "").await?;
    let bearer = bearer_token(h);
    let via_cookie = bearer.is_empty();
    let token = if via_cookie { cookie_val(h, "ow_session") } else { bearer };
    let cursor = match q.get("since").and_then(|s| s.parse::<i64>().ok()).filter(|n| *n > 0) {
        Some(since) => since,
        None => st.db.one("SELECT COALESCE(MAX(id),0) AS cursor FROM live_events", &[]).await.map_err(|e| bad(&e))?.map(|r| db::n(&r,"cursor")).unwrap_or(0),
    };
    let trust_proxy = !cfg!(target_arch = "wasm32") && crate::envcfg::var("OPENWARP_TRUST_PROXY").map(|v| v == "1").unwrap_or(false);
    let proxy_ok = crate::envcfg::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1/32,::1".into())
        .split(',').any(|cidr| ip_in_cidr(&peer.0.to_string(), cidr));
    let client_ip = if trust_proxy && proxy_ok {
        h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(|v| v.split(',').next().unwrap_or("").trim().to_string()).unwrap_or_else(|| peer.0.to_string())
    } else { peer.0.to_string() };
    let admission = LiveAdmission { uid, credential_hash: oc::hash_token(&token), via_cookie, cursor, peer: client_ip };
    st.live_identity(&admission).await?;
    Ok(admission)
}
#[cfg(target_arch = "wasm32")]
async fn live_ws(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, peer: PeerAddr) -> Response {
    if !h.get("upgrade").and_then(|v| v.to_str().ok()).map(|v| v.eq_ignore_ascii_case("websocket")).unwrap_or(false) { return err(StatusCode::BAD_REQUEST, "WebSocket upgrade required").into_response(); }
    match live_admission(&st, &h, &q, peer).await {
        Ok(admission) => { let mut response = StatusCode::OK.into_response(); response.extensions_mut().insert(admission); response }
        Err(e) => e.into_response(),
    }
}
#[cfg(not(target_arch = "wasm32"))]
async fn live_ws(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, peer: PeerAddr, ws: WebSocketUpgrade) -> Response {
    // Subscribe before the database snapshot so replay and the stream overlap.
    let rx = st.live.subscribe();
    let admission = match live_admission(&st, &h, &q, peer).await { Ok(a) => a, Err(e) => return e.into_response() };
    ws.on_upgrade(move |socket| live_socket(st, admission, rx, socket)) }
#[cfg(not(target_arch = "wasm32"))]
async fn live_socket(st: S, admission: LiveAdmission, mut rx: broadcast::Receiver<Arc<str>>, mut socket: WebSocket) {
    if socket.send(Message::Text(json!({"type":"hello","instance": st.instance_id}).to_string().into())).await.is_err() { return; }
    let mut auth_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut sent = admission.cursor;
    loop {
        let Ok(missed) = st.live_replay(sent).await else { return };
        let full = missed.len() == 500;
        for ev in missed {
            sent = ev["id"].as_i64().unwrap_or(sent);
            if !st.live_authorize(&admission, &ev).await { continue; }
            if socket.send(Message::Text(ev.to_string().into())).await.is_err() { return; }
        }
        if !full { break; }
    }
    loop {
        tokio::select! {
            _ = auth_tick.tick() => { if st.live_identity(&admission).await.is_err() { let _ = socket.send(Message::Close(None)).await; break; } }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(p))) => { if socket.send(Message::Pong(p)).await.is_err() { break; } }
                    _ => {}
                }
            }
            // Cloudflare's edge closes a WebSocket after about 100 seconds with no
            // frames. A ping is a frame, so a quiet console survives the proxy.
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if socket.send(Message::Ping(Bytes::new())).await.is_err() { break; }
            }
            ev = rx.recv() => {
                let raw = match ev { Ok(v) => v, Err(_) => break };
                let Ok(v) = serde_json::from_str::<Value>(&raw) else { continue };
                if v.get("id").and_then(|x| x.as_i64()).unwrap_or(0) <= sent { continue; }
                if st.live_identity(&admission).await.is_err() { break; }
                sent = v.get("id").and_then(Value::as_i64).unwrap_or(sent);
                if !st.live_authorize(&admission, &v).await { continue; }
                let mut out = v; out["type"] = json!("event");
                if socket.send(Message::Text(out.to_string().into())).await.is_err() { return; }
            }
        }
    }
}
fn origin_matches(st: &S, h: &HeaderMap, origin: &str) -> bool {
    let origin = origin.trim_end_matches('/');
    let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    if host.is_empty() { return false; }
    if origin == format!("http://{}", host) || origin == format!("https://{}", host) { return true; }
    let pub_url = st.pub_url.trim_end_matches('/');
    !pub_url.is_empty() && origin == pub_url }
async fn env_scope_of(st: &S, h: &HeaderMap) -> Result<String,(StatusCode,Json<Value>)> { st.db.one("SELECT env_id FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(h)))]).await.map(|r| r.map(|r| db::s(&r, "env_id")).unwrap_or_default()).map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE,"credential scope unavailable")) }
async fn mcp_resources(st: &S, uid: &str, h: &HeaderMap) -> Result<Value, String> {
    let scoped = env_scope_of(st, h).await.map_err(|_| "credential scope unavailable".to_string())?;
    let rows = st.db.query("SELECT e.id AS id, e.name AS name, a.name AS app, a.org_id AS org FROM envs e JOIN apps a ON a.id=e.app_id JOIN org_members m ON m.org_id=a.org_id WHERE m.user_id=?", &[json!(uid)]).await?;
    let mut resources = Vec::new();
    for r in &rows {
        let eid = db::s(r, "id");
        if !scoped.is_empty() && eid != scoped { continue; }
        if st.require_env(&eid, uid).await.is_err() { continue; }
        if st.check_perm(&db::s(r,"org"), uid, "secrets:read").await.is_err() { continue; }
        resources.push(json!({"uri": format!("openwarp://env/{}", eid), "name": format!("{} / {}", db::s(r,"app"), db::s(r,"name")), "mimeType": "application/json"}));
    }
    Ok(json!({"resources": resources})) }
async fn mcp_resource_read(st: &S, uid: &str, h: &HeaderMap, params: &Value) -> Result<Value, String> {
    let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or(""); let eid = uri.strip_prefix("openwarp://env/").ok_or("bad resource uri")?;
    st.check_scope(h, eid).await.map_err(|_| "forbidden".to_string())?;
    let (org, _) = st.require_env(eid, uid).await.map_err(|_| "forbidden".to_string())?;
    st.check_perm(&org, uid, "secrets:read").await.map_err(|_| "forbidden".to_string())?;
    let items = st.list_secrets_decrypted(eid, uid).await.map_err(|_| "read failed".to_string())?;
    let text = serde_json::to_string(&items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()).unwrap();
    Ok(json!({"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]})) }
async fn mcp_env_audit(st: &S, uid: &str, eid: &str, action: &str, detail: &str) {
    if let Ok((org, app)) = st.env_org_app(eid).await { st.audit(&org, &app, eid, uid, action, detail).await; }
}
async fn mcp_env_check(st: &S, uid: &str, h: &HeaderMap, eid: &str) -> Result<(), String> {
    st.check_scope(h, eid).await.map_err(|_| "forbidden".to_string())?;
    st.require_env(eid, uid).await.map_err(|_| "forbidden".to_string())?;
    Ok(())
}
async fn mcp_env_read(st: &S, uid: &str, h: &HeaderMap, eid: &str) -> Result<(), String> {
    mcp_env_check(st, uid, h, eid).await?;
    let (org, _) = st.env_org_app(eid).await.map_err(|_| "forbidden".to_string())?;
    st.check_perm(&org, uid, "secrets:read").await.map_err(|_| "forbidden".to_string())
}
async fn mcp_call(st: &S, uid: &str, h: &HeaderMap, params: &Value) -> Result<Value, String> {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or(""); let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let arg = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let text = |v: Value| json!({"content": [{"type":"text","text": v.to_string()}], "isError": false});
    if st.restricted_principal(uid).await.map_err(|_| "path policy unavailable".to_string())? && !matches!(name,"list_envs"|"list_secrets"|"get_secret"|"search_secrets"|"set_secret"|"delete_secret") { return Err("path policy denies this tool".into()); }
    match name {
        "list_envs" => { let r = mcp_resources(st, uid, h).await?; Ok(text(r)) }
        "list_secrets" => { let eid = arg("env_id"); mcp_env_read(st, uid, h, &eid).await?; let items = st.list_secrets_decrypted(&eid, uid).await.map_err(|_| "read failed".to_string())?; mcp_env_audit(st, uid, &eid, "mcp.list_secrets", &format!("{}", items.len())).await; Ok(text(json!(items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()))) }
        "get_secret" => { let eid = arg("env_id"); let key = arg("key"); mcp_env_read(st, uid, h, &eid).await?; let items = st.list_secrets_decrypted(&eid, uid).await.map_err(|_| "read failed".to_string())?;
            let found = items.iter().find(|(k, _, _)| k == &key.to_uppercase()).map(|(_, v, _)| v.clone()).ok_or("secret not found")?; mcp_env_audit(st, uid, &eid, "mcp.get_secret", &key).await; Ok(text(json!(found))) }
        "search_secrets" => { let q = arg("query").to_uppercase(); let res = mcp_resources(st, uid, h).await?; let mut hits = Vec::new();
            for r in res["resources"].as_array().cloned().unwrap_or_default() { let eid = r["uri"].as_str().unwrap_or("").replace("openwarp://env/", "");
                if mcp_env_read(st, uid, h, &eid).await.is_err() { continue; }
                if let Ok(items) = st.list_secrets_decrypted(&eid, uid).await { for (k, _, _) in items { if q.is_empty() || k.contains(&q) { hits.push(json!({"env_id": eid, "key": k})); } } } }
            Ok(text(json!(hits))) }
        "set_secret" => { let eid = arg("env_id"); mcp_env_check(st, uid, h, &eid).await?; let (org, app) = st.env_org_app(&eid).await.map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:write").await.map_err(|_| "forbidden".to_string())?;
            let key = st.env_key(&eid).await.map_err(|_| "env key failed".to_string())?; let master = st.master(); let s = SecretIn{ key: arg("key"), value: arg("value"), path: { let p = arg("path"); if p.is_empty() { "/".into() } else { p } }, comment: "via MCP".into(), tags: "".into(), secret_type: "secret".into(), expected_version: None };
            let mut statements = vec![("UPDATE envs SET id=id WHERE id=?".into(), vec![json!(&eid)])];
            statements.extend(secret_statements(st, &eid, &org, &key, uid, &s, &master).await.map_err(|_| "write failed".to_string())?);
            st.audited_batch_master(&statements, &[0,1], [&org, &app, &eid, uid, "mcp.set_secret", &s.key], master).await.map_err(|e| if e==webhooks::EPOCH_STALE {"epoch_stale".to_string()} else {"write failed".to_string()})?; Ok(text(json!({"ok": true}))) }
        "delete_secret" => { let eid = arg("env_id"); mcp_env_check(st, uid, h, &eid).await?; let (org, app) = st.env_org_app(&eid).await.map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:delete").await.map_err(|_| "forbidden".to_string())?;
            let items = st.list_secrets_decrypted(&eid, uid).await.map_err(|_| "read failed".to_string())?; let sid = items.iter().find(|(k, _, _)| k == &arg("key").to_uppercase()).map(|(_, _, raw)| raw["id"].as_str().unwrap_or("").to_string()).ok_or("secret not found")?;
            st.check_secret_path(&sid,uid,"delete").await.map_err(|_| "path policy denies delete".to_string())?;
            rotation_secret_batch(st,&eid,&sid,&[("UPDATE secrets SET deleted=1,updated_at=? WHERE id=?".into(), vec![json!(now()), json!(sid)])], [&org, &app, &eid, uid, "mcp.delete_secret", &arg("key")],None).await.map_err(|e| e.1.0.to_string())?; Ok(text(json!({"ok": true}))) }
        "create_lease" => { let eid = arg("env_id"); mcp_env_check(st, uid, h, &eid).await?; let (org, app) = st.env_org_app(&eid).await.map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "leases:write").await.map_err(|_| "forbidden".to_string())?; let key = st.env_key(&eid).await.map_err(|_| "env key failed".to_string())?;
            let value = oc::random_token("dyn"); let lid = id();
            st.audited_batch(&[("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)".into(), vec![json!(lid), json!(eid), json!(arg("name")), json!(oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), value.as_bytes())), json!(now()+3600), json!(now())])], &[], [&org, &app, &eid, uid, "mcp.create_lease", &lid]).await.map_err(|e| e.to_string())?;
            Ok(text(json!({"id": lid, "value": value, "expires_at": now()+3600}))) }
        "sync_integration" => { let iid = arg("integration_id"); let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).await.map_err(|_| "lookup failed".to_string())?.ok_or("integration not found")?; let eid = db::s(&row, "env_id"); mcp_env_check(st, uid, h, &eid).await?; let (org, _) = st.env_org_app(&eid).await.map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "integrations:write").await.map_err(|_| "forbidden".to_string())?;
            let msg = sync_one(st, &iid, uid).await.map_err(|_| "sync failed".to_string())?; Ok(text(json!(msg))) }
        _ => Err(format!("unknown tool: {}", name)),
    } }

async fn health(State(st): State<S>) -> impl IntoResponse {
    match st.db.one("SELECT 1 AS n", &[]).await {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true, "service": "openwarp"}))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "service": "openwarp", "error": e}))),
    } }
// One-time share page: the decryption key rides in the fragment and is sent only
// to the API as a header, never in a request line or a server log.
const LOCKBOX_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
async fn lockbox_page() -> Response {
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenWarp lockbox</title><script>(function(){try{var p;try{p=localStorage.getItem('ow_theme')}catch(e){}if(p!=='light'&&p!=='dark'&&p!=='system')p='system';var de=document.documentElement;if(!de)return;de.dataset.themePref=p;var mq=window.matchMedia?window.matchMedia('(prefers-color-scheme: dark)'):null;var ap=function(){de.dataset.theme=p==='system'?((mq&&mq.matches)?'dark':'light'):p};ap();if(mq&&mq.addEventListener)mq.addEventListener('change',ap)}catch(e){}})();
</script><style>:root{color-scheme:light;--bg:#f4f5f9;--panel:#ffffff;--line:#dcdee9;--text:#1d1c2e;--muted:#5f5d78}
:root[data-theme=dark]{color-scheme:dark;--bg:#08080c;--panel:#12121b;--line:#23233a;--text:#eceaf8;--muted:#9a97b3}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;min-height:100vh}
main{width:620px;max-width:92vw;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:24px}pre{white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,Menlo,monospace}</style></head>
<body><main><h2>OpenWarp lockbox</h2><p id="out">Loading…</p></main><script>
(function(){var out=document.getElementById('out');var id=decodeURIComponent(location.pathname.split('/').pop());var key=location.hash.slice(1);
if(!key){out.textContent='This link is missing its decryption key.';return}
fetch('/api/lockbox/'+encodeURIComponent(id),{headers:{'x-lockbox-key':key}}).then(function(r){return r.json()}).then(function(d){
out.innerHTML='';var pre=document.createElement('pre');pre.textContent=d.value!==undefined?d.value:(d.error||'Not found');out.replaceWith(pre)
}).catch(function(e){out.textContent='Error: '+e})})();
</script></body></html>"#;
    let mut r = Html(body).into_response();
    r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(LOCKBOX_CSP));
    r }
async fn index() -> Response {
    let mut r = Html(ui::INDEX).into_response();
    r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.pwnedpasswords.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    r }
#[cfg(not(target_arch = "wasm32"))]
async fn peer_middleware(mut req: axum::extract::Request, next: Next) -> Response {
    let peer = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip());
    if let Some(ip) = peer { req.extensions_mut().insert(PeerAddr(ip)); }
    next.run(req).await }
#[cfg(target_arch = "wasm32")]
async fn peer_middleware(req: axum::extract::Request, next: Next) -> Response { next.run(req).await }
async fn key_lifecycle_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    #[cfg(not(target_arch="wasm32"))] {
        let path=match canonical_policy_path(req.uri().path()) {Ok(v)=>v,Err(_)=>return bad("invalid path encoding").into_response()};
        let mutation=!matches!(*req.method(),axum::http::Method::GET|axum::http::Method::HEAD|axum::http::Method::OPTIONS);
        if path.starts_with("/api/") && mutation {
            if path=="/api/instance/rotate-master" {
                let uid=match st.token_user(req.headers()).await {Ok(v)=>v,Err(e)=>return e.into_response()};
                if instance_owner(&st).await.as_deref()!=Some(uid.as_str()) {return err(StatusCode::FORBIDDEN,"only the instance owner can rotate the master key").into_response();}
                return next.run(req).await;
            }
            let _permit=st.key_lifecycle.read().await;
            return next.run(req).await;
        }
    }
    #[cfg(target_arch="wasm32")] let _=st;
    next.run(req).await
}
// Rotation takes the write gate only after body extraction and owner authentication.
async fn key_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    if req.method() == axum::http::Method::POST && req.extensions().get::<axum::extract::MatchedPath>().map(|p| p.as_str()) == Some("/api/instance/rotate-master") {
        next.run(req).await
    } else {
        let _key_guard = st.key_gate.read().await;
        next.run(req).await
    }
}
async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("x-content-type-options", axum::http::HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", axum::http::HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", axum::http::HeaderValue::from_static("DENY"));
    res }
// A hung handler must not pin a worker forever; five minutes covers a deploy
// that fans out to several integrations (30s timeout each).
#[cfg(not(target_arch = "wasm32"))]
async fn timeout_middleware(req: axum::extract::Request, next: Next) -> Response {
    match tokio::time::timeout(std::time::Duration::from_secs(300), next.run(req)).await {
        Ok(r) => r,
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, Json(json!({"error": "request timed out"}))).into_response() } }
#[cfg(target_arch = "wasm32")]
async fn timeout_middleware(req: axum::extract::Request, next: Next) -> Response { next.run(req).await }
static HTTP_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static HTTP_ERRORS: AtomicUsize = AtomicUsize::new(0);
async fn metrics_middleware(req: axum::extract::Request, next: Next) -> Response {
    let r = next.run(req).await;
    HTTP_REQUESTS.fetch_add(1, AtomicOrdering::Relaxed);
    if r.status().is_server_error() { HTTP_ERRORS.fetch_add(1, AtomicOrdering::Relaxed); }
    r }
// Disabled unless OPENWARP_METRICS_TOKEN is set; the token is compared by hash.
async fn metric_count(st: &S, sql: &str) -> i64 {
    st.db.one(sql, &[]).await.ok().flatten().map(|r| db::n(&r, "n")).unwrap_or(0)
}
async fn metrics(State(st): State<S>, h: HeaderMap) -> Response {
    let expected = crate::envcfg::var("OPENWARP_METRICS_TOKEN").unwrap_or_default();
    if expected.is_empty() { return StatusCode::NOT_FOUND.into_response(); }
    if oc::hash_token(&bearer_token(&h)) != oc::hash_token(&expected) { return StatusCode::UNAUTHORIZED.into_response(); }
    let body = format!(
        "# TYPE openwarp_http_requests_total counter\nopenwarp_http_requests_total {}\n\
         # TYPE openwarp_http_5xx_total counter\nopenwarp_http_5xx_total {}\n\
         # TYPE openwarp_orgs gauge\nopenwarp_orgs {}\n\
         # TYPE openwarp_users gauge\nopenwarp_users {}\n\
         # TYPE openwarp_apps gauge\nopenwarp_apps {}\n\
         # TYPE openwarp_envs gauge\nopenwarp_envs {}\n\
         # TYPE openwarp_secrets gauge\nopenwarp_secrets {}\n\
         # TYPE openwarp_sessions gauge\nopenwarp_sessions {}\n",
        HTTP_REQUESTS.load(AtomicOrdering::Relaxed), HTTP_ERRORS.load(AtomicOrdering::Relaxed),
        metric_count(&st, "SELECT COUNT(*) AS n FROM orgs").await, metric_count(&st, "SELECT COUNT(*) AS n FROM users").await, metric_count(&st, "SELECT COUNT(*) AS n FROM apps").await,
        metric_count(&st, "SELECT COUNT(*) AS n FROM envs").await, metric_count(&st, "SELECT COUNT(*) AS n FROM secrets WHERE deleted=0").await, metric_count(&st, "SELECT COUNT(*) AS n FROM sessions").await);
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response() }



#[derive(Clone)]
struct McpDispatch;
fn management_result(value: Value, failed: bool) -> Value { json!({"structuredContent":value,"content":[{"type":"text","text":value.to_string()}],"isError":failed}) }
fn route_catalog() -> Value {
    let mut routes = Vec::new();
    for source in [include_str!("app.rs"), include_str!("webhooks.rs")] {
        for segment in source.split(".route(\"").skip(1) {
            let Some((path, handler)) = segment.split_once('\"') else { continue };
            if !path.starts_with("/api/") { continue; }
            if !cfg!(feature="ldap") && (path=="/api/auth/ldap" || path.ends_with("/ldap")) {continue;}
            let handler = handler.split(".route(").next().unwrap_or(handler).split(';').next().unwrap_or(handler);
            for (name, method) in [("get(","GET"),("post(","POST"),("put(","PUT"),("patch(","PATCH"),("delete(","DELETE")] {
                if handler.contains(name) { routes.push(json!({"method":method,"path":path})); }
            }
        }
    }
    routes.sort_by_key(Value::to_string); routes.dedup();
    json!({"routes":routes,"webhooks":{"dispatch":if cfg!(target_arch="wasm32") { "unsupported" } else { "native" }}})
}
async fn api_capabilities(State(st): State<S>, h: HeaderMap) -> Res { st.token_user(&h).await?; Ok(j(route_catalog())) }
async fn api_request(st: &S, h: &HeaderMap, peer: PeerAddr, args: &Value) -> Result<Value, String> {
    use tower::ServiceExt;
    let a = args.as_object().ok_or("arguments must be an object")?;
    if a.keys().any(|k| !["method","path","body","step_up"].contains(&k.as_str())) { return Err("unsupported request argument".into()); }
    let method = args["method"].as_str().ok_or("method required")?;
    if !["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"].contains(&method) { return Err("unsupported method".into()); }
    let path = args["path"].as_str().ok_or("path required")?;
    if !path.starts_with("/api/") || (path.starts_with("/api/auth/") && !["/api/auth/step-up/start","/api/auth/step-up/verify"].contains(&path)) || path.len()>4096 || path.bytes().any(|b| b<=32 || b>=127 || b==b'\\' || b==b'#') { return Err("invalid API path".into()); }
    let route_path = path.split('?').next().unwrap_or(path);
    for component in route_path.split('/') {
        let bytes = component.as_bytes(); let mut decoded = Vec::new(); let mut i=0;
        while i<bytes.len() { if bytes[i]==b'%' { if i+2>=bytes.len() { return Err("invalid escape".into()); } let n=u8::from_str_radix(&component[i+1..i+3],16).map_err(|_| "invalid escape")?; decoded.push(n); i+=3; } else { decoded.push(bytes[i]); i+=1; } }
        if decoded==b"." || decoded==b".." || decoded.iter().any(|b| matches!(b,b'/'|b'\\'|b'%'|0..=31|127)) { return Err("invalid API segment".into()); }
    }
    let payload = args.get("body").map(Value::to_string).unwrap_or_default();
    if payload.len()>8*1024*1024 { return Err("body too large".into()); }
    let mut req = axum::http::Request::builder().method(method).uri(path).body(axum::body::Body::from(payload)).map_err(|e|e.to_string())?;
    *req.headers_mut()=h.clone(); req.headers_mut().remove("content-length"); req.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/json"));
    if let Some(grant)=args.get("step_up") { let grant=grant.as_str().ok_or("step_up must be a string")?; if grant.len()>1024 {return Err("step_up too long".into());} req.headers_mut().insert("x-openwarp-step-up",grant.parse().map_err(|_|"invalid step_up")?); }
    req.extensions_mut().insert(peer); req.extensions_mut().insert(McpDispatch);
    let response = api_router(st.clone()).oneshot(req).await.map_err(|e|e.to_string())?;
    let status=response.status(); let bytes=axum::body::to_bytes(response.into_body(),8*1024*1024).await.map_err(|e|e.to_string())?;
    let body=serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_|json!(String::from_utf8_lossy(&bytes)));
    Ok(management_result(json!({"status":status.as_u16(),"body":body}), !status.is_success()))
}
#[path = "webhooks.rs"]
mod webhooks;

async fn workload_login(State(st): State<S>, _h: HeaderMap, _peer: PeerAddr, Json(body): Json<Value>) -> Res {
    match (body.get("identity_id"), body.get("trust_id")) {
        (Some(_), None) => workloads::login(State(st), Json(body)).await,
        #[cfg(feature = "workload-identity")]
        (None, Some(_)) => workload::login(State(st), _h, _peer, Json(body)).await,
        _ => Err(bad("exactly one of identity_id or trust_id is required")),
    }
}
async fn lifecycle_middleware(State(_st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let rotation=req.method()==axum::http::Method::POST && req.extensions().get::<axum::extract::MatchedPath>().is_some_and(|p| p.as_str()=="/api/instance/rotate-master");
    if rotation { return next.run(req).await; }
    #[cfg(not(target_arch="wasm32"))] let _guard=_st.lifecycle.read().await;
    next.run(req).await
}
pub fn router(state: S) -> Router {
    let mcp = Router::new().route("/mcp", post(mcp_post).get(mcp_get).delete(mcp_get))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .layer(axum::middleware::from_fn(peer_middleware)).with_state(state.clone());
    api_router(state).merge(mcp)
}
fn api_router(state: S) -> Router {
    let app = Router::new()
        .route("/api/capabilities", get(api_capabilities))
        .merge(webhooks::routes())
        .route("/api/rotations/{rid}/run", post(static_rotation::run))
        .route("/api/orgs/{oid}/identities/{iid}/workload", get(workloads::manage).put(workloads::manage).delete(workloads::manage))
        .route("/api/v1/machine/auth/workload/login", post(workload_login).layer(axum::extract::DefaultBodyLimit::max(40*1024)))
        .route("/api/envs/{eid}/path-policy/{role}", get(path_policy::get).put(path_policy::put).delete(path_policy::delete))
        .route("/api/orgs/{oid}/transit-compat/keys", get(transit_compat::list).post(transit_compat::create))
        .route("/api/orgs/{oid}/transit-compat/keys/{kid}/rotate", post(transit_compat::rotate))
        .route("/api/orgs/{oid}/transit-compat/keys/{kid}/encrypt", post(transit_compat::encrypt))
        .route("/api/orgs/{oid}/transit-compat/keys/{kid}/decrypt", post(transit_compat::decrypt))
        .route("/api/orgs/{oid}/transit-compat/keys/{kid}/rewrap", post(transit_compat::rewrap))
        .route("/", get(index)).route("/e2e.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("e2e.js")) }))
        .route("/i18n.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("i18n.js")) }))
        .route("/auth-v2.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("auth-v2.js")) }))
        .route("/api/me/secret-health", get(secret_health_settings).put(secret_health_save))
        .route("/api/me/secret-health/email", post(secret_health_email))
        .route("/api/me/secret-health/enzoic", get(enzoic_settings).put(enzoic_save))
        .route("/api/me/secret-health/enzoic/password", post(enzoic_password))
        .route("/api/me/secret-health/enzoic/accounts", post(enzoic_accounts))
        .route("/api/me/secret-health/enzoic/credentials", post(enzoic_credentials))
        .route("/enzoic-pairs.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("enzoic-pairs.js")) }))
        .route("/hash-wasm.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("vendor/hash-wasm.js")) }))
        .route("/api/me/secret-health/leakcheck", post(leakcheck_email))
        .route("/secret-health.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("secret-health.js")) }))
        .route("/zxcvbn.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("vendor/zxcvbn.js")) }))
        .route("/libsodium.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("vendor/libsodium.js")) }))
        .route("/libsodium-wrappers.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("vendor/libsodium-wrappers.js")) }))
        .route("/metrics", get(metrics)).route("/lockbox/{lid}", get(lockbox_page))
        .route("/api/auth/invite", get(workspaces::metadata)).route("/api/auth/providers", get(auth_providers)).route("/api/auth/accept-invite", post(accept_invite))
        .route("/api/auth/kdf", get(auth_kdf)).route("/api/auth/register-v2", post(register_v2)).route("/api/auth/challenge", post(auth_challenge)).route("/api/auth/login-v2", post(login_v2)).route("/api/auth/reset-v2", post(reset_password_v2)).route("/api/auth/reset-info", post(reset_info)).route("/api/auth/accept-invite-v2", post(accept_invite_v2)).route("/api/me/auth", get(me_auth))
        .route("/api/auth/verify", get(verify_email)).route("/api/auth/forgot", post(forgot_password)).route("/api/auth/reset", post(reset_password)).route("/api/auth/resend-verification", post(resend_verification))
        .route("/api/auth/social/{provider}/start", get(social_start)).route("/api/auth/social/{provider}/callback", get(social_callback).post(social_callback))
        .route("/api/instance", get(instance_info)).route("/api/instance/edition", get(edition_info)).route("/api/instance/features", get(list_feature_grants).put(put_feature_grants)).route("/api/instance/signups", put(set_signups)).route("/api/instance/workspaces", put(workspaces::set_creation)).route("/api/instance/owner", put(set_instance_owner)).route("/api/instance/auth", put(set_auth_providers)).route("/api/instance/email-test", post(test_email)).route("/api/instance/rewrap", post(rewrap_env_keys)).route("/api/instance/encrypt-metadata", post(encrypt_metadata)).route("/api/instance/rotate-master", post(rotate_master))
        .route("/health", get(health)).route("/.well-known/oauth-protected-resource", get(prm)).route("/.well-known/oauth-authorization-server", get(asm)).route("/oauth/register", post(oauth_register)).route("/oauth/authorize", get(oauth_authorize)).route("/oauth/authorize/decision", post(oauth_decision)).route("/oauth/token", post(oauth_token)).route("/oauth/revoke", post(oauth_revoke))
        .route("/api/orgs/{oid}/emergency", get(get_emergency).put(put_emergency))
        .route("/api/apps/{aid}/emergency", get(get_app_emergency).put(put_app_emergency))
        .route("/api/auth/register", post(register)).route("/api/auth/login", post(login)).route("/api/auth/logout", post(logout)).route("/api/me", get(me).delete(delete_me)).route("/api/me/sessions", get(list_sessions).delete(revoke_all_sessions)).route("/api/me/sessions/{sid}", delete(revoke_session))
        .route("/api/orgs", get(list_orgs).post(create_org)).route("/api/orgs/{oid}", axum::routing::patch(update_org).delete(delete_org)).route("/api/orgs/{oid}/leave", post(leave_org)).route("/api/orgs/{oid}/transfer", post(transfer_org))
        .route("/api/orgs/{oid}/invites", get(workspaces::list)).route("/api/orgs/{oid}/invites/{iid}", delete(workspaces::revoke)).route("/api/orgs/{oid}/invites/{iid}/resend", post(workspaces::resend))
        .route("/api/orgs/{oid}/members", get(list_members).post(invite_member)).route("/api/orgs/{oid}/members/{uid}", axum::routing::patch(update_member_role).delete(remove_member)).route("/api/orgs/{oid}/apps", get(list_apps).post(create_app))
        .route("/api/orgs/{oid}/audit", get(audit_list)).route("/api/orgs/{oid}/audit/verify", get(audit_verify)).route("/api/orgs/{oid}/roles", get(list_roles).post(create_role)).route("/api/orgs/{oid}/log-streams", get(list_streams).post(create_stream)).route("/api/orgs/{oid}/log-streams/deliveries", get(list_deliveries)).route("/api/orgs/{oid}/settings", get(get_org_settings).put(org_settings)).route("/api/orgs/{oid}/features", get(org_features)).route("/api/orgs/{oid}/rotation-hook", get(get_rotation_hook).put(put_rotation_hook).delete(delete_rotation_hook)).route("/api/orgs/{oid}/teams", get(list_teams).post(create_team)).route("/api/orgs/{oid}/teams/{tid}/members", get(list_team_members).post(add_team_member)).route("/api/orgs/{oid}/teams/{tid}/members/{uid}", delete(remove_team_member))
        .route("/api/apps/{aid}", axum::routing::patch(update_app).delete(delete_app)).route("/api/apps/{aid}/settings", get(get_app_settings).put(put_app_settings)).route("/api/apps/{aid}/envs", get(list_envs).post(create_env)).route("/api/apps/{aid}/envs/e2e", post(create_e2e_env)).route("/api/apps/{aid}/tokens", get(list_tokens).post(create_token)).route("/api/tokens/{tid}", delete(revoke_token)).route("/api/orgs/{oid}/identities", get(list_identities).post(create_identity)).route("/api/orgs/{oid}/identities/{iid}", delete(delete_identity)).route("/api/orgs/{oid}/identities/{iid}/rotate", post(rotate_identity)).route("/api/orgs/{oid}/runners", get(list_runners).post(create_runner)).route("/api/orgs/{oid}/runners/{rid}", delete(delete_runner)).route("/api/runner/jobs", get(runner_jobs)).route("/api/runner/jobs/{jid}/result", post(runner_job_result)).route("/api/v1/machine/auth/universal/login", post(universal_login))
        .route("/api/envs/{eid}", delete(delete_env).patch(update_env)).route("/api/envs/{eid}/policy", put(set_env_policy)).route("/api/envs/{eid}/clone", post(clone_env)).route("/api/envs/{eid}/compare", get(compare_envs)).route("/api/envs/{eid}/team-grants", get(list_team_grants).post(add_team_grant)).route("/api/envs/{eid}/team-grants/{tid}", delete(remove_team_grant))
        .route("/api/envs/{eid}/secrets", get(list_secrets).put(deploy_secrets)).route("/api/envs/{eid}/tags", get(list_tags)).route("/api/envs/{eid}/secrets/reuse-check", post(reuse_check)).route("/api/envs/{eid}/e2e/secrets", get(e2e_get).put(e2e_put)).route("/api/envs/{eid}/e2e/meta", get(e2e_meta)).route("/api/envs/{eid}/e2e/rekey", post(e2e_rekey)).route("/api/envs/{eid}/e2e/grant", post(e2e_grant)).route("/api/envs/{eid}/e2e/grants", get(e2e_grants)).route("/api/envs/{eid}/e2e/grants/{uid}", delete(e2e_revoke)).route("/api/users/lookup", get(user_lookup))
        .route("/api/envs/{eid}/export", get(export_env)).route("/api/envs/{eid}/import", post(deploy_secrets)).route("/api/envs/{eid}/scan", get(scan_env)).route("/api/envs/{eid}/meta", get(env_meta)).route("/api/envs/{eid}/wrap", post(create_wrap)).route("/api/unwrap", get(lookup_wrap).post(consume_wrap))
        .route("/api/envs/{eid}/integrations", get(list_integrations).post(create_integration))
        .route("/api/envs/{eid}/dynamic", get(list_leases).post(create_lease_v2)).route("/api/leases/{lid}", get(lookup_lease).delete(revoke_lease)).route("/api/leases/{lid}/renew", post(renew_lease)).route("/api/envs/{eid}/rotations", get(list_rotations).post(create_rotation)).route("/api/rotations/{rid}", delete(delete_rotation)).route("/api/envs/{eid}/rotate", post(rotate_secret)).route("/api/envs/{eid}/restore-point", post(pitr))
        .route("/api/integrations/{iid}/sync", post(sync_integration)).route("/api/integrations/{iid}/history", get(integration_history)).route("/api/integrations/{iid}/test", post(test_integration)).route("/api/integrations/{iid}", axum::routing::patch(update_integration).delete(delete_integration))
        .route("/api/secrets/{sid}", delete(delete_secret)).route("/api/secrets/{sid}/history", get(history))
        .route("/api/secrets/{sid}/restore/{ver}", post(restore)).route("/api/secrets/{sid}/override", get(get_override).post(set_override).delete(delete_override))
        .route("/api/secrets/{sid}/undelete", post(undelete_secret)).route("/api/secrets/{sid}/destroy", post(destroy_secret))
        .route("/api/search", get(search)).route("/api/me/totp/setup", post(totp_setup)).route("/api/me/totp/verify", post(totp_verify)).route("/api/me/totp", delete(mfa::totp_disable)).route("/api/me/mfa", get(mfa::status)).route("/api/me/mfa/recovery-codes", post(mfa::recovery_regenerate)).route("/api/me/mfa/email/start", post(mfa::email_enroll_start)).route("/api/me/mfa/email/verify", post(mfa::email_enroll_verify)).route("/api/me/mfa/email", delete(mfa::email_disable)).route("/api/me/passkeys/start", post(mfa::passkey_register_start)).route("/api/me/passkeys/finish", post(mfa::passkey_register_finish)).route("/api/me/passkeys/{pid}", delete(mfa::passkey_delete)).route("/api/auth/mfa", post(mfa_login)).route("/api/auth/mfa/options", post(mfa::mfa_options)).route("/api/auth/mfa/email/send", post(mfa::email_login_send)).route("/api/auth/mfa/passkey/start", post(mfa::passkey_login_start)).route("/api/auth/mfa/passkey/finish", post(mfa::passkey_login_finish)).route("/api/envs/{eid}/proposals", get(list_proposals).post(create_proposal)).route("/api/proposals/{pid}/{action}", post(decide_proposal)).route("/api/envs/{eid}/access-requests", get(list_access_requests).post(request_access)).route("/api/access-requests/{rid}/{action}", post(decide_access))
        .route("/api/auth/oidc/{oid}/start", get(oidc_start)).route("/api/auth/oidc/callback", get(oidc_callback)).route("/api/lockbox", post(create_lockbox)).route("/api/lockbox/{lid}", get(open_lockbox));
    // LDAP needs raw TCP/TLS sockets, so the feature is off in a Workers build
    // and these routes do not exist there.
    #[cfg(feature = "ldap")]
    let app = app
        .route("/api/orgs/{oid}/ldap", get(get_ldap_config).put(put_ldap_config).delete(delete_ldap_config))
        .route("/api/auth/ldap", post(ldap_login));
    #[cfg(feature = "saml")]
    let app = app
        .route("/api/orgs/{oid}/saml", get(get_saml_config).put(put_saml_config))
        .route("/api/auth/saml/{oid}/metadata", get(saml_metadata)).route("/api/auth/saml/{oid}/start", get(saml_start)).route("/api/auth/saml/{oid}/acs", post(saml_acs));
    #[cfg(feature = "scim")]
    let app = app
        .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user)).route("/scim/v2/Users/{uid}", put(scim_put_user).patch(scim_patch_user).delete(scim_delete_user))
        .route("/scim/v2/Groups", get(scim_list_groups).post(scim_create_group)).route("/scim/v2/Groups/{tid}", get(scim_get_group).put(scim_put_group).patch(scim_patch_group).delete(scim_delete_group))
        .route("/scim/v2/ServiceProviderConfig", get(scim_service_config)).route("/scim/v2/ResourceTypes", get(scim_resource_types)).route("/scim/v2/Schemas", get(scim_schemas));
    #[cfg(feature = "pki")]
    let app = app
        .route("/api/orgs/{oid}/pki/cas", get(list_cas).post(create_ca)).route("/api/orgs/{oid}/pki/expiring", get(expiring_certs)).route("/api/orgs/{oid}/pki/expiry-notify", post(manual_pki_expiry)).route("/api/pki/cas/{caid}/issue", post(issue_cert)).route("/api/pki/cas/{caid}/certs", get(list_certs)).route("/api/pki/cas/{caid}/devices", get(list_devices).post(create_device)).route("/api/pki/cas/{caid}/devices/import", post(import_devices)).route("/api/pki/cas/{caid}/devices/codes", post(bulk_codes)).route("/api/pki/cas/{caid}/devices/export", get(export_devices)).route("/api/pki/cas/{caid}/groups", get(list_groups).post(create_group)).route("/api/pki/cas/{caid}/hook", get(get_ca_hook).put(put_ca_hook)).route("/api/pki/cas/{caid}/attestation", get(get_ca_attestation).put(put_ca_attestation)).route("/api/pki/cas/{caid}/revoke", post(revoke_ca)).route("/api/pki/cas/{caid}/crl", get(ca_crl)).route("/api/pki/cas/{caid}/ocsp", post(ocsp_respond)).route("/api/pki/devices/{did}", get(get_device).patch(update_device).delete(delete_device)).route("/api/pki/devices/{did}/revoke", post(revoke_device)).route("/api/pki/devices/{did}/renew", post(renew_device)).route("/api/pki/devices/{did}/enrollment", post(create_enrollment)).route("/api/pki/groups/{gid}", axum::routing::patch(update_group).delete(delete_group)).route("/api/pki/groups/{gid}/revoke", post(revoke_group)).route("/api/pki/enroll", post(enroll_device)).route("/api/pki/renew/challenge", post(renewal_challenge)).route("/api/pki/renew", post(self_renew_device)).route("/api/pki/devices/{did}/tpm", get(get_device_tpm).put(put_device_tpm)).route("/api/pki/certs/{cid}/revoke", post(revoke_cert));
    #[cfg(feature = "ssh-ca")]
    let app = app
        .route("/api/orgs/{oid}/ssh/cas", get(list_ssh_cas).post(create_ssh_ca)).route("/api/ssh/cas/{caid}", get(get_ssh_ca))
        .route("/api/ssh/cas/{caid}/grants", put(put_ssh_grants)).route("/api/ssh/cas/{caid}/sign", post(ssh_sign))
        .route("/api/ssh/cas/{caid}/certs", get(list_ssh_certs)).route("/api/ssh/cas/{caid}/revoked-keys", get(ssh_revoked_keys))
        .route("/api/ssh/cas/{caid}/krl", get(ssh_krl)).route("/api/ssh/cas/{caid}/hosts", get(list_ssh_hosts).post(add_ssh_host))
        .route("/api/ssh/cas/{caid}/hosts/{hid}", delete(delete_ssh_host)).route("/api/ssh/cas/{caid}/sign-host", post(ssh_sign_host))
        .route("/api/ssh/certs/{cid}/revoke", post(revoke_ssh_cert));
    #[cfg(feature = "workload-identity")]
    let app = app
        .route("/api/orgs/{oid}/identities/{iid}/workload-trust", get(workload::list).post(workload::create))
        .route("/api/orgs/{oid}/identities/{iid}/workload-trust/{tid}", delete(workload::revoke));
    #[cfg(feature = "change-requests")]
    let app = app
        .route("/api/orgs/{oid}/change-requests", get(change_requests::list).post(change_requests::create))
        .route("/api/change-requests/{id}", get(change_requests::detail).put(change_requests::edit))
        .route("/api/change-requests/{id}/{action}", post(change_requests::action));
    #[cfg(feature = "transit")]
    let app = app
        .route("/api/orgs/{oid}/transit/keys", get(transit::list).post(transit::create))
        .route("/api/orgs/{oid}/transit/keys/{kid}/rotate", post(transit::rotate))
        .route("/api/orgs/{oid}/transit/keys/{kid}/{action}", post(transit::operate));
    let app = app
        .route("/api/auth/step-up/start", post(step_up_start)).route("/api/auth/step-up/verify", post(step_up_verify));
    let app = app
        .merge(crate::ai::router())
        .layer(axum::middleware::from_fn_with_state(state.clone(), path_policy::middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), emergency_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), oauth_scope_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), lifecycle_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(metrics_middleware))
        .layer(axum::middleware::from_fn(timeout_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(axum::middleware::from_fn(peer_middleware))
        .with_state::<()>(state.clone());
    let app = { let live = Router::new().route("/api/live", get(live_ws))
        .layer(axum::middleware::from_fn_with_state(state.clone(), path_policy::middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), emergency_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), oauth_scope_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), lifecycle_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(metrics_middleware))
        .layer(axum::middleware::from_fn(peer_middleware))
        .with_state(state.clone());
        live.merge(app) };

    app.layer(axum::middleware::from_fn_with_state(state.clone(), key_lifecycle_middleware))
       .layer(axum::middleware::from_fn_with_state(state, key_middleware))
}

// ---------- step-up verification ----------
// This is the same protocol as the auth-hardening branch (428 plus an
// X-OpenWarp-Step-Up grant), kept to the minimum SSH issuance needs so the two
// implementations collapse when that branch merges. Only privileged SSH
// principals enforce it here.

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum StepUpRisk { Ok, TwoFactor, VeryRisky }
impl StepUpRisk {
    fn as_str(self) -> &'static str { match self { StepUpRisk::Ok => "ok", StepUpRisk::TwoFactor => "two_factor", StepUpRisk::VeryRisky => "very_risky" } }
    fn parse(s: &str) -> Self { match s { "very_risky" => StepUpRisk::VeryRisky, "two_factor" => StepUpRisk::TwoFactor, _ => StepUpRisk::Ok } }
    #[cfg(feature = "ssh-ca")]
    fn rank(self) -> u8 { match self { StepUpRisk::Ok => 0, StepUpRisk::TwoFactor => 1, StepUpRisk::VeryRisky => 2 } } }

fn six_digit_code() -> String { use rand_core::RngCore; let mut b = [0u8; 4]; rand_core::OsRng.fill_bytes(&mut b); format!("{:06}", u32::from_le_bytes(b) % 1_000_000) }

/// Only a real account can satisfy a second factor. A machine identity has no
/// TOTP secret and no mailbox, so it must never look like a stepped-up human.
async fn step_up_user(st: &S, h: &HeaderMap) -> Option<String> {
    let uid = st.token_user(h).await.ok()?;
    st.db.one("SELECT id FROM users WHERE id=?", &[json!(&uid)]).await.ok().flatten().map(|_| uid) }

async fn has_totp(st: &S, uid: &str) -> bool { meta_get(st, &format!("totp_enabled:{}", uid)).await == "1" }

#[cfg(feature = "ssh-ca")]
async fn consume_step_up_grant(st: &S, uid: &str, risk: StepUpRisk, raw: &str) -> bool {
    let hash = oc::hash_token(raw.trim());
    let Ok(Some(row)) = st.db.one("SELECT risk FROM step_up_grants WHERE token_hash=? AND user_id=? AND used=0 AND expires_at>?", &[json!(&hash), json!(uid), json!(now())]).await else { return false };
    if StepUpRisk::parse(&db::s(&row, "risk")).rank() < risk.rank() { return false; }
    st.db.exec("UPDATE step_up_grants SET used=1 WHERE token_hash=? AND used=0", &[json!(&hash)]).await.unwrap_or(0) > 0 }

#[cfg(feature = "ssh-ca")]
async fn require_step_up(st: &S, h: &HeaderMap, uid: &str, risk: StepUpRisk) -> Result<(), (StatusCode, Json<Value>)> {
    let totp = has_totp(st, uid).await;
    let email = mailer::MailConfig::from_env().enabled();
    if risk == StepUpRisk::TwoFactor && !totp { return Ok(()); }
    if risk == StepUpRisk::VeryRisky && !email {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "this action needs an emailed verification code, but no email provider is configured")); }
    if let Some(raw) = h.get("x-openwarp-step-up").and_then(|v| v.to_str().ok()) {
        if consume_step_up_grant(st, uid, risk, raw).await { return Ok(()); } }
    Err((StatusCode::PRECONDITION_REQUIRED, Json(json!({
        "error": "step-up verification required",
        "step_up_required": true,
        "risk": risk.as_str(),
        "totp_required": totp,
        "email_required": risk == StepUpRisk::VeryRisky,
        "email_available": email,
    })))) }

#[derive(Deserialize)] struct StepUpStartReq { #[serde(default)] risk: String }
async fn step_up_start(State(st): State<S>, h: HeaderMap, Json(r): Json<StepUpStartReq>) -> Res {
    let uid = st.token_user(&h).await?;
    let risk = StepUpRisk::parse(&r.risk);
    if risk == StepUpRisk::Ok { return Err(bad("risk must be two_factor or very_risky")); }
    if step_up_user(&st, &h).await.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "machine identities cannot complete step-up verification; ask an admin to sign this certificate")); }
    let key = format!("stepup-start:{}", uid);
    if !st.rate_ok(&key, 5, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many verification requests; try again later")); }
    st.rate_fail(&key, 900).await;
    let totp = has_totp(&st, &uid).await;
    if risk == StepUpRisk::TwoFactor && !totp { return Ok(j(json!({"not_required": true, "methods": []}))); }
    let need_email = risk == StepUpRisk::VeryRisky;
    if need_email && !mailer::MailConfig::from_env().enabled() {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "this action needs an emailed verification code, but no email provider is configured")); }
    let challenge = oc::random_token("stepup");
    let mut code_hash = String::new();
    if need_email {
        let user = st.db.one("SELECT email FROM users WHERE id=?", &[json!(&uid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("account not found"))?;
        let email = db::s(&user, "email");
        let code = six_digit_code();
        code_hash = oc::hash_token(&code);
        send_template(&email, "stepup", &[("code", &code), ("email", &email)]).await; }
    st.db.exec("INSERT INTO step_up_challenges(challenge_hash,user_id,risk,need_totp,need_email,email_code_hash,attempts,created_at,expires_at,used) VALUES(?,?,?,?,?,?,0,?,?,0)",
        &[json!(oc::hash_token(&challenge)), json!(&uid), json!(risk.as_str()), json!(if totp {1} else {0}), json!(if need_email {1} else {0}), json!(&code_hash), json!(now()), json!(now() + 600)]).await.map_err(|e| bad(&e))?;
    let methods = match (totp, need_email) { (true, true) => vec!["totp", "email"], (true, false) => vec!["totp"], _ => vec!["email"] };
    Ok(j(json!({"challenge": challenge, "risk": risk.as_str(), "methods": methods, "email_sent": need_email}))) }

#[derive(Deserialize)] struct StepUpVerifyReq { challenge: String, #[serde(default)] totp: String, #[serde(default)] email_code: String }
async fn step_up_verify(State(st): State<S>, h: HeaderMap, Json(r): Json<StepUpVerifyReq>) -> Res {
    let uid = st.token_user(&h).await?;
    if step_up_user(&st, &h).await.is_none() { return Err(err(StatusCode::FORBIDDEN, "machine identities cannot complete step-up verification")); }
    let key = format!("stepup-verify:{}", uid);
    if !st.rate_ok(&key, 10, 900).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many verification attempts; try again later")); }
    let hash = oc::hash_token(r.challenge.trim());
    let row = st.db.one("SELECT * FROM step_up_challenges WHERE challenge_hash=? AND user_id=? AND used=0 AND expires_at>?", &[json!(&hash), json!(&uid), json!(now())]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| bad("verification request is invalid or expired"))?;
    let risk = StepUpRisk::parse(&db::s(&row, "risk"));
    let need_totp = db::n(&row, "need_totp") == 1; let need_email = db::n(&row, "need_email") == 1;
    let mut ok = true;
    if need_email {
        let expected = db::s(&row, "email_code_hash");
        if expected.is_empty() || oc::hash_token(r.email_code.trim()) != expected { ok = false; } }
    if ok && need_totp { match otp_ok(&st, &uid, &r.totp).await { Ok(v)=>{ if !v { ok=false; } }, Err(e)=>return Err(mfa_failure(e)) } }
    if !ok {
        st.rate_fail(&key, 900).await;
        let attempts = db::n(&row, "attempts") + 1;
        let _ = st.db.exec("UPDATE step_up_challenges SET attempts=?,used=CASE WHEN ?>=5 THEN 1 ELSE used END WHERE challenge_hash=?", &[json!(attempts), json!(attempts), json!(&hash)]).await;
        return Err(err(StatusCode::UNAUTHORIZED, "invalid verification code")); }
    let _ = st.db.exec("UPDATE step_up_challenges SET used=1 WHERE challenge_hash=?", &[json!(&hash)]).await;
    let grant = oc::random_token("stepupg");
    st.db.exec("INSERT INTO step_up_grants(token_hash,user_id,risk,created_at,expires_at,used) VALUES(?,?,?,?,?,0)",
        &[json!(oc::hash_token(&grant)), json!(&uid), json!(risk.as_str()), json!(now()), json!(now() + 300)]).await.map_err(|e| bad(&e))?;
    st.audit("", "", "", &uid, "auth.step_up", risk.as_str()).await;
    Ok(j(json!({"token": grant, "risk": risk.as_str(), "expires_in": 300}))) }


// ---------- SSH certificate authority ----------
// An SSH CA lives in pki_cas with kind='ssh' so its private key shares the
// sealed key column, and master-key rotation, with X.509 CAs. Everything below
// only ever sees an SSH CA; the X.509 handlers reject kind='ssh'.

#[cfg(feature = "ssh-ca")]
fn ssh_grants(raw: &str) -> Vec<String> { serde_json::from_str::<Vec<String>>(raw).unwrap_or_default() }

#[cfg(feature = "ssh-ca")]
async fn ssh_ca_row(st: &S, caid: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM pki_cas WHERE id=? AND kind='ssh'", &[json!(caid)]).await
        .map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "SSH CA not found"))?;
    st.require_feature(&db::s(&row, "org_id"), "ssh-ca").await?;
    Ok(row) }

#[cfg(feature = "ssh-ca")]
async fn create_ssh_ca(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new(); let master = st.master();
    st.check_admin(&oid, &uid).await?;
    st.require_feature(&oid, "ssh-ca").await?;
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = if name.is_empty() { "ssh-ca".to_string() } else { name };
    let forwarding = body.get("allow_forwarding").and_then(|v| v.as_bool()).unwrap_or(false);
    let (secret, public) = ssh_ca::generate_ca().map_err(|e| bad(&e))?;
    let cid = id();
    statements.push((("INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,serial,kind,allow_forwarding,created_at) VALUES(?,?,?,?,?,?,?,?,?)").to_string(), ([json!(&cid), json!(oid), json!(&name), json!(&public), json!(oc::encrypt_symmetric(&master, secret.as_bytes())), json!(""), json!("ssh"), json!(if forwarding { 1 } else { 0 }), json!(now())]).to_vec()));
    st.audited_batch_master(&statements, &[], [&oid, "", "", &uid, "ssh.ca.create", &name], master).await.map_err(master_write_error)?;
    Ok(j(json!({"id": cid, "name": name, "public_key": public, "fingerprint": ssh_ca::ca_fingerprint(&public).unwrap_or_default(),
        "sshd": ssh_ca::sshd_snippet(&public), "note": "no certificate can be issued until a role grant names the principals it may request"}))) }

#[cfg(feature = "ssh-ca")]
async fn list_ssh_cas(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.require_org(&oid, &uid).await?;
    st.require_feature(&oid, "ssh-ca").await?;
    let rows = st.db.query("SELECT id,name,cert_pem,allow_forwarding,created_at FROM pki_cas WHERE org_id=? AND kind='ssh' ORDER BY created_at DESC", &[json!(oid)]).await.map_err(|e| bad(&e))?;
    let out: Vec<Value> = rows.iter().map(|r| { let public = db::s(r, "cert_pem");
        json!({"id": db::s(r, "id"), "name": db::s(r, "name"), "public_key": public,
            "fingerprint": ssh_ca::ca_fingerprint(&public).unwrap_or_default(),
            "allow_forwarding": db::n(r, "allow_forwarding") == 1, "created_at": r.get("created_at").cloned().unwrap_or(Value::Null)}) }).collect();
    Ok(j(json!(out))) }

#[cfg(feature = "ssh-ca")]
async fn get_ssh_ca(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?;
    let ca = ssh_ca_row(&st, &caid).await?;
    st.check_admin(&db::s(&ca, "org_id"), &uid).await?;
    let public = db::s(&ca, "cert_pem");
    let grants = st.db.query("SELECT role,principals,max_ttl FROM ssh_principal_grants WHERE ca_id=? ORDER BY role", &[json!(&caid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"id": caid, "name": db::s(&ca, "name"), "public_key": public, "fingerprint": ssh_ca::ca_fingerprint(&public).unwrap_or_default(),
        "allow_forwarding": db::n(&ca, "allow_forwarding") == 1, "sshd": ssh_ca::sshd_snippet(&public),
        "grants": grants.iter().map(|r| json!({"role": db::s(r,"role"), "principals": ssh_grants(&db::s(r,"principals")), "max_ttl": db::n(r,"max_ttl")})).collect::<Vec<_>>()}))) }

// Replace-all: a role left out of the new list loses its grant, so nobody keeps
// an old permission by accident.
#[cfg(feature = "ssh-ca")]
async fn put_ssh_grants(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let ca = ssh_ca_row(&st, &caid).await?;
    let org = db::s(&ca, "org_id");
    st.check_admin(&org, &uid).await?;
    let caller_role = st.require_org(&org, &uid).await?;
    let items = body.get("grants").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if items.is_empty() { return Err(bad("grants must be a non-empty array of {role, principals, max_ttl}")); }
    let mut stmts: Vec<(String, Vec<Value>)> = vec![("DELETE FROM ssh_principal_grants WHERE ca_id=?".into(), vec![json!(&caid)])];
    let mut granted = Vec::new();
    for it in &items {
        let role = it.get("role").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let patterns: Vec<String> = it.get("principals").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).collect()).unwrap_or_default();
        if role.is_empty() || patterns.is_empty() { return Err(bad("each grant needs a role and at least one principal pattern")); }
        // A duplicate role would fail its second insert after the delete has
        // already run, which would leave the CA with no grants at all.
        if granted.contains(&role) { return Err(bad(&format!("role {:?} is listed twice", role))); }
        let builtin = matches!(role.as_str(), "owner" | "admin" | "developer");
        if !builtin && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(&org), json!(&role)]).await.map_err(|e| bad(&e))?.is_none() {
            return Err(bad(&format!("unknown role {:?}: create it first, grants are per existing role", role)));
        }
        for p in &patterns {
            if !ssh_ca::valid_pattern(p) { return Err(bad(&format!("{:?} is not a principal pattern (an exact name, a prefix ending in *, or *)", p))); }
        }
        // A bare "*" lets that role authenticate as any local account, root
        // included, so it takes the same owner-only bar as an admin role.
        if patterns.iter().any(|p| p == "*") && caller_role != "owner" {
            return Err(err(StatusCode::FORBIDDEN, "only an owner can grant the * (any principal) pattern"));
        }
        let ttl = it.get("max_ttl").and_then(|v| v.as_i64()).unwrap_or(ssh_ca::DEFAULT_TTL).clamp(60, ssh_ca::MAX_TTL);
        stmts.push(("INSERT INTO ssh_principal_grants(ca_id,role,principals,max_ttl) VALUES(?,?,?,?)".into(),
            vec![json!(&caid), json!(&role), json!(serde_json::to_string(&patterns).unwrap_or_default()), json!(ttl)]));
        granted.push(role);
    }
    for (sql, params) in &stmts { statements.push((sql.clone(),params.clone())); }
    st.audited_batch(&statements, &[], [&org, "", "", &uid, "ssh.ca.grants", &format!("{} role(s): {}", granted.len(), granted.join(","))]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"ca_id": caid, "roles": granted}))) }

#[cfg(feature = "ssh-ca")]
async fn ssh_sign(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new(); st.epoch_ok().await?;
    let ca = ssh_ca_row(&st, &caid).await?;
    let org = db::s(&ca, "org_id");
    // Works for a person and for a machine identity: require_org resolves both.
    let role = st.require_org(&org, &uid).await?;
    let principal = body.get("principal").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !ssh_ca::valid_principal(&principal) { return Err(bad("principal must be one account name (letters, digits, . _ - @)")); }
    let public_key = body.get("public_key").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if public_key.is_empty() { return Err(bad("public_key is required: send the OpenSSH public key to certify, never a private key")); }
    let grant = st.db.one("SELECT principals,max_ttl FROM ssh_principal_grants WHERE ca_id=? AND role=?", &[json!(&caid), json!(&role)]).await.map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::FORBIDDEN, &format!("role {} has no SSH principal grant on this CA; an admin must grant one", role)))?;
    let patterns = ssh_grants(&db::s(&grant, "principals"));
    if !ssh_ca::principal_allowed(&patterns, &principal) {
        return Err(err(StatusCode::FORBIDDEN, &format!("role {} may not request principal {:?}", role, principal))); }
    // root, or any principal admitted by a bare * grant, is root-equivalent on
    // every host that trusts this CA, so it needs a fresh second factor.
    let privileged = principal == "root" || patterns.iter().any(|p| p == "*");
    if privileged {
        if step_up_user(&st, &h).await.is_none() {
            return Err(err(StatusCode::FORBIDDEN, "a machine identity cannot request a privileged principal; an admin must sign it from a signed-in session")); }
        require_step_up(&st, &h, &uid, StepUpRisk::VeryRisky).await?; }
    let ttl = ssh_ca::clamp_ttl(body.get("ttl").and_then(|v| v.as_i64()), db::n(&grant, "max_ttl"));
    let key = oc::decrypt_symmetric(&st.master(), &db::s(&ca, "key_enc")).map_err(|e| bad(&e))?;
    let cert_id = id();
    let key_id = format!("{}{}", ssh_ca::KEY_ID_PREFIX, cert_id);
    let signed = ssh_ca::sign_user_cert(&String::from_utf8_lossy(&key),
        &ssh_ca::SignInput { public_key: &public_key, principal: &principal, key_id: &key_id, ttl },
        db::n(&ca, "allow_forwarding") == 1, now()).map_err(|e| bad(&e))?;
    // Read the certificate back before storing it: if what we minted does not
    // parse, the caller gets an error rather than an unusable credential.
    let verified = ssh_ca::describe(&signed.certificate).map_err(|e| bad(&format!("the minted certificate did not parse back: {}", e)))?;
    statements.push((("INSERT INTO ssh_certs(id,ca_id,key_id,principal,public_key,cert,serial,actor,revoked,valid_after,valid_before,created_at) VALUES(?,?,?,?,?,?,?,?,0,?,?,?)").to_string(), [json!(&cert_id), json!(&caid), json!(&key_id), json!(&principal), json!(&public_key), json!(&signed.certificate),
          json!(signed.serial as i64), json!(&uid), json!(signed.valid_after), json!(signed.valid_before), json!(now())].to_vec()));
    st.audited_batch(&statements, &[], [&org, "", "", &uid, "ssh.sign", &format!("{} principal={} serial={} ttl={}s", key_id, principal, signed.serial, ttl)]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"id": cert_id, "certificate": signed.certificate, "key_id": key_id, "serial": signed.serial,
        "principal": principal, "valid_after": signed.valid_after, "valid_before": signed.valid_before,
        "verified": verified, "ca_public_key": db::s(&ca, "cert_pem")}))) }

#[cfg(feature = "ssh-ca")]
async fn list_ssh_certs(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?;
    let ca = ssh_ca_row(&st, &caid).await?;
    st.check_admin(&db::s(&ca, "org_id"), &uid).await?;
    let rows = st.db.query("SELECT id,key_id,principal,serial,actor,revoked,cert_type,valid_after,valid_before,created_at FROM ssh_certs WHERE ca_id=? ORDER BY created_at DESC LIMIT 200", &[json!(&caid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }

#[cfg(feature = "ssh-ca")]
async fn revoke_ssh_cert(State(st): State<S>, h: HeaderMap, Path(cid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let row = st.db.one("SELECT ca_id FROM ssh_certs WHERE id=?", &[json!(&cid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "certificate not found"))?;
    let ca = ssh_ca_row(&st, &db::s(&row, "ca_id")).await?;
    let org = db::s(&ca, "org_id");
    st.check_admin(&org, &uid).await?;
    statements.push((("UPDATE ssh_certs SET revoked=1 WHERE id=?").to_string(), ([json!(&cid)]).to_vec()));
    st.audited_batch(&statements, &[], [&org, "", "", &uid, "ssh.revoke", &cid]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"revoked": cid}))) }

// sshd's RevokedKeys file. There is no KRL writer, so this plus the short
// certificate lifetime is the whole revocation story.
#[cfg(feature = "ssh-ca")]
async fn ssh_revoked_keys(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Response {
    let uid = match st.token_user(&h).await { Ok(u) => u, Err(e) => return e.into_response() };
    let ca = match ssh_ca_row(&st, &caid).await { Ok(c) => c, Err(e) => return e.into_response() };
    if let Err(e) = st.check_admin(&db::s(&ca, "org_id"), &uid).await { return e.into_response(); }
    let rows = match st.db.query("SELECT cert FROM ssh_certs WHERE ca_id=? AND revoked=1 ORDER BY created_at", &[json!(&caid)]).await {
        Ok(r) => r, Err(e) => return bad(&e).into_response() };
    let certs: Vec<String> = rows.iter().map(|r| db::s(r, "cert")).collect();
    let mut resp = ssh_ca::revoked_keys_file(&certs).into_response();
    resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("text/plain; charset=utf-8"));
    resp }

// The same list in OpenSSH's own revocation format. Serial-based, so it stays
// small and does not need the certificate body.
#[cfg(feature = "ssh-ca")]
async fn ssh_krl(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Response {
    let uid = match st.token_user(&h).await { Ok(u) => u, Err(e) => return e.into_response() };
    let ca = match ssh_ca_row(&st, &caid).await { Ok(c) => c, Err(e) => return e.into_response() };
    if let Err(e) = st.check_admin(&db::s(&ca, "org_id"), &uid).await { return e.into_response(); }
    let rows = match st.db.query("SELECT serial FROM ssh_certs WHERE ca_id=? AND revoked=1 ORDER BY created_at", &[json!(&caid)]).await {
        Ok(r) => r, Err(e) => return bad(&e).into_response() };
    let serials: Vec<u64> = rows.iter().map(|r| db::n(r, "serial").max(0) as u64).collect();
    let bytes = match ssh_ca::krl(&db::s(&ca, "cert_pem"), &serials, now()) { Ok(b) => b, Err(e) => return bad(&e).into_response() };
    let mut resp = bytes.into_response();
    resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/octet-stream"));
    resp.headers_mut().insert("content-disposition", axum::http::HeaderValue::from_static("attachment; filename=\"openwarp.krl\""));
    resp }

// ---------- SSH host certificates ----------
// A host certificate is only as trustworthy as the key it certifies, so an
// admin registers the hostname together with its public key. Issuance then
// matches that pair, which lets anyone deploy the certificate without letting
// anyone invent a host.

#[cfg(feature = "ssh-ca")]
async fn add_ssh_host(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new();
    let ca = ssh_ca_row(&st, &caid).await?;
    let org = db::s(&ca, "org_id");
    st.check_admin(&org, &uid).await?;
    let hostname = body.get("hostname").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !ssh_ca::valid_hostname(&hostname) { return Err(bad("hostname must be a literal name or address: letters, digits, dots and hyphens, no wildcards")); }
    let public_key = body.get("public_key").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if public_key.is_empty() { return Err(bad("public_key is required: send the host's OpenSSH public key")); }
    let fingerprint = ssh_ca::key_fingerprint(&public_key).map_err(|e| bad(&e))?;
    if let Some(row) = st.db.one("SELECT id FROM ssh_hosts WHERE ca_id=? AND hostname=? AND fingerprint=?", &[json!(&caid), json!(&hostname), json!(&fingerprint)]).await.map_err(|e| bad(&e))? {
        return Ok(j(json!({"id": db::s(&row, "id"), "hostname": hostname, "fingerprint": fingerprint, "existing": true}))); }
    let hid = id();
    statements.push((("INSERT INTO ssh_hosts(id,ca_id,hostname,public_key,fingerprint,created_at) VALUES(?,?,?,?,?,?)").to_string(), ([json!(&hid), json!(&caid), json!(&hostname), json!(&public_key), json!(&fingerprint), json!(now())]).to_vec()));
    st.audited_batch(&statements, &[], [&org, "", "", &uid, "ssh.host.add", &format!("{} {}", hostname, fingerprint)]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"id": hid, "hostname": hostname, "fingerprint": fingerprint}))) }

#[cfg(feature = "ssh-ca")]
async fn list_ssh_hosts(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?;
    let ca = ssh_ca_row(&st, &caid).await?;
    st.check_admin(&db::s(&ca, "org_id"), &uid).await?;
    let rows = st.db.query("SELECT id,hostname,fingerprint,created_at FROM ssh_hosts WHERE ca_id=? ORDER BY hostname", &[json!(&caid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }

// Removing a registration is how a host key is rotated: delete, then register
// the new key. Outstanding certificates keep working until they expire.
#[cfg(feature = "ssh-ca")]
async fn delete_ssh_host(State(st): State<S>, h: HeaderMap, Path((caid, hid)): Path<(String, String)>) -> Res {
    let uid = st.token_user(&h).await?;
    let ca = ssh_ca_row(&st, &caid).await?;
    let org = db::s(&ca, "org_id");
    st.check_admin(&org, &uid).await?;
    st.audited_batch(&[("DELETE FROM ssh_hosts WHERE id=? AND ca_id=?".into(), vec![json!(&hid), json!(&caid)])], &[0], [&org, "", "", &uid, "ssh.host.remove", &hid]).await.map_err(|e| if e.contains("version conflict") {err(StatusCode::NOT_FOUND, "host not found")} else {bad(&e)})?;
    Ok(j(json!({"deleted": hid}))) }

#[cfg(feature = "ssh-ca")]
async fn ssh_sign_host(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let mut statements = Vec::new(); st.epoch_ok().await?;
    let ca = ssh_ca_row(&st, &caid).await?;
    let org = db::s(&ca, "org_id");
    st.require_org(&org, &uid).await?;
    let hostname = body.get("hostname").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !ssh_ca::valid_hostname(&hostname) { return Err(bad("hostname must be a literal name or address")); }
    let public_key = body.get("public_key").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if public_key.is_empty() { return Err(bad("public_key is required: send the host's OpenSSH public key")); }
    let fingerprint = ssh_ca::key_fingerprint(&public_key).map_err(|e| bad(&e))?;
    if st.db.one("SELECT id FROM ssh_hosts WHERE ca_id=? AND hostname=? AND fingerprint=?", &[json!(&caid), json!(&hostname), json!(&fingerprint)]).await.map_err(|e| bad(&e))?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "this hostname and key are not registered on the CA; an admin registers a host before it can be certified")); }
    let requested = body.get("ttl").and_then(|v| v.as_i64()).unwrap_or(ssh_ca::DEFAULT_HOST_TTL);
    let ttl = requested.clamp(60, ssh_ca::MAX_HOST_TTL);
    let key = oc::decrypt_symmetric(&st.master(), &db::s(&ca, "key_enc")).map_err(|e| bad(&e))?;
    let cert_id = id();
    let key_id = format!("{}{}", ssh_ca::KEY_ID_PREFIX, cert_id);
    let signed = ssh_ca::sign_host_cert(&String::from_utf8_lossy(&key), &hostname, &public_key, &key_id, ttl, now()).map_err(|e| bad(&e))?;
    let verified = ssh_ca::describe(&signed.certificate).map_err(|e| bad(&format!("the minted certificate did not parse back: {}", e)))?;
    statements.push((("INSERT INTO ssh_certs(id,ca_id,key_id,principal,public_key,cert,serial,actor,revoked,cert_type,valid_after,valid_before,created_at) VALUES(?,?,?,?,?,?,?,?,0,'host',?,?,?)").to_string(), [json!(&cert_id), json!(&caid), json!(&key_id), json!(&hostname), json!(&public_key), json!(&signed.certificate),
          json!(signed.serial as i64), json!(&uid), json!(signed.valid_after), json!(signed.valid_before), json!(now())].to_vec()));
    st.audited_batch(&statements, &[], [&org, "", "", &uid, "ssh.sign_host", &format!("{} {} serial={}", hostname, key_id, signed.serial)]).await.map_err(|e|bad(&e))?;
    Ok(j(json!({"id": cert_id, "certificate": signed.certificate, "key_id": key_id, "serial": signed.serial,
        "hostname": hostname, "cert_type": "host", "valid_after": signed.valid_after, "valid_before": signed.valid_before,
        "verified": verified, "ca_public_key": db::s(&ca, "cert_pem")}))) }




pub enum Job {
    Log { url: String, secret: String, payload: String, signed_at: i64, delivery_id: String },
    Webhook { url: String, payload: String },
}
#[cfg(target_arch = "wasm32")]
thread_local! { static JOBS: std::cell::RefCell<Vec<Job>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[cfg(target_arch = "wasm32")]
fn push_job(job: Job) { JOBS.with(|j| j.borrow_mut().push(job)); }
pub fn take_jobs() -> Vec<Job> {
    #[cfg(target_arch = "wasm32")] { JOBS.with(|j| std::mem::take(&mut *j.borrow_mut())) }
    #[cfg(not(target_arch = "wasm32"))] { Vec::new() }
}
pub async fn deliver_job(db: &Db, job: Job) {
    match job {
        Job::Log { url, secret, payload, signed_at, delivery_id } => {
            let client = crate::http::Client::new(); let mut status = "failed"; let mut attempts = 0;
            for i in 0..3 { attempts = i + 1;
                let mut req = client.post(&url).json(&serde_json::from_str::<Value>(&payload).unwrap_or(json!({})));
                if !secret.is_empty() { let sig = hmac_hex(secret.as_bytes(), format!("{}.{}", signed_at, payload).as_bytes()); req = req.header("X-OpenWarp-Timestamp", signed_at.to_string()).header("X-OpenWarp-Signature", format!("t={},v1={}", signed_at, sig)); }
                if let Ok(r) = req.send().await { if r.status().is_success() { status = "delivered"; break; } }
                crate::clock::sleep_ms(200).await; }
            let _ = db.exec("UPDATE log_deliveries SET status=?,attempts=? WHERE id=?", &[json!(status), json!(attempts), json!(&delivery_id)]).await;
        }
        Job::Webhook { url, payload } => {
            let _ = crate::http::Client::new().post(&url).json(&serde_json::from_str::<Value>(&payload).unwrap_or(json!({}))).send().await; }
    }
}
#[cfg(target_arch = "wasm32")]
async fn rotate_master(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { Err(err(StatusCode::NOT_IMPLEMENTED, "master key rotation requires the native server")) }
#[cfg(test)]
mod tests {
    use super::*;
    fn test_state(db: Db) -> S {
        let (live, _) = broadcast::channel(16);
        new_state(db, String::new(), "test".into(), String::new(), [7u8; 32], live, #[cfg(feature = "redis-cache")] None)
    }
    #[test]
    fn region_labels_are_a_closed_vocabulary() {
        assert!(region_label_ok("eu"));
        assert!(region_label_ok("us-east-1"));
        assert!(region_label_ok("global"));
        assert!(!region_label_ok(""));
        assert!(!region_label_ok("EU East"));
        assert!(!region_label_ok("eu/east"));
        assert!(!region_label_ok(&"a".repeat(33)));
    }
    #[test]
    fn a_region_list_must_name_the_deployment_and_stay_well_formed() {
        let ok = "global=https://global.example.test,eu=https://eu.example.test";
        assert!(validate_regions(Some("eu"), Some(ok)).is_ok(), "the deployment's own label is listed");
        assert!(validate_regions(None, Some(ok)).is_ok(), "unset region means global, which the list names");
        assert!(validate_regions(None, None).is_ok(), "a single deployment needs no list");
        let missing = validate_regions(Some("ap"), Some(ok)).expect_err("an unlisted deployment must not start");
        assert!(missing.contains("does not list this deployment"), "{}", missing);
        let dup = validate_regions(Some("eu"), Some("eu=https://a.example.test,eu=https://b.example.test"));
        assert!(dup.expect_err("duplicate labels are ambiguous").contains("twice"));
        let shape = validate_regions(Some("eu"), Some("eu"));
        assert!(shape.expect_err("a bare label has no origin").contains("label=origin"));
        let origin = validate_regions(Some("eu"), Some("eu=ftp://eu.example.test"));
        assert!(origin.expect_err("the origin must be a web URL").contains("origin"));
        let label = validate_regions(Some("EU East"), None);
        assert!(label.expect_err("spaces cannot label a jurisdiction").contains("OPENWARP_REGION"));
    }
    #[test]
    fn region_choices_are_ordered_and_normalised() {
        let parsed = parse_regions(" eu = https://eu.example.test/ , us=https://us.example.test").expect("valid list");
        assert_eq!(parsed, vec![("eu".to_string(), "https://eu.example.test".to_string()), ("us".to_string(), "https://us.example.test".to_string())]);
    }
    #[test]
    fn a_hand_off_origin_cannot_smuggle_a_different_host_or_a_path() {
        for bad in ["eu=http://localhost:80@outside.example", "eu=http://127.0.0.1@outside.example",
            "eu=https://eu.example.test/path", "eu=https://eu.example.test?x=1", "eu=https://eu.example.test#frag",
            "eu=https://:443", "eu=https://?x", "eu=http://10.0.0.1", "eu=ftp://eu.example.test"] {
            assert!(parse_regions(bad).is_err(), "{} must be refused", bad); }
        for ok in ["eu=https://eu.example.test", "eu=http://localhost:8080", "eu=http://[::1]:8080", "eu=https://eu.example.test:8443"] {
            assert!(parse_regions(ok).is_ok(), "{} should be accepted", ok); }
    }
    #[test]
    fn an_empty_jurisdiction_setting_means_unset() {
        // Compose and similar templating turn an unset substitution into an
        // empty string; that must not stop a single-deployment instance.
        assert!(validate_regions(Some(""), None).is_ok());
        assert!(validate_regions(Some("   "), Some("global=https://global.example.test")).is_ok());
    }
    #[test]
    fn loopback_origins_are_recognised_in_both_address_families() {
        for ok in ["http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080", "https://eu.example.test"] {
            assert!(issuer_url_ok(ok), "{} should be accepted", ok); }
        for bad in ["http://10.0.0.1:8080", "http://169.254.169.254", "ftp://eu.example.test", "http://[fe80::1]:8080"] {
            assert!(!issuer_url_ok(bad), "{} should be refused", bad); }
        assert_eq!(url_host("http://[::1]:8080/x"), "[::1]");
        assert_eq!(url_host("http://127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(url_host("https://eu.example.test"), "eu.example.test");
    }
    // Run environment-sensitive assertions in an isolated copy of this test binary.
    #[cfg(not(target_arch = "wasm32"))]
    fn egress_test_child(name: &str, environment: &str, private_egress: Option<&str>) -> bool {
        const CHILD: &str = "OPENWARP_EGRESS_TEST_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(name) { return true; }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", &format!("app::tests::{}", name), "--nocapture"])
            .env(CHILD, name).env("OPENWARP_ENV", environment)
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS");
        if let Some(value) = private_egress { command.env("OPENWARP_ALLOW_PRIVATE_EGRESS", value); }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{} child failed: {}\n{}\n{}", name, output.status,
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "{} child did not run its assertion: {}", name, String::from_utf8_lossy(&output.stdout));
        false
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn egress_production_rejects_private_ipv6_literals() {
        if !egress_test_child("egress_production_rejects_private_ipv6_literals", "production", None) { return; }
        let mut allowed = Vec::new();
        for host in ["::1", "0:0:0:0:0:0:0:1", "fc00::1", "fd00::1", "fe80::1", "febf::1", "::"] {
            for scheme in ["http", "https"] {
                let url = format!("{}://[{}]:8443/metadata", scheme, host);
                if egress_allowed(&url) { allowed.push(url); }
            }
        }
        assert!(allowed.is_empty(), "production allowed private IPv6 destinations: {:?}", allowed);
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn egress_production_preserves_public_and_ipv4_boundaries() {
        if !egress_test_child("egress_production_preserves_public_and_ipv4_boundaries", "PrOdUcTiOn", None) { return; }
        for url in ["https://[2606:4700:4700::1111]/", "http://[2001:4860:4860::8888]:8080/", "https://8.8.8.8/", "https://example.com/"] {
            assert!(egress_allowed(url), "production rejected public destination {}", url);
        }
        for url in ["http://127.0.0.1/", "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.0.1/", "http://169.254.169.254/", "http://0.0.0.0/", "http://LOCALHOST/", "not a URL", "file:///tmp/egress-test"] {
            assert!(!egress_allowed(url), "production allowed blocked destination {}", url);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn egress_production_preserves_operator_override() {
        if !egress_test_child("egress_production_preserves_operator_override", "production", Some("1")) { return; }
        for url in ["https://[::1]/", "https://[fc00::1]/", "https://[fd00::1]/", "https://[fe80::1]/", "https://[::]/", "http://127.0.0.1/", "http://10.0.0.1/", "http://localhost/"] {
            assert!(egress_allowed(url), "operator override rejected {}", url);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn egress_development_preserves_private_destinations() {
        if !egress_test_child("egress_development_preserves_private_destinations", "development", None) { return; }
        for url in ["https://[::1]/", "https://[fc00::1]/", "https://[fd00::1]/", "https://[fe80::1]/", "https://[::]/", "http://127.0.0.1/", "http://10.0.0.1/", "http://localhost/"] {
            assert!(egress_allowed(url), "development rejected {}", url);
        }
    }
    #[test]
    fn administrative_scope_includes_destructive_and_policy_routes() {
        use axum::http::Method;
        for (method, path) in [
            (Method::DELETE, "/api/envs/e1"), (Method::PUT, "/api/envs/e1/policy"),
            (Method::GET, "/api/envs/e1/team-grants"), (Method::POST, "/api/envs/e1/team-grants"),
            (Method::DELETE, "/api/envs/e1/team-grants/t1"), (Method::PATCH, "/api/apps/a1"),
            (Method::DELETE, "/api/apps/a1"), (Method::PUT, "/api/apps/a1/settings"),
        ] { assert!(admin_scope_path(&method, path), "{} {}", method, path); }
        for (method, path) in [(Method::POST, "/api/apps/a1/envs"), (Method::POST, "/api/apps/a1/envs/e2e"), (Method::GET, "/api/apps/a1/settings"), (Method::PATCH, "/api/envs/e1")] {
            assert!(!admin_scope_path(&method, path), "{} {}", method, path);
        }
    }
    #[tokio::test]
    async fn workspace_delete_preserves_pending_leases_then_allows_confirmed_revocation() {
        let db = Db::open_memory().await.unwrap(); let st = test_state(db);
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('u1','delete@example.test','','','',1)", &[]).await.unwrap();
        st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'u1',?)", &[json!(oc::hash_token("delete-test")), json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES('o1','Acme',1)", &[]).await.unwrap();
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('o1','u1','owner')", &[]).await.unwrap();
        st.db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('a1','o1','app',1)", &[]).await.unwrap();
        let key = [9u8;32];
        st.db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES('e1','a1','prod',?,1)", &[json!(oc::encrypt_symmetric(&st.master(), &key))]).await.unwrap();
        for k in ["instance_owner", "0", "rekey_required:e1", "rekey_required:other"] {
            st.db.exec("INSERT INTO meta(k,v) VALUES(?,'preserve')", &[json!(k)]).await.unwrap();
        }
        let mut h = HeaderMap::new(); h.insert("authorization", "Bearer delete-test".parse().unwrap());
        let q = HashMap::from([("confirm".to_string(), "true".to_string())]);
        let pending = oc::encrypt_symmetric_aad(&key, &lease_aad("e1", "l1", "config"), br#"{"type":"pending"}"#);
        reserve_lease(&st, "o1", "e1", "l1", "test", &pending, now()+60).await.unwrap();
        assert_eq!(delete_org(State(st.clone()), h.clone(), Path("o1".into()), Query(q.clone())).await.unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(revoke_lease_remote(&st, "l1").await.unwrap_err().0, StatusCode::CONFLICT);
        let value = oc::encrypt_symmetric_aad(&key, &lease_aad("e1", "l1", "value"), b"random");
        complete_lease(&st, "l1", &value, "", "").await.unwrap();
        assert_eq!(delete_org(State(st.clone()), h.clone(), Path("o1".into()), Query(q.clone())).await.unwrap_err().0, StatusCode::CONFLICT);
        revoke_lease_remote(&st, "l1").await.unwrap();
        let deleted = delete_org(State(st.clone()), h, Path("o1".into()), Query(q)).await.unwrap();
        assert_eq!(deleted.0["deleted"], true);
        for k in ["instance_owner", "0", "rekey_required:other"] { assert!(st.db.one("SELECT v FROM meta WHERE k=?", &[json!(k)]).await.unwrap().is_some()); }
        assert!(st.db.one("SELECT v FROM meta WHERE k='rekey_required:e1'", &[]).await.unwrap().is_none());
        assert!(reserve_lease(&st, "o1", "e1", "l2", "late", &pending, now()+60).await.is_err());
        assert!(st.db.one("SELECT id FROM leases WHERE id='l2'", &[]).await.unwrap().is_none());
    }
    #[test]
    fn ssh_administration_scope_excludes_certificate_signing() {
        use axum::http::Method;
        for (method, path) in [
            (Method::PUT, "/api/ssh/cas/c1/grants"), (Method::GET, "/api/ssh/cas/c1/certs"),
            (Method::GET, "/api/ssh/cas/c1/revoked-keys"), (Method::GET, "/api/ssh/cas/c1/krl"),
            (Method::GET, "/api/ssh/cas/c1/hosts"), (Method::POST, "/api/ssh/cas/c1/hosts"),
            (Method::DELETE, "/api/ssh/cas/c1/hosts/h1"), (Method::POST, "/api/ssh/certs/c1/revoke"),
        ] { assert!(admin_scope_path(&method, path), "{} {}", method, path); }
        for path in ["/api/ssh/cas/c1/sign", "/api/ssh/cas/c1/sign-host"] { assert!(!admin_scope_path(&Method::POST, path)); }
    }
    #[tokio::test]
    async fn owner_recovery_skips_inactive_and_unverified_accounts() {
        let st = test_state(Db::open_memory().await.unwrap());
        for (uid, active, verified, created) in [("inactive", 0, 1, 1), ("unverified", 1, 0, 2), ("eligible", 1, 1, 3)] {
            st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,'','','',?,?,?)",
                &[json!(uid), json!(format!("{}@example.test", uid)), json!(created), json!(active), json!(verified)]).await.unwrap();
        }
        claim_instance_owner_on_verify(&st, "eligible").await;
        assert_eq!(instance_owner(&st).await.as_deref(), Some("eligible"));
        st.db.exec("DELETE FROM meta WHERE k='instance_owner'", &[]).await.unwrap();
        assert_eq!(instance_owner(&st).await.as_deref(), Some("eligible"));
        assert_eq!(meta_get(&st, "instance_owner").await, "eligible");
    }
    #[tokio::test]
    async fn child_deletion_preserves_pending_lease_and_wrapping_tokens() {
        let st = test_state(Db::open_memory().await.unwrap());
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('u1','child@example.test','','','',1)", &[]).await.unwrap();
        st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'u1',?)", &[json!(oc::hash_token("child-test")), json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES('o1','Acme',1)", &[]).await.unwrap();
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('o1','u1','owner')", &[]).await.unwrap();
        st.db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('a1','o1','app',1)", &[]).await.unwrap();
        create_env_batch(&st, "o1", "a1", &[env_insert(&st, "e1", "a1", "prod").await.unwrap()]).await.unwrap();
        st.db.exec("INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_by,created_at,expires_at) VALUES('w1','e1','','u1',1,?)", &[json!(now()+60)]).await.unwrap();
        reserve_lease(&st, "o1", "e1", "l1", "pending", "", now()+60).await.unwrap();
        let mut h = HeaderMap::new(); h.insert("authorization", "Bearer child-test".parse().unwrap());
        assert_eq!(delete_env(State(st.clone()), h.clone(), Path("e1".into())).await.unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(delete_app(State(st.clone()), h.clone(), Path("a1".into())).await.unwrap_err().0, StatusCode::CONFLICT);
        assert!(st.db.one("SELECT token_hash FROM wrap_tokens WHERE token_hash='w1'", &[]).await.unwrap().is_some());
        st.db.exec("UPDATE leases SET revoked=1 WHERE id='l1'", &[]).await.unwrap();
        assert_eq!(delete_app(State(st.clone()), h, Path("a1".into())).await.unwrap().0["ok"], true);
        assert!(st.db.one("SELECT token_hash FROM wrap_tokens WHERE token_hash='w1'", &[]).await.unwrap().is_none());
        assert!(create_env_batch(&st, "o1", "a1", &[env_insert(&st, "late", "a1", "late").await.unwrap()]).await.is_err());
        assert!(st.db.one("SELECT id FROM envs WHERE id='late'", &[]).await.unwrap().is_none());
    }
    #[tokio::test]
    async fn audit_chain_links_and_detects_tampering() {
        let db = Db::open_memory().await.unwrap();
        let st = test_state(db);
        st.audit("o1", "a1", "e1", "u1", "secret.write", "K1").await;
        st.audit("o1", "a1", "e1", "u1", "secret.write", "K2").await;
        let rows = st.db.query("SELECT seq,prev_hash,hash,app_id,env_id,actor,action,detail,created_at FROM audit WHERE org_id='o1' ORDER BY seq", &[]).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(db::n(&rows[0], "seq"), 1);
        assert_eq!(db::s(&rows[0], "prev_hash"), "");
        assert_eq!(db::s(&rows[1], "prev_hash"), db::s(&rows[0], "hash"));
        let first = audit_hash(&db::s(&rows[0], "prev_hash"), 1, "o1", "a1", "e1", "u1", "secret.write", "K1", db::n(&rows[0], "created_at"));
        assert_eq!(first, db::s(&rows[0], "hash"));
        let edited = audit_hash(&db::s(&rows[0], "prev_hash"), 1, "o1", "a1", "e1", "u1", "secret.write", "EDITED", db::n(&rows[0], "created_at"));
        assert_ne!(edited, db::s(&rows[0], "hash"));
    }
    #[tokio::test]
    async fn expired_lease_is_revoked_by_the_sweeper() {
        let db = Db::open_memory().await.unwrap();
        let master = [7u8; 32]; let env_key = [9u8; 32];
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('o1','Acme',1)", &[]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('a1','o1','app',1)", &[]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES('e1','a1','prod',?,1)", &[json!(oc::encrypt_symmetric(&master, &env_key))]).await.unwrap();
        db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES('l1','e1','generic',?,?,?)",
            &[json!(oc::encrypt_symmetric(&env_key, b"x")), json!(now() - 120), json!(now() - 3600)]).await.unwrap();
        let st = test_state(db);
        reap_expired_leases(&st).await;
        let row = st.db.one("SELECT revoked FROM leases WHERE id='l1'", &[]).await.unwrap().unwrap();
        assert_eq!(db::n(&row, "revoked"), 1);
    }
}
