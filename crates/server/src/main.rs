mod db; mod inference_leases; mod integrations; mod mailer; mod ssh_keys; mod ui;
#[cfg(feature = "ldap")] mod ldap;
use axum::{body::Bytes, extract::{ConnectInfo, Path, Query, State, WebSocketUpgrade, ws::{Message, WebSocket}}, http::{HeaderMap, StatusCode}, middleware::Next, response::{Html, IntoResponse, Response}, routing::{delete, get, post, put}, Json, Router};
use db::{Db, Row};
use openwarp_crypto as oc;
use risaml::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpDescriptor, MetadataTrustPolicy, Pending, PendingSnapshot, PrivateKeyPem, RelayStateParam,
    ReplayCache, ReplayKey, ReplayPolicy, Saml, SamlError, SamlInstant, SamlValidationContext,
    SpConfig, SpValidationPolicy, SsoResponse, StartSso,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, sync::atomic::{AtomicUsize, Ordering as AtomicOrdering}, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::broadcast;

pub struct AppState {
    db: Db,
    db_url: String,
    instance_id: String,
    pub_url: String,
    master: std::sync::RwLock<[u8; 32]>,
    #[cfg(feature = "redis-cache")] redis: std::sync::Mutex<Option<redis::Connection>>,
    live: broadcast::Sender<Arc<str>>,
}
type S = Arc<AppState>;
type Res = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn issuer(st: &S, h: &HeaderMap) -> String { if !st.pub_url.is_empty() { return st.pub_url.trim_end_matches('/').to_string(); } let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("127.0.0.1:8080"); format!("http://{}", host) }
fn cookie_val(h: &HeaderMap, name: &str) -> String { h.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").split(';').filter_map(|p| p.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string()).unwrap_or_default() }
fn session_cookie(token: &str) -> String {
    let secure = std::env::var("OPENWARP_PUBLIC_URL").map(|v| v.starts_with("https://")).unwrap_or(false)
        || std::env::var("OPENWARP_SECURE_COOKIES").map(|v| v == "1").unwrap_or(false);
    format!("ow_session={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800{}", token, if secure { "; Secure" } else { "" }) }
fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) { (code, Json(json!({"error": msg}))) }
fn bad(msg: &str) -> (StatusCode, Json<Value>) { err(StatusCode::BAD_REQUEST, msg) }
fn now() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 }
fn id() -> String { oc::random_token("id").replace("id_", "") }
fn j(v: impl Into<Value>) -> Json<Value> { Json(v.into()) }
fn esc(s: &str) -> String { s.chars().map(|c| match c { '&' => "&amp;".into(), '<' => "&lt;".into(), '>' => "&gt;".into(), '"' => "&quot;".into(), '\'' => "&#39;".into(), c => c.to_string() }).collect() }
fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    type H = Hmac<sha2::Sha256>;
    let mut m = H::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect() }
fn hex_encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect() }
const OAUTH_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
fn html_csp(body: String) -> Response { let mut r = Html(body).into_response(); r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(OAUTH_CSP)); r }
fn hidden_fields(form: &HashMap<String, String>) -> String { form.iter().filter(|(k, _)| k.as_str() != "otp").map(|(k, v)| format!("<input type=hidden name=\"{}\" value=\"{}\">", esc(k), esc(v))).collect() }
fn bearer_token(h: &HeaderMap) -> String { h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").strip_prefix("Bearer ").unwrap_or("").to_string() }
static DELIVERY_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_DELIVERY_THREADS: usize = 16;
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
fn otp_ok(st: &S, uid: &str, code: &str) -> bool {
    if meta_get(st, &format!("totp_enabled:{}", uid)) != "1" { return true; }
    if code.is_empty() { return false; }
    if let Ok(secret) = oc::decrypt_symmetric(&st.master(), &meta_get(st, &format!("totp_secret:{}", uid))) {
        let counter = (now() / 30) as u64;
        for c in [counter.wrapping_sub(1), counter, counter + 1] {
            if totp_code(&secret, c) == code {
                let last = meta_get(st, &format!("totp_last:{}", uid)).parse::<u64>().unwrap_or(0);
                if c <= last { return false; }
                meta_set(st, &format!("totp_last:{}", uid), &c.to_string());
                return true;
            }
        }
    }
    let stored = meta_get(st, &format!("totp_recovery:{}", uid)); let hash = oc::hash_token(code);
    let mut list: Vec<String> = stored.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    if let Some(pos) = list.iter().position(|x| *x == hash) { list.remove(pos); meta_set(st, &format!("totp_recovery:{}", uid), &list.join(",")); return true; }
    false }

#[derive(Deserialize, Default)] struct AuthReq { email: String, password: String }
#[derive(Deserialize, Default)] struct NameReq { #[serde(default)] name: String, #[serde(default)] email: String, #[serde(default)] role: String, #[serde(default)] readme: String, #[serde(default)] env_id: String, #[serde(default)] expires_in: i64, #[serde(default)] scopes: String }
#[derive(Deserialize, Default, Clone)] struct SecretIn { key: String, value: String, #[serde(default = "def_path")] path: String, #[serde(default)] comment: String, #[serde(default)] tags: String, #[serde(default, rename = "type")] secret_type: String }
fn def_path() -> String { "/".into() }
#[derive(Deserialize, Default)] struct DeployReq { #[serde(default)] secrets: Vec<SecretIn>, #[serde(default)] text: String }

impl AppState {
    fn audit(&self, org: &str, app: &str, env: &str, actor: &str, action: &str, detail: &str) {
        // log streams (T10): persist delivery then send with retries in a thread
        if let Ok(streams) = self.db.query("SELECT id,url,secret FROM log_streams WHERE org_id=?", &[json!(org)]) { for srow in &streams {
            let did = id(); let payload = json!({"org":org,"app":app,"env":env,"actor":actor,"action":action,"detail":detail,"ts":now()}).to_string();
            let _ = self.db.exec("INSERT INTO log_deliveries(id,stream_id,event,payload,status,created_at) VALUES(?,?,?,?,'pending',?)", &[json!(did), json!(db::s(srow,"id")), json!(action), json!(payload), json!(now())]);
            let raw_secret = db::s(srow,"secret");
            let secret = if raw_secret.is_empty() { raw_secret } else {
                oc::decrypt_symmetric(&self.master(), &raw_secret).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or(raw_secret) };
            if DELIVERY_INFLIGHT.fetch_add(1, AtomicOrdering::SeqCst) >= MAX_DELIVERY_THREADS {
                DELIVERY_INFLIGHT.fetch_sub(1, AtomicOrdering::SeqCst);
                let _ = self.db.exec("UPDATE log_deliveries SET status='dropped' WHERE id=?", &[json!(&did)]);
                continue; }
            let (url, db_url, did2, signed_at) = (db::s(srow,"url"), self.db_url.clone(), did.clone(), now());
            std::thread::spawn(move || {
                let client = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(5)).build();
                let mut status = "failed"; let mut attempts = 0;
                if let Ok(client) = client {
                    for i in 0..3 { attempts = i + 1; let mut req = client.post(&url).json(&serde_json::from_str::<Value>(&payload).unwrap_or(json!({})));
                        if !secret.is_empty() { let sig = hmac_hex(secret.as_bytes(), format!("{}.{}", signed_at, payload).as_bytes()); req = req.header("X-OpenWarp-Timestamp", signed_at.to_string()).header("X-OpenWarp-Signature", format!("t={},v1={}", signed_at, sig)); }
                        if let Ok(r) = req.send() { if r.status().is_success() { status = "delivered"; break; } } std::thread::sleep(std::time::Duration::from_millis(200)); } }
                if let Ok(db2) = Db::open(&db_url) { let _ = db2.exec("UPDATE log_deliveries SET status=?,attempts=? WHERE id=?", &[json!(status), json!(attempts), json!(&did2)]); }
                DELIVERY_INFLIGHT.fetch_sub(1, AtomicOrdering::SeqCst); });
        } }
        if let Ok(Some(wh)) = self.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("audit_webhook:{}", org))]) { let url = db::s(&wh, "v"); let payload = json!({"org":org,"app":app,"env":env,"actor":actor,"action":action,"detail":detail,"ts":now()}); std::thread::spawn(move || { if let Ok(c) = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(5)).build() { let _ = c.post(&url).json(&payload).send(); } }); }
        let _ = self.db.exec("INSERT INTO audit(id,org_id,app_id,env_id,actor,action,detail,created_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(id()), json!(org), json!(app), json!(env), json!(actor), json!(action), json!(detail), json!(now())]);
        // Names and actions only. Values stay in the encrypted tables, so a
        // replica can forward the event without ever seeing plaintext.
        let mut seq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as i64;
        for _ in 0..4 {
            if self.db.exec("INSERT INTO live_events(id,org_id,app_id,env_id,action,detail,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(seq), json!(org), json!(app), json!(env), json!(action), json!(detail), json!(now())]).is_ok() { break; }
            seq += 1;
        }
    }
    fn env_key(&self, env_id: &str) -> Result<[u8;32], (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT env_key_wrapped FROM envs WHERE id=?", &[json!(env_id)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        let raw = oc::decrypt_symmetric(&self.master(), &db::s(&row, "env_key_wrapped")).map_err(|e| bad(&e))?;
        raw.try_into().map_err(|_| bad("bad env key"))
    }
    fn master(&self) -> [u8; 32] { *self.master.read().unwrap_or_else(|e| e.into_inner()) }
    fn token_user(&self, headers: &HeaderMap) -> Result<String, (StatusCode, Json<Value>)> {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        let mut token = auth.strip_prefix("Bearer ").unwrap_or("").to_string();
        // The browser console keeps its session in the HttpOnly cookie, so an
        // injected script cannot read it. API clients keep using Bearer tokens.
        if token.is_empty() { token = cookie_val(headers, "ow_session"); }
        if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "missing Bearer token")); }
        let hash = oc::hash_token(&token);
        #[cfg(feature = "redis-cache")]
        if let Some(uid) = self.redis_get(&format!("sess:{}", hash)) { return Ok(uid); }
        // OAuth 2.1 access tokens (CLI / MCP clients)
        if let Some(row) = self.db.one("SELECT user_id FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(hash), json!(now())]).map_err(|e| bad(&e))? {
            let uid = db::s(&row, "user_id");
            if !self.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
            return Ok(uid); }
        // service / personal access tokens
        if let Some(row) = self.db.one("SELECT created_by,kind,created_at,expires_at,last_used_at FROM tokens WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))? {
            let expires = db::n(&row, "expires_at");
            if expires > 0 && expires < now() { return Err(err(StatusCode::UNAUTHORIZED, "token expired")); }
            if db::s(&row, "kind") == "machine" && db::n(&row, "created_at") + 3600 < now() { return Err(err(StatusCode::UNAUTHORIZED, "machine token expired (1h TTL); login again via Universal Auth")); }
            let uid = db::s(&row, "created_by"); if !uid.is_empty() {
                if !self.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "token owner is deactivated")); }
                if db::n(&row, "last_used_at") + 60 < now() { let _ = self.db.exec("UPDATE tokens SET last_used_at=? WHERE token_hash=?", &[json!(now()), json!(&hash)]); }
                return Ok(uid); }
        }
        let row = self.db.one("SELECT user_id,created_at FROM sessions WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
        if db::n(&row, "created_at") + 7 * 86400 < now() { let _ = self.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(hash)]); return Err(err(StatusCode::UNAUTHORIZED, "session expired (7d); login again")); }
        let uid = db::s(&row, "user_id");
        if !self.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        #[cfg(feature = "redis-cache")] self.redis_set(&format!("sess:{}", hash), &uid);
        Ok(uid)
    }
    #[cfg(feature = "redis-cache")]
    fn redis_get(&self, k: &str) -> Option<String> { let mut g = self.redis.lock().unwrap(); let c = g.as_mut()?; redis::Commands::get(c, k).ok() }
    #[cfg(feature = "redis-cache")]
    fn redis_set(&self, k: &str, v: &str) { let mut g = self.redis.lock().unwrap(); if let Some(c) = g.as_mut() { let _: Result<(), _> = redis::Commands::set_ex(c, k, v, 3600u64); } }
    #[cfg(feature = "redis-cache")]
    fn redis_del(&self, k: &str) { let mut g = self.redis.lock().unwrap(); if let Some(c) = g.as_mut() { let _: Result<(), _> = redis::Commands::del(c, k); } }

    fn org_role(&self, org: &str, user: &str) -> Option<String> {
        self.db.one("SELECT role FROM org_members WHERE org_id=? AND user_id=?", &[json!(org), json!(user)]).ok().flatten().map(|r| db::s(&r, "role"))
    }
    fn check_scope(&self, headers: &HeaderMap, env_id: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""); let token = auth.strip_prefix("Bearer ").unwrap_or("");
        if let Ok(Some(row)) = self.db.one("SELECT env_id FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(token))]) { let scope = db::s(&row, "env_id"); if !scope.is_empty() && scope != env_id { return Err(err(StatusCode::FORBIDDEN, "this token is scoped to a different environment")); } }
        Ok(()) }
    fn role_perms(&self, org: &str, role: &str) -> Vec<String> {
        match role {
            "owner" | "admin" => vec!["*".to_string()],
            "developer" => DEVELOPER_PERMS.iter().map(|p| p.to_string()).collect(),
            _ => self.db.one("SELECT permissions FROM roles WHERE org_id=? AND name=?", &[json!(org), json!(role)]).ok().flatten()
                .and_then(|row| serde_json::from_str::<Vec<String>>(&db::s(&row, "permissions")).ok()).unwrap_or_default(),
        } }
    fn check_perm(&self, org: &str, user: &str, action: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let role = self.require_org(org, user)?;
        let perms = self.role_perms(org, &role);
        if perms.iter().any(|p| p == "*" || p == action) { Ok(()) } else { Err(err(StatusCode::FORBIDDEN, &format!("role {} lacks permission {}", role, action))) } }
    fn check_admin(&self, org: &str, user: &str) -> Result<(), (StatusCode, Json<Value>)> { self.check_perm(org, user, "org:admin") }
    // Counters live in the database so a restart, or a second replica behind a
    // load balancer, does not reset an attacker's budget.
    fn rate_ok(&self, key: &str, max: usize, window: i64) -> bool {
        let cutoff = now() - window;
        let count = self.db.one("SELECT count FROM rate_limits WHERE key=? AND window_start>?", &[json!(key), json!(cutoff)])
            .ok().flatten().map(|r| db::n(&r, "count")).unwrap_or(0);
        (count as usize) < max }
    fn rate_fail(&self, key: &str, window: i64) {
        let current = now(); let cutoff = current - window;
        let _ = self.db.query(
            "INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,1) \
             ON CONFLICT(key) DO UPDATE SET \
               count = CASE WHEN rate_limits.window_start <= ? THEN 1 ELSE rate_limits.count + 1 END, \
               window_start = CASE WHEN rate_limits.window_start <= ? THEN ? ELSE rate_limits.window_start END \
             RETURNING count",
            &[json!(key), json!(current), json!(cutoff), json!(cutoff), json!(current)]); }
    fn rate_clear(&self, key: &str) { let _ = self.db.exec("DELETE FROM rate_limits WHERE key=?", &[json!(key)]); }
    // Deactivated users and deleted identities must lose every credential at once.
    fn principal_active(&self, uid: &str) -> bool {
        match self.db.one("SELECT active,email_verified FROM users WHERE id=?", &[json!(uid)]) {
            Ok(Some(row)) => {
                if db::n(&row, "active") == 0 { return false; }
                if db::n(&row, "email_verified") == 0 { return false; }
                true },
            Ok(None) => self.db.one("SELECT id FROM identities WHERE id=?", &[json!(uid)]).ok().flatten().is_some(),
            Err(_) => false,
        } }
    fn require_org(&self, org: &str, user: &str) -> Result<String, (StatusCode, Json<Value>)> {
        if let Some(r) = self.org_role(org, user) { return Ok(r); }
        // machine identities belong to an org directly
        if let Ok(Some(idn)) = self.db.one("SELECT role FROM identities WHERE id=? AND org_id=?", &[json!(user), json!(org)]) { return Ok(db::s(&idn, "role")); }
        Err(err(StatusCode::FORBIDDEN, "not an organisation member")) }
    fn env_org_app(&self, env_id: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT a.org_id AS org_id, e.app_id AS app_id FROM envs e JOIN apps a ON a.id=e.app_id WHERE e.id=?", &[json!(env_id)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        Ok((db::s(&row, "org_id"), db::s(&row, "app_id")))
    }
    fn require_env(&self, env_id: &str, user: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
        let (org, app) = self.env_org_app(env_id)?; let role = self.require_org(&org, user)?;
        if role == "owner" || role == "admin" { return Ok((org, app)); }
        let env = self.db.one("SELECT restricted FROM envs WHERE id=?", &[json!(env_id)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        let restricted = db::n(&env, "restricted") == 1;
        let granted = |table: &str, col: &str, id: &str| -> Result<bool, (StatusCode, Json<Value>)> {
            let rows = self.db.query(&format!("SELECT user_id FROM {} WHERE {}=?", table, col), &[json!(id)]).map_err(|e| bad(&e))?;
            Ok(rows.iter().any(|r| db::s(r, "user_id") == user)) };
        // Only an explicit restriction narrows access. require_approval gates
        // writes, not membership, so it must never lock readers out.
        if !restricted { return Ok((org, app)); }
        let in_env = granted("env_members", "env_id", env_id)?;
        if in_env { return Ok((org, app)); }
        if granted("app_members", "app_id", &app)? { return Ok((org, app)); }
        if self.db.one("SELECT g.team_id FROM team_env_grants g JOIN team_members tm ON tm.team_id=g.team_id WHERE g.env_id=? AND tm.user_id=? LIMIT 1", &[json!(env_id), json!(user)]).map_err(|e| bad(&e))?.is_some() { return Ok((org, app)); }
        Err(err(StatusCode::FORBIDDEN, "no access to this environment"))
    }
    fn decrypt_secret(&self, key: &[u8;32], row: &Row, user: Option<&str>) -> Value {
        let sid = db::s(row, "id");
        let (mut value, mut decrypt_error) = match oc::decrypt_symmetric(key, &db::s(row, "value_enc")) {
            Ok(b) => (String::from_utf8_lossy(&b).into_owned(), false),
            Err(_) => (String::new(), true) };
        if let Some(user) = user {
            if let Ok(Some(ov)) = self.db.one("SELECT value_enc FROM overrides WHERE secret_id=? AND user_id=?", &[json!(sid), json!(user)]) {
                if let Ok(b) = oc::decrypt_symmetric(key, &db::s(&ov, "value_enc")) { value = String::from_utf8_lossy(&b).into_owned(); decrypt_error = false; }
            }
        }
        let stype = db::s(row, "secret_type");
        json!({"id": sid, "key": oc::decrypt_symmetric(key, &db::s(row, "key_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            "value": if stype == "sealed" { Value::Null } else { json!(value) }, "decrypt_error": decrypt_error,
            "path": db::s(row,"path"), "comment": oc::decrypt_symmetric(key, &db::s(row,"comment_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            "tags": db::s(row,"tags"), "type": stype, "version": db::n(row,"version"), "updated_at": db::n(row,"updated_at")})
    }
    #[allow(clippy::type_complexity)]
    fn list_secrets_with(&self, env_id: &str, user: Option<&str>) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        let key = self.env_key(env_id)?;
        let rows = self.db.query("SELECT * FROM secrets WHERE env_id=? AND deleted=0 ORDER BY path, key_hash", &[json!(env_id)]).map_err(|e| bad(&e))?;
        let mut out = Vec::new();
        for r in &rows { let v = self.decrypt_secret(&key, r, user); out.push((v["key"].as_str().unwrap_or("").to_string(), v["value"].as_str().unwrap_or("").to_string(), v)); }
        // resolve ${KEY} and ${/path/KEY} references
        let map: HashMap<String, String> = out.iter().map(|(k, v, raw)| (format!("{}{}", raw["path"].as_str().unwrap_or("/"), k), v.clone())).collect();
        let by_key: HashMap<String, String> = out.iter().map(|(k, v, _)| (k.clone(), v.clone())).collect();
        for item in out.iter_mut() { if item.2["type"].as_str() == Some("sealed") { continue; } for _ in 0..5 { let before = item.1.clone(); item.1 = resolve_refs(&item.1, &map, &by_key); if item.1 == before { break; } } item.2["value"] = json!(item.1); }
        Ok(out)
    }
    #[allow(clippy::type_complexity)]
    fn list_secrets_decrypted(&self, env_id: &str, user: &str) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        self.list_secrets_with(env_id, Some(user)) }
    // Integrations must never deploy a caller's personal override as the shared value.
    #[allow(clippy::type_complexity)]
    fn list_secrets_base(&self, env_id: &str) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        self.list_secrets_with(env_id, None) }
}
fn resolve_refs(v: &str, by_path: &HashMap<String, String>, by_key: &HashMap<String, String>) -> String {
    let mut out = String::new(); let mut rest = v;
    while let Some(start) = rest.find("${") { out.push_str(&rest[..start]); let tail = &rest[start + 2..];
        match tail.find('}') { Some(end) => { let name = &tail[..end]; let val = by_path.get(name).or_else(|| by_key.get(name)).cloned().unwrap_or_else(|| format!("${{{}}}", name)); out.push_str(&val); rest = &tail[end + 1..]; } None => { out.push_str(&rest[start..]); return out; } } }
    out.push_str(rest); out
}

// ---------- auth ----------
async fn register(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, h: HeaderMap, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let rl = format!("register:{}", addr.ip());
    if !st.rate_ok(&rl, 5, 3600) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many registrations from this address; try again later")); }
    st.rate_fail(&rl, 3600);
    if r.email.is_empty() || r.password.len() < 8 { return Err(bad("email and password (>=8 chars) required")); }
    if !signups_open(&st) { return Err(err(StatusCode::FORBIDDEN, "signups are disabled on this instance; ask an administrator to invite you")); }
    if production() && !mailer::MailConfig::from_env().enabled() { return Err(err(StatusCode::SERVICE_UNAVAILABLE, "password signup is unavailable: no email provider is configured; use a configured sign-in provider or ask an administrator")); }
    let kp = oc::Keypair::generate();
    let wrapped = oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    let uid = id(); let hash = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    // A password signup proves nothing about the address until the link is opened.
    // The instance-owner claim in particular waits for verification.
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,0)", &[json!(uid), json!(r.email.to_lowercase()), json!(hash), json!(kp.public), json!(wrapped), json!(now())]).map_err(|_| err(StatusCode::CONFLICT, "an account with this email already exists"))?;
    let oid = id(); st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(oid), json!(format!("{}'s organisation", r.email)), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", &[json!(oid), json!(&uid)]).map_err(|e| bad(&e))?;
    let link_token = issue_auth_token(&st, &uid, "verify", 86400);
    let link = format!("{}/api/auth/verify?token={}", issuer(&st, &h), link_token);
    send_template(&r.email, "verify", &[("link", &link), ("email", &r.email)]).await;
    Ok((HeaderMap::new(), j(json!({"user_id": uid, "org_id": oid, "public_key": kp.public, "recovery_kit": kp.secret_b64(), "verification_required": true}))))
}
fn make_session(st: &S, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { let t = oc::random_token("ow"); st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&t)), json!(uid), json!(now())]).map_err(|e| bad(&e))?; Ok(t) }
async fn login(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let key = format!("login:{}:{}", addr.ip(), r.email.trim().to_lowercase());
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later")); }
    let row = match st.db.one("SELECT * FROM users WHERE email=?", &[json!(r.email.trim().to_lowercase())]).map_err(|e| bad(&e))? { Some(x) => x, None => { st.rate_fail(&key, 900); return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); } };
    if db::n(&row, "active") == 0 && row.contains_key("active") { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
    if !oc::verify_password(&r.password, &db::s(&row, "pass_hash")) { st.rate_fail(&key, 900); return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    if db::n(&row, "email_verified") == 0 { return Err(err(StatusCode::FORBIDDEN, "verify your email address before signing in; POST /api/auth/resend-verification for a new link")); }
    st.rate_clear(&key);
    let uid = db::s(&row, "id");
    if meta_get(&st, &format!("totp_enabled:{}", uid)) == "1" { let challenge = oc::random_token("mfa"); st.db.exec("INSERT INTO mfa_challenges(token,user_id,created_at) VALUES(?,?,?)", &[json!(challenge), json!(uid), json!(now())]).map_err(|e| bad(&e))?; return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge})))); }
    let token = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "public_key": db::s(&row, "pubkey")}))))
}

async fn me(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h)?; let r = st.db.one("SELECT id,email,pubkey FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
    // A caller can always learn the environment its own credential is confined to.
    let mut out = db::obj(&r); out["env_scope"] = json!(env_scope_of(&st, &h)); Ok(j(out)) }
async fn list_orgs(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h)?;
    let rows = st.db.query("SELECT o.id,o.name,o.ip_allowlist,m.role FROM orgs o JOIN org_members m ON m.org_id=o.id WHERE m.user_id=?", &[json!(uid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_org(State(st): State<S>, h: HeaderMap, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; let oid = id();
    st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(oid), json!(r.name), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", &[json!(oid), json!(uid)]).map_err(|e| bad(&e))?; Ok(j(json!({"id": oid}))) }
async fn update_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    if r.name.trim().is_empty() { return Err(bad("organisation name required")); }
    st.db.exec("UPDATE orgs SET name=? WHERE id=?", &[json!(r.name.trim()), json!(&oid)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "org.rename", r.name.trim()); Ok(j(json!({"ok": true}))) }
async fn leave_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let role = st.require_org(&oid, &uid)?;
    if role == "owner" {
        let owners = st.db.query("SELECT user_id FROM org_members WHERE org_id=? AND role='owner'", &[json!(&oid)]).map_err(|e| bad(&e))?;
        if owners.len() <= 1 { return Err(err(StatusCode::CONFLICT, "transfer ownership before leaving; an organisation needs an owner")); }
    }
    st.db.exec("DELETE FROM org_members WHERE org_id=? AND user_id=?", &[json!(&oid), json!(&uid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM team_members WHERE user_id=? AND team_id IN (SELECT id FROM teams WHERE org_id=?)", &[json!(&uid), json!(&oid)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "org.leave", ""); Ok(j(json!({"ok": true}))) }
async fn transfer_org(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    if st.require_org(&oid, &uid)? != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can transfer ownership")); }
    let target = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    if target.is_empty() || target == uid { return Err(bad("user_id of another member required")); }
    if st.org_role(&oid, target).is_none() { return Err(err(StatusCode::NOT_FOUND, "member not found")); }
    st.db.exec("UPDATE org_members SET role='owner' WHERE org_id=? AND user_id=?", &[json!(&oid), json!(target)]).map_err(|e| bad(&e))?;
    st.db.exec("UPDATE org_members SET role='admin' WHERE org_id=? AND user_id=?", &[json!(&oid), json!(&uid)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "org.transfer", target); Ok(j(json!({"ok": true}))) }
async fn update_member_role(State(st): State<S>, h: HeaderMap, Path((oid, target)): Path<(String, String)>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    let caller_role = st.require_org(&oid, &uid)?;
    let target_role = st.org_role(&oid, &target).ok_or_else(|| err(StatusCode::NOT_FOUND, "member not found"))?;
    let new_role = r.role.trim();
    if new_role.is_empty() { return Err(bad("role required")); }
    if !["owner", "admin", "developer"].contains(&new_role) && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(&oid), json!(new_role)]).map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    if (new_role == "owner" || new_role == "admin") && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can grant the owner or admin role")); }
    if target_role == "owner" && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can change another owner")); }
    if target_role == "owner" && new_role != "owner" {
        let owners = st.db.query("SELECT user_id FROM org_members WHERE org_id=? AND role='owner'", &[json!(&oid)]).map_err(|e| bad(&e))?;
        if owners.len() <= 1 { return Err(err(StatusCode::CONFLICT, "an organisation needs at least one owner")); }
    }
    st.db.exec("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?", &[json!(new_role), json!(&oid), json!(target)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "member.role", &format!("{}={}", target, new_role)); Ok(j(json!({"ok": true}))) }
async fn invite_member(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let caller_role = st.require_org(&oid, &uid)?; st.check_admin(&oid, &uid)?;
    let email = r.email.trim().to_lowercase();
    if email.is_empty() { return Err(bad("email required")); }
    let new_role = if r.role.trim().is_empty() { "developer".to_string() } else { r.role.trim().to_string() };
    if (new_role == "owner" || new_role == "admin") && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can grant the owner or admin role")); }
    if new_role != "owner" && new_role != "admin" && new_role != "developer" && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(&oid), json!(&new_role)]).map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    if let Some(target) = st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).map_err(|e| bad(&e))? {
        let tid = db::s(&target, "id");
        if st.org_role(&oid, &tid).is_some() { return Err(err(StatusCode::CONFLICT, "user is already a member")); }
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(oid), json!(tid), json!(new_role)]).map_err(|e| bad(&e))?;
        st.audit(&oid, "", "", &uid, "member.invite", &email); return Ok(j(json!({"ok": true, "added": true})));
    }
    // No account yet: issue a single-use invite the invitee redeems with a
    // password, or with Google/GitHub when those providers are configured.
    let token = oc::random_token("inv"); let expires = now() + 7 * 86400;
    let _ = st.db.exec("DELETE FROM invites WHERE email=? AND org_id=? AND accepted=0", &[json!(&email), json!(&oid)]);
    st.db.exec("INSERT INTO invites(token_hash,email,org_id,role,created_at,expires_at) VALUES(?,?,?,?,?,?)", &[json!(oc::hash_token(&token)), json!(&email), json!(&oid), json!(&new_role), json!(now()), json!(expires)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "member.invite", &email);
    Ok(j(json!({"ok": true, "invite_token": token, "expires_at": expires, "note": "single use, valid 7 days; the invitee redeems it at POST /api/auth/accept-invite or by signing in with a configured social provider"}))) }
#[derive(Deserialize)] struct InviteReq { token: String, password: String }
async fn accept_invite(State(st): State<S>, Json(r): Json<InviteReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if r.password.len() < 8 { return Err(bad("password (>=8 chars) required")); }
    let hash = oc::hash_token(r.token.trim());
    let row = st.db.one("SELECT * FROM invites WHERE token_hash=? AND accepted=0 AND expires_at>?", &[json!(&hash), json!(now())]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invite is invalid or expired"))?;
    let email = db::s(&row, "email"); let org = db::s(&row, "org_id"); let role = db::s(&row, "role");
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in instead")); }
    let kp = oc::Keypair::generate(); let uid = id();
    // The invite token reached this address, which is the proof a password
    // signup would otherwise obtain by email.
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)", &[json!(uid), json!(&email), json!(oc::hash_password(&r.password).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(&org), json!(&uid), json!(&role)]).map_err(|e| bad(&e))?;
    st.db.exec("UPDATE invites SET accepted=1 WHERE token_hash=?", &[json!(&hash)]).map_err(|e| bad(&e))?;
    claim_instance_owner(&st, &uid);
    st.audit(&org, "", "", &uid, "member.accept_invite", &email);
    let token = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "org_id": org, "role": role})))) }
async fn create_app(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?; st.check_perm(&oid, &uid, "secrets:write")?;
    let aid = id(); st.db.exec("INSERT INTO apps(id,org_id,name,readme,created_at) VALUES(?,?,?,?,?)", &[json!(aid), json!(oid), json!(r.name), json!(r.readme), json!(now())]).map_err(|e| bad(&e))?;
    for name in ["Development", "Staging", "Production"] { create_env_inner(&st, &aid, name)?; }
    st.audit(&oid, &aid, "", &uid, "app.create", &r.name); Ok(j(json!({"id": aid}))) }
fn create_env_inner(st: &S, app_id: &str, name: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let eid = id(); let key = oc::random_key(); let wrapped = oc::encrypt_symmetric(&st.master(), &key);
    st.db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)", &[json!(eid), json!(app_id), json!(name), json!(wrapped), json!(now())]).map_err(|e| bad(&e))?; Ok(eid) }
async fn list_apps(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let rows = st.db.query("SELECT id,org_id,name,readme,created_at FROM apps WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    if !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || r.name.is_empty() || r.name.len() > 32 { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    let eid = create_env_inner(&st, &aid, &r.name)?; Ok(j(json!({"id": eid}))) }
async fn list_envs(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"), &uid)?;
    let rows = st.db.query("SELECT id,app_id,name,mode,restricted,require_approval,created_at FROM envs WHERE app_id=? ORDER BY created_at", &[json!(aid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
    st.check_admin(&org, &uid)?;
    for sql in [
        "DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id=?)",
        "DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id=?)",
        "DELETE FROM secrets WHERE env_id=?",
        "DELETE FROM env_keys WHERE env_id=?",
        "DELETE FROM leases WHERE env_id=?",
        "DELETE FROM integration_sync_state WHERE integration_id IN (SELECT id FROM integrations WHERE env_id=?)",
        "DELETE FROM integrations WHERE env_id=?",
        "DELETE FROM proposals WHERE env_id=?",
        "DELETE FROM access_requests WHERE env_id=?",
        "DELETE FROM rotation_schedules WHERE env_id=?",
        "DELETE FROM env_members WHERE env_id=?",
        "DELETE FROM envs WHERE id=?",
    ] { st.db.exec(sql, &[json!(eid)]).map_err(|e| bad(&e))?; }
    st.audit(&org, &app, &eid, &uid, "env.delete", ""); Ok(j(json!({"ok": true}))) }
async fn set_env_policy(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_admin(&org, &uid)?;
    let mut changed = Vec::new();
    for field in ["restricted", "require_approval"] {
        if let Some(v) = body.get(field).and_then(|v| v.as_bool()) {
            st.db.exec(&format!("UPDATE envs SET {}=? WHERE id=?", field), &[json!(if v { 1 } else { 0 }), json!(&eid)]).map_err(|e| bad(&e))?;
            changed.push(format!("{}={}", field, v)); } }
    if changed.is_empty() { return Err(bad("restricted or require_approval (boolean) required")); }
    st.audit(&org, &app, &eid, &uid, "env.policy", &changed.join(","));
    Ok(j(json!({"ok": true, "policy": changed}))) }
async fn list_members(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let rows = st.db.query("SELECT u.id AS id, u.email AS email, u.created_at AS created_at, m.role AS role FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? ORDER BY m.role, u.email", &[json!(oid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn remove_member(State(st): State<S>, h: HeaderMap, Path((oid, target)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let role = st.require_org(&oid, &uid)?; st.check_admin(&oid, &uid)?;
    if target == uid { return Err(bad("use another admin to remove yourself; leaving your own organisation is not supported")); }
    let target_role = st.org_role(&oid, &target).ok_or_else(|| err(StatusCode::NOT_FOUND, "member not found"))?;
    if target_role == "owner" && role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can remove an owner")); }
    let deleted = st.db.exec("DELETE FROM org_members WHERE org_id=? AND user_id=? AND (role<>'owner' OR (SELECT COUNT(*) FROM org_members WHERE org_id=? AND role='owner')>1)", &[json!(oid), json!(target), json!(oid)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(bad("cannot remove the last owner")); }
    st.audit(&oid, "", "", &uid, "member.remove", &target); Ok(j(json!({"ok": true}))) }
async fn update_app(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app, "org_id"); st.check_admin(&org, &uid)?;
    if r.name.trim().is_empty() { return Err(bad("name required")); }
    st.db.exec("UPDATE apps SET name=? WHERE id=?", &[json!(r.name.trim()), json!(aid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &aid, "", &uid, "app.rename", &r.name); Ok(j(json!({"ok": true}))) }
async fn delete_app(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app, "org_id"); st.check_admin(&org, &uid)?;
    for sql in [
        "DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM env_keys WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM leases WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM integration_sync_state WHERE integration_id IN (SELECT id FROM integrations WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM integrations WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM proposals WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM access_requests WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM rotation_schedules WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM env_members WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM envs WHERE app_id=?",
    ] { st.db.exec(sql, &[json!(aid)]).map_err(|e| bad(&e))?; }
    st.db.exec("DELETE FROM app_members WHERE app_id=?", &[json!(aid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM tokens WHERE app_id=?", &[json!(aid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &aid, "", &uid, "app.delete", ""); Ok(j(json!({"ok": true}))) }
async fn update_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    if r.name.is_empty() || r.name.len() > 32 || !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    st.db.exec("UPDATE envs SET name=? WHERE id=?", &[json!(r.name), json!(eid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &app, &eid, &uid, "env.rename", &r.name); Ok(j(json!({"ok": true}))) }
async fn clone_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let target = body.get("target_env_id").and_then(|v| v.as_str()).unwrap_or("");
    if target.is_empty() || target == eid { return Err(bad("target_env_id of another environment required")); }
    let (torg, tapp) = st.require_env(target, &uid)?; st.check_perm(&torg, &uid, "secrets:write")?;
    if torg != org || tapp != app { return Err(bad("source and target must belong to the same app")); }
    let overwrite = body.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
    for id in [eid.as_str(), target] { let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(id)]).map_err(|e| bad(&e))?.map(|r| db::s(&r,"mode")).unwrap_or_default(); if mode == "e2e" { return Err(bad("E2E environments cannot be cloned server-side; use the CLI")); } }
    let items = st.list_secrets_base(&eid)?; let key = st.env_key(target)?;
    let mut cloned = 0; let mut skipped = 0;
    for (_, _, raw) in items {
        let stype = raw["type"].as_str().unwrap_or("secret");
        if stype == "sealed" { skipped += 1; continue; }
        let s = SecretIn{ key: raw["key"].as_str().unwrap_or("").into(), value: raw["value"].as_str().unwrap_or("").into(), path: raw["path"].as_str().unwrap_or("/").into(), comment: raw["comment"].as_str().unwrap_or("").into(), tags: raw["tags"].as_str().unwrap_or("").into(), secret_type: stype.into() };
        let khash = oc::hash_token(&format!("{}:{}", s.path, s.key.to_uppercase()));
        if !overwrite && st.db.one("SELECT id FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(target), json!(&khash)]).map_err(|e| bad(&e))?.is_some() { skipped += 1; continue; }
        upsert_secret(&st, target, &key, &uid, &s)?; cloned += 1;
    }
    let sync_errors = trigger_sync(&st, target, &uid).await;
    st.audit(&org, &app, &eid, &uid, "env.clone", &format!("{}->{} cloned={} skipped={}", eid, target, cloned, skipped));
    Ok(j(json!({"cloned": cloned, "skipped": skipped, "sync_errors": sync_errors}))) }
async fn compare_envs(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?;
    let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let other = q.get("other").cloned().unwrap_or_default();
    if other.is_empty() || other == eid { return Err(bad("other environment id required")); }
    let (oorg, _) = st.require_env(&other, &uid)?; st.check_perm(&oorg, &uid, "secrets:read")?;
    if oorg != org { return Err(bad("environments must belong to the same organisation")); }
    let source = st.list_secrets_base(&eid)?; let target = st.list_secrets_base(&other)?;
    let map = |items: &[(String,String,Value)]| -> HashMap<String,String> { items.iter().map(|(k,_,raw)| (format!("{}{}", raw["path"].as_str().unwrap_or("/"), k), raw["value"].as_str().unwrap_or("").to_string())).collect() };
    let a = map(&source); let b = map(&target);
    let mut only_source = Vec::new(); let mut only_target = Vec::new(); let mut changed = Vec::new(); let mut same = 0;
    for (k, v) in &a { match b.get(k) { None => only_source.push(k.clone()), Some(w) if w != v => changed.push(k.clone()), Some(_) => same += 1 } }
    for k in b.keys() { if !a.contains_key(k) { only_target.push(k.clone()); } }
    only_source.sort(); only_target.sort(); changed.sort();
    Ok(j(json!({"only_in_source": only_source, "only_in_target": only_target, "changed": changed, "same": same}))) }

async fn list_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let items = st.list_secrets_decrypted(&eid, &uid)?; st.audit(&org, &app, &eid, &uid, "secret.list", &format!("{}", items.len()));
    let total = items.len();
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(500).clamp(1, 1000);
    let offset = q.get("offset").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
    let page: Vec<Value> = items.iter().skip(offset).take(limit).map(|x| x.2.clone()).collect();
    Ok(j(json!({"secrets": page, "total": total, "limit": limit, "offset": offset}))) }
async fn deploy_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let policy = st.db.one("SELECT require_approval FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?;
    if policy.map(|p| db::n(&p, "require_approval") == 1).unwrap_or(false) {
        let role = st.require_org(&org, &uid).unwrap_or_default();
        if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "this environment requires an approved proposal; submit a proposal instead of deploying directly")); }
    }
    let mut inputs = r.secrets.clone(); if inputs.is_empty() && !r.text.is_empty() { inputs = parse_env(&r.text); }
    let scan_findings: Vec<Value> = inputs.iter().filter(|s| s.secret_type != "sealed").filter_map(|s| {
        let rules = scan_rules(&s.value);
        if rules.is_empty() { None } else { Some(json!({"key": s.key, "path": s.path, "rules": rules})) }
    }).collect();
    let key = st.env_key(&eid)?; let mut count = 0;
    for s in &inputs { if s.key.trim().is_empty() { continue; } upsert_secret(&st, &eid, &key, &uid, s)?; count += 1; }
    st.audit(&org, &app, &eid, &uid, "secret.deploy", &format!("{} secrets", count));
    let sync_errors = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"deployed": count, "sync_errors": sync_errors, "scan_findings": scan_findings}))) }
fn upsert_secret(st: &S, eid: &str, key: &[u8;32], uid: &str, s: &SecretIn) -> Result<(), (StatusCode, Json<Value>)> {
    let kname = s.key.trim().to_uppercase();
    if !valid_secret_key(&kname) { return Err(bad("secret key must match [A-Za-z0-9_.-]{1,128}")); }
    if !valid_path(&s.path) { return Err(bad("secret path must be 1-256 printable characters")); }
    let khash = oc::hash_token(&format!("{}:{}", s.path, kname));
    let existing = st.db.one("SELECT id,version,secret_type FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(khash)]).map_err(|e| bad(&e))?;
    let mut stype = if s.secret_type.is_empty() { "secret".to_string() } else { s.secret_type.clone() };
    if !matches!(stype.as_str(), "secret" | "sealed" | "ssh_key" | "config") { return Err(bad("secret type must be secret, sealed, ssh_key or config")); }
    if stype == "ssh_key" && ssh_keys::public_key_error(&kname, &s.value).is_some() { return Err(bad("an ssh_key value must be a single-line OpenSSH public key")); }
    if let Some(row) = &existing { if db::s(row, "secret_type") == "sealed" { if stype != "sealed" { return Err(bad("sealed secrets cannot change type; delete and recreate")); } stype = "sealed".to_string(); } }
    if let Some(row) = existing { let sid = db::s(&row, "id"); let ver = db::n(&row, "version") + 1;
        st.db.exec("UPDATE secrets SET value_enc=?,comment_enc=?,tags=?,secret_type=?,version=?,updated_at=?,updated_by=? WHERE id=?", &[json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(s.tags), json!(stype), json!(ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(ver), json!(oc::encrypt_symmetric(key, kname.as_bytes())), json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    } else { let sid = id();
        st.db.exec("INSERT INTO secrets(id,env_id,path,key_enc,key_hash,value_enc,comment_enc,tags,secret_type,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)", &[json!(sid), json!(eid), json!(s.path), json!(oc::encrypt_symmetric(key, kname.as_bytes())), json!(khash), json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(s.tags), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,1,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(oc::encrypt_symmetric(key, kname.as_bytes())), json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    } Ok(()) }
fn parse_env(text: &str) -> Vec<SecretIn> { let mut out = Vec::new(); let mut pending_comment = String::new();
    for line in text.lines() { let l = line.trim(); if l.is_empty() { continue; } else if l.starts_with('#') { pending_comment = l.trim_start_matches('#').trim().to_string(); continue; }
        if let Some((k, v)) = l.trim_start_matches("export ").split_once('=') { out.push(SecretIn{ key: k.trim().to_string(), value: v.trim().trim_matches('"').trim_matches('\'').to_string(), path: "/".into(), comment: pending_comment.clone(), tags: "".into(), secret_type: "".into() }); pending_comment.clear(); } } out }
async fn delete_secret(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:delete")?;
    st.db.exec("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=? WHERE id=?", &[json!(now()), json!(now()), json!(sid)]).map_err(|e| bad(&e))?; st.audit(&org, &app, &eid, &uid, "secret.delete", &sid); let _ = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"ok": true}))) }
async fn history(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let key = st.env_key(&eid)?; let sealed = st.db.one("SELECT secret_type FROM secrets WHERE id=?", &[json!(sid)]).map(|r| r.map(|x| db::s(&x,"secret_type") == "sealed").unwrap_or(false)).unwrap_or(false);
    let rows = st.db.query("SELECT * FROM secret_versions WHERE secret_id=? ORDER BY version DESC", &[json!(sid)]).map_err(|e| bad(&e))?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"version": db::n(r,"version"), "value": if sealed { "[SEALED]".to_string() } else { oc::decrypt_symmetric(&key,&db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() }, "created_at": db::n(r,"created_at"), "created_by": db::s(r,"created_by")})).collect();
    Ok(j(json!(items))) }
async fn restore(State(st): State<S>, h: HeaderMap, Path((sid, ver)): Path<(String, i64)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let v = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND version=?", &[json!(sid), json!(ver)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("version not found"))?;
    let cur = st.db.one("SELECT version FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?; let new_ver = cur.map(|r| db::n(&r,"version")).unwrap_or(0) + 1;
    st.db.exec("UPDATE secrets SET value_enc=?,comment_enc=?,version=?,deleted=0,deleted_at=0,updated_at=?,updated_by=? WHERE id=?", &[json!(db::s(&v,"value_enc")), json!(db::s(&v,"comment_enc")), json!(new_ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(db::s(&v,"value_enc")), json!(db::s(&v,"comment_enc")), json!(db::s(&v,"secret_type")), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"secret.restore",&format!("{}->v{}",sid,ver)); let _ = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"ok":true,"version":new_ver}))) }
async fn set_override(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row,"env_id"); st.require_env(&eid,&uid)?;
    let key = st.env_key(&eid)?; let val = r.secrets.first().map(|s| s.value.clone()).unwrap_or_default();
    st.db.exec("INSERT INTO overrides(secret_id,user_id,value_enc) VALUES(?,?,?)", &[json!(sid), json!(uid), json!(oc::encrypt_symmetric(&key, val.as_bytes()))]).map_err(|e| bad(&e)).or_else(|_| st.db.exec("UPDATE overrides SET value_enc=? WHERE secret_id=? AND user_id=?", &[json!(oc::encrypt_symmetric(&key, val.as_bytes())), json!(sid), json!(uid)]).map_err(|e| bad(&e)))?; Ok(j(json!({"ok":true}))) }

async fn scan_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let items = st.list_secrets_decrypted(&eid, &uid)?;
    let mut findings = Vec::new();
    for (_, _, raw) in items {
        if raw["type"].as_str() == Some("sealed") { continue; }
        let rules = scan_rules(raw["value"].as_str().unwrap_or(""));
        if !rules.is_empty() { findings.push(json!({"key": raw["key"], "path": raw["path"], "rules": rules})); }
    }
    st.audit(&org,&app,&eid,&uid,"secret.scan",&format!("{} findings", findings.len()));
    Ok(j(json!({"findings": findings}))) }
async fn export_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org,&uid,"secrets:read")?;
    // base=1 skips the caller's personal overrides. Deployments must not pick up
    // whichever stand-in values the token owner happens to keep locally.
    let items = if q.get("base").map(|v| v == "1" || v == "true").unwrap_or(false) { st.list_secrets_base(&eid)? } else { st.list_secrets_decrypted(&eid,&uid)? };
    let text = items.iter().map(|(k,v,_)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n"); Ok(j(json!({"text": text, "secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
// An environment-scoped token cannot list workspaces, so it needs a way to name
// the one environment it is confined to. The path also passes scope_path_ok.
async fn env_meta(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let name = |table: &str, id: &str| st.db.one(&format!("SELECT name FROM {} WHERE id=?", table), &[json!(id)]).ok().flatten().map(|r| db::s(&r, "name")).unwrap_or_default();
    Ok(j(json!({"id": eid, "name": name("envs", &eid), "app": name("apps", &app), "workspace": name("orgs", &org)}))) }
async fn search(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?; let needle = q.get("q").cloned().unwrap_or_default().to_uppercase();
    let orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).map_err(|e| bad(&e))?;
    let mut results = Vec::new();
    for o in &orgs { let org = db::s(o,"org_id");
        if st.check_perm(&org, &uid, "secrets:read").is_err() { continue; }
        let apps = st.db.query("SELECT id,name FROM apps WHERE org_id=?", &[json!(&org)]).map_err(|e| bad(&e))?;
        for a in &apps { let app_id = db::s(a,"id");
            let envs = st.db.query("SELECT id,name FROM envs WHERE app_id=?", &[json!(&app_id)]).map_err(|e| bad(&e))?;
            for e in &envs { let eid = db::s(e,"id");
                // Environment and application grants narrow the org-wide default.
                if st.require_env(&eid, &uid).is_err() { continue; }
                if let Ok(items) = st.list_secrets_decrypted(&eid, &uid) { for (k,_,raw) in items { if needle.is_empty() || k.contains(&needle) { results.push(json!({"app": db::s(a,"name"), "env": db::s(e,"name"), "key": k, "path": raw["path"]})); } } } } } }
    Ok(j(json!({"results": results}))) }
async fn create_token(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    // A 1h machine credential must not be convertible into a permanent one.
    if let Ok(Some(caller)) = st.db.one("SELECT env_id,kind FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(&h)))]) {
        if db::s(&caller, "kind") == "machine" { return Err(err(StatusCode::FORBIDDEN, "machine tokens cannot mint service tokens; use the identity's 1h token")); }
        if !db::s(&caller, "env_id").is_empty() { return Err(err(StatusCode::FORBIDDEN, "environment-scoped tokens cannot mint new tokens")); } }
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app,"org_id"); st.check_perm(&org, &uid, "tokens:create")?;
    if !r.env_id.is_empty() {
        let env = st.db.one("SELECT app_id FROM envs WHERE id=?", &[json!(r.env_id)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
        if db::s(&env, "app_id") != aid { return Err(bad("env does not belong to this app")); }
    }
    let token = oc::random_token("owp"); let tid = id();
    let scopes: Vec<&str> = r.scopes.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).collect();
    for s in &scopes { if !matches!(*s, "secrets:read" | "secrets:write" | "*") { return Err(bad("scopes may contain secrets:read, secrets:write or *")); } }
    let scopes = scopes.join(" ");
    let expires_at = if r.expires_in > 0 { now() + r.expires_in.clamp(60, 365 * 86400) } else { 0 };
    st.db.exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,expires_at,scopes,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)", &[json!(tid), json!(org), json!(aid), json!(r.env_id), json!(if r.name.is_empty(){"token".into()}else{r.name.clone()}), json!(oc::hash_token(&token)), json!(expires_at), json!(scopes), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": tid, "token": token, "expires_at": expires_at, "scopes": scopes}))) }
async fn audit_list(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(500).clamp(1, 1000);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0);
    let rows = st.db.query("SELECT * FROM audit WHERE org_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?", &[json!(oid), json!(limit), json!(offset)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_team(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.check_admin(&oid,&uid)?;
    let tid = id(); st.db.exec("INSERT INTO teams(id,org_id,name) VALUES(?,?,?)", &[json!(tid), json!(oid), json!(r.name)]).map_err(|e| bad(&e))?; Ok(j(json!({"id": tid}))) }
async fn list_teams(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT * FROM teams WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn list_team_grants(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT t.id AS team_id,t.name AS name FROM team_env_grants g JOIN teams t ON t.id=g.team_id WHERE g.env_id=? ORDER BY t.name", &[json!(&eid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn add_team_grant(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_admin(&org, &uid)?;
    let tid = body.get("team_id").and_then(|v| v.as_str()).unwrap_or("");
    if st.db.one("SELECT id FROM teams WHERE id=? AND org_id=?", &[json!(tid), json!(&org)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "team not found in this organisation")); }
    st.db.exec("INSERT INTO team_env_grants(team_id,env_id) VALUES(?,?)", &[json!(tid), json!(&eid)]).map_err(|_| bad("team already has a grant for this environment"))?;
    st.audit(&org,&app,&eid,&uid,"team.grant",tid); Ok(j(json!({"ok": true}))) }
async fn remove_team_grant(State(st): State<S>, h: HeaderMap, Path((eid, tid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_admin(&org, &uid)?;
    st.db.exec("DELETE FROM team_env_grants WHERE team_id=? AND env_id=?", &[json!(&tid), json!(&eid)]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"team.revoke",&tid); Ok(j(json!({"ok": true}))) }
async fn list_team_members(State(st): State<S>, h: HeaderMap, Path((oid, tid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    st.require_org(&oid, &uid)?;
    if st.db.one("SELECT id FROM teams WHERE id=? AND org_id=?", &[json!(&tid), json!(&oid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "team not found")); }
    let rows = st.db.query("SELECT u.id AS user_id,u.email AS email FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=? ORDER BY u.email", &[json!(&tid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn add_team_member(State(st): State<S>, h: HeaderMap, Path((oid, tid)): Path<(String, String)>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    if st.db.one("SELECT id FROM teams WHERE id=? AND org_id=?", &[json!(&tid), json!(&oid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "team not found")); }
    let target = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    if st.org_role(&oid, target).is_none() { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    st.db.exec("INSERT INTO team_members(team_id,user_id) VALUES(?,?)", &[json!(&tid), json!(target)]).map_err(|_| bad("user is already in this team"))?;
    st.audit(&oid,"","",&uid,"team.member.add",target); Ok(j(json!({"ok": true}))) }
async fn remove_team_member(State(st): State<S>, h: HeaderMap, Path((oid, tid, target)): Path<(String, String, String)>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    st.db.exec("DELETE FROM team_members WHERE team_id=? AND user_id=? AND team_id IN (SELECT id FROM teams WHERE org_id=?)", &[json!(&tid), json!(&target), json!(&oid)]).map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"team.member.remove",&target); Ok(j(json!({"ok": true}))) }

async fn create_lockbox(State(st): State<S>, h: HeaderMap, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; let _ = uid;
    let val = r.secrets.first().map(|s| s.value.clone()).unwrap_or(r.text.clone()); if val.is_empty() { return Err(bad("value required")); }
    let key = oc::random_key(); let lid = id();
    st.db.exec("INSERT INTO lockbox(id,value_enc,expires_at,max_views,created_at) VALUES(?,?,?,?,?)", &[json!(lid), json!(oc::encrypt_symmetric(&key, val.as_bytes())), json!(now()+86400), json!(1), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": lid, "key": oc::b64(&key), "url": format!("/lockbox/{}#{}", lid, oc::b64(&key))}))) }
async fn open_lockbox(State(st): State<S>, Path(lid): Path<String>, h: HeaderMap) -> Res {
    let key_b64 = h.get("x-lockbox-key").and_then(|v| v.to_str().ok()).unwrap_or(""); let kb = oc::unb64(key_b64).map_err(|e| bad(&e))?; let key: [u8;32] = kb.try_into().map_err(|_| bad("bad key"))?;
    let row = st.db.one("SELECT * FROM lockbox WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lockbox not found or already viewed"))?;
    if db::n(&row,"expires_at") < now() || db::n(&row,"views") >= db::n(&row,"max_views") { let _ = st.db.exec("DELETE FROM lockbox WHERE id=?", &[json!(lid)]); return Err(err(StatusCode::GONE,"expired")); }
    // Consume first: two concurrent readers must not both see the value.
    let taken = st.db.exec("DELETE FROM lockbox WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?;
    if taken == 0 { return Err(err(StatusCode::NOT_FOUND,"lockbox not found or already viewed")); }
    let val = oc::decrypt_symmetric(&key, &db::s(&row,"value_enc")).map_err(|e| bad(&e))?;
    Ok(j(json!({"value": String::from_utf8_lossy(&val)}))) }
async fn list_leases(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let key = st.env_key(&eid)?; let rows = st.db.query("SELECT * FROM leases WHERE env_id=? AND revoked=0 AND expires_at>?", &[json!(eid), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "value": oc::decrypt_symmetric(&key,&db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(), "expires_at": db::n(r,"expires_at")})).collect::<Vec<_>>()))) }

async fn create_integration(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or(""); if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
    let config = body.get("config").cloned().unwrap_or(json!({})); let key = st.env_key(&eid)?;
    let iid = id(); st.db.exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES(?,?,?,?,?,?)", &[json!(iid), json!(eid), json!(kind), json!(body.get("name").and_then(|v| v.as_str()).unwrap_or(kind)), json!(oc::encrypt_symmetric(&key, config.to_string().as_bytes())), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": iid}))) }
async fn list_integrations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT id,env_id,kind,name,created_at FROM integrations WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn sync_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let (org, _) = st.require_env(&db::s(&row, "env_id"), &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    let msg = sync_one(&st, &iid, &uid).await?; Ok(j(json!({"ok": true, "detail": msg}))) }
async fn test_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "integrations:write")?; let key = st.env_key(&eid)?;
    let config: Value = serde_json::from_slice(&oc::decrypt_symmetric(&key, &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    let kind = db::s(&row, "kind");
    if integrations::has_test(&kind) { let msg = integrations::test(&kind, &config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    Err(err(StatusCode::NOT_IMPLEMENTED, &format!("connection test is not implemented for kind {}; use Sync to verify it against the live service", kind))) }
async fn update_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    let key = st.env_key(&eid)?;
    if let Some(kind) = body.get("kind").and_then(|v| v.as_str()) {
        if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
        st.db.exec("UPDATE integrations SET kind=? WHERE id=?", &[json!(kind), json!(&iid)]).map_err(|e| bad(&e))?; }
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) { st.db.exec("UPDATE integrations SET name=? WHERE id=?", &[json!(name), json!(&iid)]).map_err(|e| bad(&e))?; }
    if let Some(config) = body.get("config") { st.db.exec("UPDATE integrations SET config_enc=? WHERE id=?", &[json!(oc::encrypt_symmetric(&key, config.to_string().as_bytes())), json!(&iid)]).map_err(|e| bad(&e))?; }
    st.audit(&org,&app,&eid,&uid,"integration.update",&iid); Ok(j(json!({"ok": true}))) }
async fn delete_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM integrations WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"integration.delete",&iid); Ok(j(json!({"deleted": iid}))) }
async fn trigger_sync(st: &S, eid: &str, uid: &str) -> Vec<String> { trigger_sync_with(st, eid, uid, true).await }
async fn trigger_sync_internal(st: &S, eid: &str) -> Vec<String> { trigger_sync_with(st, eid, "rotation-scheduler", false).await }
async fn trigger_sync_with(st: &S, eid: &str, uid: &str, enforce: bool) -> Vec<String> {
    let mut errors = Vec::new();
    if let Ok(rows) = st.db.query("SELECT id FROM integrations WHERE env_id=?", &[json!(eid)]) {
        for r in &rows { let iid = db::s(r, "id");
            if let Err((_, Json(v))) = sync_one_inner(st, &iid, uid, enforce, false).await {
                let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("integration sync failed").to_string();
                if let Ok((org, app)) = st.env_org_app(eid) { st.audit(&org, &app, eid, uid, "integration.sync_failed", &format!("{}: {}", iid, msg)); }
                errors.push(format!("{}: {}", iid, msg)); } }
    }
    errors
}
async fn sync_one(st: &S, iid: &str, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { sync_one_inner(st, iid, uid, true, true).await }
async fn sync_one_inner(st: &S, iid: &str, uid: &str, enforce: bool, manual: bool) -> Result<String, (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id");
    let (org, app) = if enforce { st.require_env(&eid, uid)? } else { st.env_org_app(&eid)? };
    let key = st.env_key(&eid)?;
    let mut config: Value = serde_json::from_slice(&oc::decrypt_symmetric(&key, &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    let kind = db::s(&row, "kind");
    if !manual && config.get("auto_sync").and_then(Value::as_bool) == Some(false) { return Ok(format!("{}: skipped (auto_sync is disabled)", kind)); }
    let env_name = st.db.one("SELECT name FROM envs WHERE id=?", &[json!(&eid)]).map(|r| r.map(|x| db::s(&x, "name")).unwrap_or_default()).unwrap_or_default();
    config["_environment"] = json!(env_name);
    let prev_rows = st.db.query("SELECT remote_name FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]).map_err(|e| bad(&e))?;
    let prev: Vec<String> = prev_rows.iter().map(|r| db::s(r, "remote_name")).collect();
    let initial = config.get("initial_sync").and_then(Value::as_str).unwrap_or("overwrite");
    if !matches!(initial, "overwrite" | "import_local" | "import_remote") { return Err(bad("initial_sync must be overwrite, import_local or import_remote")); }
    if initial != "overwrite" && prev.is_empty() {
        if !integrations::is_stateful(&kind) {
            return Err(bad("initial_sync is only supported for stateful sync adapters"));
        }
        let imported = integrations::pull(&kind, &config).await.map_err(|e| bad(&e))?;
        let existing: HashMap<String, String> = st.list_secrets_base(&eid)?.iter().map(|(k, _, raw)| (k.clone(), raw["type"].as_str().unwrap_or("secret").to_string())).collect();
        let env_key = st.env_key(&eid)?;
        let mut count = 0; let mut skipped: Vec<String> = Vec::new();
        for (name, value) in imported {
            let kname = name.trim().to_uppercase();
            if !valid_secret_key(&kname) { skipped.push(name); continue; }
            if initial == "import_local" && existing.contains_key(&kname) { continue; }
            if initial == "import_remote" && existing.get(&kname).map(String::as_str) == Some("sealed") { skipped.push(format!("{} (sealed)", kname)); continue; }
            let s = SecretIn { key: kname, value, path: "/".into(), comment: "imported by integration sync".into(), tags: "import".into(), secret_type: "secret".into() };
            upsert_secret(st, &eid, &env_key, uid, &s)?;
            count += 1;
        }
        st.audit(&org, &app, &eid, uid, "integration.import", &format!("{} keys from {}", count, kind));
        if !skipped.is_empty() { return Err(bad(&format!("imported {} keys but skipped: {}", count, skipped.join(", ")))); }
    }
    // Sealed secrets are never readable, so they must never be pushed: an empty
    // string would overwrite the value on the remote side. Personal overrides are
    // a per-user view and must not become the shared deployed value either.
    let items = st.list_secrets_base(&eid)?;
    let located: Vec<(String, String, String, String)> = items.iter().filter(|(_, _, raw)| raw["type"].as_str() != Some("sealed")).map(|(k, v, raw)| (raw["path"].as_str().unwrap_or("/").to_string(), k.clone(), v.clone(), raw["type"].as_str().unwrap_or("secret").to_string())).collect();
    let pairs = integrations::secret_keys(&located);
    if integrations::is_stateful(&kind) {
        let dry = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
        let prefix = config.get("prefix").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let result = integrations::sync_managed(&kind, &config, &located, &prev).await.unwrap_or_else(|| Err(format!("unsupported sync kind {}", kind)));
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
                    let _ = st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]);
                    for n in &union { let base = n.strip_prefix(&prefix).unwrap_or(n); let hv = pairs.iter().find(|(k, _)| k.as_str() == base).map(|(_, v)| oc::hash_token(v)).unwrap_or_default(); let _ = st.db.exec("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)", &[json!(iid), json!(n), json!(hv)]); }
                }
                return Err(bad(&e));
            }
        };
        if !dry {
            st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]).map_err(|e| bad(&format!("sync succeeded but state could not be saved: {}", e)))?;
            for n in &managed { let base = n.strip_prefix(&prefix).unwrap_or(n); let hv = pairs.iter().find(|(k, _)| k.as_str() == base).map(|(_, v)| oc::hash_token(v)).unwrap_or_default();
                st.db.exec("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)", &[json!(iid), json!(n), json!(hv)]).map_err(|e| bad(&format!("sync succeeded but state could not be saved: {}", e)))?; }
        }
        st.audit(&org, &app, &eid, uid, "integration.sync", &msg); return Ok(msg); }
    let msg = integrations::sync(&kind, &config, &pairs).await.map_err(|e| bad(&e))?;
    st.audit(&org, &app, &eid, uid, "integration.sync", &msg); Ok(msg)
}

async fn pitr(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let ts = body.get("timestamp").and_then(|v| v.as_i64()).unwrap_or_else(now);
    // Restore the whole environment as it stood at ts: a secret created later
    // must disappear, and a secret deleted before ts must stay deleted.
    let rows = st.db.query("SELECT id,version,deleted_at FROM secrets WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?;
    let mut restored = 0; let mut removed = 0;
    for r in &rows {
        let sid = db::s(r,"id"); let cur = db::n(r,"version"); let del_at = db::n(r,"deleted_at");
        let v = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND created_at<=? ORDER BY created_at DESC, version DESC LIMIT 1", &[json!(&sid), json!(ts)]).map_err(|e| bad(&e))?;
        match v {
            Some(v) => {
                let was_deleted = del_at > 0 && del_at <= ts;
                let new_ver = cur + 1;
                let tomb = if was_deleted { 1 } else { 0 };
                let tomb_at = if was_deleted { if del_at > 0 { del_at } else { now() } } else { 0 };
                st.db.exec("UPDATE secrets SET key_enc=?,value_enc=?,comment_enc=?,secret_type=?,version=?,deleted=?,deleted_at=?,updated_at=?,updated_by=? WHERE id=?",
                    &[json!(db::s(&v,"key_enc")), json!(db::s(&v,"value_enc")), json!(db::s(&v,"comment_enc")), json!(db::s(&v,"secret_type")), json!(new_ver), json!(tomb), json!(tomb_at), json!(now()), json!(&uid), json!(&sid)]).map_err(|e| bad(&e))?;
                st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)",
                    &[json!(id()), json!(&sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(db::s(&v,"value_enc")), json!(db::s(&v,"comment_enc")), json!(db::s(&v,"secret_type")), json!(now()), json!(&uid)]).map_err(|e| bad(&e))?;
                if was_deleted { removed += 1 } else { restored += 1 }
            }
            None => {
                st.db.exec("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=? WHERE id=?", &[json!(now()), json!(now()), json!(&sid)]).map_err(|e| bad(&e))?;
                removed += 1;
            }
        }
    }
    st.audit(&org,&app,&eid,&uid,"env.pitr",&format!("ts={} restored={} removed={}",ts,restored,removed));
    let _ = trigger_sync(&st, &eid, &uid).await;
    Ok(j(json!({"restored": restored, "removed": removed}))) }


async fn get_org_settings(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h)?; st.check_admin(&oid,&uid)?;
    let ip = st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?", &[json!(&oid)]).map_err(|e| bad(&e))?
        .map(|r| db::s(&r,"ip_allowlist")).unwrap_or_default();
    let secret = meta_get(&st, &format!("oidc_client_secret:{}", oid));
    Ok(j(json!({
        "ip_allowlist": ip,
        "oidc_issuer": meta_get(&st, &format!("oidc_issuer:{}", oid)),
        "oidc_client_id": meta_get(&st, &format!("oidc_client_id:{}", oid)),
        "oidc_redirect_uri": meta_get(&st, &format!("oidc_redirect_uri:{}", oid)),
        "oidc_client_secret_set": !secret.is_empty(),
        "oidc_auto_provision": meta_get(&st, &format!("oidc_auto_provision:{}", oid)) == "1",
        "oidc_allowed_domains": meta_get(&st, &format!("oidc_allowed_domains:{}", oid)),
        "audit_webhook": meta_get(&st, &format!("audit_webhook:{}", oid)),
    }))) }
async fn org_settings(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid,&uid)?;
    if let Some(v)=body.get("ip_allowlist").and_then(|x|x.as_str()) {
        if !valid_cidr_list(v) { return Err(bad("ip_allowlist must be comma-separated IP addresses or CIDR ranges")); }
        st.db.exec("UPDATE orgs SET ip_allowlist=? WHERE id=?", &[json!(v), json!(oid)]).map_err(|e| bad(&e))?; }
    if let Some(v)=body.get("audit_webhook").and_then(|x|x.as_str()) { if !v.is_empty() && (!url_ok(v) || !egress_allowed(v)) { return Err(bad("audit_webhook must be an http(s) URL outside private networks; set OPENWARP_ALLOW_PRIVATE_EGRESS=1 to allow one")); } meta_set(&st, &format!("audit_webhook:{}",oid), v); }
    if let Some(v)=body.get("oidc_redirect_uri").and_then(|x|x.as_str()) { if !v.is_empty() && !url_ok(v) { return Err(bad("oidc_redirect_uri must be an http(s) URL")); } }
    if let Some(v)=body.get("oidc_allowed_domains").and_then(|x|x.as_str()) { if !valid_domain_list(v) { return Err(bad("oidc_allowed_domains must be comma-separated DNS domains")); } }
    // A stored client secret belongs to the issuer that was configured with it.
    // Changing the issuer without supplying a new secret drops the old one so it
    // is never sent to a different identity provider.
    let new_issuer = body.get("oidc_issuer").and_then(|x| x.as_str());
    if let Some(issuer) = new_issuer {
        if !url_ok(issuer) { return Err(bad("oidc_issuer must be an http(s) URL")); }
        let stored_issuer = meta_get(&st, &format!("oidc_issuer:{}", oid));
        let supplied_secret = body.get("oidc_client_secret").and_then(|x| x.as_str()).unwrap_or("");
        if issuer != stored_issuer && supplied_secret.is_empty() { meta_set(&st, &format!("oidc_client_secret:{}", oid), ""); }
    }
    if let Some(v)=body.get("oidc_auto_provision").and_then(|x|x.as_bool()) { meta_set(&st, &format!("oidc_auto_provision:{}",oid), if v {"1"} else {"0"}); }
    for (field, enc) in [("oidc_issuer", false), ("oidc_client_id", false), ("oidc_redirect_uri", false), ("oidc_allowed_domains", false), ("oidc_client_secret", true)] {
        if let Some(v)=body.get(field).and_then(|x|x.as_str()) {
            // An omitted secret keeps the stored one; an explicit empty secret
            // clears it only when the caller asks for that.
            if field == "oidc_client_secret" && v.is_empty() && !body.get("clear_oidc_client_secret").and_then(|x|x.as_bool()).unwrap_or(false) { continue; }
            let stored = if enc { oc::encrypt_symmetric(&st.master(), v.as_bytes()) } else { v.to_string() };
            meta_set(&st, &format!("{}:{}", field, oid), &stored); } }
    st.audit(&oid, "", "", &uid, "org.settings", "");
    Ok(j(json!({"ok":true}))) }
async fn get_rotation_hook(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    let hook = st.db.one("SELECT url,secret_enc FROM rotation_hooks WHERE org_id=?", &[json!(&oid)]).map_err(|e| bad(&e))?;
    Ok(j(match hook { Some(row) => json!({"configured": true, "url": db::s(&row,"url"), "secret_set": !db::s(&row,"secret_enc").is_empty()}), None => json!({"configured": false}) })) }
async fn put_rotation_hook(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !url_ok(&url) || !egress_allowed(&url) { return Err(bad("rotation hook url must be http(s) and outside private networks unless OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let secret = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let existing = st.db.one("SELECT secret_enc FROM rotation_hooks WHERE org_id=?", &[json!(&oid)]).map_err(|e| bad(&e))?;
    let secret_enc = if secret.is_empty() { existing.as_ref().map(|r| db::s(r,"secret_enc")).unwrap_or_default() } else { oc::encrypt_symmetric(&st.master(), secret.as_bytes()) };
    if existing.is_some() {
        st.db.exec("UPDATE rotation_hooks SET url=?,secret_enc=? WHERE org_id=?", &[json!(&url), json!(&secret_enc), json!(&oid)]).map_err(|e| bad(&e))?;
    } else {
        st.db.exec("INSERT INTO rotation_hooks(org_id,url,secret_enc,created_at) VALUES(?,?,?,?)", &[json!(&oid), json!(&url), json!(&secret_enc), json!(now())]).map_err(|e| bad(&e))?;
    }
    st.audit(&oid, "", "", &uid, "rotation_hook.set", &url); Ok(j(json!({"ok": true}))) }
async fn delete_rotation_hook(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    st.db.exec("DELETE FROM rotation_hooks WHERE org_id=?", &[json!(&oid)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "rotation_hook.delete", ""); Ok(j(json!({"ok": true}))) }
async fn fire_rotation_hook(st: &S, org: &str, env: &str, key: &str, value: &str) -> Option<String> {
    let hook = match st.db.one("SELECT url,secret_enc FROM rotation_hooks WHERE org_id=?", &[json!(org)]) { Ok(Some(r)) => r, _ => return None };
    let url = db::s(&hook, "url"); if url.is_empty() { return None; }
    let secret = { let enc = db::s(&hook, "secret_enc"); if enc.is_empty() { String::new() } else { oc::decrypt_symmetric(&st.master(), &enc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() } };
    let payload = json!({"event": "secret.rotated", "org_id": org, "env_id": env, "key": key, "value": value, "ts": now()});
    let body = payload.to_string(); let signed_at = now();
    let mut req = http_client().post(&url).header("content-type", "application/json").body(body.clone());
    if !secret.is_empty() { let sig = hmac_hex(secret.as_bytes(), format!("{}.{}", signed_at, body).as_bytes()); req = req.header("X-OpenWarp-Timestamp", signed_at.to_string()).header("X-OpenWarp-Signature", format!("t={},v1={}", signed_at, sig)); }
    match req.send().await { Ok(r) if r.status().is_success() => None, Ok(r) => Some(format!("rotation hook returned HTTP {}", r.status())), Err(e) => Some(e.to_string()) } }
async fn rotate_secret(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org,app)=st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let key_name = body.get("key").and_then(|v|v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v|v.as_str()).unwrap_or("/");
    let new_val = body.get("value").and_then(|v|v.as_str()).map(|s|s.to_string()).unwrap_or_else(|| oc::random_token("rot"));
    let key = st.env_key(&eid)?; let khash = oc::hash_token(&format!("{}:{}", path, key_name.to_uppercase()));
    let row = st.db.one("SELECT id FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(khash)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found; create it first"))?;
    upsert_secret(&st,&eid,&key,&uid,&SecretIn{key:key_name.into(),value:new_val.clone(),path:path.into(),comment:"auto-rotation".into(),tags:"".into(),secret_type:"secret".into()})?;
    st.audit(&org,&app,&eid,&uid,"secret.rotate",key_name);
    let sync_errors = trigger_sync(&st, &eid, &uid).await;
    let rotation_hook_error = fire_rotation_hook(&st, &org, &eid, key_name, &new_val).await;
    Ok(j(json!({"key":key_name,"value":new_val,"secret_id":db::s(&row,"id"),"sync_errors":sync_errors,"rotation_hook_error":rotation_hook_error}))) }
fn scim_org(st: &S, h: &HeaderMap, q: &HashMap<String, String>) -> Result<String, (StatusCode, Json<Value>)> {
    if oauth_access(st, h).is_some() { return Err(err(StatusCode::FORBIDDEN, "OAuth access tokens cannot call SCIM; use a session or a service token")); }
    let uid = st.token_user(h)?;
    let oid = q.get("org_id").cloned().unwrap_or_default();
    if oid.is_empty() { return Err(bad("org_id query parameter required")); }
    let role = st.require_org(&oid, &uid)?;
    if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "SCIM requires admin of this organisation")); }
    Ok(oid) }
fn scim_member(st: &S, org: &str, user: &str) -> bool { st.db.one("SELECT user_id FROM org_members WHERE org_id=? AND user_id=?", &[json!(org), json!(user)]).ok().flatten().is_some() }
fn scim_page(q: &HashMap<String, String>) -> (usize, usize) {
    let start = q.get("startIndex").and_then(|s| s.parse::<usize>().ok()).unwrap_or(1).max(1);
    let count = q.get("count").and_then(|s| s.parse::<usize>().ok()).unwrap_or(100).clamp(1, 1000);
    (start, count) }
fn scim_eq_filter(q: &HashMap<String, String>) -> Option<String> {
    q.get("filter").and_then(|f| f.split(" eq ").nth(1)).map(|s| s.trim().trim_matches('"').to_string()) }
async fn scim_service_config() -> impl IntoResponse { Json(json!({
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "patch": {"supported": true}, "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
    "filter": {"supported": true, "maxResults": 1000}, "changePassword": {"supported": false},
    "sort": {"supported": false}, "etag": {"supported": false},
    "authenticationSchemes": [{"type": "bearer", "name": "Bearer", "primary": true}]
})) }
async fn scim_resource_types() -> impl IntoResponse { Json(json!([
    {"id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User"},
    {"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"}
])) }
async fn scim_schemas() -> impl IntoResponse { Json(json!([
    {"id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User",
     "attributes": [{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
                    {"name": "active", "type": "boolean"}, {"name": "emails", "type": "complex", "multiValued": true}]},
    {"id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group",
     "attributes": [{"name": "displayName", "type": "string", "required": true},
                    {"name": "members", "type": "complex", "multiValued": true}]}
])) }
async fn scim_create_user(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res {
    let org = scim_org(&st, &h, &q)?;
    let email = body.get("userName").and_then(|v| v.as_str()).unwrap_or(""); if email.is_empty() { return Err(bad("userName required")); }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("scim"); let nid = id();
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)", &[json!(nid), json!(email.to_lowercase()), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|_| bad("user exists"))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')", &[json!(org), json!(nid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id":nid,"userName":email,"active":true,"temp_password":pw}))) }
async fn scim_list_users(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res {
    let org = scim_org(&st, &h, &q)?;
    let (start, count) = scim_page(&q); let filter = scim_eq_filter(&q);
    let rows = if let Some(email) = filter {
        st.db.query("SELECT u.id AS id, u.email AS email FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? AND u.email=? ORDER BY u.created_at", &[json!(&org), json!(email.to_lowercase())]).map_err(|e| bad(&e))?
    } else {
        st.db.query("SELECT u.id AS id, u.email AS email FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? ORDER BY u.created_at", &[json!(&org)]).map_err(|e| bad(&e))?
    };
    let total = rows.len(); let page: Vec<Value> = rows.iter().skip(start - 1).take(count).map(|r| json!({"id":db::s(r,"id"),"userName":db::s(r,"email"),"active":true})).collect();
    let page_len = page.len();
    Ok(j(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": page, "totalResults": total, "startIndex": start, "itemsPerPage": page_len}))) }


async fn create_e2e_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if name.is_empty() || name.len() > 32 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c=='-' || c=='_') { return Err(bad("bad env name")); }
    let user = st.db.one("SELECT pubkey FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
    let eid = id();
    let provided = body.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
    let (wrapped, server_generated) = if provided.is_empty() {
        let env_key = oc::random_key(); (oc::encrypt_to(&db::s(&user,"pubkey"), &env_key).map_err(|e| bad(&e))?, true)
    } else { (provided.to_string(), false) };
    st.db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,'','e2e',?)", &[json!(eid), json!(aid), json!(name), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(eid), json!(uid), json!(wrapped)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": eid, "mode": "e2e", "server_generated": server_generated}))) }
async fn e2e_put(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r,"mode")).unwrap_or_default();
    if mode != "e2e" { return Err(bad("env is not in e2e mode")); }
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN, "no wrapped env key for caller")); }
    let mut count = 0;
    for s in body.get("secrets").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let key_enc = s.get("key_enc").and_then(|v| v.as_str()).unwrap_or(""); let value_enc = s.get("value_enc").and_then(|v| v.as_str()).unwrap_or("");
        let key_hash = s.get("key_hash").and_then(|v| v.as_str()).unwrap_or(""); let path = s.get("path").and_then(|v| v.as_str()).unwrap_or("/");
        if key_enc.is_empty() || key_hash.is_empty() { continue; }
        if let Some(row) = st.db.one("SELECT id,version FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(key_hash)]).map_err(|e| bad(&e))? {
            let ver = db::n(&row,"version")+1; let sid = db::s(&row,"id");
            st.db.exec("UPDATE secrets SET key_enc=?,value_enc=?,version=?,updated_at=?,updated_by=? WHERE id=?", &[json!(key_enc), json!(value_enc), json!(ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
            st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,created_at,created_by) VALUES(?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(ver), json!(key_enc), json!(value_enc), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        } else { let sid = id();
            st.db.exec("INSERT INTO secrets(id,env_id,path,key_enc,key_hash,value_enc,e2e,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,1,1,?,?)", &[json!(sid), json!(eid), json!(path), json!(key_enc), json!(key_hash), json!(value_enc), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
            st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,created_at,created_by) VALUES(?,?,1,?,?,?,?)", &[json!(id()), json!(sid), json!(key_enc), json!(value_enc), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        } count += 1;
    }
    st.audit(&org,&app,&eid,&uid,"secret.e2e_deploy",&format!("{} secrets",count)); Ok(j(json!({"deployed": count}))) }
async fn e2e_get(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let wrapped = st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN, "no wrapped env key for caller; ask a member to grant access"))?;
    let rows = st.db.query("SELECT id,path,key_enc,value_enc,version,updated_at FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1", &[json!(eid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"wrapped_key": db::s(&wrapped,"wrapped_key"), "secrets": rows.iter().map(db::obj).collect::<Vec<_>>()}))) }
async fn e2e_grant(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN, "caller has no env key to grant")); }
    let email = body.get("email").and_then(|v| v.as_str()).unwrap_or(""); let wrapped = body.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
    if email.is_empty() || wrapped.is_empty() { return Err(bad("email and wrapped_key (wrapped client-side for grantee) required")); }
    let target = st.db.one("SELECT id FROM users WHERE email=?", &[json!(email.to_lowercase())]).map_err(|e| bad(&e))?.ok_or_else(|| bad("user not found"))?;
    st.db.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(eid), json!(db::s(&target,"id")), json!(wrapped)]).map_err(|e| bad(&e))
        .or_else(|_| st.db.exec("UPDATE env_keys SET wrapped_key=? WHERE env_id=? AND user_id=?", &[json!(wrapped), json!(eid), json!(db::s(&target,"id"))]).map_err(|e| bad(&e)))?;
    Ok(j(json!({"ok": true}))) }
async fn e2e_grants(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT k.user_id AS user_id, u.email AS email FROM env_keys k JOIN users u ON u.id=k.user_id WHERE k.env_id=?", &[json!(&eid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn e2e_revoke(State(st): State<S>, h: HeaderMap, Path((eid, target)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let deleted = st.db.exec("DELETE FROM env_keys WHERE env_id=? AND user_id=?", &[json!(&eid), json!(&target)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(err(StatusCode::NOT_FOUND, "no key grant for that user")); }
    st.audit(&org,&app,&eid,&uid,"e2e.revoke",&target); Ok(j(json!({"revoked": target}))) }
async fn user_lookup(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?;
    let email = q.get("email").cloned().unwrap_or_default();
    // One response for "no such account" and "exists but shares no organisation"
    // so the endpoint is not an account-existence oracle.
    let denied = || err(StatusCode::FORBIDDEN, "no user with this email shares an organisation with you");
    let row = st.db.one("SELECT id,email,pubkey FROM users WHERE email=?", &[json!(email.to_lowercase())]).map_err(|e| bad(&e))?.ok_or_else(denied)?;
    let tid = db::s(&row, "id");
    if tid != uid { let shared = st.db.query("SELECT a.org_id FROM org_members a JOIN org_members b ON b.org_id=a.org_id WHERE a.user_id=? AND b.user_id=?", &[json!(uid), json!(&tid)]).map_err(|e| bad(&e))?; if shared.is_empty() { return Err(denied()); } }
    Ok(j(json!({"id": db::s(&row,"id"), "email": db::s(&row,"email"), "pubkey": db::s(&row,"pubkey")}))) }


fn meta_get(st: &S, k: &str) -> String { st.db.one("SELECT v FROM meta WHERE k=?", &[json!(k)]).ok().flatten().map(|r| db::s(&r,"v")).unwrap_or_default() }
fn url_ok(u: &str) -> bool { let u = u.trim().to_ascii_lowercase(); (u.starts_with("https://") || u.starts_with("http://")) && !u.contains(' ') && !u.contains('\n') }
// Admin-configured URLs are trusted, but production should not be usable as a
// probe into loopback or private networks. Self-hosted services can opt out.
fn egress_allowed(u: &str) -> bool {
    if std::env::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false) { return true; }
    if !std::env::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) { return true; }
    let Ok(url) = reqwest::Url::parse(u) else { return false };
    let Some(host) = url.host_str() else { return false };
    if host.eq_ignore_ascii_case("localhost") { return false; }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()),
            std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local()),
        };
    }
    true }
// Outbound OIDC/SAML metadata may only use TLS, except for a loopback IdP used in
// development or tests. Link-local metadata addresses are always refused.
fn issuer_url_ok(issuer: &str) -> bool {
    let u = issuer.trim().to_ascii_lowercase();
    if !url_ok(&u) { return false; }
    if u.contains("169.254.169.254") || u.contains("metadata.google.internal") { return false; }
    if u.starts_with("https://") { return true; }
    let host = u.trim_start_matches("http://").split(['/', ':']).next().unwrap_or("");
    host == "127.0.0.1" || host == "localhost" || host == "[::1]" }
fn http_client() -> reqwest::Client { reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| reqwest::Client::new()) }
// Dynamic Postgres leases dial a host from the request. Nothing may dial unless
// the operator named that host: this is the SSRF boundary for the feature.
fn db_target_allowed(conn: &str) -> Result<(), String> {
    let allow = std::env::var("OPENWARP_ALLOWED_DB_HOSTS").unwrap_or_default();
    let entries: Vec<String> = allow.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if entries.is_empty() { return Err("dynamic Postgres leases are disabled; set OPENWARP_ALLOWED_DB_HOSTS=host[:port],... to enable them".into()); }
    let rest = conn.split_once("://").map(|x| x.1).ok_or("connection string must be a postgres:// URL")?;
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.contains(',') { return Err("multi-host connection strings are not allowed".into()); }
    let hostport = authority.rsplit('@').next().unwrap_or("");
    if hostport.is_empty() { return Err("connection string has no host".into()); }
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, tail) = inner.split_once(']').ok_or("invalid IPv6 host")?;
        (h.to_string(), tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(5432))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse::<u16>().unwrap_or(5432)),
            _ => (hostport.to_string(), 5432) } };
    if host.is_empty() { return Err("connection string has no host".into()); }
    let target = format!("{}:{}", host, port);
    if entries.iter().any(|e| *e == host || *e == target) { return Ok(()); }
    Err(format!("postgres host is not permitted; OPENWARP_ALLOWED_DB_HOSTS must list {} (allowed: {})", target, entries.join(","))) }
async fn oidc_discovery(issuer: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    http_client().get(&url).send().await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string())) }
async fn oidc_start(State(st): State<S>, Path(oid): Path<String>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)); let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)); let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid));
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid));
    let client_secret = oc::decrypt_symmetric(&st.master(), &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    if issuer.is_empty() || client_id.is_empty() || redirect_uri.is_empty() { return Err(bad("OIDC not configured for this org (set oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri via org settings)")); }
    if client_secret.is_empty() { return Err(bad("OIDC client secret is not configured or was cleared by an issuer change; re-enter the client secret in org settings")); }
    if !issuer_url_ok(&issuer) || !egress_allowed(&issuer) { return Err(bad("OIDC issuer must be https, or http on a loopback address; private addresses need OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let disc = oidc_discovery(&issuer).await?; let auth_ep = disc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    if !url_ok(auth_ep) || !egress_allowed(auth_ep) { return Err(bad("OIDC discovery returned no usable authorization_endpoint")); }
    let state = oc::random_token("st"); let nonce = oc::random_token("n");
    st.db.exec("INSERT INTO oidc_states(state,org_id,created_at,nonce) VALUES(?,?,?,?)", &[json!(state), json!(oid), json!(now()), json!(nonce)]).map_err(|e| bad(&e))?;
    let url = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&nonce={}", auth_ep, urlencode(&client_id), urlencode(&redirect_uri), state, nonce);
    Ok(axum::response::Redirect::temporary(&url)) }
fn urlencode(s: &str) -> String { s.chars().map(|c| match c { 'A'..='Z'|'a'..='z'|'0'..='9'|'-'|'_'|'.'|'~' => c.to_string(), _ => format!("%{:02X}", c as u32) }).collect() }
async fn oidc_callback(State(st): State<S>, Query(q): Query<HashMap<String,String>>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let code = q.get("code").cloned().unwrap_or_default(); let state = q.get("state").cloned().unwrap_or_default();
    let srow = st.db.one("SELECT org_id,created_at,nonce FROM oidc_states WHERE state=?", &[json!(state)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    let oid = db::s(&srow, "org_id"); let expected_nonce = db::s(&srow, "nonce");
    let _ = st.db.exec("DELETE FROM oidc_states WHERE state=?", &[json!(state)]);
    if db::n(&srow, "created_at") + 600 < now() { return Err(bad("invalid or expired state")); }
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)); let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)); let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid));
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid)); let client_secret = oc::decrypt_symmetric(&st.master(), &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    if !issuer_url_ok(&issuer) || !egress_allowed(&issuer) { return Err(bad("OIDC issuer must be https, or http on a loopback address; private addresses need OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let disc = oidc_discovery(&issuer).await?;
    let (subject, email) = oidc_identity_from_doc(&disc, &issuer, &client_id, &client_secret, &redirect_uri, &code, "", &expected_nonce, false, if issuer.contains("login.microsoftonline.com") { "microsoft" } else { "oidc" }).await.map_err(|e| bad(&e))?;
    let issuer_key = issuer.clone();
    // An SSO login may attach an account to this organisation only through a
    // pending invite, or when the org explicitly enables auto-provisioning for
    // this email domain. Instance-wide signups are not enough.
    let pending = st.db.one("SELECT role,token_hash FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(&email), json!(&oid), json!(now())]).map_err(|e| bad(&e))?;
    let auto = meta_get(&st, &format!("oidc_auto_provision:{}", oid)) == "1";
    let domains = meta_get(&st, &format!("oidc_allowed_domains:{}", oid));
    let domain = email.split('@').nth(1).unwrap_or("");
    let domain_ok = domains.is_empty() || domains.split(',').any(|d| d.trim().eq_ignore_ascii_case(domain));
    let provision_allowed = pending.is_some() || (auto && domain_ok && signups_open(&st));
    let uid = if let Some(bound) = st.db.one("SELECT user_id FROM oidc_subjects WHERE issuer=? AND subject=?", &[json!(issuer_key), json!(subject)]).map_err(|e| bad(&e))? { db::s(&bound, "user_id") } else {
        if st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password, or ask an organisation admin to link this identity")); }
        if !provision_allowed { return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow SSO self-provisioning; ask an administrator to invite you or enable it in organisation settings")); }
        let kp = oc::Keypair::generate(); let pw = oc::random_token("oidc"); let nid = id();
        // The organisation's IdP asserted this address; no local verification.
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)", &[json!(nid), json!(email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO oidc_subjects(issuer,subject,user_id,created_at) VALUES(?,?,?,?)", &[json!(issuer_key), json!(subject), json!(nid), json!(now())]).map_err(|e| bad(&e))?;
        claim_instance_owner(&st, &nid);
        nid };
    if let Some(u) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))? { if db::n(&u, "active") == 0 { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); } }
    if st.org_role(&oid, &uid).is_none() {
        if let Some(inv) = &pending {
            st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(&oid), json!(&uid), json!(db::s(inv, "role"))]).map_err(|e| bad(&e))?;
            let _ = st.db.exec("UPDATE invites SET accepted=1 WHERE token_hash=?", &[json!(db::s(inv, "token_hash"))]);
        } else if auto && domain_ok && signups_open(&st) {
            st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')", &[json!(&oid), json!(&uid)]).map_err(|e| bad(&e))?;
        } else {
            return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow SSO self-provisioning; ask an administrator to invite you or enable it in organisation settings"));
        } }
    st.audit(&oid,"","",&uid,"auth.oidc_login",&format!("{} sub={}", email, subject));
    let token = make_session(&st, &uid)?;
    Ok(axum::response::Redirect::temporary(&format!("/#token={}&org={}", token, oid))) }

// ---------- SAML 2.0 service provider ----------
struct SamlReplayCache { st: S }
impl ReplayCache for SamlReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        let expires = expires_at.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_else(|_| now() + 600);
        match self.st.db.exec("INSERT INTO saml_replay(key,expires_at) VALUES(?,?)", &[json!(cache_key), json!(expires)]) {
            Ok(_) => Ok(()),
            Err(_) => Err(SamlError::ReplayDetected { key: cache_key }),
        } } }
fn saml_config_row(st: &S, org: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    st.db.one("SELECT * FROM saml_configs WHERE org_id=?", &[json!(org)]).map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "SAML is not configured for this organisation")) }
fn saml_sp_entity(base: &str, org: &str) -> String { format!("{}/api/auth/saml/{}/metadata", base.trim_end_matches('/'), org) }
fn saml_acs_url(base: &str, org: &str) -> String { format!("{}/api/auth/saml/{}/acs", base.trim_end_matches('/'), org) }
fn saml_signing_keypair(cn: &str) -> Result<(String, String), String> {
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|e| e.to_string())?;
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).map_err(|e| e.to_string())?.to_string();
    let kp = rcgen::KeyPair::from_pem(&pem).map_err(|e| e.to_string())?;
    let cert = ca_params(cn, false).self_signed(&kp).map_err(|e| e.to_string())?;
    Ok((pem, cert.pem())) }
fn saml_descriptor(idp_entity: &str, xml: &str, trusted_cert: &str, allow_unsigned: bool) -> Result<IdpDescriptor, String> {
    let entity = EntityId::try_new(idp_entity).map_err(|e| e.to_string())?;
    if !trusted_cert.trim().is_empty() {
        let certs = [CertificatePem::new(trusted_cert.trim().to_string())];
        IdpDescriptor::from_metadata_xml_for(entity, xml, MetadataTrustPolicy::RequireSignature { trusted_certificates: &certs }).map_err(|e| e.to_string())
    } else if allow_unsigned {
        IdpDescriptor::from_metadata_xml_for(entity, xml, MetadataTrustPolicy::UnsignedForCompatibility).map_err(|e| e.to_string())
    } else { Err("SAML metadata must be signed by metadata_trusted_cert, or set allow_unsigned_metadata".into()) } }
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
async fn get_saml_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    let cfg = saml_config_row(&st, &oid)?; let base = issuer(&st, &h);
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
async fn put_saml_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
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
    let existing = st.db.one("SELECT sp_key_enc,sp_cert_pem FROM saml_configs WHERE org_id=?", &[json!(&oid)]).map_err(|e| bad(&e))?;
    let (key_enc, cert_pem) = match existing {
        Some(ref row) => (db::s(row,"sp_key_enc"), db::s(row,"sp_cert_pem")),
        None => {
            let (key_pem, cert_pem) = saml_signing_keypair(&format!("openwarp-saml-{}", oid)).map_err(|e| bad(&e))?;
            (oc::encrypt_symmetric(&st.master(), key_pem.as_bytes()), cert_pem)
        }
    };
    if existing.is_some() {
        st.db.exec("UPDATE saml_configs SET idp_entity_id=?,idp_metadata_xml=?,allow_unsigned_metadata=?,metadata_trusted_cert=?,auto_provision=?,allowed_domains=? WHERE org_id=?",
            &[json!(&idp_entity_id), json!(&xml), json!(if allow_unsigned {1} else {0}), json!(&trusted_cert), json!(if auto {1} else {0}), json!(&domains), json!(&oid)]).map_err(|e| bad(&e))?;
    } else {
        st.db.exec("INSERT INTO saml_configs(org_id,idp_entity_id,idp_metadata_xml,sp_key_enc,sp_cert_pem,allow_unsigned_metadata,metadata_trusted_cert,auto_provision,allowed_domains,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            &[json!(&oid), json!(&idp_entity_id), json!(&xml), json!(&key_enc), json!(&cert_pem), json!(if allow_unsigned {1} else {0}), json!(&trusted_cert), json!(if auto {1} else {0}), json!(&domains), json!(now())]).map_err(|e| bad(&e))?;
    }
    st.audit(&oid, "", "", &uid, "saml.configure", &idp_entity_id);
    Ok(j(json!({"ok": true, "sp_metadata_url": saml_sp_entity(&issuer(&st,&h), &oid)}))) }
async fn saml_metadata(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Response {
    let cfg = match saml_config_row(&st, &oid) { Ok(c) => c, Err(e) => return e.into_response() };
    let sp = match saml_sp_config(&st, &issuer(&st,&h), &oid, &cfg).and_then(|c| Saml::sp(c).map_err(|e| e.to_string())) { Ok(s) => s, Err(e) => return bad(&e).into_response() };
    let mut resp = sp.metadata_xml().to_string().into_response();
    resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/samlmetadata+xml"));
    resp }
async fn saml_start(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Response {
    let cfg = match saml_config_row(&st, &oid) { Ok(c) => c, Err(e) => return e.into_response() };
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
    let _ = st.db.exec("DELETE FROM saml_pending WHERE created_at<?", &[json!(now() - 600)]);
    if let Err(e) = st.db.exec("INSERT INTO saml_pending(state,org_id,snapshot,created_at) VALUES(?,?,?,?)", &[json!(&state), json!(&oid), json!(&snapshot), json!(now())]) { return bad(&e).into_response(); }
    axum::response::Redirect::temporary(&url).into_response() }
fn provision_saml_user(st: &S, org: &str, idp_entity: &str, name_id: &str, email: &str) -> Result<String, (StatusCode, Json<Value>)> {
    if let Some(bound) = st.db.one("SELECT user_id FROM saml_subjects WHERE org_id=? AND idp_entity_id=? AND name_id=?", &[json!(org), json!(idp_entity), json!(name_id)]).map_err(|e| bad(&e))? {
        let uid = db::s(&bound, "user_id");
        if !st.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        return Ok(uid);
    }
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password or ask an admin to link this SAML identity"));
    }
    let cfg = saml_config_row(st, org)?;
    let pending = st.db.one("SELECT role,token_hash FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(email), json!(org), json!(now())]).map_err(|e| bad(&e))?;
    let auto = db::n(&cfg, "auto_provision") == 1;
    let domains = db::s(&cfg, "allowed_domains");
    let domain = email.split('@').nth(1).unwrap_or("");
    let domain_ok = domains.is_empty() || domains.split(',').any(|d| d.trim().eq_ignore_ascii_case(domain));
    if pending.is_none() && !(auto && domain_ok && signups_open(st)) {
        return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow SAML self-provisioning; ask an administrator to invite you"));
    }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("saml"); let uid = id();
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)",
        &[json!(&uid), json!(email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO saml_subjects(org_id,idp_entity_id,name_id,user_id,created_at) VALUES(?,?,?,?,?)",
        &[json!(org), json!(idp_entity), json!(name_id), json!(&uid), json!(now())]).map_err(|e| bad(&e))?;
    let role = pending.as_ref().map(|p| db::s(p, "role")).unwrap_or_else(|| "developer".to_string());
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(org), json!(&uid), json!(role)]).map_err(|e| bad(&e))?;
    if let Some(inv) = &pending { let _ = st.db.exec("UPDATE invites SET accepted=1 WHERE token_hash=?", &[json!(db::s(inv,"token_hash"))]); }
    claim_instance_owner(st, &uid);
    st.audit(org, "", "", &uid, "auth.saml_provision", &format!("{} {}", email, name_id));
    Ok(uid) }
async fn saml_acs(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> Response {
    let pending_row = match st.db.one("SELECT * FROM saml_pending WHERE org_id=? AND state=?", &[json!(&oid), json!(form.get("RelayState").cloned().unwrap_or_default())]) { Ok(Some(r)) => r, _ => return bad("SAML request is missing, expired, or already used").into_response() };
    if db::n(&pending_row,"created_at") + 600 < now() { return bad("SAML request expired").into_response(); }
    let snapshot: Value = match serde_json::from_str(&db::s(&pending_row,"snapshot")) { Ok(v) => v, Err(_) => return bad("SAML pending request is corrupt").into_response() };
    let cfg = match saml_config_row(&st, &oid) { Ok(c) => c, Err(e) => return e.into_response() };
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
    let ctx = SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));
    let fields: Vec<FormField> = form.iter().map(|(k,v)| FormField::new(k.clone(), v.clone())).collect();
    let session = match sp.finish_sso(&idp, &pending, BrowserInput::<SsoResponse>::post(fields), ctx) { Ok(s) => s, Err(e) => return bad(&format!("SAML validation failed: {}", e)).into_response() };
    let name_id = session.name_id().value().to_string(); let email = name_id.to_lowercase();
    if !valid_email(&email) { return bad("SAML NameID must be an email address; configure the IdP NameID format").into_response(); }
    let uid = match provision_saml_user(&st, &oid, &db::s(&cfg,"idp_entity_id"), &name_id, &email) { Ok(u) => u, Err(e) => return e.into_response() };
    let _ = st.db.exec("DELETE FROM saml_pending WHERE state=?", &[json!(form.get("RelayState").cloned().unwrap_or_default())]);
    let token = match make_session(&st, &uid) { Ok(t) => t, Err(e) => return e.into_response() };
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    (hdr, axum::response::Redirect::to(&format!("/#org={}", oid))).into_response() }
// ---------- LDAP directory sign-in ----------
// The directory validates the password, so this path shares the password
// login's rate limits, MFA challenge and audit trail. It is compiled out when
// the `ldap` feature is off (a Workers/WASM build has no raw TCP sockets).
#[cfg(feature = "ldap")]
fn ldap_row(st: &S, org: &str) -> Result<Option<Row>, (StatusCode, Json<Value>)> {
    st.db.one("SELECT * FROM ldap_configs WHERE org_id=?", &[json!(org)]).map_err(|e| bad(&e)) }
#[cfg(feature = "ldap")]
fn role_known(st: &S, org: &str, role: &str) -> bool {
    matches!(role, "owner" | "admin" | "developer")
        || st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(org), json!(role)]).ok().flatten().is_some() }
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
    let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    let Some(row) = ldap_row(&st, &oid)? else { return Ok(j(json!({"configured": false}))) };
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
    let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    let existing = ldap_row(&st, &oid)?;
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
    if group_roles.split(';').filter_map(|p| p.rsplit_once('=')).any(|(_, r)| !role_known(&st, &oid, r.trim())) {
        return Err(bad("group_roles may only reference roles that exist in this organisation; create the role first")); }
    let default_role = ldap_field(&body, existing.as_ref(), "default_role");
    let default_role = if default_role.is_empty() { "developer".to_string() } else { default_role };
    if !role_known(&st, &oid, &default_role) { return Err(bad("default_role must be owner, admin, developer or a custom role in this organisation")); }
    // The membership API lets only an owner grant owner or admin; a directory
    // mapping must not become the side door around that rule. Custom roles are
    // checked by effective permissions, because one carrying "*" or
    // "org:admin" is admin by another name.
    let requested = std::iter::once(default_role.clone()).chain(
        group_roles.split(';').filter_map(|p| p.rsplit_once('=')).map(|(_, r)| r.trim().to_string()));
    let privileged = requested.into_iter().any(|role| {
        st.role_perms(&oid, &role).iter().any(|p| p == "*" || p == "org:admin") });
    if privileged && st.require_org(&oid, &uid)? != "owner" {
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
    let password_enc = if supplied.is_empty() { stored } else { oc::encrypt_symmetric(&st.master(), supplied.as_bytes()) };
    if password_enc.is_empty() { return Err(bad("bind_password is required: LDAP search needs a service account")); }
    if existing.is_some() {
        st.db.exec("UPDATE ldap_configs SET url=?,bind_dn=?,bind_password_enc=?,base_dn=?,user_filter=?,email_attr=?,name_attr=?,group_attr=?,group_roles=?,default_role=?,auto_provision=?,allowed_domains=?,ca_cert_pem=?,updated_at=? WHERE org_id=?",
            &[json!(&url), json!(&bind_dn), json!(&password_enc), json!(&base_dn), json!(&user_filter), json!(&email_attr), json!(&name_attr), json!(&group_attr), json!(&group_roles), json!(&default_role), json!(if auto {1} else {0}), json!(&allowed_domains), json!(&ca_cert_pem), json!(now()), json!(&oid)]).map_err(|e| bad(&e))?;
    } else {
        st.db.exec("INSERT INTO ldap_configs(org_id,url,bind_dn,bind_password_enc,base_dn,user_filter,email_attr,name_attr,group_attr,group_roles,default_role,auto_provision,allowed_domains,ca_cert_pem,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            &[json!(&oid), json!(&url), json!(&bind_dn), json!(&password_enc), json!(&base_dn), json!(&user_filter), json!(&email_attr), json!(&name_attr), json!(&group_attr), json!(&group_roles), json!(&default_role), json!(if auto {1} else {0}), json!(&allowed_domains), json!(&ca_cert_pem), json!(now())]).map_err(|e| bad(&e))?;
    }
    // Bindings belong to the directory that was configured when they were
    // created. A new endpoint must not inherit them, or an admin could point
    // the URL at a directory that asserts an existing member's DN.
    if url_changed { let _ = st.db.exec("DELETE FROM ldap_subjects WHERE org_id=?", &[json!(&oid)]); }
    st.audit(&oid, "", "", &uid, "ldap.configure", &format!("{} url_changed={}", url, url_changed));
    Ok(j(json!({"ok": true}))) }
#[cfg(feature = "ldap")]
async fn delete_ldap_config(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    st.db.exec("DELETE FROM ldap_configs WHERE org_id=?", &[json!(&oid)]).map_err(|e| bad(&e))?;
    let _ = st.db.exec("DELETE FROM ldap_subjects WHERE org_id=?", &[json!(&oid)]);
    st.audit(&oid, "", "", &uid, "ldap.delete", "");
    Ok(j(json!({"ok": true}))) }
#[cfg(feature = "ldap")]
#[derive(Deserialize)] struct LdapLoginReq { org_id: String, username: String, password: String }
#[cfg(feature = "ldap")]
async fn ldap_login(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<LdapLoginReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let org = r.org_id.trim().to_string();
    let username = r.username.trim().to_string();
    // Two budgets: one per account and one per address, so spraying many names
    // from one host is limited even when each name is tried only once.
    let ip_key = format!("ldap-ip:{}", addr.ip());
    if !st.rate_ok(&ip_key, 30, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many directory sign-in attempts from this address; try again later")); }
    let key = format!("ldap:{}:{}:{}", addr.ip(), org, username.to_lowercase());
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed directory sign-in attempts; try again later")); }
    // Count before contacting the directory: a read-then-write check lets
    // concurrent guesses all pass while no failure has been recorded yet.
    st.rate_fail(&key, 900); st.rate_fail(&ip_key, 900);
    if org.is_empty() { return Err(bad("org_id is required")); }
    let Some(row) = ldap_row(&st, &org)? else { return Err(bad("LDAP sign-in is not configured for this workspace; ask an administrator to set it up")); };
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
    st.rate_clear(&key);
    if !ldap::valid_email(&user.email) { return Err(bad("the directory entry has no usable email attribute; check email_attr")); }
    let mapped = ldap::mapping_role(&cfg.group_roles, &user.groups).filter(|role| role_known(&st, &org, role));
    let pending = st.db.one("SELECT role,token_hash FROM invites WHERE email=? AND org_id=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(&user.email), json!(&org), json!(now())]).map_err(|e| bad(&e))?;
    let domain = user.email.rsplit_once('@').map(|(_, d)| d).unwrap_or("").to_string();
    let domain_ok = cfg.allowed_domains.is_empty() || cfg.allowed_domains.split(',').any(|d| d.trim().eq_ignore_ascii_case(&domain));
    let bound = st.db.one("SELECT user_id,role FROM ldap_subjects WHERE org_id=? AND dn=?", &[json!(&org), json!(&user.dn)]).map_err(|e| bad(&e))?;
    let stored_role = bound.as_ref().map(|b| db::s(b, "role")).unwrap_or_default();
    let uid = if let Some(b) = &bound {
        let uid = db::s(b, "user_id");
        if !st.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        uid
    } else {
        if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&user.email)]).map_err(|e| bad(&e))?.is_some() {
            return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password, or ask an organisation admin to link this identity"));
        }
        // Same gate as OIDC: an invitation, or explicitly enabled
        // self-provisioning for an allowed email domain while signups are open.
        if pending.is_none() && !(db::n(&row, "auto_provision") == 1 && domain_ok && signups_open(&st)) {
            return Err(err(StatusCode::FORBIDDEN, "this organisation does not allow LDAP self-provisioning; ask an administrator to invite you or enable it in organisation settings"));
        }
        let kp = oc::Keypair::generate(); let pw = oc::random_token("ldap"); let nid = id();
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)",
            &[json!(&nid), json!(&user.email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO ldap_subjects(org_id,dn,user_id,created_at) VALUES(?,?,?,?)",
            &[json!(&org), json!(&user.dn), json!(&nid), json!(now())]).map_err(|e| bad(&e))?;
        claim_instance_owner(&st, &nid);
        st.audit(&org, "", "", &nid, "auth.ldap_provision", &format!("{} {} dn={}", audit_safe(&user.email), audit_safe(&user.name), audit_safe(&user.dn)));
        nid };
    if st.org_role(&org, &uid).is_none() {
        // A bound directory user is re-admitted only through a fresh invite;
        // otherwise removing a member would be undone by their next sign-in.
        if bound.is_some() && pending.is_none() {
            return Err(err(StatusCode::FORBIDDEN, "this account is no longer a member of this organisation; ask an administrator to invite you again"));
        }
        let role = mapped.clone().or_else(|| pending.as_ref().map(|p| db::s(p, "role"))).unwrap_or_else(|| db::s(&row, "default_role"));
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(&org), json!(&uid), json!(role)]).map_err(|e| bad(&e))?;
        if let Some(inv) = &pending { let _ = st.db.exec("UPDATE invites SET accepted=1 WHERE token_hash=?", &[json!(db::s(inv, "token_hash"))]); }
        // Record a role that came from the group map, so leaving the group can
        // revoke it later. Invite and default roles are not directory-derived.
        let mapped_role = if mapped.is_some() { role } else { String::new() };
        let _ = st.db.exec("UPDATE ldap_subjects SET role=? WHERE org_id=? AND dn=?", &[json!(&mapped_role), json!(&org), json!(&user.dn)]);
    } else {
        let current = st.org_role(&org, &uid).unwrap_or_default();
        if let Some(role) = &mapped {
            // The directory's group mapping stays authoritative, except that it
            // never demotes an owner: a group change must not lock out the only one.
            if &current != role && current != "owner" {
                st.db.exec("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?", &[json!(role), json!(&org), json!(&uid)]).map_err(|e| bad(&e))?;
            }
            if current != "owner" {
                let _ = st.db.exec("UPDATE ldap_subjects SET role=? WHERE org_id=? AND dn=?", &[json!(role), json!(&org), json!(&user.dn)]);
            }
        } else if !stored_role.is_empty() && current == stored_role && current != "owner" {
            // The user left the mapped group: revoke a directory-granted role,
            // unless a human has changed it since.
            let fallback = db::s(&row, "default_role");
            st.db.exec("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?", &[json!(&fallback), json!(&org), json!(&uid)]).map_err(|e| bad(&e))?;
            let _ = st.db.exec("UPDATE ldap_subjects SET role='' WHERE org_id=? AND dn=?", &[json!(&org), json!(&user.dn)]);
        }
    }
    st.audit(&org, "", "", &uid, "auth.ldap_credentials", &format!("{} {} dn={}", audit_safe(&user.email), audit_safe(&user.name), audit_safe(&user.dn)));
    if meta_get(&st, &format!("totp_enabled:{}", uid)) == "1" {
        st.audit(&org, "", "", &uid, "auth.ldap_mfa_challenge", &audit_safe(&user.email));
        let challenge = oc::random_token("mfa");
        st.db.exec("INSERT INTO mfa_challenges(token,user_id,created_at) VALUES(?,?,?)", &[json!(&challenge), json!(&uid), json!(now())]).map_err(|e| bad(&e))?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge})))); }
    let token = make_session(&st, &uid)?;
    st.audit(&org, "", "", &uid, "auth.ldap_login", &format!("{} dn={}", audit_safe(&user.email), audit_safe(&user.dn)));
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    let pubkey = st.db.one("SELECT pubkey FROM users WHERE id=?", &[json!(&uid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "pubkey")).unwrap_or_default();
    Ok((hdr, j(json!({"token": token, "user_id": uid, "public_key": pubkey})))) }

// ---------- email, verification and password reset ----------
fn production() -> bool {
    std::env::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) }
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
async fn test_email(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "instance owner required")); }
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if to.is_empty() { return Err(bad("to is required")); }
    let cfg = mailer::MailConfig::from_env();
    if !cfg.enabled() { return Err(bad("no email provider is configured")); }
    let msg = mailer::render("test", to, &[]);
    mailer::send(&cfg, &msg).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"ok": true, "provider": cfg.provider}))) }
fn issue_auth_token(st: &S, uid: &str, kind: &str, ttl: i64) -> String {
    let token = oc::random_token(kind);
    let _ = st.db.exec("INSERT INTO auth_tokens(token_hash,user_id,kind,created_at,expires_at) VALUES(?,?,?,?,?)", &[json!(oc::hash_token(&token)), json!(uid), json!(kind), json!(now()), json!(now() + ttl)]);
    token }
#[derive(Deserialize)] struct EmailReq { email: String }
#[derive(Deserialize)] struct ResetReq { token: String, password: String, #[serde(default)] recovery_kit: String, #[serde(default)] discard_e2e_key: bool }
async fn verify_email(State(st): State<S>, Query(q): Query<HashMap<String,String>>) -> Response {
    let token = q.get("token").cloned().unwrap_or_default(); let hash = oc::hash_token(token.trim());
    let found = st.db.one("SELECT user_id FROM auth_tokens WHERE token_hash=? AND kind='verify' AND used=0 AND expires_at>?", &[json!(&hash), json!(now())]).ok().flatten();
    let (status, title, detail) = match found {
        Some(row) => { let uid = db::s(&row, "user_id");
            let _ = st.db.exec("UPDATE users SET email_verified=1 WHERE id=?", &[json!(&uid)]);
            let _ = st.db.exec("UPDATE auth_tokens SET used=1 WHERE token_hash=?", &[json!(&hash)]);
            claim_instance_owner_on_verify(&st, &uid);
            st.audit("", "", "", &uid, "auth.email_verified", "");
            (StatusCode::OK, "Email verified", "You can sign in now.") }
        None => (StatusCode::BAD_REQUEST, "Link not valid", "This verification link is invalid, already used, or expired.") };
    let mut r = Html(format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>OpenWarp</title></head><body style=\"margin:0;background:#08080c;color:#eceaf8;font:15px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;min-height:100vh\"><main style=\"max-width:520px;padding:28px\"><h1 style=\"font-size:20px\">{}</h1><p style=\"color:#9a97b3\">{}</p><p><a style=\"color:#9d8fff\" href=\"/\">Open the console</a></p></main></body></html>", esc(title), esc(detail))).into_response();
    *r.status_mut() = status;
    r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(OAUTH_CSP));
    r }
async fn forgot_password(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, h: HeaderMap, Json(r): Json<EmailReq>) -> Res {
    let key = format!("forgot:{}", addr.ip());
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many reset requests; try again later")); }
    st.rate_fail(&key, 900);
    let email = r.email.trim().to_lowercase();
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE email=? AND active=1", &[json!(&email)]) {
        let uid = db::s(&row, "id"); let token = issue_auth_token(&st, &uid, "reset", 3600);
        let link = format!("{}/#reset={}", issuer(&st, &h), token);
        send_template(&email, "reset", &[("link", &link), ("email", &email)]).await;
        st.audit("", "", "", &uid, "auth.password_reset_requested", "");
    }
    // Same answer whether or not the address exists.
    Ok(j(json!({"ok": true, "note": "if that address has an account, a reset link is on its way"}))) }
async fn resend_verification(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, h: HeaderMap, Json(r): Json<EmailReq>) -> Res {
    let key = format!("verify-resend:{}", addr.ip());
    if !st.rate_ok(&key, 5, 3600) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many verification requests; try again later")); }
    st.rate_fail(&key, 3600);
    let email = r.email.trim().to_lowercase();
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE email=? AND active=1 AND email_verified=0", &[json!(&email)]) {
        let uid = db::s(&row, "id"); let token = issue_auth_token(&st, &uid, "verify", 86400);
        let link = format!("{}/api/auth/verify?token={}", issuer(&st, &h), token);
        send_template(&email, "verify", &[("link", &link), ("email", &email)]).await;
    }
    Ok(j(json!({"ok": true}))) }
async fn reset_password(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<ResetReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let key = format!("reset:{}", addr.ip());
    if !st.rate_ok(&key, 10, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again later")); }
    if r.password.len() < 8 { return Err(bad("password (>=8 chars) required")); }
    let hash = oc::hash_token(r.token.trim());
    let row = st.db.one("SELECT user_id FROM auth_tokens WHERE token_hash=? AND kind='reset' AND used=0 AND expires_at>?", &[json!(&hash), json!(now())]).map_err(|e| bad(&e))?.ok_or_else(|| bad("reset link is invalid, already used, or expired"))?;
    let uid = db::s(&row, "user_id");
    let user = st.db.one("SELECT email,pubkey,email_verified FROM users WHERE id=?", &[json!(&uid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("account not found"))?;
    st.rate_fail(&key, 900);
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
    st.db.exec("UPDATE users SET pass_hash=?,pubkey=?,wrapped_privkey=?,email_verified=1 WHERE id=?", &[json!(pass), json!(pubkey), json!(wrapped), json!(&uid)]).map_err(|e| bad(&e))?;
    let _ = st.db.exec("UPDATE auth_tokens SET used=1 WHERE token_hash=?", &[json!(&hash)]);
    let _ = st.db.exec("DELETE FROM sessions WHERE user_id=?", &[json!(&uid)]);
    let _ = st.db.exec("DELETE FROM oauth_tokens WHERE user_id=?", &[json!(&uid)]);
    st.audit("", "", "", &uid, "auth.password_reset", if replaced { "key replaced" } else { "kit supplied" });
    let session = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap());
    Ok((hdr, j(json!({"token": session, "user_id": uid, "e2e_key_replaced": replaced})))) }

// ---------- instance settings + Google/GitHub sign-in ----------
fn signups_open(st: &S) -> bool {
    match std::env::var("OPENWARP_SIGNUPS") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "closed" | "invite" | "invite_only" | "0" | "false"),
        Err(_) => meta_get(st, "signups_open") != "0" } }
// The first account ever created owns instance-level policy. The claim is
// written once, so two accounts created in the same second cannot both win.
fn claim_instance_owner(st: &S, uid: &str) {
    if meta_get(st, "instance_owner").is_empty() { let _ = st.db.exec("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(uid)]); } }
// A password account owns the instance only once its address is proven. The
// oldest verified account wins if the original registration was never opened.
fn claim_instance_owner_on_verify(st: &S, uid: &str) {
    if !meta_get(st, "instance_owner").is_empty() { return; }
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE email_verified=1 ORDER BY created_at, id LIMIT 1", &[]) {
        if db::s(&row, "id") == uid { claim_instance_owner(st, uid); } } }
fn instance_owner(st: &S) -> Option<String> {
    let stored = meta_get(st, "instance_owner");
    if !stored.is_empty() { return Some(stored); }
    let uid = st.db.one("SELECT id FROM users WHERE email_verified=1 ORDER BY created_at, id LIMIT 1", &[]).ok().flatten().map(|r| db::s(&r, "id"));
    if let Some(u) = &uid { claim_instance_owner(st, u); }
    uid }
fn env_nonempty(key: &str) -> String { std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_default() }
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
        _ => return None };
    let id = env_nonempty(id_key);
    let secret = env_nonempty(secret_key);
    if id.is_empty() || secret.is_empty() { None } else { Some((id, secret)) } }
// OIDC providers also need an issuer; GitHub and X are plain OAuth 2.0.
fn social_enabled(provider: &str) -> bool {
    social_provider(provider).is_some() && (matches!(provider, "github" | "x") || social_issuer(provider).is_some()) }
fn google_issuer() -> String { std::env::var("OPENWARP_GOOGLE_ISSUER").unwrap_or_else(|_| "https://accounts.google.com".into()) }
// Apple's client secret is a short-lived JWT the operator generates with their
// Sign in with Apple key; OpenAI issues a regular OAuth client secret.
fn social_issuer(provider: &str) -> Option<String> {
    match provider {
        "google" => Some(google_issuer()),
        "apple" => Some(std::env::var("OPENWARP_APPLE_ISSUER").unwrap_or_else(|_| "https://appleid.apple.com".into())),
        "openai" => Some(std::env::var("OPENWARP_OPENAI_ISSUER").unwrap_or_else(|_| "https://auth.openai.com".into())),
        "microsoft" => Some(microsoft_issuer()),
        "okta" => issuer_or("OPENWARP_OKTA_ISSUER", ""),
        "auth0" => issuer_or("OPENWARP_AUTH0_ISSUER", ""),
        "gitlab" => issuer_or("OPENWARP_GITLAB_ISSUER", "https://gitlab.com"),
        "slack" => issuer_or("OPENWARP_SLACK_ISSUER", "https://slack.com"),
        "salesforce" => issuer_or("OPENWARP_SALESFORCE_ISSUER", "https://login.salesforce.com"),
        "atlassian" => issuer_or("OPENWARP_ATLASSIAN_ISSUER", "https://auth.atlassian.com"),
        "oidc" => { let issuer = env_nonempty("OPENWARP_OIDC_ISSUER"); if issuer.is_empty() { None } else { Some(issuer) } },
        _ => None } }
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
        _ => "openid email profile" } }
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
fn github_web() -> String { std::env::var("OPENWARP_GITHUB_WEB").unwrap_or_else(|_| "https://github.com".into()) }
fn github_api() -> String { std::env::var("OPENWARP_GITHUB_API").unwrap_or_else(|_| "https://api.github.com".into()) }
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
fn resolve_social(st: &S, provider: &str, subject: &str, email: &str) -> Result<String, (StatusCode, Json<Value>)> {
    if let Some(bound) = st.db.one("SELECT user_id FROM social_subjects WHERE provider=? AND subject=?", &[json!(provider), json!(subject)]).map_err(|e| bad(&e))? {
        let uid = db::s(&bound, "user_id");
        if !st.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
        return Ok(uid); }
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password first")); }
    // A pending invite admits the user even when self-signup is closed.
    let invite = st.db.one("SELECT * FROM invites WHERE email=? AND accepted=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", &[json!(email), json!(now())]).map_err(|e| bad(&e))?;
    if invite.is_none() && !signups_open(st) { return Err(err(StatusCode::FORBIDDEN, "signups are disabled on this instance; ask an administrator to invite you")); }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("social"); let uid = id();
    // The provider asserted a verified address, so this account needs no
    // separate email round-trip.
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)", &[json!(uid), json!(email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO social_subjects(provider,subject,user_id,created_at) VALUES(?,?,?,?)", &[json!(provider), json!(subject), json!(uid), json!(now())]).map_err(|e| bad(&e))?;
    claim_instance_owner(st, &uid);
    match invite {
        Some(inv) => {
            st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(db::s(&inv, "org_id")), json!(uid), json!(db::s(&inv, "role"))]).map_err(|e| bad(&e))?;
            st.db.exec("UPDATE invites SET accepted=1 WHERE token_hash=?", &[json!(db::s(&inv, "token_hash"))]).map_err(|e| bad(&e))?; }
        None => {
            let oid = id();
            st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(oid), json!(format!("{}'s organisation", email)), json!(now())]).map_err(|e| bad(&e))?;
            st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", &[json!(oid), json!(uid)]).map_err(|e| bad(&e))?; }
    }
    st.audit("", "", "", &uid, "auth.social_login", &format!("{} {}", provider, email));
    Ok(uid) }
async fn auth_providers(State(st): State<S>) -> Res {
    let oidc = social_enabled("oidc");
    Ok(j(json!({
        "password": true,
        "ldap": cfg!(feature = "ldap"),
        "google": social_enabled("google"),
        "github": social_enabled("github"),
        "apple": social_enabled("apple"),
        "openai": social_enabled("openai"),
        "microsoft": social_enabled("microsoft"),
        "okta": social_enabled("okta"),
        "auth0": social_enabled("auth0"),
        "gitlab": social_enabled("gitlab"),
        "slack": social_enabled("slack"),
        "salesforce": social_enabled("salesforce"),
        "atlassian": social_enabled("atlassian"),
        "x": social_enabled("x"),
        "oidc": oidc,
        "oidc_name": if oidc { oidc_custom_name() } else { String::new() },
        "signups": if signups_open(&st) { "open" } else { "invite" },
    }))) }
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
async fn social_start(State(st): State<S>, h: HeaderMap, Path(provider): Path<String>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let (client_id, _) = social_provider(&provider).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
    let redirect = social_redirect(&st, &h, &provider);
    let state = oc::random_token("sst");
    if provider == "github" {
        st.db.exec("INSERT INTO social_states(state,provider,created_at) VALUES(?,?,?)", &[json!(state), json!(&provider), json!(now())]).map_err(|e| bad(&e))?;
        let url = format!("{}/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}", github_web(), urlencode(&client_id), urlencode(&redirect), state);
        return Ok(axum::response::Redirect::temporary(&url)); }
    if provider == "x" {
        let verifier = oc::random_token("pkce");
        st.db.exec("INSERT INTO social_states(state,provider,created_at,code_verifier) VALUES(?,?,?,?)", &[json!(state), json!(&provider), json!(now()), json!(&verifier)]).map_err(|e| bad(&e))?;
        let url = format!("{}/i/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            x_web(), urlencode(&client_id), urlencode(&redirect), urlencode(social_scope("x")), state, pkce_challenge(&verifier));
        return Ok(axum::response::Redirect::temporary(&url)); }
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
    st.db.exec("INSERT INTO social_states(state,provider,created_at,nonce,code_verifier) VALUES(?,?,?,?,?)", &[json!(state), json!(&provider), json!(now()), json!(&nonce), json!(&verifier)]).map_err(|e| bad(&e))?;
    let scope = if provider == "oidc" { oidc_custom_scope() } else { social_scope(&provider).to_string() };
    let mut url = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}", auth_ep, urlencode(&client_id), urlencode(&redirect), urlencode(&scope), state, nonce);
    if provider == "apple" { url.push_str("&response_mode=form_post"); }
    if !verifier.is_empty() { url.push_str(&format!("&code_challenge={}&code_challenge_method=S256", pkce_challenge(&verifier))); }
    Ok(axum::response::Redirect::temporary(&url)) }
async fn social_callback(State(st): State<S>, h: HeaderMap, Path(provider): Path<String>, Query(q): Query<HashMap<String,String>>, form: Result<axum::extract::Form<HashMap<String,String>>, axum::extract::rejection::FormRejection>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let (client_id, client_secret) = social_provider(&provider).filter(|_| social_enabled(&provider)).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
    // Apple answers with a form POST; every other provider uses the query string.
    let params = if q.contains_key("code") || q.contains_key("state") { q } else { form.ok().map(|axum::extract::Form(f)| f).unwrap_or_default() };
    let code = params.get("code").cloned().unwrap_or_default(); let state = params.get("state").cloned().unwrap_or_default();
    let row = st.db.one("SELECT provider,created_at,nonce,code_verifier FROM social_states WHERE state=?", &[json!(state)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    let _ = st.db.exec("DELETE FROM social_states WHERE state=?", &[json!(state)]);
    if db::s(&row, "provider") != provider || db::n(&row, "created_at") + 600 < now() { return Err(bad("invalid or expired state")); }
    if code.is_empty() { return Err(bad("missing authorization code")); }
    let redirect = social_redirect(&st, &h, &provider);
    let (subject, email) = if provider == "github" {
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
    let uid = resolve_social(&st, &bound_provider, &subject, &email)?;
    let token = make_session(&st, &uid)?;
    Ok(axum::response::Redirect::temporary(&format!("/#token={}", token))) }
async fn instance_info(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h)?;
    Ok(j(json!({
        "signups_open": signups_open(&st),
        "signups_env_locked": std::env::var("OPENWARP_SIGNUPS").is_ok(),
        "instance_owner": instance_owner(&st).as_deref() == Some(uid.as_str()),
        "google": social_enabled("google"),
        "github": social_enabled("github"),
        "apple": social_enabled("apple"),
        "openai": social_enabled("openai"),
        "microsoft": social_enabled("microsoft"),
        "okta": social_enabled("okta"),
        "auth0": social_enabled("auth0"),
        "gitlab": social_enabled("gitlab"),
        "slack": social_enabled("slack"),
        "salesforce": social_enabled("salesforce"),
        "atlassian": social_enabled("atlassian"),
        "x": social_enabled("x"),
        "oidc": social_enabled("oidc"),
    }))) }
async fn set_signups(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can change signup policy")); }
    if std::env::var("OPENWARP_SIGNUPS").is_ok() { return Err(err(StatusCode::CONFLICT, "OPENWARP_SIGNUPS controls signups on this instance")); }
    let open = body.get("open").and_then(|v| v.as_bool()).ok_or_else(|| bad("open must be a boolean"))?;
    meta_set(&st, "signups_open", if open { "1" } else { "0" });
    st.audit("", "", "", &uid, "instance.signups", if open { "open" } else { "invite" });
    Ok(j(json!({"signups_open": open}))) }
async fn rotate_master(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can rotate the master key")); }
    let new_key = body.get("new_key").and_then(|v| v.as_str()).unwrap_or("");
    let new: [u8; 32] = oc::unb64(new_key).map_err(|_| bad("new_key must be base64"))?.try_into().map_err(|_| bad("new_key must decode to exactly 32 bytes"))?;
    let old = st.master();
    if old == new { return Err(bad("new_key is the current key")); }
    // Preflight every encrypted value before touching the database.
    let envs = st.db.query("SELECT id,env_key_wrapped FROM envs", &[]).map_err(|e| bad(&e))?;
    let mut env_updates = Vec::new();
    for r in &envs {
        let plain = oc::decrypt_symmetric(&old, &db::s(r, "env_key_wrapped"))
            .map_err(|_| bad("existing environment keys cannot be decrypted with the current master key; refusing rotation"))?;
        env_updates.push((db::s(r, "id"), oc::encrypt_symmetric(&new, &plain)));
    }
    let metas = st.db.query("SELECT k,v FROM meta WHERE k LIKE 'oidc_client_secret:%' OR k LIKE 'totp_secret:%'", &[]).map_err(|e| bad(&e))?;
    let mut meta_updates = Vec::new();
    for r in &metas {
        let value = db::s(r, "v"); if value.is_empty() { continue; }
        let plain = oc::decrypt_symmetric(&old, &value)
            .map_err(|_| bad(&format!("stored secret {} cannot be decrypted with the current master key; refusing rotation", db::s(r, "k"))))?;
        meta_updates.push((db::s(r, "k"), oc::encrypt_symmetric(&new, &plain)));
    }
    let cas = st.db.query("SELECT id,key_enc FROM pki_cas", &[]).map_err(|e| bad(&e))?;
    let mut ca_updates = Vec::new();
    for r in &cas {
        let plain = oc::decrypt_symmetric(&old, &db::s(r, "key_enc"))
            .map_err(|_| bad("a CA private key cannot be decrypted with the current master key; refusing rotation"))?;
        ca_updates.push((db::s(r, "id"), oc::encrypt_symmetric(&new, &plain)));
    }
    let streams = st.db.query("SELECT id,secret FROM log_streams", &[]).map_err(|e| bad(&e))?;
    let mut stream_updates = Vec::new();
    for r in &streams {
        let value = db::s(r, "secret"); if value.is_empty() { continue; }
        let plain = oc::decrypt_symmetric(&old, &value)
            .map_err(|_| bad("a log stream secret cannot be decrypted with the current master key; refusing rotation"))?;
        stream_updates.push((db::s(r, "id"), oc::encrypt_symmetric(&new, &plain)));
    }
    let samls = st.db.query("SELECT org_id,sp_key_enc FROM saml_configs", &[]).map_err(|e| bad(&e))?;
    let mut saml_updates = Vec::new();
    for r in &samls {
        let plain = oc::decrypt_symmetric(&old, &db::s(r, "sp_key_enc"))
            .map_err(|_| bad("a SAML signing key cannot be decrypted with the current master key; refusing rotation"))?;
        saml_updates.push((db::s(r, "org_id"), oc::encrypt_symmetric(&new, &plain)));
    }
    let hooks = st.db.query("SELECT org_id,secret_enc FROM rotation_hooks WHERE secret_enc<>''", &[]).map_err(|e| bad(&e))?;
    let mut hook_updates = Vec::new();
    for r in &hooks {
        let plain = oc::decrypt_symmetric(&old, &db::s(r, "secret_enc"))
            .map_err(|_| bad("a rotation hook secret cannot be decrypted with the current master key; refusing rotation"))?;
        hook_updates.push((db::s(r, "org_id"), oc::encrypt_symmetric(&new, &plain)));
    }
    let generated_master = st.db.one("SELECT v FROM meta WHERE k='master'", &[]).map_err(|e| bad(&e))?.is_some();

    // Block new encryptions with the old key while the database is updated.
    let mut guard = st.master.write().unwrap_or_else(|e| e.into_inner());
    for (id, wrapped) in &env_updates { st.db.exec("UPDATE envs SET env_key_wrapped=? WHERE id=?", &[json!(wrapped), json!(id)]).map_err(|e| bad(&e))?; }
    for (k, value) in &meta_updates { st.db.exec("UPDATE meta SET v=? WHERE k=?", &[json!(value), json!(k)]).map_err(|e| bad(&e))?; }
    for (id, key_enc) in &ca_updates { st.db.exec("UPDATE pki_cas SET key_enc=? WHERE id=?", &[json!(key_enc), json!(id)]).map_err(|e| bad(&e))?; }
    for (id, secret) in &stream_updates { st.db.exec("UPDATE log_streams SET secret=? WHERE id=?", &[json!(secret), json!(id)]).map_err(|e| bad(&e))?; }
    for (org, key_enc) in &saml_updates { st.db.exec("UPDATE saml_configs SET sp_key_enc=? WHERE org_id=?", &[json!(key_enc), json!(org)]).map_err(|e| bad(&e))?; }
    for (org, secret) in &hook_updates { st.db.exec("UPDATE rotation_hooks SET secret_enc=? WHERE org_id=?", &[json!(secret), json!(org)]).map_err(|e| bad(&e))?; }
    if generated_master { st.db.exec("UPDATE meta SET v=? WHERE k='master'", &[json!(oc::b64(&new))]).map_err(|e| bad(&e))?; }
    *guard = new;
    drop(guard);
    st.audit("", "", "", &uid, "instance.master_rotate", &format!("envs={} meta={} cas={} streams={} saml={} hooks={}", env_updates.len(), meta_updates.len(), ca_updates.len(), stream_updates.len(), saml_updates.len(), hook_updates.len()));
    Ok(j(json!({"ok": true, "rotated": {"envs": env_updates.len(), "meta": meta_updates.len(), "cas": ca_updates.len(), "streams": stream_updates.len(), "saml": saml_updates.len(), "hooks": hook_updates.len()}, "note": "If OPENWARP_MASTER_KEY is set in the environment, update it and restart with the new value."}))) }

// ---------- SCIM groups + user lifecycle ----------
fn scim_group_json(st: &S, row: &Row) -> Value { let tid = db::s(row,"id");
    let members = st.db.query("SELECT user_id FROM team_members WHERE team_id=?", &[json!(tid)]).unwrap_or_default();
    json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": tid, "displayName": db::s(row,"name"), "members": members.iter().map(|m| json!({"value": db::s(m,"user_id"), "$ref": format!("/scim/v2/Users/{}", db::s(m,"user_id"))})).collect::<Vec<_>>()}) }
fn scim_replace_members(st: &S, org: &str, tid: &str, body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    st.db.exec("DELETE FROM team_members WHERE team_id=?", &[json!(tid)]).map_err(|e| bad(&e))?;
    for m in body.get("members").and_then(|v| v.as_array()).cloned().unwrap_or_default() { if let Some(uid) = m.get("value").and_then(|v| v.as_str()) { if scim_member(st, org, uid) { let _ = st.db.exec("INSERT INTO team_members(team_id,user_id) VALUES(?,?)", &[json!(tid), json!(uid)]); } } } Ok(()) }
async fn scim_create_group(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res {
    let org = scim_org(&st, &h, &q)?;
    let name = body.get("displayName").and_then(|v| v.as_str()).unwrap_or(""); if name.is_empty() { return Err(bad("displayName required")); }
    let tid = id(); st.db.exec("INSERT INTO teams(id,org_id,name) VALUES(?,?,?)", &[json!(tid), json!(org), json!(name)]).map_err(|e| bad(&e))?;
    scim_replace_members(&st, &org, &tid, &body)?; let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.unwrap(); Ok(j(scim_group_json(&st,&row))) }
async fn scim_list_groups(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q)?;
    let rows = st.db.query("SELECT * FROM teams WHERE org_id=? ORDER BY name", &[json!(org)]).map_err(|e| bad(&e))?;
    let (start, count) = scim_page(&q); let filter = scim_eq_filter(&q);
    let mut all: Vec<Value> = rows.iter().map(|r| scim_group_json(&st,r)).collect();
    if let Some(name) = filter { all.retain(|g| g["displayName"].as_str().map(|d| d.eq_ignore_ascii_case(&name)).unwrap_or(false)); }
    let total = all.len(); let page: Vec<Value> = all.into_iter().skip(start - 1).take(count).collect();
    let page_len = page.len();
    Ok(j(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": page, "totalResults": total, "startIndex": start, "itemsPerPage": page_len}))) }
async fn scim_get_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q)?;
    let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&row,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    Ok(j(scim_group_json(&st,&row))) }
async fn scim_put_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q)?;
    let existing = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&existing,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    if let Some(name) = body.get("displayName").and_then(|v| v.as_str()) { st.db.exec("UPDATE teams SET name=? WHERE id=?", &[json!(name), json!(tid)]).map_err(|e| bad(&e))?; }
    scim_replace_members(&st, &org, &tid, &body)?; let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?; Ok(j(scim_group_json(&st,&row))) }
async fn scim_patch_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q)?;
    let existing = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&existing,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    for op in body.get("Operations").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let path = op.get("path").and_then(|v| v.as_str()).unwrap_or(""); let val = op.get("value").cloned().unwrap_or(json!({}));
        if path == "displayName" { if let Some(n) = val.as_str() { st.db.exec("UPDATE teams SET name=? WHERE id=?", &[json!(n), json!(tid)]).map_err(|e| bad(&e))?; } }
        else if path.starts_with("members") { scim_replace_members(&st, &org, &tid, &json!({"members": val}))?; } }
    let row = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?; Ok(j(scim_group_json(&st,&row))) }
async fn scim_delete_group(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q)?;
    let existing = st.db.one("SELECT * FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"group not found"))?;
    if db::s(&existing,"org_id") != org { return Err(err(StatusCode::NOT_FOUND,"group not found")); }
    st.db.exec("DELETE FROM team_members WHERE team_id=?", &[json!(tid)]).map_err(|e| bad(&e))?; st.db.exec("DELETE FROM teams WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?; Ok(j(json!({"deleted": tid}))) }
async fn scim_put_user(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q)?; let caller = st.token_user(&h)?; let uid = tid;
    if !scim_member(&st, &org, &uid) { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    if let Some(email) = body.get("userName").and_then(|v| v.as_str()) {
        let current = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "email")).unwrap_or_default();
        if !email.eq_ignore_ascii_case(&current) {
            let orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).map_err(|e| bad(&e))?;
            for o in &orgs { let r = st.org_role(&db::s(o, "org_id"), &caller).unwrap_or_default(); if r != "owner" && r != "admin" { return Err(err(StatusCode::FORBIDDEN, "changing an account email requires admin rights in every organisation the user belongs to")); } }
            st.db.exec("UPDATE users SET email=? WHERE id=?", &[json!(email.to_lowercase()), json!(uid)]).map_err(|e| bad(&e))?; } }
    if let Some(active) = body.get("active").and_then(|v| v.as_bool()) { if !active { scim_deactivate(&st, &org, &uid, &caller)?; } }
    Ok(j(json!({"id": uid, "active": body.get("active").and_then(|v| v.as_bool()).unwrap_or(true)}))) }
async fn scim_patch_user(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res { let org = scim_org(&st, &h, &q)?; let caller = st.token_user(&h)?; let uid = tid;
    if !scim_member(&st, &org, &uid) { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    for op in body.get("Operations").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        if op.get("path").and_then(|v| v.as_str()) == Some("active") { if let Some(a) = op.get("value").and_then(|v| v.as_bool()) { if !a { scim_deactivate(&st, &org, &uid, &caller)?; } } } }
    Ok(j(json!({"id": uid}))) }
async fn scim_delete_user(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>, Query(q): Query<HashMap<String,String>>) -> Res { let org = scim_org(&st, &h, &q)?; let caller = st.token_user(&h)?;
    if !scim_member(&st, &org, &tid) { return Err(err(StatusCode::NOT_FOUND, "user is not a member of this organisation")); }
    scim_deactivate(&st, &org, &tid, &caller)?; Ok(j(json!({"id": tid, "active": false}))) }
fn scim_deactivate(st: &S, org: &str, uid: &str, caller: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let target_role = st.org_role(org, uid).unwrap_or_default();
    if target_role == "owner" { let caller_role = st.org_role(org, caller).unwrap_or_default(); if caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can remove an owner")); } }
    let deleted = st.db.exec("DELETE FROM org_members WHERE org_id=? AND user_id=? AND (role<>'owner' OR (SELECT COUNT(*) FROM org_members WHERE org_id=? AND role='owner')>1)", &[json!(org), json!(uid), json!(org)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(bad("cannot remove the last owner")); }
    st.db.exec("DELETE FROM team_members WHERE user_id=? AND team_id IN (SELECT id FROM teams WHERE org_id=?)", &[json!(uid), json!(org)]).map_err(|e| bad(&e))?;
    if let Ok(rows) = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]) { if rows.is_empty() {
        let _ = st.db.exec("DELETE FROM sessions WHERE user_id=?", &[json!(uid)]);
        let _ = st.db.exec("DELETE FROM oauth_tokens WHERE user_id=?", &[json!(uid)]);
        let _ = st.db.exec("UPDATE users SET active=0 WHERE id=?", &[json!(uid)]); } }
    Ok(()) }


// ---------- machine identities + Universal Auth (Infisical-inspired) ----------
async fn create_identity(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let caller_role = st.require_org(&oid, &uid)?; st.check_admin(&oid, &uid)?;
    let want = if r.role.trim().is_empty() { "developer".to_string() } else { r.role.trim().to_string() };
    if want == "owner" { return Err(bad("machine identities cannot hold the owner role")); }
    if want == "admin" && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can create an admin identity")); }
    if want != "developer" && want != "admin" && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(oid), json!(want)]).map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    let iid = id(); let client_id = oc::random_token("cid"); let client_secret = oc::random_token("csec");
    st.db.exec("INSERT INTO identities(id,org_id,name,role,created_at) VALUES(?,?,?,?,?)", &[json!(iid), json!(oid), json!(r.name), json!(want), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO identity_credentials(id,identity_id,client_id,secret_hash,created_at) VALUES(?,?,?,?,?)", &[json!(id()), json!(iid), json!(client_id), json!(oc::hash_token(&client_secret)), json!(now())]).map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"identity.create",&r.name);
    Ok(j(json!({"id": iid, "client_id": client_id, "client_secret": client_secret, "note": "client_secret shown once; POST /api/v1/machine/auth/universal/login {client_id, client_secret} for a 1h access token"}))) }
async fn list_identities(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    let rows = st.db.query("SELECT i.id,i.org_id,i.name,i.role,i.created_at,c.client_id FROM identities i LEFT JOIN identity_credentials c ON c.identity_id=i.id WHERE i.org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_identity(State(st): State<S>, h: HeaderMap, Path((oid, iid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    if st.db.one("SELECT id FROM identities WHERE id=? AND org_id=?", &[json!(&iid), json!(&oid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "identity not found")); }
    st.db.exec("DELETE FROM identity_credentials WHERE identity_id=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM tokens WHERE created_by=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM identities WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"identity.delete",&iid); Ok(j(json!({"deleted": iid}))) }
async fn rotate_identity(State(st): State<S>, h: HeaderMap, Path((oid, iid)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid, &uid)?;
    if st.db.one("SELECT id FROM identities WHERE id=? AND org_id=?", &[json!(&iid), json!(&oid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::NOT_FOUND, "identity not found")); }
    let secret = oc::random_token("csec");
    let client_id = st.db.one("SELECT client_id FROM identity_credentials WHERE identity_id=?", &[json!(&iid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r,"client_id")).unwrap_or_else(|| oc::random_token("cid"));
    let updated = st.db.exec("UPDATE identity_credentials SET secret_hash=? WHERE identity_id=?", &[json!(oc::hash_token(&secret)), json!(&iid)]).map_err(|e| bad(&e))?;
    if updated == 0 { st.db.exec("INSERT INTO identity_credentials(id,identity_id,client_id,secret_hash,created_at) VALUES(?,?,?,?,?)", &[json!(id()), json!(&iid), json!(&client_id), json!(oc::hash_token(&secret)), json!(now())]).map_err(|e| bad(&e))?; }
    st.audit(&oid,"","",&uid,"identity.rotate",&iid);
    Ok(j(json!({"id": iid, "client_id": client_id, "client_secret": secret, "note": "client_secret shown once"}))) }
async fn universal_login(State(st): State<S>, Json(body): Json<Value>) -> Res {
    let cid = body.get("client_id").and_then(|v| v.as_str()).unwrap_or(""); let secret = body.get("client_secret").and_then(|v| v.as_str()).unwrap_or("");
    let cred = st.db.one("SELECT identity_id FROM identity_credentials WHERE client_id=? AND secret_hash=?", &[json!(cid), json!(oc::hash_token(secret))]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid client credentials"))?;
    let iid = db::s(&cred, "identity_id"); let token = oc::random_token("owm");
    st.db.exec("INSERT INTO tokens(id,org_id,name,token_hash,kind,expires_at,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)", &[json!(id()), json!(""), json!("machine"), json!(oc::hash_token(&token)), json!("machine"), json!(now()+3600), json!(now()), json!(iid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"accessToken": token, "expiresIn": 3600, "tokenType": "Bearer", "identity_id": iid}))) }

// ---------- approval workflow: secret change proposals ----------
async fn create_proposal(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "proposals:write")?;
    let key = st.env_key(&eid)?; let payload = serde_json::to_string(&r.secrets.iter().map(|s| json!({"key":s.key,"value":s.value,"path":s.path,"comment":s.comment,"tags":s.tags,"type":s.secret_type})).collect::<Vec<_>>()).unwrap();
    let pid = id(); st.db.exec("INSERT INTO proposals(id,env_id,author,payload_enc,created_at) VALUES(?,?,?,?,?)", &[json!(pid), json!(eid), json!(uid), json!(oc::encrypt_symmetric(&key, payload.as_bytes())), json!(now())]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"proposal.create",&pid); Ok(j(json!({"id": pid, "status": "pending"}))) }
async fn list_proposals(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT id,env_id,author,status,created_at,decided_by FROM proposals WHERE env_id=? ORDER BY created_at DESC", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn decide_proposal(State(st): State<S>, h: HeaderMap, Path((pid, action)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM proposals WHERE id=?", &[json!(pid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"proposal not found"))?;
    if db::s(&row,"status") != "pending" { return Err(bad("proposal already decided")); }
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid, &uid)?;
    st.check_admin(&org, &uid).map_err(|_| err(StatusCode::FORBIDDEN, "proposals need approval by an admin (not the author)"))?;
    if action == "approve" {
        let key = st.env_key(&eid)?; let plain = oc::decrypt_symmetric(&key, &db::s(&row,"payload_enc")).map_err(|e| bad(&e))?;
        let items: Vec<Value> = serde_json::from_slice(&plain).unwrap_or_default(); let mut count = 0;
        for it in &items { let s = SecretIn{ key: it["key"].as_str().unwrap_or("").into(), value: it["value"].as_str().unwrap_or("").into(), path: it["path"].as_str().unwrap_or("/").into(), comment: it["comment"].as_str().unwrap_or("").into(), tags: it["tags"].as_str().unwrap_or("").into(), secret_type: it["type"].as_str().unwrap_or("secret").into() };
            if !s.key.is_empty() { upsert_secret(&st, &eid, &key, &uid, &s)?; count += 1; } }
        st.db.exec("UPDATE proposals SET status='approved',decided_by=? WHERE id=?", &[json!(uid), json!(pid)]).map_err(|e| bad(&e))?;
        st.audit(&org,&app,&eid,&uid,"proposal.approve",&format!("{} applied {} secrets",pid,count)); let sync_errors = trigger_sync(&st,&eid,&uid).await;
        Ok(j(json!({"status":"approved","applied":count,"sync_errors":sync_errors})))
    } else if action == "reject" {
        st.db.exec("UPDATE proposals SET status='rejected',decided_by=? WHERE id=?", &[json!(uid), json!(pid)]).map_err(|e| bad(&e))?;
        st.audit(&org,&app,&eid,&uid,"proposal.reject",&pid); Ok(j(json!({"status":"rejected"})))
    } else { Err(bad("action must be approve or reject")) } }

// ---------- access requests ----------
async fn request_access(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let (org, _) = st.env_org_app(&eid)?; st.require_org(&org, &uid)?;
    let rid = id(); st.db.exec("INSERT INTO access_requests(id,env_id,user_id,reason,created_at) VALUES(?,?,?,?,?)", &[json!(rid), json!(eid), json!(uid), json!(body.get("reason").and_then(|v| v.as_str()).unwrap_or("")), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "status": "pending"}))) }
async fn list_access_requests(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid, &uid)?;
    let rows = st.db.query("SELECT * FROM access_requests WHERE env_id=? ORDER BY created_at DESC", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn decide_access(State(st): State<S>, h: HeaderMap, Path((rid, action)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM access_requests WHERE id=?", &[json!(rid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"request not found"))?;
    if db::s(&row,"status") != "pending" { return Err(bad("already decided")); }
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid, &uid)?;
    st.check_admin(&org, &uid)?;
    if action == "approve" { let _ = st.db.exec("INSERT INTO env_members(env_id,user_id) VALUES(?,?)", &[json!(eid), json!(db::s(&row,"user_id"))]);
        st.db.exec("UPDATE access_requests SET status='approved',decided_by=? WHERE id=?", &[json!(uid), json!(rid)]).map_err(|e| bad(&e))?; st.audit(&org,&app,&eid,&uid,"access.approve",&db::s(&row,"user_id")); Ok(j(json!({"status":"approved"})))
    } else { st.db.exec("UPDATE access_requests SET status='rejected',decided_by=? WHERE id=?", &[json!(uid), json!(rid)]).map_err(|e| bad(&e))?; Ok(j(json!({"status":"rejected"}))) } }

// ---------- dynamic Postgres secrets + PKI ----------
async fn create_lease_v2(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "leases:write")?;
    let key = st.env_key(&eid)?; let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("lease").to_string();
    let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600).clamp(60, 30 * 86400); let lid = id();
    let typ = body.get("type").and_then(|v| v.as_str()).unwrap_or("generic");
    if typ == "postgres" {
        let conn = body.get("config").and_then(|c| c.get("connection")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if conn.is_empty() { return Err(bad("postgres dynamic secret requires config.connection")); }
        db_target_allowed(&conn).map_err(|e| bad(&e))?;
        let username = format!("dyn_{}", oc::random_token("").chars().take(12).collect::<String>().to_lowercase());
        let password = oc::random_token("dyn");
        let (u2,p2,c2) = (username.clone(), password.clone(), conn.clone()); let exp = ttl;
        let res = std::thread::spawn(move || { let mut cl = postgres::Client::connect(&c2, postgres::NoTls).map_err(|e| e.to_string())?;
            cl.execute(&format!("CREATE ROLE \"{}\" LOGIN PASSWORD '{}'", u2, p2), &[]).map_err(|e| e.to_string())?; let _ = exp; Ok::<(),String>(()) }).join().map_err(|_| bad("pg thread panicked"))?;
        res.map_err(|e: String| bad(&e))?;
        let config_enc = oc::encrypt_symmetric(&key, json!({"connection":conn,"type":"postgres"}).to_string().as_bytes());
        st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,username,config_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric(&key, password.as_bytes())), json!(username), json!(config_enc), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
        return Ok(j(json!({"id": lid, "username": username, "password": password, "expires_at": now()+ttl, "type":"postgres"}))); }
    if typ == "aws_iam" {
        let config = body.get("config").cloned().unwrap_or(json!({}));
        let creds = integrations::sts_assume_role(&config).await.map_err(|e| bad(&e))?;
        let config_enc = oc::encrypt_symmetric(&key, json!({"type":"aws_iam"}).to_string().as_bytes());
        st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,config_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric(&key, creds.to_string().as_bytes())), json!(config_enc), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
        return Ok(j(json!({"id": lid, "credentials": creds, "expires_at": now()+ttl, "type":"aws_iam"})));
    }
	    if matches!(typ, "openrouter" | "resend" | "openai" | "huggingface" | "fireworks" | "mistral" | "perplexity" | "xai" | "gemini" | "cloudflare" | "deepgram" | "elevenlabs" | "deepinfra" | "baseten" | "fal" | "speechmatics" | "chutes") {
        let config = body.get("config").cloned().unwrap_or(json!({}));
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
        let config_enc = oc::encrypt_symmetric(&key, stored.to_string().as_bytes());
        st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,config_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric(&key, secret.as_bytes())), json!(config_enc), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
        return Ok(j(json!({"id": lid, "value": secret, "remote_id": remote_id, "expires_at": now()+ttl, "type": typ})));
    }
    let value = oc::random_token("dyn");
    st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric(&key, value.as_bytes())), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": lid, "value": value, "expires_at": now()+ttl}))) }
async fn revoke_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM leases WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    let eid = db::s(&row,"env_id"); let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "leases:write")?; let key = st.env_key(&eid)?;
    if !db::s(&row,"config_enc").is_empty() { if let Ok(plain) = oc::decrypt_symmetric(&key, &db::s(&row,"config_enc")) { if let Ok(cfg) = serde_json::from_slice::<Value>(&plain) {
        match cfg.get("type").and_then(|v| v.as_str()) {
            Some("postgres") => { let conn = cfg.get("connection").and_then(|v| v.as_str()).unwrap_or("").to_string(); let username = db::s(&row,"username");
                let _ = std::thread::spawn(move || { if let Ok(mut cl) = postgres::Client::connect(&conn, postgres::NoTls) { let _ = cl.execute(&format!("DROP ROLE IF EXISTS \"{}\"", username), &[]); } }).join(); }
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
        } } } }
    st.db.exec("UPDATE leases SET revoked=1 WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": lid}))) }

fn ca_params(cn: &str, is_ca: bool) -> rcgen::CertificateParams {
    let mut p = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2050, 1, 1);
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    if is_ca { p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained); p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign]; }
    else { p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature]; p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth, rcgen::ExtendedKeyUsagePurpose::ClientAuth]; }
    p }
async fn create_ca(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid,&uid)?;
    let kp = rcgen::KeyPair::generate().map_err(|e| bad(&e.to_string()))?;
    let mut params = ca_params(if r.name.is_empty(){"OpenWarp CA"}else{&r.name}, true);
    let serial_bytes = oc::random_key()[..16].to_vec();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));
    let cert = params.self_signed(&kp).map_err(|e| bad(&e.to_string()))?;
    let cid = id(); st.db.exec("INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,serial,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(cid), json!(oid), json!(r.name), json!(cert.pem()), json!(oc::encrypt_symmetric(&st.master(), kp.serialize_pem().as_bytes())), json!(hex_encode(&serial_bytes)), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": cid, "certificate": cert.pem()}))) }
fn load_issuer(st: &S, ca: &Row) -> Result<(rcgen::Certificate, rcgen::KeyPair), (StatusCode, Json<Value>)> {
    let pem = oc::decrypt_symmetric(&st.master(), &db::s(ca,"key_enc")).map_err(|e| bad(&e))?;
    let kp = rcgen::KeyPair::from_pem(&String::from_utf8_lossy(&pem)).map_err(|e| bad(&e.to_string()))?;
    let mut params = ca_params(&db::s(ca,"name"), true);
    if let Some(serial) = hex_decode(&db::s(ca,"serial")) { params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial)); }
    let cert = params.self_signed(&kp).map_err(|e| bad(&e.to_string()))?;
    Ok((cert, kp)) }
async fn issue_cert(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(caid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    st.check_admin(&db::s(&ca,"org_id"), &uid)?;
    let cn = body.get("cn").and_then(|v| v.as_str()).unwrap_or("service"); let days = body.get("days").and_then(|v| v.as_i64()).unwrap_or(365).clamp(1, 3650);
    let (issuer_cert, issuer_kp) = load_issuer(&st, &ca)?;
    let leaf_kp = rcgen::KeyPair::generate().map_err(|e| bad(&e.to_string()))?;
    let mut leaf_params = ca_params(cn, false);
    let leaf_serial = oc::random_key()[..16].to_vec();
    leaf_params.serial_number = Some(rcgen::SerialNumber::from_slice(&leaf_serial));
    if let Some(sans) = body.get("sans").and_then(|v| v.as_array()) {
        let mut names = Vec::new();
        for n in sans.iter().filter_map(|s| s.as_str()) {
            let dns: rcgen::Ia5String = n.try_into().map_err(|_| bad(&format!("invalid SAN {:?}: must be an ASCII DNS name or IP", n)))?;
            names.push(rcgen::SanType::DnsName(dns));
        }
        if !names.is_empty() { leaf_params.subject_alt_names = names; } }
    let leaf = leaf_params.signed_by(&leaf_kp, &issuer_cert, &issuer_kp).map_err(|e| bad(&e.to_string()))?;
    let cert_id = id(); let serial = hex_encode(&leaf_serial);
    st.db.exec("INSERT INTO pki_certs(id,ca_id,cn,cert_pem,serial,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(cert_id), json!(caid), json!(cn), json!(leaf.pem()), json!(serial), json!(now()+days*86400), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": cert_id, "certificate": leaf.pem(), "private_key": leaf_kp.serialize_pem(), "ca_certificate": db::s(&ca,"cert_pem")}))) }
async fn ocsp_respond(State(st): State<S>, Path(caid): Path<String>, body: Bytes) -> Response {
    let ca = match st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(&caid)]) { Ok(Some(c)) => c, _ => return err(StatusCode::NOT_FOUND, "CA not found").into_response() };
    let cert_der = match keystore_ocsp::pem::decode("CERTIFICATE", &db::s(&ca,"cert_pem")) { Ok(d) => d, Err(e) => return bad(&e.to_string()).into_response() };
    let key_pem = match oc::decrypt_symmetric(&st.master(), &db::s(&ca,"key_enc")) { Ok(k) => k, Err(e) => return bad(&e).into_response() };
    let key_text = String::from_utf8_lossy(&key_pem);
    let label = if key_text.contains("BEGIN EC PRIVATE KEY") { "EC PRIVATE KEY" } else { "PRIVATE KEY" };
    let key_der = match keystore_ocsp::pem::decode(label, &key_text) { Ok(d) => d, Err(e) => return bad(&e.to_string()).into_response() };
    let request = match keystore_ocsp::OcspRequest::from_der(&body) { Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let responder = match keystore_ocsp::Responder::new(&cert_der, &key_der, keystore_pki::SignatureAlgorithm::Sha256WithEcdsa) {
        Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let response = match responder.respond(&request, |cert_id| {
        let serial = cert_id.serial_hex();
        let revoked = st.db.one("SELECT revoked FROM pki_certs WHERE ca_id=? AND lower(serial)=lower(?)", &[json!(&caid), json!(serial)]).ok().flatten().map(|r| db::n(&r,"revoked") == 1);
        match revoked {
            Some(true) => keystore_ocsp::CertStatus::Revoked { revocation_time: now(), reason: None },
            Some(false) => keystore_ocsp::CertStatus::Good,
            None => keystore_ocsp::CertStatus::Unknown,
        }
    }) { Ok(r) => r, Err(e) => return bad(&e.to_string()).into_response() };
    let mut resp = response.to_der().into_response();
    resp.headers_mut().insert("content-type", axum::http::HeaderValue::from_static("application/ocsp-response"));
    resp }
async fn list_certs(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(caid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?; st.require_org(&db::s(&ca,"org_id"),&uid)?;
    let rows = st.db.query("SELECT id,ca_id,cn,serial,revoked,expires_at,created_at FROM pki_certs WHERE ca_id=?", &[json!(caid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn revoke_cert(State(st): State<S>, h: HeaderMap, Path(cid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT ca_id FROM pki_certs WHERE id=?", &[json!(cid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"cert not found"))?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(db::s(&row,"ca_id"))]).map_err(|e| bad(&e))?; if let Some(ca)=ca { st.check_admin(&db::s(&ca,"org_id"),&uid)?; }
    st.db.exec("UPDATE pki_certs SET revoked=1 WHERE id=?", &[json!(cid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": cid}))) }
async fn ca_crl(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Response { let uid = match st.token_user(&h) { Ok(u) => u, Err(e) => return e.into_response() };
    let ca = match st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(&caid)]) { Ok(Some(c)) => c, _ => return err(StatusCode::NOT_FOUND, "CA not found").into_response() };
    if let Err(e) = st.check_admin(&db::s(&ca,"org_id"), &uid) { return e.into_response(); }
    let (issuer_cert, issuer_kp) = match load_issuer(&st, &ca) { Ok(x) => x, Err(e) => return e.into_response() };
    let rows = match st.db.query("SELECT serial,revoked FROM pki_certs WHERE ca_id=?", &[json!(&caid)]) { Ok(r) => r, Err(e) => return bad(&e).into_response() };
    let mut revoked = Vec::new();
    for r in &rows { if db::n(r,"revoked") == 1 { if let Some(serial) = hex_decode(&db::s(r,"serial")) {
        revoked.push(rcgen::RevokedCertParams { serial_number: rcgen::SerialNumber::from_slice(&serial), revocation_time: time::OffsetDateTime::now_utc(), reason_code: None, invalidity_date: None }); } } }
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


// ---------- IP allowlist enforcement (T01) ----------
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let ip = ip.trim(); let cidr = cidr.trim(); if cidr.is_empty() { return false; }
    let addr = match ip.parse::<std::net::IpAddr>() { Ok(a) => a, Err(_) => return false };
    if let Ok(net) = cidr.parse::<ipnet::IpNet>() { return net.contains(&addr); }
    match cidr.parse::<std::net::IpAddr>() { Ok(a) => a == addr, Err(_) => false } }
fn request_org(st: &S, path: &str, query: &str) -> Option<String> {
    let seg = |prefix: &str| path.strip_prefix(prefix).and_then(|r| r.split('/').next()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    if let Some(oid) = seg("/api/orgs/") { return Some(oid); }
    if let Some(aid) = seg("/api/apps/") { return st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).ok().flatten().map(|r| db::s(&r, "org_id")); }
    if let Some(eid) = seg("/api/envs/") { return st.env_org_app(&eid).ok().map(|(o, _)| o); }
    for (prefix, table) in [("/api/secrets/", "secrets"), ("/api/leases/", "leases"), ("/api/integrations/", "integrations"), ("/api/rotations/", "rotation_schedules")] {
        if let Some(id) = seg(prefix) { return st.db.one(&format!("SELECT env_id FROM {} WHERE id=?", table), &[json!(id)]).ok().flatten().and_then(|r| st.env_org_app(&db::s(&r, "env_id")).ok().map(|(o, _)| o)); }
    }
    if let Some(caid) = seg("/api/pki/cas/") { return st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(caid)]).ok().flatten().map(|r| db::s(&r, "org_id")); }
    if let Some(cid) = seg("/api/pki/certs/") { return st.db.one("SELECT ca_id FROM pki_certs WHERE id=?", &[json!(cid)]).ok().flatten().and_then(|r| st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(db::s(&r, "ca_id"))]).ok().flatten()).map(|r| db::s(&r, "org_id")); }
    if path.starts_with("/scim/") { return query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == "org_id").map(|(_, v)| v.to_string()); }
    None }
async fn ip_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let protected = path.starts_with("/api/") || path == "/mcp" || path.starts_with("/scim/");
    if !protected || path.starts_with("/api/auth/login") || path.starts_with("/api/auth/register") || path.starts_with("/api/auth/oidc/") || path.starts_with("/api/v1/machine") { return next.run(req).await; }
    let headers = req.headers().clone(); let uid = match st.token_user(&headers) { Ok(u) => u, Err(_) => return next.run(req).await };
    let trust_proxy = std::env::var("OPENWARP_TRUST_PROXY").map(|v| v == "1").unwrap_or(false);
    let conn_ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string());
    // X-Forwarded-For is only honoured from a proxy the operator named, so
    // exposing the port directly cannot spoof allowlists or rate-limit keys.
    let proxy_ok = conn_ip.as_deref().map(|ip| {
        std::env::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1/32,::1".into())
            .split(',').any(|c| ip_in_cidr(ip, c)) }).unwrap_or(false);
    let forwarded = if trust_proxy && proxy_ok { headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(|s| s.split(',').next().unwrap_or("").trim().to_string()) } else { None };
    let client_ip = forwarded.or(conn_ip).unwrap_or_default();
    let query = req.uri().query().unwrap_or("").to_string();
    let allowed = if client_ip.is_empty() { false } else { match request_org(&st, &path, &query) {
        Some(oid) => { let list = st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?", &[json!(oid)]).ok().flatten().map(|r| db::s(&r, "ip_allowlist")).unwrap_or_default();
            list.trim().is_empty() || list.split(',').any(|c| ip_in_cidr(&client_ip, c)) }
        None => { let mut lists: Vec<String> = st.db.query("SELECT o.ip_allowlist AS ip_allowlist FROM orgs o JOIN org_members m ON m.org_id=o.id WHERE m.user_id=?", &[json!(uid)]).unwrap_or_default().iter().map(|r| db::s(r, "ip_allowlist")).filter(|s| !s.trim().is_empty()).collect();
            if lists.is_empty() { lists = st.db.query("SELECT o.ip_allowlist AS ip_allowlist FROM orgs o JOIN identities i ON i.org_id=o.id WHERE i.id=?", &[json!(uid)]).unwrap_or_default().iter().map(|r| db::s(r, "ip_allowlist")).filter(|s| !s.trim().is_empty()).collect(); }
            lists.is_empty() || lists.iter().all(|l| l.split(',').any(|c| ip_in_cidr(&client_ip, c))) } } };
    if !allowed { return (StatusCode::FORBIDDEN, Json(json!({"error": format!("source IP {} not in organisation allowlist", client_ip)}))).into_response(); }
    next.run(req).await }

// OAuth access tokens carry explicit scopes; REST reads need secrets:read and
// mutations need secrets:write. Sessions, PATs and machine tokens are unchanged.
async fn oauth_scope_middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    // SCIM is governed too: an environment-scoped credential must not be able to
    // deprovision users just because the route lives outside /api.
    if !(path.starts_with("/api/") || path.starts_with("/scim/")) || path == "/api/auth/logout" { return next.run(req).await; }
    let token = bearer_token(req.headers());
    if token.is_empty() { return next.run(req).await; }
    let hash = oc::hash_token(&token);
    if let Ok(Some(row)) = st.db.one("SELECT scope FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(hash), json!(now())]) {
        let read = matches!(req.method(), &axum::http::Method::GET | &axum::http::Method::HEAD | &axum::http::Method::OPTIONS);
        let need = if read { "secrets:read" } else { "secrets:write" };
        let scope = db::s(&row, "scope");
        if !scope.split_whitespace().any(|s| s == "*" || s == need) { return (StatusCode::FORBIDDEN, Json(json!({"error": format!("OAuth token lacks scope {}", need)}))).into_response(); }
    } else if let Ok(Some(row)) = st.db.one("SELECT scopes FROM tokens WHERE token_hash=?", &[json!(&hash)]) {
        let scope = db::s(&row, "scopes");
        if !scope.is_empty() {
            let read = matches!(req.method(), &axum::http::Method::GET | &axum::http::Method::HEAD | &axum::http::Method::OPTIONS);
            let need = if read { "secrets:read" } else { "secrets:write" };
            if !scope.split_whitespace().any(|s| s == "*" || s == need) { return (StatusCode::FORBIDDEN, Json(json!({"error": format!("token lacks scope {}", need)}))).into_response(); }
        }
    }
    let scoped = env_scope_of(&st, req.headers());
    if !scoped.is_empty() && !scope_path_ok(&st, &scoped, &path) { return (StatusCode::FORBIDDEN, Json(json!({"error": "this token is scoped to a different environment"}))).into_response(); }
    next.run(req).await }
fn scope_path_ok(st: &S, scope: &str, path: &str) -> bool {
    if path == "/api/me" || path == "/api/auth/logout" { return true; }
    if let Some(rest) = path.strip_prefix("/api/envs/") {
        let (eid, tail) = rest.split_once('/').unwrap_or((rest, ""));
        return eid == scope && !tail.is_empty();
    }
    let target = path.strip_prefix("/api/secrets/").map(|r| ("secrets", r))
        .or_else(|| path.strip_prefix("/api/leases/").map(|r| ("leases", r)))
        .or_else(|| path.strip_prefix("/api/integrations/").map(|r| ("integrations", r)))
        .or_else(|| path.strip_prefix("/api/rotations/").map(|r| ("rotation_schedules", r)));
    match target {
        Some((table, rest)) => { let id = rest.split('/').next().unwrap_or(""); st.db.one(&format!("SELECT env_id FROM {} WHERE id=?", table), &[json!(id)]).ok().flatten().map(|r| db::s(&r, "env_id") == scope).unwrap_or(false) }
        None => false,
    } }

// ---------- logout / token management (T04) ----------
async fn logout(State(st): State<S>, h: HeaderMap) -> Res {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let mut token = auth.strip_prefix("Bearer ").unwrap_or("").to_string();
    if token.is_empty() { token = cookie_val(&h, "ow_session"); }
    let hash = oc::hash_token(&token); let _ = st.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(hash)]);
    // An OAuth access or refresh token is a credential too: revoke its whole pair.
    if let Ok(Some(row)) = st.db.one("SELECT pair_id FROM oauth_tokens WHERE token_hash=?", &[json!(&hash)]) {
        let pair = db::s(&row, "pair_id");
        if pair.is_empty() { let _ = st.db.exec("DELETE FROM oauth_tokens WHERE token_hash=?", &[json!(&hash)]); }
        else { let _ = st.db.exec("DELETE FROM oauth_tokens WHERE pair_id=?", &[json!(&pair)]); } }
    #[cfg(feature = "redis-cache")] st.redis_del(&format!("sess:{}", hash));
    Ok(j(json!({"ok": true}))) }
async fn list_tokens(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org,&uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT id,app_id,env_id,name,kind,expires_at,scopes,last_used_at,created_at,created_by FROM tokens WHERE app_id=?", &[json!(aid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn revoke_token(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT created_by,org_id FROM tokens WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"token not found"))?;
    if db::s(&row,"created_by") != uid && st.org_role(&db::s(&row,"org_id"),&uid).as_deref() != Some("owner") && st.org_role(&db::s(&row,"org_id"),&uid).as_deref() != Some("admin") { return Err(err(StatusCode::FORBIDDEN,"token owner or org admin required")); }
    st.db.exec("DELETE FROM tokens WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": tid}))) }


// ---------- custom RBAC roles (T07) ----------
async fn create_role(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid,&uid)?;
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(""); if name.is_empty() || ["owner","admin","developer"].contains(&name) { return Err(bad("role name required and cannot shadow managed roles")); }
    let perms = body.get("permissions").cloned().unwrap_or(json!([]));
    let rid = id(); st.db.exec("INSERT INTO roles(id,org_id,name,permissions) VALUES(?,?,?,?)", &[json!(rid), json!(oid), json!(name), json!(perms.to_string())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "name": name, "permissions": perms}))) }
async fn list_roles(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT id,name,permissions FROM roles WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?;
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
fn totp_code(secret: &[u8], counter: u64) -> String { use sha1::Sha1; use hmac::{Hmac, Mac}; type H = Hmac<Sha1>;
    let mut m = H::new_from_slice(secret).unwrap(); m.update(&counter.to_be_bytes()); let hash = m.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize; let code = ((hash[off] as u32 & 0x7f) << 24) | ((hash[off+1] as u32) << 16) | ((hash[off+2] as u32) << 8) | hash[off+3] as u32; format!("{:06}", code % 1_000_000) }
fn meta_set(st: &S, k: &str, v: &str) { if st.db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(k), json!(v)]).is_err() { let _ = st.db.exec("UPDATE meta SET v=? WHERE k=?", &[json!(v), json!(k)]); } }
async fn totp_setup(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    // Re-enrolling is equivalent to removing the second factor, so it needs the
    // password once MFA is already active.
    if meta_get(&st, &format!("totp_enabled:{}", uid)) == "1" {
        let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
        let row = st.db.one("SELECT pass_hash FROM users WHERE id=?", &[json!(&uid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
        if password.is_empty() || !oc::verify_password(password, &db::s(&row, "pass_hash")) { return Err(err(StatusCode::UNAUTHORIZED, "current password required to change two-factor settings")); } }
    let provided = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let secret_bytes: Vec<u8> = if provided.is_empty() { oc::random_key()[..20].to_vec() } else { let d = b32decode(provided); if d.len() < 10 { return Err(bad("provided TOTP secret must be base32, at least 10 bytes")); } d };
    let secret_b32 = b32encode(&secret_bytes);
    meta_set(&st, &format!("totp_secret:{}", uid), &oc::encrypt_symmetric(&st.master(), &secret_bytes));
    meta_set(&st, &format!("totp_enabled:{}", uid), "0");
    let codes: Vec<String> = (0..8).map(|_| oc::random_token("rc")).collect();
    let hashed: Vec<String> = codes.iter().map(|c| oc::hash_token(c)).collect();
    meta_set(&st, &format!("totp_recovery:{}", uid), &hashed.join(","));
    let email = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).map(|r| r.map(|x| db::s(&x,"email")).unwrap_or_default()).unwrap_or_default(); let _ = &secret_bytes;
    Ok(j(json!({"secret": secret_b32, "otpauth_url": format!("otpauth://totp/OpenWarp:{}?secret={}&issuer=OpenWarp", email, secret_b32), "recovery_codes": codes, "note": "call POST /api/me/totp/verify {code} with a current TOTP code to enable"}))) }
async fn totp_verify(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let enc = meta_get(&st, &format!("totp_secret:{}", uid)); let secret = oc::decrypt_symmetric(&st.master(), &enc).map_err(|_| bad("TOTP not set up"))?;
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or(""); let counter = (now() / 30) as u64;
    if ![counter.wrapping_sub(1), counter, counter + 1].iter().any(|c| totp_code(&secret, *c) == code) { return Err(err(StatusCode::UNAUTHORIZED, "invalid TOTP code")); }
    meta_set(&st, &format!("totp_enabled:{}", uid), "1"); Ok(j(json!({"enabled": true}))) }
async fn mfa_login(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(body): Json<Value>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let token = body.get("mfa_token").and_then(|v| v.as_str()).unwrap_or(""); let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let row = st.db.one("SELECT user_id,created_at FROM mfa_challenges WHERE token=?", &[json!(token)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid MFA challenge"))?;
    if db::n(&row,"created_at") + 300 < now() { return Err(err(StatusCode::UNAUTHORIZED, "MFA challenge expired")); }
    let uid = db::s(&row,"user_id");
    // The password was already accepted upstream, so this step guards the second
    // factor itself: cap guesses per address and account.
    let key = format!("mfa:{}:{}", addr.ip(), uid);
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later")); }
    if !otp_ok(&st, &uid, code) { st.rate_fail(&key, 900); return Err(err(StatusCode::UNAUTHORIZED, "invalid MFA code")); }
    st.rate_clear(&key);
    let _ = st.db.exec("DELETE FROM mfa_challenges WHERE token=?", &[json!(token)]);
    let session = make_session(&st, &uid)?; let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap()); Ok((hdr, j(json!({"token": session, "user_id": uid})))) }


// ---------- log streams (T10) ----------
async fn create_stream(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid,&uid)?;
    let url = body.get("url").and_then(|v|v.as_str()).unwrap_or("");
    if !url_ok(url) || !egress_allowed(url) { return Err(bad("log stream url must be http(s) and outside private networks unless OPENWARP_ALLOW_PRIVATE_EGRESS=1")); }
    let secret = body.get("secret").and_then(|v|v.as_str()).unwrap_or("");
    let secret_enc = if secret.is_empty() { String::new() } else { oc::encrypt_symmetric(&st.master(), secret.as_bytes()) };
    let sid = id(); st.db.exec("INSERT INTO log_streams(id,org_id,name,url,secret,created_at) VALUES(?,?,?,?,?,?)", &[json!(sid), json!(oid), json!(body.get("name").and_then(|v|v.as_str()).unwrap_or("stream")), json!(url), json!(secret_enc), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": sid}))) }
async fn list_streams(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_admin(&oid,&uid)?;
    let rows = st.db.query("SELECT id,org_id,name,url,created_at FROM log_streams WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn list_deliveries(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_admin(&oid,&uid)?;
    let rows = st.db.query("SELECT d.id,d.stream_id,d.event,d.status,d.attempts,d.created_at FROM log_deliveries d JOIN log_streams s ON s.id=d.stream_id WHERE s.org_id=? ORDER BY d.created_at DESC LIMIT 200", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }

// ---------- lease renew + rotation schedules (T09) ----------
async fn renew_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id,revoked FROM leases WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    if db::n(&row,"revoked") == 1 { return Err(bad("lease revoked")); }
    let (org, _) = st.require_env(&db::s(&row,"env_id"), &uid)?; st.check_perm(&org, &uid, "leases:write")?;
    let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600).clamp(60, 30 * 86400);
    st.db.exec("UPDATE leases SET expires_at=? WHERE id=?", &[json!(now()+ttl), json!(lid)]).map_err(|e| bad(&e))?; Ok(j(json!({"id": lid, "expires_at": now()+ttl}))) }
async fn create_rotation(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org,&uid,"rotations:write")?;
    let key_name = body.get("key").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let interval = body.get("interval_secs").and_then(|v| v.as_i64()).unwrap_or(86400);
    if !valid_secret_key(&key_name) || interval < 60 { return Err(bad("key ([A-Za-z0-9_.-]{1,128}) and interval_secs (>=60) required")); }
    if !valid_path(path) { return Err(bad("path is invalid")); }
    let rid = id(); st.db.exec("INSERT INTO rotation_schedules(id,env_id,key_name,path,interval_secs,next_run,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(rid), json!(eid), json!(key_name), json!(path), json!(interval), json!(now()+interval), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "next_run": now()+interval}))) }
async fn list_rotations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT * FROM rotation_schedules WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_rotation(State(st): State<S>, h: HeaderMap, Path(rid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM rotation_schedules WHERE id=?", &[json!(rid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"schedule not found"))?;
    let (org, _) = st.require_env(&db::s(&row,"env_id"),&uid)?; st.check_perm(&org, &uid, "rotations:write")?;
    st.db.exec("DELETE FROM rotation_schedules WHERE id=?", &[json!(rid)]).map_err(|e| bad(&e))?; Ok(j(json!({"deleted": rid}))) }
fn try_leader(st: &S, name: &str, owner: &str, ttl: i64) -> bool {
    let current = now(); let expires = current + ttl;
    if st.db.exec("UPDATE instance_leases SET owner=?,expires_at=? WHERE name=? AND (owner=? OR expires_at<?)", &[json!(owner), json!(expires), json!(name), json!(owner), json!(current)]).unwrap_or(0) > 0 { return true; }
    st.db.exec("INSERT INTO instance_leases(name,owner,expires_at) VALUES(?,?,?)", &[json!(name), json!(owner), json!(expires)]).is_ok() }
async fn process_rotations(st: &S) {
    let _ = st.db.exec("DELETE FROM instance_leases WHERE expires_at<?", &[json!(now() - 3600)]);
    let _ = st.db.exec("DELETE FROM saml_pending WHERE created_at<?", &[json!(now() - 600)]);
    let _ = st.db.exec("DELETE FROM saml_replay WHERE expires_at<?", &[json!(now() - 3600)]);
    let _ = st.db.exec("DELETE FROM rate_limits WHERE window_start<?", &[json!(now() - 86400)]);
    let _ = st.db.exec("DELETE FROM live_events WHERE created_at<?", &[json!(now() - 3600)]);
    let due = st.db.query("SELECT * FROM rotation_schedules WHERE enabled=1 AND next_run<=?", &[json!(now())]).unwrap_or_default();
    for r in &due {
        let id = db::s(r,"id"); let eid = db::s(r,"env_id"); let key_name = db::s(r,"key_name");
        let interval = db::n(r,"interval_secs").max(60); let old_next = db::n(r,"next_run");
        // Claim the slot atomically so two replicas cannot rotate the same key twice.
        let claimed = st.db.exec("UPDATE rotation_schedules SET next_run=? WHERE id=? AND next_run=?", &[json!(now()+interval), json!(&id), json!(old_next)]).unwrap_or(0);
        if claimed == 0 { continue; }
        let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).ok().flatten().map(|x| db::s(&x,"mode")).unwrap_or_default();
        if mode == "e2e" { continue; }
        let path = { let p = db::s(r,"path"); if p.is_empty() { "/".to_string() } else { p } };
        let khash = oc::hash_token(&format!("{}:{}", path, key_name.to_uppercase()));
        let existing = st.db.one("SELECT secret_type FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(&eid), json!(&khash)]).ok().flatten();
        let stype = match existing {
            Some(row) if db::s(&row,"secret_type") == "sealed" => {
                if let Ok((org, app)) = st.env_org_app(&eid) { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.skipped_sealed",&key_name); }
                continue;
            }
            Some(row) => { let t = db::s(&row,"secret_type"); if t.is_empty() { "secret".to_string() } else { t } }
            None => {
                if let Ok((org, app)) = st.env_org_app(&eid) { st.audit(&org,&app,&eid,"rotation-scheduler","rotation.missing",&key_name); }
                continue;
            }
        };
        if let Ok(key) = st.env_key(&eid) {
            let new_val = oc::random_token("rot");
            let s = SecretIn{ key: key_name.clone(), value: new_val.clone(), path: path.clone(), comment: "scheduled rotation".into(), tags: "".into(), secret_type: stype };
            if upsert_secret(st, &eid, &key, "rotation-scheduler", &s).is_ok() {
                if let Ok((org, app)) = st.env_org_app(&eid) {
                    st.audit(&org,&app,&eid,"rotation-scheduler","secret.rotate",&key_name);
                    if let Some(err) = fire_rotation_hook(st, &org, &eid, &key_name, &new_val).await {
                        st.audit(&org,&app,&eid,"rotation-scheduler","rotation_hook_failed",&err);
                    }
                }
                let _ = trigger_sync_internal(st, &eid).await;
            }
        }
    } }


// ---------- OAuth 2.1 authorization server (shared by CLI login + MCP) ----------
fn b64url(data: &[u8]) -> String { use base64ct::{Base64UrlUnpadded, Encoding}; Base64UrlUnpadded::encode_string(data) }
fn oauth_user(st: &S, h: &HeaderMap) -> Option<String> {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let bearer = auth.strip_prefix("Bearer ").unwrap_or("").to_string();
    let cookie = cookie_val(h, "ow_session");
    for tok in [bearer, cookie] { if tok.is_empty() { continue; }
        if let Ok(Some(r)) = st.db.one("SELECT user_id,created_at FROM sessions WHERE token_hash=?", &[json!(oc::hash_token(&tok))]) { if db::n(&r,"created_at") + 7*86400 >= now() { return Some(db::s(&r,"user_id")); } } }
    None }
pub fn oauth_access(st: &S, h: &HeaderMap) -> Option<(String, String, String)> {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""); let tok = auth.strip_prefix("Bearer ").unwrap_or("");
    if tok.is_empty() { return None; }
    st.db.one("SELECT user_id,scope,resource FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(oc::hash_token(tok)), json!(now())]).ok().flatten().map(|r| (db::s(&r,"user_id"), db::s(&r,"scope"), db::s(&r,"resource"))) }
async fn prm(State(st): State<S>, h: HeaderMap) -> impl IntoResponse { let iss = issuer(&st, &h);
    Json(json!({"resource": format!("{}/mcp", iss), "authorization_servers": [iss], "scopes_supported": ["secrets:read","secrets:write","mcp"], "bearer_methods_supported": ["header"]})) }
async fn asm(State(st): State<S>, h: HeaderMap) -> impl IntoResponse { let iss = issuer(&st, &h);
    Json(json!({"issuer": iss, "authorization_endpoint": format!("{}/oauth/authorize", iss), "token_endpoint": format!("{}/oauth/token", iss), "registration_endpoint": format!("{}/oauth/register", iss), "revocation_endpoint": format!("{}/oauth/revoke", iss), "response_types_supported": ["code"], "grant_types_supported": ["authorization_code","refresh_token"], "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["client_secret_post","none"], "scopes_supported": ["secrets:read","secrets:write","mcp"], "revocation_endpoint_auth_methods_supported": ["client_secret_post","none"]})) }
async fn oauth_register(State(st): State<S>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let redirects = body.get("redirect_uris").cloned().unwrap_or(json!([]));
    if !redirects.as_array().map(|a| !a.is_empty()).unwrap_or(false) { return (StatusCode::BAD_REQUEST, Json(json!({"error":"redirect_uris required"}))); }
    let auth_method = body.get("token_endpoint_auth_method").and_then(|v| v.as_str()).unwrap_or("client_secret_post");
    let client_id = oc::random_token("client"); let secret = if auth_method == "none" { String::new() } else { oc::random_token("secret") };
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("secrets:read");
    match st.db.exec("INSERT INTO oauth_clients(client_id,client_secret_hash,name,redirect_uris,scopes,created_at) VALUES(?,?,?,?,?,?)", &[json!(client_id), json!(if secret.is_empty(){String::new()}else{oc::hash_token(&secret)}), json!(body.get("client_name").and_then(|v| v.as_str()).unwrap_or("client")), json!(redirects.to_string()), json!(scope), json!(now())]) {
        Ok(_) => { let mut out = json!({"client_id": client_id, "redirect_uris": redirects, "scope": scope, "token_endpoint_auth_method": auth_method}); if !secret.is_empty() { out["client_secret"] = json!(secret); } (StatusCode::CREATED, Json(out)) }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))) } }
const KNOWN_SCOPES: &[&str] = &["secrets:read", "secrets:write", "mcp"];
fn authorize_params_ok(st: &S, q: &HashMap<String, String>) -> Result<(String, String, String), String> {
    let client_id = q.get("client_id").cloned().unwrap_or_default(); let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let client = st.db.one("SELECT redirect_uris,scopes FROM oauth_clients WHERE client_id=?", &[json!(client_id)]).ok().flatten().ok_or("unknown client_id")?;
    let uris: Vec<String> = serde_json::from_str(&db::s(&client, "redirect_uris")).unwrap_or_default();
    if !uris.iter().any(|u| u == &redirect) { return Err("redirect_uri does not exactly match a registered URI".into()); }
    if q.get("response_type").map(|s| s.as_str()) != Some("code") { return Err("response_type must be code".into()); }
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
    if let Err(e) = authorize_params_ok(&st, &q) { return html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>OAuth error</h1><p>{}</p></body></html>", esc(&e))); }
    let hidden = hidden_fields(&q);
    let client = esc(q.get("client_id").map(|s| s.as_str()).unwrap_or(""));
    let scope = esc(q.get("scope").map(|s| s.as_str()).unwrap_or(""));
    if let Some(uid) = oauth_user(&st, &h) {
        let otp = if meta_get(&st, &format!("totp_enabled:{}", uid)) == "1" { "<input name=otp placeholder=\"authenticator code\" autocomplete=one-time-code><br>".to_string() } else { String::new() };
        return html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Authorize application</h1><p>Client: {}<br>Scopes: {}</p><form method=post action=\"/oauth/authorize/decision\">{}{}<button name=approve value=1 style=\"padding:10px 20px\">Approve</button> <button name=approve value=0 style=\"padding:10px 20px\">Deny</button></form></body></html>", client, scope, hidden, otp));
    }
    html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Sign in to OpenWarp</h1><form method=post action=\"/oauth/authorize/decision\">{}<input name=email type=email placeholder=email required style=\"padding:8px\"><br><input name=password type=password placeholder=password required style=\"padding:8px\"><br><input name=otp placeholder=\"authenticator code (if enabled)\" autocomplete=one-time-code style=\"padding:8px\"><br><button name=approve value=1 style=\"padding:10px 20px;margin-top:8px\">Sign in and approve</button></form></body></html>", hidden))
}
async fn oauth_decision(State(st): State<S>, h: HeaderMap, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> Response {
    let (client_id, redirect, scope) = match authorize_params_ok(&st, &form) { Ok(x) => x, Err(e) => return (StatusCode::BAD_REQUEST, e).into_response() };
    let uid = if let Some(u) = oauth_user(&st, &h) { u } else {
        let email = form.get("email").cloned().unwrap_or_default(); let password = form.get("password").cloned().unwrap_or_default();
        let key = format!("oauth:{}:{}", addr.ip(), email.to_lowercase());
        if !st.rate_ok(&key, 5, 900) { return (StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later").into_response(); }
        let row = match st.db.one("SELECT id,pass_hash,active FROM users WHERE email=?", &[json!(email.to_lowercase())]) { Ok(Some(r)) => r, _ => { st.rate_fail(&key, 900); return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); } };
        if db::n(&row, "active") == 0 { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
        if !oc::verify_password(&password, &db::s(&row, "pass_hash")) { st.rate_fail(&key, 900); return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); }
        db::s(&row, "id") };
    if !st.db.one("SELECT active FROM users WHERE id=?", &[json!(uid)]).ok().flatten().map(|u| db::n(&u, "active") != 0).unwrap_or(true) { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
    let otp_key = format!("otp:{}:{}", addr.ip(), uid);
    if !st.rate_ok(&otp_key, 5, 900) { return (StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later").into_response(); }
    if !otp_ok(&st, &uid, form.get("otp").map(|s| s.as_str()).unwrap_or("")) {
        st.rate_fail(&otp_key, 900);
        let page = format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Two-factor required</h1><p>Enter the code from your authenticator app or a recovery code.</p><form method=post action=\"/oauth/authorize/decision\">{}<input name=otp placeholder=\"authenticator code\" autocomplete=one-time-code required><br><button name=approve value=1 style=\"padding:10px 20px;margin-top:8px\">Continue</button></form></body></html>", hidden_fields(&form));
        return (StatusCode::UNAUTHORIZED, html_csp(page)).into_response();
    }
    st.rate_clear(&otp_key);
    let state = form.get("state").cloned().unwrap_or_default();
    if form.get("approve").map(|s| s.as_str()) != Some("1") { return axum::response::Redirect::to(&format!("{}?error=access_denied&state={}", redirect, urlencode(&state))).into_response(); }
    let code = oc::random_token("code"); let resource = form.get("resource").cloned().unwrap_or_else(|| format!("{}/mcp", issuer(&st, &h)));
    if st.db.exec("INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(oc::hash_token(&code)), json!(client_id), json!(uid), json!(redirect), json!(form.get("code_challenge").cloned().unwrap_or_default()), json!(scope), json!(resource), json!(now()+300)]).is_err() { return (StatusCode::INTERNAL_SERVER_ERROR, "could not create code").into_response(); }
    axum::response::Redirect::to(&format!("{}?code={}&state={}", redirect, code, urlencode(&state))).into_response() }
fn issue_oauth_tokens(st: &S, client_id: &str, uid: &str, scope: &str, resource: &str, pair: &str) -> Value {
    let access = oc::random_token("oat"); let refresh = oc::random_token("ort"); let pair = if pair.is_empty() { id() } else { pair.to_string() };
    let _ = st.db.exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,kind,pair_id,expires_at,created_at) VALUES(?,?,?,?,?,'access',?,?,?)", &[json!(oc::hash_token(&access)), json!(client_id), json!(uid), json!(scope), json!(resource), json!(pair), json!(now()+3600), json!(now())]);
    let _ = st.db.exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,kind,pair_id,expires_at,created_at) VALUES(?,?,?,?,?,'refresh',?,?,?)", &[json!(oc::hash_token(&refresh)), json!(client_id), json!(uid), json!(scope), json!(resource), json!(pair), json!(now()+30*86400), json!(now())]);
    json!({"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh, "scope": scope}) }
async fn oauth_token(State(st): State<S>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> (StatusCode, Json<Value>) {
    let grant = form.get("grant_type").map(|s| s.as_str()).unwrap_or("");
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    let client = match st.db.one("SELECT client_secret_hash FROM oauth_clients WHERE client_id=?", &[json!(client_id)]) { Ok(Some(r)) => r, _ => return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid_client"}))) };
    let stored_secret = db::s(&client, "client_secret_hash");
    if !stored_secret.is_empty() { let provided = form.get("client_secret").cloned().unwrap_or_default(); if oc::hash_token(&provided) != stored_secret { return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid_client"}))); } }
    if grant == "authorization_code" {
        let code = form.get("code").cloned().unwrap_or_default();
        let row = match st.db.one("SELECT * FROM oauth_codes WHERE code_hash=? AND expires_at>?", &[json!(oc::hash_token(&code)), json!(now())]) { Ok(Some(r)) => r, _ => return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))) };
        if db::s(&row, "client_id") != client_id || db::s(&row, "redirect_uri") != form.get("redirect_uri").cloned().unwrap_or_default() { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        if verifier.is_empty() { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
        use sha2::{Digest, Sha256}; let computed = b64url(&Sha256::digest(verifier.as_bytes()));
        if computed != db::s(&row, "code_challenge") { return (StatusCode::BAD_REQUEST, Json(json!({"error":"PKCE verification failed"}))); }
        if let Ok(Some(u)) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(db::s(&row, "user_id"))]) { if db::n(&u, "active") == 0 { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); } }
        let _ = st.db.exec("DELETE FROM oauth_codes WHERE code_hash=?", &[json!(oc::hash_token(&code))]);
        (StatusCode::OK, Json(issue_oauth_tokens(&st, &client_id, &db::s(&row,"user_id"), &db::s(&row,"scope"), &db::s(&row,"resource"), "")))
    } else if grant == "refresh_token" {
        let rt = form.get("refresh_token").cloned().unwrap_or_default();
        let row = match st.db.one("SELECT * FROM oauth_tokens WHERE token_hash=? AND kind='refresh' AND expires_at>?", &[json!(oc::hash_token(&rt)), json!(now())]) { Ok(Some(r)) => r, _ => return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))) };
        if db::s(&row, "client_id") != client_id { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
        if let Ok(Some(u)) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(db::s(&row, "user_id"))]) { if db::n(&u, "active") == 0 { return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); } }
        let _ = st.db.exec("DELETE FROM oauth_tokens WHERE pair_id=?", &[json!(db::s(&row,"pair_id"))]);
        (StatusCode::OK, Json(issue_oauth_tokens(&st, &client_id, &db::s(&row,"user_id"), &db::s(&row,"scope"), &db::s(&row,"resource"), &db::s(&row,"pair_id"))))
    } else { (StatusCode::BAD_REQUEST, Json(json!({"error":"unsupported_grant_type"}))) } }
async fn oauth_revoke(State(st): State<S>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> StatusCode {
    let tok = form.get("token").cloned().unwrap_or_default(); let _ = st.db.exec("DELETE FROM oauth_tokens WHERE token_hash=?", &[json!(oc::hash_token(&tok))]); StatusCode::OK }


// ---------- MCP server (Streamable HTTP, OAuth protected) ----------
fn mcp_tools() -> Value { json!([
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
async fn mcp_auth(st: &S, h: &HeaderMap) -> Result<(String, String), (StatusCode, HeaderMap, Json<Value>)> {
    let iss = issuer(st, h);
    let mut hdr = HeaderMap::new(); hdr.insert("www-authenticate", format!("Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"", iss).parse().unwrap());
    if let Some(origin) = h.get("origin").and_then(|v| v.to_str().ok()) {
        if !origin_matches(st, h, origin) { return Err((StatusCode::FORBIDDEN, hdr, Json(json!({"error":"Origin does not match Host"})))); } }
    if let Some((uid, scope, audience)) = oauth_access(st, h) {
        if audience != format!("{}/mcp", iss) { return Err((StatusCode::UNAUTHORIZED, hdr, Json(json!({"error":"token audience does not match this MCP endpoint"})))); }
        return Ok((uid, scope)); }
    if let Ok(uid) = st.token_user(h) { return Ok((uid, "secrets:read secrets:write".into())); }
    Err((StatusCode::UNAUTHORIZED, hdr, Json(json!({"error":"unauthorized; OAuth access token required, see /.well-known/oauth-protected-resource"})))) }
async fn mcp_post(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    let (uid, scope) = match mcp_auth(&st, &h).await { Ok(x) => x, Err(e) => return e.into_response() };
    let id = body.get("id").cloned().unwrap_or(Value::Null); let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(json!({}));
    if id.is_null() { return StatusCode::ACCEPTED.into_response(); }
    let write_tool = ["set_secret","delete_secret","create_lease","sync_integration"].contains(&method) || (method == "tools/call" && ["set_secret","delete_secret","create_lease","sync_integration"].contains(&params.get("name").and_then(|v| v.as_str()).unwrap_or("")));
    if write_tool && !scope.split_whitespace().any(|s| s == "secrets:write" || s == "*") { return Json(rpc_error(&id, -32001, "insufficient scope: secrets:write required")).into_response(); }
    let result: Result<Value, String> = match method {
        "initialize" => Ok(json!({"protocolVersion": params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("2025-06-18"), "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "openwarp", "version": env!("CARGO_PKG_VERSION")}})),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": mcp_tools()})),
        "prompts/list" => Ok(json!({"prompts": []})),
        "resources/list" => mcp_resources(&st, &uid, &h),
        "resources/read" => mcp_resource_read(&st, &uid, &h, &params),
        "tools/call" => mcp_call(&st, &uid, &h, &params).await,
        _ => Err(format!("method not found: {}", method)),
    };
    match result { Ok(r) => Json(rpc_result(&id, r)).into_response(), Err(e) => Json(rpc_error(&id, -32000, &e)).into_response() } }
async fn mcp_get() -> impl IntoResponse { (StatusCode::METHOD_NOT_ALLOWED, Json(json!({"error":"stateless MCP server: POST JSON-RPC to /mcp"}))) }
// The socket stays on the replica that accepted it. That replica's single poll
// reads the shared table and fans matching events out, so a write on any
// replica shows up here within a second. Frames carry audit fields only.
async fn live_ws(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, ws: WebSocketUpgrade) -> Response {
    let uid = match st.token_user(&h) { Ok(u) => u, Err(e) => return e.into_response() };
    let mut orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(&uid)]).unwrap_or_default().iter().map(|r| db::s(r, "org_id")).collect::<Vec<_>>();
    if let Ok(rows) = st.db.query("SELECT org_id FROM identities WHERE id=?", &[json!(&uid)]) {
        for r in rows { let org = db::s(&r, "org_id"); if !orgs.contains(&org) { orgs.push(org); } } }
    // Reconnect with the last id the client saw. Capped at an hour and 500 rows:
    // the table is pruned at an hour, and a wider catch-up belongs to the audit log.
    let since = q.get("since").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    // One placeholder per organisation, capped: a caller in more orgs than this
    // gets the first 32 and relies on the live stream for the rest.
    let missed = if since > 0 && !orgs.is_empty() {
        let scope: Vec<&String> = orgs.iter().take(32).collect();
        let marks = scope.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut params = vec![json!(since), json!(now() - 3600)];
        params.extend(scope.iter().map(|o| json!(o.as_str())));
        st.db.query(&format!("SELECT id,org_id,app_id,env_id,action,detail,created_at FROM live_events WHERE id>? AND created_at>=? AND org_id IN ({}) ORDER BY id LIMIT 500", marks), &params).unwrap_or_default()
    } else { Vec::new() };
    // Subscribing before the upgrade means the poll is already running when the
    // first frame could be missed, and a slow client is dropped rather than blocking.
    let rx = st.live.subscribe();
    ws.on_upgrade(move |socket| live_socket(st, uid, orgs, missed, rx, socket)) }
async fn live_socket(st: S, uid: String, orgs: Vec<String>, missed: Vec<db::Row>, mut rx: broadcast::Receiver<Arc<str>>, mut socket: WebSocket) {
    if socket.send(Message::Text(json!({"type":"hello","instance": st.instance_id}).to_string().into())).await.is_err() { return; }
    // Rows already in the table are sent before the live subscription, and the
    // subscription may repeat the newest of them. The client dedupes on id.
    let mut sent = 0i64;
    for r in &missed {
        let env = db::s(r, "env_id");
        if !env.is_empty() && st.require_env(&env, &uid).is_err() { continue; }
        sent = db::n(r, "id");
        let ev = json!({"type":"event","id":sent,"org":db::s(r,"org_id"),"app":db::s(r,"app_id"),"env":env,"action":db::s(r,"action"),"detail":db::s(r,"detail"),"ts":db::n(r,"created_at")});
        if socket.send(Message::Text(ev.to_string().into())).await.is_err() { return; }
    }
    loop {
        tokio::select! {
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
                let org = v.get("org").and_then(|x| x.as_str()).unwrap_or("");
                if !orgs.iter().any(|o| o == org) { continue; }
                let env = v.get("env").and_then(|x| x.as_str()).unwrap_or("");
                if !env.is_empty() && st.require_env(env, &uid).is_err() { continue; }
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
fn env_scope_of(st: &S, h: &HeaderMap) -> String { st.db.one("SELECT env_id FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(h)))]).ok().flatten().map(|r| db::s(&r, "env_id")).unwrap_or_default() }
fn mcp_resources(st: &S, uid: &str, h: &HeaderMap) -> Result<Value, String> {
    let scoped = env_scope_of(st, h);
    let rows = st.db.query("SELECT e.id AS id, e.name AS name, a.name AS app, a.org_id AS org FROM envs e JOIN apps a ON a.id=e.app_id JOIN org_members m ON m.org_id=a.org_id WHERE m.user_id=?", &[json!(uid)])?;
    Ok(json!({"resources": rows.iter().filter(|r| {
        let eid = db::s(r,"id");
        (scoped.is_empty() || eid == scoped)
            && st.require_env(&eid, uid).is_ok()
            && st.check_perm(&db::s(r,"org"), uid, "secrets:read").is_ok()
    }).map(|r| json!({"uri": format!("openwarp://env/{}", db::s(r,"id")), "name": format!("{} / {}", db::s(r,"app"), db::s(r,"name")), "mimeType": "application/json"})).collect::<Vec<_>>()})) }
fn mcp_resource_read(st: &S, uid: &str, h: &HeaderMap, params: &Value) -> Result<Value, String> {
    let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or(""); let eid = uri.strip_prefix("openwarp://env/").ok_or("bad resource uri")?;
    st.check_scope(h, eid).map_err(|_| "forbidden".to_string())?;
    let (org, _) = st.require_env(eid, uid).map_err(|_| "forbidden".to_string())?;
    st.check_perm(&org, uid, "secrets:read").map_err(|_| "forbidden".to_string())?;
    let items = st.list_secrets_decrypted(eid, uid).map_err(|_| "read failed".to_string())?;
    let text = serde_json::to_string(&items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()).unwrap();
    Ok(json!({"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]})) }
async fn mcp_call(st: &S, uid: &str, h: &HeaderMap, params: &Value) -> Result<Value, String> {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or(""); let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let arg = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let text = |v: Value| json!({"content": [{"type":"text","text": v.to_string()}], "isError": false});
    let env_audit = |st: &S, eid: &str, action: &str, detail: &str| { if let Ok((org, app)) = st.env_org_app(eid) { st.audit(&org, &app, eid, uid, action, detail); } };
    let env_check = |eid: &str| -> Result<(), String> { st.check_scope(h, eid).map_err(|_| "forbidden".to_string())?; st.require_env(eid, uid).map_err(|_| "forbidden".to_string())?; Ok(()) };
    let env_read = |eid: &str| -> Result<(), String> { env_check(eid)?; let (org, _) = st.env_org_app(eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:read").map_err(|_| "forbidden".to_string()) };
    match name {
        "list_envs" => { let r = mcp_resources(st, uid, h)?; Ok(text(r)) }
        "list_secrets" => { let eid = arg("env_id"); env_read(&eid)?; let items = st.list_secrets_decrypted(&eid, uid).map_err(|_| "read failed".to_string())?; env_audit(st, &eid, "mcp.list_secrets", &format!("{}", items.len())); Ok(text(json!(items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()))) }
        "get_secret" => { let eid = arg("env_id"); let key = arg("key"); env_read(&eid)?; let items = st.list_secrets_decrypted(&eid, uid).map_err(|_| "read failed".to_string())?;
            let found = items.iter().find(|(k, _, _)| k == &key.to_uppercase()).map(|(_, v, _)| v.clone()).ok_or("secret not found")?; env_audit(st, &eid, "mcp.get_secret", &key); Ok(text(json!(found))) }
        "search_secrets" => { let q = arg("query").to_uppercase(); let res = mcp_resources(st, uid, h)?; let mut hits = Vec::new();
            for r in res["resources"].as_array().cloned().unwrap_or_default() { let eid = r["uri"].as_str().unwrap_or("").replace("openwarp://env/", "");
                if env_read(&eid).is_err() { continue; }
                if let Ok(items) = st.list_secrets_decrypted(&eid, uid) { for (k, _, _) in items { if q.is_empty() || k.contains(&q) { hits.push(json!({"env_id": eid, "key": k})); } } } }
            Ok(text(json!(hits))) }
        "set_secret" => { let eid = arg("env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:write").map_err(|_| "forbidden".to_string())?;
            let key = st.env_key(&eid).map_err(|_| "env key failed".to_string())?; let s = SecretIn{ key: arg("key"), value: arg("value"), path: { let p = arg("path"); if p.is_empty() { "/".into() } else { p } }, comment: "via MCP".into(), tags: "".into(), secret_type: "secret".into() };
            upsert_secret(st, &eid, &key, uid, &s).map_err(|_| "write failed".to_string())?; env_audit(st, &eid, "mcp.set_secret", &s.key); Ok(text(json!({"ok": true}))) }
        "delete_secret" => { let eid = arg("env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:delete").map_err(|_| "forbidden".to_string())?;
            let items = st.list_secrets_decrypted(&eid, uid).map_err(|_| "read failed".to_string())?; let sid = items.iter().find(|(k, _, _)| k == &arg("key").to_uppercase()).map(|(_, _, raw)| raw["id"].as_str().unwrap_or("").to_string()).ok_or("secret not found")?;
            st.db.exec("UPDATE secrets SET deleted=1,updated_at=? WHERE id=?", &[json!(now()), json!(sid)])?; env_audit(st, &eid, "mcp.delete_secret", &arg("key")); Ok(text(json!({"ok": true}))) }
        "create_lease" => { let eid = arg("env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "leases:write").map_err(|_| "forbidden".to_string())?; let key = st.env_key(&eid).map_err(|_| "env key failed".to_string())?;
            let value = oc::random_token("dyn"); let lid = id(); st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(arg("name")), json!(oc::encrypt_symmetric(&key, value.as_bytes())), json!(now()+3600), json!(now())])?;
            env_audit(st, &eid, "mcp.create_lease", &lid); Ok(text(json!({"id": lid, "value": value, "expires_at": now()+3600}))) }
        "sync_integration" => { let iid = arg("integration_id"); let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).map_err(|_| "lookup failed".to_string())?.ok_or("integration not found")?; let eid = db::s(&row, "env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "integrations:write").map_err(|_| "forbidden".to_string())?;
            let msg = sync_one(st, &iid, uid).await.map_err(|_| "sync failed".to_string())?; Ok(text(json!(msg))) }
        _ => Err(format!("unknown tool: {}", name)),
    } }

async fn health(State(st): State<S>) -> impl IntoResponse {
    match st.db.one("SELECT 1 AS n", &[]) {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true, "service": "openwarp"}))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "service": "openwarp", "error": e}))),
    } }
// One-time share page: the decryption key rides in the fragment and is sent only
// to the API as a header, never in a request line or a server log.
const LOCKBOX_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
async fn lockbox_page() -> Response {
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenWarp lockbox</title><style>body{margin:0;background:#08080c;color:#eceaf8;font:14px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;min-height:100vh}
main{width:620px;max-width:92vw;background:#12121b;border:1px solid #23233a;border-radius:14px;padding:24px}pre{white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,Menlo,monospace}</style></head>
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
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    r }
async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("x-content-type-options", axum::http::HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", axum::http::HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", axum::http::HeaderValue::from_static("DENY"));
    res }
// A hung handler must not pin a worker forever; five minutes covers a deploy
// that fans out to several integrations (30s timeout each).
async fn timeout_middleware(req: axum::extract::Request, next: Next) -> Response {
    match tokio::time::timeout(std::time::Duration::from_secs(300), next.run(req)).await {
        Ok(r) => r,
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, Json(json!({"error": "request timed out"}))).into_response() } }
static HTTP_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static HTTP_ERRORS: AtomicUsize = AtomicUsize::new(0);
async fn metrics_middleware(req: axum::extract::Request, next: Next) -> Response {
    let r = next.run(req).await;
    HTTP_REQUESTS.fetch_add(1, AtomicOrdering::Relaxed);
    if r.status().is_server_error() { HTTP_ERRORS.fetch_add(1, AtomicOrdering::Relaxed); }
    r }
// Disabled unless OPENWARP_METRICS_TOKEN is set; the token is compared by hash.
async fn metrics(State(st): State<S>, h: HeaderMap) -> Response {
    let expected = std::env::var("OPENWARP_METRICS_TOKEN").unwrap_or_default();
    if expected.is_empty() { return StatusCode::NOT_FOUND.into_response(); }
    if oc::hash_token(&bearer_token(&h)) != oc::hash_token(&expected) { return StatusCode::UNAUTHORIZED.into_response(); }
    let count = |sql: &str| st.db.one(sql, &[]).ok().flatten().map(|r| db::n(&r, "n")).unwrap_or(0);
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
        count("SELECT COUNT(*) AS n FROM orgs"), count("SELECT COUNT(*) AS n FROM users"), count("SELECT COUNT(*) AS n FROM apps"),
        count("SELECT COUNT(*) AS n FROM envs"), count("SELECT COUNT(*) AS n FROM secrets WHERE deleted=0"), count("SELECT COUNT(*) AS n FROM sessions"));
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response() }
async fn shutdown_signal() {
    let ctrl_c = async { let _ = tokio::signal::ctrl_c().await; };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) { s.recv().await; } };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    eprintln!("shutdown signal received; draining connections"); }

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://openwarp.db".into());
    let db = Db::open(&db_url).expect("open database (sqlite://file.db or postgres://...)");
    let master = load_master(&db).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    if !mailer::MailConfig::from_env().enabled() {
        if production() {
            eprintln!("no email provider is configured: password signup is disabled until one is set; configured SSO sign-in still works");
        } else {
            eprintln!("no email provider is configured: verification and reset links are written to this log");
        }
    }
    #[cfg(feature = "redis-cache")]
    let redis_conn = std::env::var("REDIS_URL").ok().and_then(|u| redis::Client::open(u).ok()).and_then(|c| c.get_connection().ok());
    let pub_url = std::env::var("OPENWARP_PUBLIC_URL").unwrap_or_default();
    let (live, _) = broadcast::channel(256);
    let state = Arc::new(AppState { db, db_url: db_url.clone(), instance_id: oc::random_token("inst"), pub_url, master: std::sync::RwLock::new(master), #[cfg(feature = "redis-cache")] redis: std::sync::Mutex::new(redis_conn), live });
    { let st2 = state.clone(); tokio::spawn(async move { loop { tokio::time::sleep(std::time::Duration::from_secs(30)).await; if try_leader(&st2, "background", &st2.instance_id, 60) { process_rotations(&st2).await; } } }); }
    // One poll for the whole process. With no sockets subscribed it only reads
    // the current high-water mark, so the next connection starts from now.
    { let st2 = state.clone(); tokio::spawn(async move {
        let mut cursor = st2.db.one("SELECT MAX(id) AS id FROM live_events", &[]).ok().flatten().map(|r| db::n(&r, "id")).unwrap_or(0);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if st2.live.receiver_count() == 0 {
                if let Some(r) = st2.db.one("SELECT MAX(id) AS id FROM live_events", &[]).ok().flatten() { cursor = db::n(&r, "id"); }
                continue; }
            let rows = st2.db.query("SELECT id,org_id,app_id,env_id,action,detail,created_at FROM live_events WHERE id>? ORDER BY id LIMIT 200", &[json!(cursor)]).unwrap_or_default();
            for r in &rows {
                cursor = cursor.max(db::n(r, "id"));
                let ev = json!({"id":db::n(r,"id"),"org":db::s(r,"org_id"),"app":db::s(r,"app_id"),"env":db::s(r,"env_id"),"action":db::s(r,"action"),"detail":db::s(r,"detail"),"ts":db::n(r,"created_at")}).to_string();
                let _ = st2.live.send(Arc::from(ev));
            }
        }
    }); }
    let app = Router::new()
        .route("/", get(index)).route("/e2e.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("e2e.js")) }))
        .route("/metrics", get(metrics)).route("/lockbox/{lid}", get(lockbox_page))
        .route("/api/auth/providers", get(auth_providers)).route("/api/auth/accept-invite", post(accept_invite))
        .route("/api/auth/verify", get(verify_email)).route("/api/auth/forgot", post(forgot_password)).route("/api/auth/reset", post(reset_password)).route("/api/auth/resend-verification", post(resend_verification))
        .route("/api/auth/social/{provider}/start", get(social_start)).route("/api/auth/social/{provider}/callback", get(social_callback).post(social_callback))
        .route("/api/instance", get(instance_info)).route("/api/instance/signups", put(set_signups)).route("/api/instance/email-test", post(test_email)).route("/api/instance/rotate-master", post(rotate_master))
        .route("/health", get(health)).route("/.well-known/oauth-protected-resource", get(prm)).route("/.well-known/oauth-authorization-server", get(asm)).route("/oauth/register", post(oauth_register)).route("/oauth/authorize", get(oauth_authorize)).route("/oauth/authorize/decision", post(oauth_decision)).route("/oauth/token", post(oauth_token)).route("/oauth/revoke", post(oauth_revoke)).route("/mcp", post(mcp_post).get(mcp_get).delete(mcp_get))
        .route("/api/auth/register", post(register)).route("/api/auth/login", post(login)).route("/api/auth/logout", post(logout)).route("/api/me", get(me))
        .route("/api/orgs", get(list_orgs).post(create_org)).route("/api/orgs/{oid}", axum::routing::patch(update_org)).route("/api/orgs/{oid}/leave", post(leave_org)).route("/api/orgs/{oid}/transfer", post(transfer_org))
        .route("/api/orgs/{oid}/members", get(list_members).post(invite_member)).route("/api/orgs/{oid}/members/{uid}", axum::routing::patch(update_member_role).delete(remove_member)).route("/api/orgs/{oid}/apps", get(list_apps).post(create_app))
        .route("/api/orgs/{oid}/audit", get(audit_list)).route("/api/orgs/{oid}/roles", get(list_roles).post(create_role)).route("/api/orgs/{oid}/log-streams", get(list_streams).post(create_stream)).route("/api/orgs/{oid}/log-streams/deliveries", get(list_deliveries)).route("/api/orgs/{oid}/settings", get(get_org_settings).put(org_settings)).route("/api/orgs/{oid}/saml", get(get_saml_config).put(put_saml_config)).route("/api/orgs/{oid}/rotation-hook", get(get_rotation_hook).put(put_rotation_hook).delete(delete_rotation_hook)).route("/api/orgs/{oid}/teams", get(list_teams).post(create_team)).route("/api/orgs/{oid}/teams/{tid}/members", get(list_team_members).post(add_team_member)).route("/api/orgs/{oid}/teams/{tid}/members/{uid}", delete(remove_team_member))
        .route("/api/apps/{aid}", axum::routing::patch(update_app).delete(delete_app)).route("/api/apps/{aid}/envs", get(list_envs).post(create_env)).route("/api/apps/{aid}/envs/e2e", post(create_e2e_env)).route("/api/apps/{aid}/tokens", get(list_tokens).post(create_token)).route("/api/tokens/{tid}", delete(revoke_token)).route("/api/orgs/{oid}/identities", get(list_identities).post(create_identity)).route("/api/orgs/{oid}/identities/{iid}", delete(delete_identity)).route("/api/orgs/{oid}/identities/{iid}/rotate", post(rotate_identity)).route("/api/v1/machine/auth/universal/login", post(universal_login))
        .route("/api/envs/{eid}", delete(delete_env).patch(update_env)).route("/api/envs/{eid}/policy", put(set_env_policy)).route("/api/envs/{eid}/clone", post(clone_env)).route("/api/envs/{eid}/compare", get(compare_envs)).route("/api/envs/{eid}/team-grants", get(list_team_grants).post(add_team_grant)).route("/api/envs/{eid}/team-grants/{tid}", delete(remove_team_grant))
        .route("/api/envs/{eid}/secrets", get(list_secrets).put(deploy_secrets)).route("/api/envs/{eid}/e2e/secrets", get(e2e_get).put(e2e_put)).route("/api/envs/{eid}/e2e/grant", post(e2e_grant)).route("/api/envs/{eid}/e2e/grants", get(e2e_grants)).route("/api/envs/{eid}/e2e/grants/{uid}", delete(e2e_revoke)).route("/api/users/lookup", get(user_lookup))
        .route("/api/envs/{eid}/export", get(export_env)).route("/api/envs/{eid}/import", post(deploy_secrets)).route("/api/envs/{eid}/scan", get(scan_env)).route("/api/envs/{eid}/meta", get(env_meta))
        .route("/api/envs/{eid}/integrations", get(list_integrations).post(create_integration))
        .route("/api/envs/{eid}/dynamic", get(list_leases).post(create_lease_v2)).route("/api/leases/{lid}", delete(revoke_lease)).route("/api/leases/{lid}/renew", post(renew_lease)).route("/api/envs/{eid}/rotations", get(list_rotations).post(create_rotation)).route("/api/rotations/{rid}", delete(delete_rotation)).route("/api/envs/{eid}/rotate", post(rotate_secret)).route("/api/envs/{eid}/restore-point", post(pitr))
        .route("/api/integrations/{iid}/sync", post(sync_integration)).route("/api/integrations/{iid}/test", post(test_integration)).route("/api/integrations/{iid}", axum::routing::patch(update_integration).delete(delete_integration))
        .route("/api/secrets/{sid}", delete(delete_secret)).route("/api/secrets/{sid}/history", get(history))
        .route("/api/secrets/{sid}/restore/{ver}", post(restore)).route("/api/secrets/{sid}/override", post(set_override))
        .route("/api/search", get(search)).route("/api/me/totp/setup", post(totp_setup)).route("/api/me/totp/verify", post(totp_verify)).route("/api/auth/mfa", post(mfa_login)).route("/api/envs/{eid}/proposals", get(list_proposals).post(create_proposal)).route("/api/proposals/{pid}/{action}", post(decide_proposal)).route("/api/envs/{eid}/access-requests", get(list_access_requests).post(request_access)).route("/api/access-requests/{rid}/{action}", post(decide_access)).route("/api/orgs/{oid}/pki/cas", post(create_ca)).route("/api/pki/cas/{caid}/issue", post(issue_cert)).route("/api/pki/cas/{caid}/certs", get(list_certs)).route("/api/pki/cas/{caid}/crl", get(ca_crl)).route("/api/pki/cas/{caid}/ocsp", post(ocsp_respond)).route("/api/pki/certs/{cid}/revoke", post(revoke_cert)).route("/scim/v2/Users", get(scim_list_users).post(scim_create_user)).route("/scim/v2/Users/{uid}", put(scim_put_user).patch(scim_patch_user).delete(scim_delete_user))
        .route("/scim/v2/Groups", get(scim_list_groups).post(scim_create_group)).route("/scim/v2/Groups/{tid}", get(scim_get_group).put(scim_put_group).patch(scim_patch_group).delete(scim_delete_group))
        .route("/scim/v2/ServiceProviderConfig", get(scim_service_config)).route("/scim/v2/ResourceTypes", get(scim_resource_types)).route("/scim/v2/Schemas", get(scim_schemas))
        .route("/api/auth/oidc/{oid}/start", get(oidc_start)).route("/api/auth/oidc/callback", get(oidc_callback)).route("/api/auth/saml/{oid}/metadata", get(saml_metadata)).route("/api/auth/saml/{oid}/start", get(saml_start)).route("/api/auth/saml/{oid}/acs", post(saml_acs)).route("/api/lockbox", post(create_lockbox)).route("/api/lockbox/{lid}", get(open_lockbox));
    // LDAP needs raw TCP/TLS sockets, so the feature is off in a Workers build
    // and these routes do not exist there.
    #[cfg(feature = "ldap")]
    let app = app
        .route("/api/orgs/{oid}/ldap", get(get_ldap_config).put(put_ldap_config).delete(delete_ldap_config))
        .route("/api/auth/ldap", post(ldap_login));
    let app = app
        .layer(axum::middleware::from_fn_with_state(state.clone(), oauth_scope_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(metrics_middleware))
        .layer(axum::middleware::from_fn(timeout_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state::<()>(state.clone());
    // The five-minute handler deadline would close a socket that is behaving
    // correctly. Auth and the IP allowlist still apply; only the deadline does not.
    let live = Router::new().route("/api/live", get(live_ws))
        .layer(axum::middleware::from_fn_with_state(state.clone(), oauth_scope_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(metrics_middleware))
        .with_state(state);
    let app = live.merge(app);
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    println!("openwarp listening on {} db={}", addr, db_url);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal()).await.unwrap();
}
fn load_master(db: &Db) -> Result<[u8;32], String> {
    if let Ok(v) = std::env::var("OPENWARP_MASTER_KEY") {
        let bytes = oc::unb64(&v).map_err(|_| "OPENWARP_MASTER_KEY is not valid base64".to_string())?;
        return bytes.try_into().map_err(|_| "OPENWARP_MASTER_KEY must decode to exactly 32 bytes".to_string());
    }
    if std::env::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) {
        return Err("OPENWARP_MASTER_KEY is required in production. If this database already has a generated key in the meta table, copy it into OPENWARP_MASTER_KEY, or start once with OPENWARP_ENV unset and set the key before going live.".into());
    }
    if let Ok(Some(r)) = db.one("SELECT v FROM meta WHERE k='master'", &[]) { if let Ok(b) = oc::unb64(&db::s(&r,"v")) { if let Ok(k) = b.try_into() { return Ok(k); } } }
    let k = oc::random_key(); let _ = db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&k))]);
    eprintln!("warning: OPENWARP_MASTER_KEY is not set; a generated key was stored in the database. Set OPENWARP_MASTER_KEY before production use.");
    Ok(k)
}

