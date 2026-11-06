mod db; mod kms; mod mfa; mod ui;
use openwarp_server::integrations;
use axum::{extract::{ConnectInfo, Path, Query, State}, http::{HeaderMap, StatusCode}, middleware::Next, response::{Html, IntoResponse, Response}, routing::{delete, get, post, put}, Json, Router};
use db::{Db, Row};
use openwarp_crypto as oc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, sync::atomic::{AtomicUsize, Ordering as AtomicOrdering}};

pub struct AppState {
    db: Db,
    db_url: String,
    pub_url: String,
    master: [u8; 32],
    kms: Option<kms::Kms>,
    #[cfg(feature = "redis-cache")] redis: std::sync::Mutex<Option<redis::Connection>>,
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
const OAUTH_MFA_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
fn html_csp(body: String) -> Response { html_csp_with(OAUTH_CSP, body) }
fn html_csp_with(csp: &'static str, body: String) -> Response { let mut r = Html(body).into_response(); r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(csp)); r }
// Only authorization parameters may survive a failed attempt. Passwords and
// one-time codes must never be echoed back into the page.
fn hidden_fields(form: &HashMap<String, String>) -> String {
    ["client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "resource"]
        .iter().filter_map(|k| form.get(*k).map(|v| format!("<input type=hidden name=\"{}\" value=\"{}\">", esc(k), esc(v)))).collect() }
fn bearer_token(h: &HeaderMap) -> String { h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").strip_prefix("Bearer ").unwrap_or("").to_string() }
static DELIVERY_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_DELIVERY_THREADS: usize = 16;
// Managed roles keep their historic breadth; custom roles are exactly their
// stored permission list, deny by default.
const DEVELOPER_PERMS: &[&str] = &["secrets:read","secrets:write","secrets:delete","integrations:write","leases:write","rotations:write","proposals:write","tokens:create","access:request"];
fn valid_secret_key(k: &str) -> bool { !k.is_empty() && k.len() <= 128 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') }
fn valid_path(p: &str) -> bool { !p.is_empty() && p.len() <= 256 && !p.chars().any(|c| c.is_control()) }
fn valid_cidr_list(list: &str) -> bool {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
        .all(|s| s.parse::<ipnet::IpNet>().is_ok() || s.parse::<std::net::IpAddr>().is_ok()) }
fn valid_domain_list(list: &str) -> bool {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
        .all(|d| !d.is_empty() && d.len() <= 253 && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')) }

#[derive(Deserialize, Default)] struct AuthReq { email: String, password: String }
#[derive(Deserialize, Default)] struct NameReq { #[serde(default)] name: String, #[serde(default)] email: String, #[serde(default)] role: String, #[serde(default)] readme: String, #[serde(default)] env_id: String, #[serde(default)] expires_in: i64,
    // Delegated environments: the client generates the environment key and
    // supplies it wrapped to itself and to the customer-run sync runner.
    #[serde(default)] mode: String, #[serde(default)] runner_id: String, #[serde(default)] wrapped_key: String, #[serde(default)] runner_wrapped_key: String }
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
                oc::decrypt_symmetric(&self.master, &raw_secret).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or(raw_secret) };
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
    }
    fn env_key(&self, env_id: &str) -> Result<[u8;32], (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT env_key_wrapped FROM envs WHERE id=?", &[json!(env_id)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        let wrapped = db::s(&row, "env_key_wrapped");
        if wrapped.is_empty() { return Err(err(StatusCode::CONFLICT, "this environment is client-encrypted; the server has no key for it")); }
        if wrapped.starts_with("owkms:") {
            let kms = self.kms.as_ref().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "this environment is wrapped by a KMS that is not configured"))?;
            let raw = kms.unwrap(&wrapped, &format!("env:{}", env_id)).map_err(|e| bad(&format!("KMS could not unwrap the environment key: {}", e)))?;
            return raw.try_into().map_err(|_| bad("bad env key"));
        }
        // A row written before KMS was enabled is rewrapped on first use. The
        // legacy master is still required for every other root-encrypted record.
        let raw = oc::decrypt_symmetric(&self.master, &wrapped).map_err(|e| bad(&e))?;
        if let Some(kms) = &self.kms {
            if let Ok(rewrapped) = kms.wrap(&raw, &format!("env:{}", env_id)) {
                let _ = self.db.exec("UPDATE envs SET env_key_wrapped=? WHERE id=?", &[json!(rewrapped), json!(env_id)]);
            }
        }
        raw.try_into().map_err(|_| bad("bad env key"))
    }
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
        if let Some(row) = self.db.one("SELECT created_by,kind,created_at,expires_at FROM tokens WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))? {
            let expires = db::n(&row, "expires_at");
            if expires > 0 && expires < now() { return Err(err(StatusCode::UNAUTHORIZED, "token expired")); }
            if db::s(&row, "kind") == "machine" && db::n(&row, "created_at") + 3600 < now() { return Err(err(StatusCode::UNAUTHORIZED, "machine token expired (1h TTL); login again via Universal Auth")); }
            let uid = db::s(&row, "created_by"); if !uid.is_empty() {
                if !self.principal_active(&uid) { return Err(err(StatusCode::UNAUTHORIZED, "token owner is deactivated")); }
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
                if verification_required() && db::n(&row, "email_verified") == 0 { return false; }
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
        Err(err(StatusCode::FORBIDDEN, "no access to this environment"))
    }
    fn decrypt_secret(&self, key: &[u8;32], row: &Row, user: Option<&str>) -> Value {
        let sid = db::s(row, "id"); let env = db::s(row, "env_id"); let version = db::n(row, "version");
        let (mut value, mut decrypt_error) = match decrypt_secret_value(key, &env, &sid, "value", version, &db::s(row, "value_enc")) {
            Ok(b) => (String::from_utf8_lossy(&b).into_owned(), false),
            Err(_) => (String::new(), true) };
        if let Some(user) = user {
            if let Ok(Some(ov)) = self.db.one("SELECT value_enc FROM overrides WHERE secret_id=? AND user_id=?", &[json!(sid), json!(user)]) {
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
    fn list_secrets_with(&self, env_id: &str, user: Option<&str>) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
        let key = self.env_key(env_id)?;
        let rows = self.db.query("SELECT * FROM secrets WHERE env_id=? AND deleted=0 ORDER BY key_index, key_hash", &[json!(env_id)]).map_err(|e| bad(&e))?;
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
// Bind ciphertext to the record it belongs to. The version is deliberately not
// included: restore and point-in-time recovery copy ciphertext into a new
// version, and binding to the version would make that ciphertext unreadable.
fn secret_aad(env: &str, sid: &str, field: &str) -> Vec<u8> { format!("ow-secret:v2|{}|{}|{}", env, sid, field).into_bytes() }
// A deterministic index is still needed to look a secret up. HMAC under the
// environment key removes the offline dictionary attack a bare SHA-256 allows.
fn key_index(env_key: &[u8;32], path: &str, key: &str) -> String { hmac_hex(env_key, format!("ow-key-index:v1|{}|{}", path, key).as_bytes()) }
fn secret_aad_v(env: &str, sid: &str, field: &str, version: i64) -> Vec<u8> { format!("ow-secret:v2|{}|{}|{}|v{}", env, sid, field, version).into_bytes() }
fn integration_aad(env: &str, iid: &str, field: &str) -> Vec<u8> { format!("ow-integration:v1|{}|{}|{}", env, iid, field).into_bytes() }
fn lease_aad(env: &str, lid: &str, field: &str) -> Vec<u8> { format!("ow-lease:v1|{}|{}|{}", env, lid, field).into_bytes() }
fn proposal_aad(env: &str, pid: &str, field: &str) -> Vec<u8> { format!("ow-proposal:v1|{}|{}|{}", env, pid, field).into_bytes() }
// Version rows are bound to their version, but value and comment ciphertext
// written before that binding (or by an earlier release) must stay readable.
fn decrypt_secret_value(key: &[u8;32], env: &str, sid: &str, field: &str, version: i64, payload: &str) -> Result<Vec<u8>, String> {
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
async fn register(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, h: HeaderMap, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let rl = format!("register:{}", addr.ip());
    if !st.rate_ok(&rl, 5, 3600) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many registrations from this address; try again later")); }
    st.rate_fail(&rl, 3600);
    if !auth_enabled(&st, "password") { return Err(err(StatusCode::FORBIDDEN, "password registration is disabled on this instance; sign in with a configured provider")); }
    if r.email.is_empty() || r.password.len() < 8 { return Err(bad("email and password (>=8 chars) required")); }
    if !signups_open(&st) { return Err(err(StatusCode::FORBIDDEN, "signups are disabled on this instance; ask an administrator to invite you")); }
    let kp = oc::Keypair::generate();
    let wrapped = oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    let uid = id(); let hash = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    let verified = if verification_required() { 0 } else { 1 };
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,?)", &[json!(uid), json!(r.email.to_lowercase()), json!(hash), json!(kp.public), json!(wrapped), json!(now()), json!(verified)]).map_err(|_| err(StatusCode::CONFLICT, "an account with this email already exists"))?;
    let oid = id(); st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(oid), json!(format!("{}'s organisation", r.email)), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", &[json!(oid), json!(uid)]).map_err(|e| bad(&e))?;
    claim_instance_owner(&st, &uid);
    mfa::note_password_login(&st, &uid);
    if verification_required() {
        let link_token = issue_auth_token(&st, &uid, "verify", 86400);
        let link = format!("{}/api/auth/verify?token={}", issuer(&st, &h), link_token);
        send_email(&r.email, "Verify your OpenWarp address", &format!("Confirm your email address by opening this link:\n{}\n\nIt expires in 24 hours.", link)).await;
        return Ok((HeaderMap::new(), j(json!({"user_id": uid, "org_id": oid, "public_key": kp.public, "recovery_kit": kp.secret_b64(), "verification_required": true}))));
    }
    let token = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "org_id": oid, "public_key": kp.public, "recovery_kit": kp.secret_b64()}))))
}
fn make_session(st: &S, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { let t = oc::random_token("ow"); st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&t)), json!(uid), json!(now())]).map_err(|e| bad(&e))?; Ok(t) }
async fn login(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "password") { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance; use a configured provider")); }
    let key = format!("login:{}:{}", addr.ip(), r.email.trim().to_lowercase());
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later")); }
    let row = match st.db.one("SELECT * FROM users WHERE email=?", &[json!(r.email.trim().to_lowercase())]).map_err(|e| bad(&e))? { Some(x) => x, None => { st.rate_fail(&key, 900); return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); } };
    if db::n(&row, "active") == 0 && row.contains_key("active") { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
    if !oc::verify_password(&r.password, &db::s(&row, "pass_hash")) { st.rate_fail(&key, 900); return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    if verification_required() && db::n(&row, "email_verified") == 0 { return Err(err(StatusCode::FORBIDDEN, "verify your email address before signing in; POST /api/auth/resend-verification for a new link")); }
    st.rate_clear(&key);
    let uid = db::s(&row, "id");
    mfa::note_password_login(&st, &uid);
    if mfa::required(&st, &uid) {
        let challenge = mfa::new_challenge(&st, &uid)?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge,
            "methods": mfa::methods(&st, &uid), "email_available": mfa::email_available() && mfa::email_enabled(&st, &uid)})))); }
    let token = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "public_key": db::s(&row, "pubkey")}))))
}

async fn me(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h)?; let r = st.db.one("SELECT id,email,pubkey FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?; Ok(j(db::obj(&r))) }
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
    if !auth_enabled(&st, "password") { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance; sign in with the configured provider to redeem this invite")); }
    if r.password.len() < 8 { return Err(bad("password (>=8 chars) required")); }
    let hash = oc::hash_token(r.token.trim());
    let row = st.db.one("SELECT * FROM invites WHERE token_hash=? AND accepted=0 AND expires_at>?", &[json!(&hash), json!(now())]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invite is invalid or expired"))?;
    let email = db::s(&row, "email"); let org = db::s(&row, "org_id"); let role = db::s(&row, "role");
    if st.db.one("SELECT id FROM users WHERE email=?", &[json!(&email)]).map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in instead")); }
    let kp = oc::Keypair::generate(); let uid = id();
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(uid), json!(&email), json!(oc::hash_password(&r.password).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(&org), json!(&uid), json!(&role)]).map_err(|e| bad(&e))?;
    st.db.exec("UPDATE invites SET accepted=1 WHERE token_hash=?", &[json!(&hash)]).map_err(|e| bad(&e))?;
    claim_instance_owner(&st, &uid);
    mfa::note_password_login(&st, &uid);
    st.audit(&org, "", "", &uid, "member.accept_invite", &email);
    let token = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "org_id": org, "role": role})))) }
async fn create_app(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?; st.check_perm(&oid, &uid, "secrets:write")?;
    let aid = id(); st.db.exec("INSERT INTO apps(id,org_id,name,readme,created_at) VALUES(?,?,?,?,?)", &[json!(aid), json!(oid), json!(r.name), json!(r.readme), json!(now())]).map_err(|e| bad(&e))?;
    for name in ["Development", "Staging", "Production"] { create_env_inner(&st, &aid, name)?; }
    st.audit(&oid, &aid, "", &uid, "app.create", &r.name); Ok(j(json!({"id": aid}))) }
fn create_env_inner(st: &S, app_id: &str, name: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let eid = id(); let key = oc::random_key();
    let wrapped = match &st.kms {
        Some(kms) => kms.wrap(&key, &format!("env:{}", eid)).map_err(|e| bad(&format!("KMS could not wrap the environment key: {}", e)))?,
        None => oc::encrypt_symmetric(&st.master, &key),
    };
    st.db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)", &[json!(eid), json!(app_id), json!(name), json!(wrapped), json!(now())]).map_err(|e| bad(&e))?; Ok(eid) }
async fn list_apps(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let rows = st.db.query("SELECT id,org_id,name,readme,created_at FROM apps WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; let org = db::s(&app,"org_id"); st.require_org(&org, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    if !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || r.name.is_empty() || r.name.len() > 32 { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    if r.mode == "delegated" {
        if r.runner_id.is_empty() || r.wrapped_key.is_empty() || r.runner_wrapped_key.is_empty() {
            return Err(bad("delegated environments need runner_id, wrapped_key and runner_wrapped_key")); }
        if st.db.one("SELECT id FROM runners WHERE id=? AND org_id=?", &[json!(&r.runner_id), json!(&org)]).map_err(|e| bad(&e))?.is_none() {
            return Err(bad("runner not found in this organisation")); }
        let eid = id();
        st.db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,runner_id,created_at) VALUES(?,?,?,'','delegated',?,?)",
            &[json!(&eid), json!(&aid), json!(&r.name), json!(&r.runner_id), json!(now())]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(&eid), json!(&uid), json!(&r.wrapped_key)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO runner_env_keys(runner_id,env_id,wrapped_key) VALUES(?,?,?)", &[json!(&r.runner_id), json!(&eid), json!(&r.runner_wrapped_key)]).map_err(|e| bad(&e))?;
        st.audit(&org, &aid, &eid, &uid, "env.create.delegated", &r.runner_id);
        return Ok(j(json!({"id": eid, "mode": "delegated", "runner_id": r.runner_id}))); }
    let eid = create_env_inner(&st, &aid, &r.name)?; Ok(j(json!({"id": eid}))) }
async fn list_envs(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"), &uid)?;
    let rows = st.db.query("SELECT id,app_id,name,mode,runner_id,restricted,require_approval,created_at FROM envs WHERE app_id=? ORDER BY created_at", &[json!(aid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
    st.check_admin(&org, &uid)?;
    for sql in [
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
        "DELETE FROM runner_env_keys WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM sync_jobs WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
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
    for id in [eid.as_str(), target] { let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(id)]).map_err(|e| bad(&e))?.map(|r| db::s(&r,"mode")).unwrap_or_default(); if mode == "e2e" || mode == "delegated" { return Err(bad("client-encrypted environments cannot be cloned server-side; use the CLI")); } }
    let items = st.list_secrets_base(&eid)?; let key = st.env_key(target)?;
    let mut cloned = 0; let mut skipped = 0;
    for (_, _, raw) in items {
        let stype = raw["type"].as_str().unwrap_or("secret");
        if stype == "sealed" { skipped += 1; continue; }
        let s = SecretIn{ key: raw["key"].as_str().unwrap_or("").into(), value: raw["value"].as_str().unwrap_or("").into(), path: raw["path"].as_str().unwrap_or("/").into(), comment: raw["comment"].as_str().unwrap_or("").into(), tags: raw["tags"].as_str().unwrap_or("").into(), secret_type: stype.into() };
        let kname = s.key.to_uppercase();
        let khash = key_index(&key, &s.path, &kname);
        let legacy = oc::hash_token(&format!("{}:{}", s.path, kname));
        if !overwrite && st.db.one("SELECT id FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(target), json!(&khash), json!(&legacy)]).map_err(|e| bad(&e))?.is_some() { skipped += 1; continue; }
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

async fn list_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let items = st.list_secrets_decrypted(&eid, &uid)?; st.audit(&org, &app, &eid, &uid, "secret.list", &format!("{}", items.len()));
    Ok(j(json!({"secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
async fn deploy_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let policy = st.db.one("SELECT require_approval FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?;
    if policy.map(|p| db::n(&p, "require_approval") == 1).unwrap_or(false) {
        let role = st.require_org(&org, &uid).unwrap_or_default();
        if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "this environment requires an approved proposal; submit a proposal instead of deploying directly")); }
    }
    let mut inputs = r.secrets.clone(); if inputs.is_empty() && !r.text.is_empty() { inputs = parse_env(&r.text); }
    let key = st.env_key(&eid)?; let mut count = 0;
    for s in &inputs { if s.key.trim().is_empty() { continue; } upsert_secret(&st, &eid, &key, &uid, s)?; count += 1; }
    st.audit(&org, &app, &eid, &uid, "secret.deploy", &format!("{} secrets", count));
    let sync_errors = trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"deployed": count, "sync_errors": sync_errors}))) }
fn upsert_secret(st: &S, eid: &str, key: &[u8;32], uid: &str, s: &SecretIn) -> Result<(), (StatusCode, Json<Value>)> {
    let kname = s.key.trim().to_uppercase();
    if !valid_secret_key(&kname) { return Err(bad("secret key must match [A-Za-z0-9_.-]{1,128}")); }
    if !valid_path(&s.path) { return Err(bad("secret path must be 1-256 printable characters")); }
    let khash = key_index(key, &s.path, &kname);
    let legacy = oc::hash_token(&format!("{}:{}", s.path, kname));
    let existing = st.db.one("SELECT id,version,secret_type FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid), json!(&khash), json!(&legacy)]).map_err(|e| bad(&e))?;
    let mut stype = if s.secret_type.is_empty() { "secret".to_string() } else { s.secret_type.clone() };
    if let Some(row) = &existing { if db::s(row, "secret_type") == "sealed" { if stype != "sealed" { return Err(bad("sealed secrets cannot change type; delete and recreate")); } stype = "sealed".to_string(); } }
    if let Some(row) = existing { let sid = db::s(&row, "id"); let ver = db::n(&row, "version") + 1;
        let value_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "value", ver), s.value.as_bytes());
        let comment_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "comment", ver), s.comment.as_bytes());
        let path_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "path"), s.path.as_bytes());
        let tags_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "tags"), s.tags.as_bytes());
        // path and tags become ciphertext; key_hash carries the blind index.
        st.db.exec("UPDATE secrets SET value_enc=?,comment_enc=?,path='',path_enc=?,tags='',tags_enc=?,key_hash=?,key_index=?,secret_type=?,version=?,updated_at=?,updated_by=? WHERE id=?",
            &[json!(value_enc), json!(comment_enc), json!(path_enc), json!(tags_enc), json!(&khash), json!(&khash), json!(stype), json!(ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(ver), json!(oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "key"), kname.as_bytes())), json!(value_enc), json!(comment_enc), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    } else { let sid = id(); let ver = 1;
        let key_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "key"), kname.as_bytes());
        let value_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "value", ver), s.value.as_bytes());
        let comment_enc = oc::encrypt_symmetric_aad(key, &secret_aad_v(eid, &sid, "comment", ver), s.comment.as_bytes());
        let path_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "path"), s.path.as_bytes());
        let tags_enc = oc::encrypt_symmetric_aad(key, &secret_aad(eid, &sid, "tags"), s.tags.as_bytes());
        st.db.exec("INSERT INTO secrets(id,env_id,path,path_enc,key_enc,key_hash,key_index,value_enc,comment_enc,tags,tags_enc,secret_type,version,updated_at,updated_by) VALUES(?,?,'',?,?,?,?,?,?,'',?,?,1,?,?)",
            &[json!(sid), json!(eid), json!(path_enc), json!(key_enc), json!(&khash), json!(&khash), json!(value_enc), json!(comment_enc), json!(tags_enc), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,1,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(key_enc), json!(value_enc), json!(comment_enc), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    } Ok(()) }
fn parse_env(text: &str) -> Vec<SecretIn> { let mut out = Vec::new(); let mut pending_comment = String::new();
    for line in text.lines() { let l = line.trim(); if l.is_empty() { continue; } else if l.starts_with('#') { pending_comment = l.trim_start_matches('#').trim().to_string(); continue; }
        if let Some((k, v)) = l.trim_start_matches("export ").split_once('=') { out.push(SecretIn{ key: k.trim().to_string(), value: v.trim().trim_matches('"').trim_matches('\'').to_string(), path: "/".into(), comment: pending_comment.clone(), tags: "".into(), secret_type: "".into() }); pending_comment.clear(); } } out }
async fn delete_secret(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:delete")?;
    st.db.exec("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=? WHERE id=?", &[json!(now()), json!(now()), json!(sid)]).map_err(|e| bad(&e))?; st.audit(&org, &app, &eid, &uid, "secret.delete", &sid); Ok(j(json!({"ok": true}))) }
async fn history(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let key = st.env_key(&eid)?; let sealed = st.db.one("SELECT secret_type FROM secrets WHERE id=?", &[json!(sid)]).map(|r| r.map(|x| db::s(&x,"secret_type") == "sealed").unwrap_or(false)).unwrap_or(false);
    let rows = st.db.query("SELECT * FROM secret_versions WHERE secret_id=? ORDER BY version DESC", &[json!(sid)]).map_err(|e| bad(&e))?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"version": db::n(r,"version"), "value": if sealed { "[SEALED]".to_string() } else { decrypt_secret_value(&key, &eid, &sid, "value", db::n(r,"version"), &db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() }, "created_at": db::n(r,"created_at"), "created_by": db::s(r,"created_by")})).collect();
    Ok(j(json!(items))) }
async fn restore(State(st): State<S>, h: HeaderMap, Path((sid, ver)): Path<(String, i64)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let v = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND version=?", &[json!(sid), json!(ver)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("version not found"))?;
    let cur = st.db.one("SELECT version FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?; let new_ver = cur.map(|r| db::n(&r,"version")).unwrap_or(0) + 1;
    let key = st.env_key(&eid)?;
    // Version ciphertext is bound to its version, so restoring it under a new
    // version means decrypting and re-binding rather than copying the blob.
    let plain_value = decrypt_secret_value(&key, &eid, &sid, "value", ver, &db::s(&v,"value_enc")).map_err(|e| bad(&e))?;
    let plain_comment = decrypt_secret_value(&key, &eid, &sid, "comment", ver, &db::s(&v,"comment_enc")).map_err(|e| bad(&e))?;
    let value_enc = oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid, &sid, "value", new_ver), &plain_value);
    let comment_enc = oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid, &sid, "comment", new_ver), &plain_comment);
    st.db.exec("UPDATE secrets SET value_enc=?,comment_enc=?,version=?,deleted=0,deleted_at=0,updated_at=?,updated_by=? WHERE id=?", &[json!(value_enc), json!(comment_enc), json!(new_ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(value_enc), json!(comment_enc), json!(db::s(&v,"secret_type")), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"secret.restore",&format!("{}->v{}",sid,ver)); Ok(j(json!({"ok":true,"version":new_ver}))) }
async fn set_override(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row,"env_id"); st.require_env(&eid,&uid)?;
    let key = st.env_key(&eid)?; let val = r.secrets.first().map(|s| s.value.clone()).unwrap_or_default();
    let enc = oc::encrypt_symmetric_aad(&key, &secret_aad(&eid, &sid, &format!("override:{}", uid)), val.as_bytes());
    st.db.exec("INSERT INTO overrides(secret_id,user_id,value_enc) VALUES(?,?,?)", &[json!(sid), json!(uid), json!(enc.clone())]).map_err(|e| bad(&e)).or_else(|_| st.db.exec("UPDATE overrides SET value_enc=? WHERE secret_id=? AND user_id=?", &[json!(enc), json!(sid), json!(uid)]).map_err(|e| bad(&e)))?; Ok(j(json!({"ok":true}))) }

async fn export_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org,&uid,"secrets:read")?;
    let items = st.list_secrets_decrypted(&eid,&uid)?; let text = items.iter().map(|(k,v,_)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n"); Ok(j(json!({"text": text, "secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
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
    let expires_at = if r.expires_in > 0 { now() + r.expires_in.clamp(60, 365 * 86400) } else { 0 };
    st.db.exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,expires_at,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(tid), json!(org), json!(aid), json!(r.env_id), json!(if r.name.is_empty(){"token".into()}else{r.name.clone()}), json!(oc::hash_token(&token)), json!(expires_at), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": tid, "token": token, "expires_at": expires_at}))) }
async fn audit_list(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT * FROM audit WHERE org_id=? ORDER BY created_at DESC LIMIT 500", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_team(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.check_admin(&oid,&uid)?;
    let tid = id(); st.db.exec("INSERT INTO teams(id,org_id,name) VALUES(?,?,?)", &[json!(tid), json!(oid), json!(r.name)]).map_err(|e| bad(&e))?; Ok(j(json!({"id": tid}))) }
async fn list_teams(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT * FROM teams WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }

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
    Ok(j(json!(rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "value": oc::decrypt_symmetric_compat(&key, &lease_aad(&eid, &db::s(r,"id"), "value"), &db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(), "expires_at": db::n(r,"expires_at")})).collect::<Vec<_>>()))) }

async fn create_integration(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or(""); if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
    let config = body.get("config").cloned().unwrap_or(json!({}));
    let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")).unwrap_or_default();
    let iid = id();
    let config_enc = if mode == "delegated" { seal_to_runner(&st, &eid, &iid, &config)? }
        else { oc::encrypt_symmetric_aad(&st.env_key(&eid)?, &integration_aad(&eid, &iid, "config"), config.to_string().as_bytes()) };
    st.db.exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES(?,?,?,?,?,?)", &[json!(iid), json!(eid), json!(kind), json!(body.get("name").and_then(|v| v.as_str()).unwrap_or(kind)), json!(config_enc), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": iid}))) }
async fn list_integrations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT id,env_id,kind,name,created_at FROM integrations WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn sync_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let (org, _) = st.require_env(&db::s(&row, "env_id"), &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    let msg = sync_one(&st, &iid, &uid).await?; Ok(j(json!({"ok": true, "detail": msg}))) }
async fn test_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    if st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")) == Some("delegated".into()) {
        enqueue_sync(&st, &eid, &iid, "test")?;
        return Ok(j(json!({"ok": true, "detail": "connection test queued for the customer runner"})));
    }
    let key = st.env_key(&eid)?;
    let config: Value = serde_json::from_slice(&oc::decrypt_symmetric_compat(&key, &integration_aad(&eid, &iid, "config"), &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    if db::s(&row, "kind") == "trigger" { let msg = integrations::trigger_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    if db::s(&row, "kind") == "instabox" { let msg = integrations::instabox_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    if db::s(&row, "kind") == "boat" { let msg = integrations::boat_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    if db::s(&row, "kind") == "daytona" { let msg = integrations::daytona_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    Err(err(StatusCode::NOT_IMPLEMENTED, &format!("connection test is not implemented for kind {}; use Sync to verify it against the live service", db::s(&row, "kind")))) }
async fn update_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")).unwrap_or_default();
    if let Some(kind) = body.get("kind").and_then(|v| v.as_str()) {
        if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
        st.db.exec("UPDATE integrations SET kind=? WHERE id=?", &[json!(kind), json!(&iid)]).map_err(|e| bad(&e))?; }
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) { st.db.exec("UPDATE integrations SET name=? WHERE id=?", &[json!(name), json!(&iid)]).map_err(|e| bad(&e))?; }
    if let Some(config) = body.get("config") {
        let enc = if mode == "delegated" { seal_to_runner(&st, &eid, &iid, config)? }
            else { oc::encrypt_symmetric_aad(&st.env_key(&eid)?, &integration_aad(&eid, &iid, "config"), config.to_string().as_bytes()) };
        st.db.exec("UPDATE integrations SET config_enc=? WHERE id=?", &[json!(enc), json!(&iid)]).map_err(|e| bad(&e))?; }
    st.audit(&org,&app,&eid,&uid,"integration.update",&iid); Ok(j(json!({"ok": true}))) }
async fn delete_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "integrations:write")?;
    st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    let _ = st.db.exec("DELETE FROM sync_jobs WHERE integration_id=?", &[json!(&iid)]);
    st.db.exec("DELETE FROM integrations WHERE id=?", &[json!(&iid)]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"integration.delete",&iid); Ok(j(json!({"deleted": iid}))) }
async fn trigger_sync(st: &S, eid: &str, uid: &str) -> Vec<String> { trigger_sync_with(st, eid, uid, true).await }
async fn trigger_sync_internal(st: &S, eid: &str) -> Vec<String> { trigger_sync_with(st, eid, "rotation-scheduler", false).await }
async fn trigger_sync_with(st: &S, eid: &str, uid: &str, enforce: bool) -> Vec<String> {
    let mut errors = Vec::new();
    if let Ok(rows) = st.db.query("SELECT id FROM integrations WHERE env_id=?", &[json!(eid)]) {
        for r in &rows { let iid = db::s(r, "id");
            if let Err((_, Json(v))) = sync_one_inner(st, &iid, uid, enforce).await {
                let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("integration sync failed").to_string();
                if let Ok((org, app)) = st.env_org_app(eid) { st.audit(&org, &app, eid, uid, "integration.sync_failed", &format!("{}: {}", iid, msg)); }
                errors.push(format!("{}: {}", iid, msg)); } }
    }
    errors
}
async fn sync_one(st: &S, iid: &str, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { sync_one_inner(st, iid, uid, true).await }
async fn sync_one_inner(st: &S, iid: &str, uid: &str, enforce: bool) -> Result<String, (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id");
    let (org, app) = if enforce { st.require_env(&eid, uid)? } else { st.env_org_app(&eid)? };
    if st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "mode")) == Some("delegated".into()) {
        enqueue_sync(st, &eid, iid, "sync")?;
        return Ok("queued for the customer runner".into());
    }
    let key = st.env_key(&eid)?;
    let config: Value = serde_json::from_slice(&oc::decrypt_symmetric_compat(&key, &integration_aad(&eid, iid, "config"), &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    // Sealed secrets are never readable, so they must never be pushed: an empty
    // string would overwrite the value on the remote side. Personal overrides are
    // a per-user view and must not become the shared deployed value either.
    let items = st.list_secrets_base(&eid)?;
    let pairs: Vec<(String, String)> = items.iter().filter(|(_, _, raw)| raw["type"].as_str() != Some("sealed")).map(|(k, v, _)| (k.clone(), v.clone())).collect();
    let kind = db::s(&row, "kind");
    if matches!(kind.as_str(), "trigger" | "instabox" | "boat" | "daytona") {
        let prev_rows = st.db.query("SELECT remote_name FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]).map_err(|e| bad(&e))?;
        let prev: Vec<String> = prev_rows.iter().map(|r| db::s(r, "remote_name")).collect();
        let dry = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
        let prefix = config.get("prefix").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let result = match kind.as_str() {
            "trigger" => integrations::trigger_sync(&config, &pairs, &prev).await,
            "instabox" => integrations::instabox_sync(&config, &pairs, &prev).await,
            "boat" => integrations::boat_sync(&config, &pairs, &prev).await,
            _ => integrations::daytona_sync(&config, &pairs, &prev).await,
        };
        let (msg, managed) = match result {
            Ok(x) => x,
            Err(e) => {
                if !dry {
                    // Some writes may have landed before the failure; keep ownership of them
                    // so a later mirror sync can still prune the remote.
                    let mut union = prev.clone();
                    for n in integrations::desired_names(&config, &pairs) { if !union.contains(&n) { union.push(n); } }
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
    let key = st.env_key(&eid)?;
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
                let src_ver = db::n(&v, "version");
                let plain_value = decrypt_secret_value(&key, &eid, &sid, "value", src_ver, &db::s(&v,"value_enc")).map_err(|e| bad(&e))?;
                let plain_comment = decrypt_secret_value(&key, &eid, &sid, "comment", src_ver, &db::s(&v,"comment_enc")).map_err(|e| bad(&e))?;
                let value_enc = oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid, &sid, "value", new_ver), &plain_value);
                let comment_enc = oc::encrypt_symmetric_aad(&key, &secret_aad_v(&eid, &sid, "comment", new_ver), &plain_comment);
                st.db.exec("UPDATE secrets SET key_enc=?,value_enc=?,comment_enc=?,secret_type=?,version=?,deleted=?,deleted_at=?,updated_at=?,updated_by=? WHERE id=?",
                    &[json!(db::s(&v,"key_enc")), json!(value_enc), json!(comment_enc), json!(db::s(&v,"secret_type")), json!(new_ver), json!(tomb), json!(tomb_at), json!(now()), json!(&uid), json!(&sid)]).map_err(|e| bad(&e))?;
                st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)",
                    &[json!(id()), json!(&sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(value_enc), json!(comment_enc), json!(db::s(&v,"secret_type")), json!(now()), json!(&uid)]).map_err(|e| bad(&e))?;
                if was_deleted { removed += 1 } else { restored += 1 }
            }
            None => {
                st.db.exec("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=? WHERE id=?", &[json!(now()), json!(now()), json!(&sid)]).map_err(|e| bad(&e))?;
                removed += 1;
            }
        }
    }
    st.audit(&org,&app,&eid,&uid,"env.pitr",&format!("ts={} restored={} removed={}",ts,restored,removed));
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
    if let Some(v)=body.get("audit_webhook").and_then(|x|x.as_str()) { if !v.is_empty() && !url_ok(v) { return Err(bad("audit_webhook must be an http(s) URL")); } meta_set(&st, &format!("audit_webhook:{}",oid), v); }
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
            let stored = if enc { oc::encrypt_symmetric(&st.master, v.as_bytes()) } else { v.to_string() };
            meta_set(&st, &format!("{}:{}", field, oid), &stored); } }
    st.audit(&oid, "", "", &uid, "org.settings", "");
    Ok(j(json!({"ok":true}))) }
async fn rotate_secret(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org,app)=st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let key_name = body.get("key").and_then(|v|v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v|v.as_str()).unwrap_or("/");
    let new_val = body.get("value").and_then(|v|v.as_str()).map(|s|s.to_string()).unwrap_or_else(|| oc::random_token("rot"));
    let key = st.env_key(&eid)?; let kname = key_name.to_uppercase();
    let khash = key_index(&key, path, &kname); let legacy = oc::hash_token(&format!("{}:{}", path, kname));
    let row = st.db.one("SELECT id FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid), json!(&khash), json!(&legacy)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found; create it first"))?;
    upsert_secret(&st,&eid,&key,&uid,&SecretIn{key:key_name.into(),value:new_val.clone(),path:path.into(),comment:"auto-rotation".into(),tags:"".into(),secret_type:"secret".into()})?;
    st.audit(&org,&app,&eid,&uid,"secret.rotate",key_name);
    let sync_errors = trigger_sync(&st, &eid, &uid).await;
    Ok(j(json!({"key":key_name,"value":new_val,"secret_id":db::s(&row,"id"),"sync_errors":sync_errors}))) }
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
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(nid), json!(email.to_lowercase()), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|_| bad("user exists"))?;
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
    if mode != "e2e" && mode != "delegated" { return Err(bad("env is not client-encrypted")); }
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN, "no wrapped env key for caller")); }
    let mut count = 0;
    for s in body.get("secrets").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let key_enc = s.get("key_enc").and_then(|v| v.as_str()).unwrap_or(""); let value_enc = s.get("value_enc").and_then(|v| v.as_str()).unwrap_or("");
        let key_hash = s.get("key_hash").and_then(|v| v.as_str()).unwrap_or("");
        let path_enc = s.get("path_enc").and_then(|v| v.as_str()).unwrap_or("");
        if key_enc.is_empty() || key_hash.is_empty() { continue; }
        if path_enc.is_empty() { return Err(bad("path_enc is required: encrypt the path with the environment key")); }
        let path_val = "";
        if let Some(row) = st.db.one("SELECT id,version FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(key_hash)]).map_err(|e| bad(&e))? {
            let ver = db::n(&row,"version")+1; let sid = db::s(&row,"id");
            st.db.exec("UPDATE secrets SET key_enc=?,value_enc=?,path=?,path_enc=?,key_index=?,version=?,updated_at=?,updated_by=? WHERE id=?", &[json!(key_enc), json!(value_enc), json!(path_val), json!(path_enc), json!(key_hash), json!(ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
            st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,created_at,created_by) VALUES(?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(ver), json!(key_enc), json!(value_enc), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        } else { let sid = id();
            st.db.exec("INSERT INTO secrets(id,env_id,path,path_enc,key_enc,key_hash,key_index,value_enc,e2e,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,1,1,?,?)", &[json!(sid), json!(eid), json!(path_val), json!(path_enc), json!(key_enc), json!(key_hash), json!(key_hash), json!(value_enc), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
            st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,created_at,created_by) VALUES(?,?,1,?,?,?,?)", &[json!(id()), json!(sid), json!(key_enc), json!(value_enc), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        } count += 1;
    }
    st.audit(&org,&app,&eid,&uid,"secret.e2e_deploy",&format!("{} secrets",count)); Ok(j(json!({"deployed": count}))) }
async fn e2e_get(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let wrapped = st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN, "no wrapped env key for caller; ask a member to grant access"))?;
    let rows = st.db.query("SELECT id,path,path_enc,key_hash,key_enc,value_enc,version,updated_at FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1", &[json!(eid)]).map_err(|e| bad(&e))?;
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
    let rows = st.db.query("SELECT k.user_id AS user_id, u.email AS email, u.pubkey AS pubkey FROM env_keys k JOIN users u ON u.id=k.user_id WHERE k.env_id=?", &[json!(&eid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn e2e_meta(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res {
    let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let env = st.db.one("SELECT mode,runner_id FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
    let runner = if db::s(&env, "runner_id").is_empty() { Value::Null } else {
        st.db.one("SELECT id,pubkey FROM runners WHERE id=?", &[json!(db::s(&env, "runner_id"))]).ok().flatten()
            .map(|r| json!({"id": db::s(&r,"id"), "public_key": db::s(&r,"pubkey")})).unwrap_or(Value::Null) };
    Ok(j(json!({"mode": db::s(&env, "mode"), "runner": runner, "rekey_required": meta_get(&st, &format!("rekey_required:{}", eid)) == "1"}))) }
async fn e2e_rekey(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let env = st.db.one("SELECT mode,runner_id FROM envs WHERE id=?", &[json!(&eid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
    let mode = db::s(&env, "mode");
    if mode != "e2e" && mode != "delegated" { return Err(bad("only client-encrypted environments can be rekeyed")); }
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(&eid), json!(&uid)]).map_err(|e| bad(&e))?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "caller has no grant for this environment")); }
    let secrets = body.get("secrets").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if secrets.is_empty() { return Err(bad("secrets array required")); }
    let mut current = std::collections::HashSet::new();
    for r in st.db.query("SELECT key_hash FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1", &[json!(&eid)]).map_err(|e| bad(&e))? { current.insert(db::s(&r, "key_hash")); }
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
    let current_grants: std::collections::HashSet<String> = st.db.query("SELECT user_id FROM env_keys WHERE env_id=?", &[json!(&eid)]).map_err(|e| bad(&e))?
        .iter().map(|r| db::s(r, "user_id")).collect();
    let mut ids = std::collections::HashSet::new();
    for g in &grants {
        let gid = g.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
        let wrapped = g.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
        if gid.is_empty() || wrapped.is_empty() { return Err(bad("each grant needs user_id and wrapped_key")); }
        if !current_grants.contains(gid) { return Err(bad("a rekey may remove grants but cannot add a grantee who does not already hold the key; grant access first")); }
        if st.db.one("SELECT id FROM users WHERE id=?", &[json!(gid)]).map_err(|e| bad(&e))?.is_none() { return Err(bad("grant refers to an unknown user")); }
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
        if st.db.one("SELECT 1 AS n FROM runner_env_keys WHERE runner_id=? AND env_id=?", &[json!(db::s(&env, "runner_id")), json!(&eid)]).map_err(|e| bad(&e))?.is_none() {
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
        let existing = st.db.one("SELECT id,version FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0 AND e2e=1", &[json!(&eid), json!(kh)]).map_err(|e| bad(&e))?;
        let (sid, ver) = match existing {
            Some(r) => (db::s(&r, "id"), db::n(&r, "version") + 1),
            None => { return Err(bad("rekey payload does not match the stored secrets")); }
        };
        stmts.push(("UPDATE secrets SET key_enc=?,value_enc=?,path=?,path_enc=?,key_index=?,version=?,updated_at=?,updated_by=? WHERE id=?".into(),
            vec![json!(key_enc), json!(value_enc), json!(path_val), json!(path_enc), json!(kh), json!(ver), json!(now()), json!(&uid), json!(&sid)]));
        // Old history is encrypted under the old key and cannot be read after
        // the rotation; replace it rather than leave undecryptable rows.
        stmts.push(("DELETE FROM secret_versions WHERE secret_id=?".into(), vec![json!(&sid)]));
        stmts.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,created_at,created_by) VALUES(?,?,?,?,?,?,?)".into(),
            vec![json!(id()), json!(&sid), json!(ver), json!(key_enc), json!(value_enc), json!(now()), json!(&uid)]));
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
    st.db.batch(&stmts).map_err(|e| bad(&format!("rekey did not complete: {}", e)))?;
    meta_set(&st, &format!("rekey_required:{}", eid), "0");
    let detail = if remove_user.is_empty() { format!("{} secrets, {} grants", rekeyed, grants.len()) } else { format!("{} secrets, {} grants, removed {}", rekeyed, grants.len(), remove_user) };
    st.audit(&org, &app, &eid, &uid, "e2e.rekey", &detail);
    Ok(j(json!({"rekeyed": rekeyed, "grants": grants.len()}))) }
async fn e2e_revoke(State(st): State<S>, h: HeaderMap, Path((eid, target)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let deleted = st.db.exec("DELETE FROM env_keys WHERE env_id=? AND user_id=?", &[json!(&eid), json!(&target)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(err(StatusCode::NOT_FOUND, "no key grant for that user")); }
    // The removed member may have kept the old key; only a rekey makes the
    // remaining ciphertext unreadable to them.
    meta_set(&st, &format!("rekey_required:{}", eid), "1");
    st.audit(&org,&app,&eid,&uid,"e2e.revoke",&target); Ok(j(json!({"revoked": target, "rekey_required": true}))) }
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
    if !auth_enabled(&st, "oidc") { return Err(err(StatusCode::FORBIDDEN, "single sign-on is disabled on this instance")); }
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)); let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)); let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid));
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid));
    let client_secret = oc::decrypt_symmetric(&st.master, &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    if issuer.is_empty() || client_id.is_empty() || redirect_uri.is_empty() { return Err(bad("OIDC not configured for this org (set oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri via org settings)")); }
    if client_secret.is_empty() { return Err(bad("OIDC client secret is not configured or was cleared by an issuer change; re-enter the client secret in org settings")); }
    if !issuer_url_ok(&issuer) { return Err(bad("OIDC issuer must be https, or http on a loopback address")); }
    let disc = oidc_discovery(&issuer).await?; let auth_ep = disc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    if !url_ok(auth_ep) { return Err(bad("OIDC discovery returned no usable authorization_endpoint")); }
    let state = oc::random_token("st"); let nonce = oc::random_token("n");
    st.db.exec("INSERT INTO oidc_states(state,org_id,created_at,nonce) VALUES(?,?,?,?)", &[json!(state), json!(oid), json!(now()), json!(nonce)]).map_err(|e| bad(&e))?;
    let url = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&nonce={}", auth_ep, urlencode(&client_id), urlencode(&redirect_uri), state, nonce);
    Ok(axum::response::Redirect::temporary(&url)) }
fn urlencode(s: &str) -> String { s.chars().map(|c| match c { 'A'..='Z'|'a'..='z'|'0'..='9'|'-'|'_'|'.'|'~' => c.to_string(), _ => format!("%{:02X}", c as u32) }).collect() }
#[derive(serde::Deserialize)] struct Claims { email: Option<String>, sub: String, #[serde(default)] nonce: Option<String>, #[serde(default)] email_verified: Option<bool> }
async fn oidc_callback(State(st): State<S>, Query(q): Query<HashMap<String,String>>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "oidc") { return Err(err(StatusCode::FORBIDDEN, "single sign-on is disabled on this instance")); }
    let code = q.get("code").cloned().unwrap_or_default(); let state = q.get("state").cloned().unwrap_or_default();
    let srow = st.db.one("SELECT org_id,created_at,nonce FROM oidc_states WHERE state=?", &[json!(state)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    let oid = db::s(&srow, "org_id"); let expected_nonce = db::s(&srow, "nonce");
    let _ = st.db.exec("DELETE FROM oidc_states WHERE state=?", &[json!(state)]);
    if db::n(&srow, "created_at") + 600 < now() { return Err(bad("invalid or expired state")); }
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)); let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)); let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid));
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid)); let client_secret = oc::decrypt_symmetric(&st.master, &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let disc = oidc_discovery(&issuer).await?;
    let token_ep = disc.get("token_endpoint").and_then(|v| v.as_str()).unwrap_or(""); let jwks_uri = disc.get("jwks_uri").and_then(|v| v.as_str()).unwrap_or("");
    if !url_ok(token_ep) || !url_ok(jwks_uri) { return Err(bad("OIDC discovery returned no usable token_endpoint or jwks_uri")); }
    let client = http_client();
    let tok: Value = client.post(token_ep).form(&[("grant_type","authorization_code"),("code",&code),("redirect_uri",&redirect_uri),("client_id",&client_id),("client_secret",&client_secret)]).send().await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string()))?;
    let id_token = tok.get("id_token").and_then(|v| v.as_str()).ok_or_else(|| bad("token response has no id_token"))?;
    let header = jsonwebtoken::decode_header(id_token).map_err(|e| bad(&e.to_string()))?; let kid = header.kid.ok_or_else(|| bad("id_token has no kid"))?;
    let jwks: Value = client.get(jwks_uri).send().await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string()))?;
    let jwk = jwks.get("keys").and_then(|v| v.as_array()).and_then(|ks| ks.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid))).ok_or_else(|| bad("kid not found in JWKS"))?;
    let dkey = jsonwebtoken::DecodingKey::from_rsa_components(jwk.get("n").and_then(|v| v.as_str()).unwrap_or(""), jwk.get("e").and_then(|v| v.as_str()).unwrap_or("")).map_err(|e| bad(&e.to_string()))?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&client_id]); validation.set_issuer(&[&issuer]);
    let data = jsonwebtoken::decode::<Claims>(id_token, &dkey, &validation).map_err(|e| bad(&format!("id_token verification failed: {}", e)))?;
    if let Some(returned) = &data.claims.nonce { if !expected_nonce.is_empty() && *returned != expected_nonce { return Err(bad("id_token nonce does not match this login attempt")); } }
    let email = data.claims.email.ok_or_else(|| bad("id_token has no email"))?.to_lowercase();
    if data.claims.email_verified == Some(false) { return Err(bad("id_token email is not verified")); }
    let subject = data.claims.sub.clone(); let issuer_key = issuer.clone();
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
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(nid), json!(email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
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
    st.audit(&oid,"","",&uid,"auth.oidc_login",&format!("{} sub={}", email, data.claims.sub));
    if mfa::required(&st, &uid) {
        let challenge = mfa::new_challenge(&st, &uid)?;
        return Ok(axum::response::Redirect::temporary(&format!("/#mfa={}&org={}", challenge, oid))); }
    let token = make_session(&st, &uid)?;
    Ok(axum::response::Redirect::temporary(&format!("/#token={}&org={}", token, oid))) }

// ---------- email, verification and password reset ----------
fn verification_required() -> bool {
    matches!(std::env::var("OPENWARP_REQUIRE_EMAIL_VERIFICATION").unwrap_or_default().to_ascii_lowercase().as_str(), "1" | "true" | "yes") }
// The operator supplies a small HTTP relay that forwards {to,subject,text} to
// their mail provider. Without one, mail is suppressed and logged, never queued.
// Security codes need the delivery outcome, so they use the fallible variant.
async fn send_email_result(to: &str, subject: &str, text: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let url = std::env::var("OPENWARP_EMAIL_WEBHOOK").unwrap_or_default();
    if url.trim().is_empty() { return Err(err(StatusCode::SERVICE_UNAVAILABLE, "email delivery is not configured on this instance")); }
    let token = std::env::var("OPENWARP_EMAIL_TOKEN").unwrap_or_default();
    let mut req = http_client().post(&url).json(&json!({"to": to, "subject": subject, "text": text}));
    if !token.is_empty() { req = req.bearer_auth(token); }
    let response = req.send().await.map_err(|_| err(StatusCode::BAD_GATEWAY, "the email relay could not be reached"))?;
    if !response.status().is_success() { return Err(err(StatusCode::BAD_GATEWAY, "the email relay rejected the message")); }
    Ok(()) }
async fn send_email(to: &str, subject: &str, text: &str) {
    if let Err((_, Json(v))) = send_email_result(to, subject, text).await {
        eprintln!("email delivery failed: {}", v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error")); } }
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
            st.audit("", "", "", &uid, "auth.email_verified", "");
            (StatusCode::OK, "Email verified", "You can sign in now.") }
        None => (StatusCode::BAD_REQUEST, "Link not valid", "This verification link is invalid, already used, or expired.") };
    let mut r = Html(format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>OpenWarp</title></head><body style=\"margin:0;background:#08080c;color:#eceaf8;font:15px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;min-height:100vh\"><main style=\"max-width:520px;padding:28px\"><h1 style=\"font-size:20px\">{}</h1><p style=\"color:#9a97b3\">{}</p><p><a style=\"color:#9d8fff\" href=\"/\">Open the console</a></p></main></body></html>", esc(title), esc(detail))).into_response();
    *r.status_mut() = status;
    r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(OAUTH_CSP));
    r }
async fn forgot_password(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, h: HeaderMap, Json(r): Json<EmailReq>) -> Res {
    if !auth_enabled(&st, "password") { return Ok(j(json!({"ok": true, "note": "if that address has an account, a reset link is on its way"}))); }
    let key = format!("forgot:{}", addr.ip());
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many reset requests; try again later")); }
    st.rate_fail(&key, 900);
    let email = r.email.trim().to_lowercase();
    if let Ok(Some(row)) = st.db.one("SELECT id FROM users WHERE email=? AND active=1", &[json!(&email)]) {
        let uid = db::s(&row, "id"); let token = issue_auth_token(&st, &uid, "reset", 3600);
        let link = format!("{}/#reset={}", issuer(&st, &h), token);
        send_email(&email, "Reset your OpenWarp password", &format!("Open this link to choose a new password:\n{}\n\nIt expires in one hour. You will be asked for your recovery kit unless you choose to replace your key.", link)).await;
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
        send_email(&email, "Verify your OpenWarp address", &format!("Confirm your email address by opening this link:\n{}\n\nIt expires in 24 hours.", link)).await;
    }
    Ok(j(json!({"ok": true}))) }
async fn reset_password(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<ResetReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth_enabled(&st, "password") { return Err(err(StatusCode::FORBIDDEN, "password sign-in is disabled on this instance")); }
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
    mfa::note_password_login(&st, &uid);
    st.audit("", "", "", &uid, "auth.password_reset", if replaced { "key replaced" } else { "kit supplied" });
    // A reset link proves the mailbox, not the second factor. Changing the
    // password must not be a way around an enrolled factor.
    if mfa::required(&st, &uid) {
        let challenge = mfa::new_challenge(&st, &uid)?;
        return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge,
            "methods": mfa::methods(&st, &uid), "email_available": mfa::email_available() && mfa::email_enabled(&st, &uid),
            "e2e_key_replaced": replaced})))); }
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
fn instance_owner(st: &S) -> Option<String> {
    let stored = meta_get(st, "instance_owner");
    if !stored.is_empty() { return Some(stored); }
    let uid = st.db.one("SELECT id FROM users ORDER BY created_at, id LIMIT 1", &[]).ok().flatten().map(|r| db::s(&r, "id"));
    if let Some(u) = &uid { claim_instance_owner(st, u); }
    uid }
fn social_provider(provider: &str) -> Option<(String, String)> {
    let (id_key, secret_key) = match provider {
        "google" => ("OPENWARP_GOOGLE_CLIENT_ID", "OPENWARP_GOOGLE_CLIENT_SECRET"),
        "github" => ("OPENWARP_GITHUB_CLIENT_ID", "OPENWARP_GITHUB_CLIENT_SECRET"),
        _ => return None };
    let id = std::env::var(id_key).ok().unwrap_or_default();
    let secret = std::env::var(secret_key).ok().unwrap_or_default();
    if id.trim().is_empty() || secret.trim().is_empty() { None } else { Some((id, secret)) } }
const AUTH_METHODS: &[&str] = &["password", "google", "github", "oidc"];
fn auth_method_configured(st: &S, method: &str) -> bool {
    match method {
        "password" => true,
        // Per-organisation SSO counts only once an org has an issuer. Otherwise
        // it could keep the "last method" check green while logging nobody in.
        "oidc" => st.db.one("SELECT COUNT(*) AS n FROM meta WHERE k LIKE 'oidc_issuer:%' AND v<>''", &[]).ok().flatten().map(|r| db::n(&r, "n") > 0).unwrap_or(false),
        "google" => social_provider("google").is_some(),
        "github" => social_provider("github").is_some(),
        _ => false } }
fn auth_env_lock() -> Option<Vec<String>> {
    std::env::var("OPENWARP_AUTH_PROVIDERS").ok()
        .map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()) }
// Operators can pin the method list with OPENWARP_AUTH_PROVIDERS. Otherwise the
// instance owner's stored choice wins, defaulting to every configured method.
fn auth_enabled(st: &S, method: &str) -> bool {
    if !auth_method_configured(st, method) { return false; }
    if let Some(lock) = auth_env_lock() { return lock.iter().any(|m| m == method); }
    let stored = meta_get(st, "auth_providers");
    if stored.is_empty() { return true; }
    serde_json::from_str::<Value>(&stored).ok()
        .and_then(|v| v.get(method).and_then(|b| b.as_bool())).unwrap_or(true) }
fn auth_settings(st: &S) -> Value {
    let enabled: Vec<&str> = AUTH_METHODS.iter().copied().filter(|m| auth_enabled(st, m)).collect();
    let configured: Vec<&str> = AUTH_METHODS.iter().copied().filter(|m| auth_method_configured(st, m)).collect();
    json!({
        "password": auth_enabled(st, "password"),
        "google": auth_enabled(st, "google"),
        "github": auth_enabled(st, "github"),
        "oidc": auth_enabled(st, "oidc"),
        "methods": enabled,
        "configured": configured,
        "env_locked": auth_env_lock().is_some(),
    }) }
fn validate_auth_env(st: &S) -> Result<(), String> {
    let Some(lock) = auth_env_lock() else { return Ok(()) };
    if lock.is_empty() { return Err("OPENWARP_AUTH_PROVIDERS is set but names no sign-in method".into()); }
    for m in &lock {
        if !AUTH_METHODS.contains(&m.as_str()) { return Err(format!("OPENWARP_AUTH_PROVIDERS contains unknown method {:?}; use {:?}", m, AUTH_METHODS)); }
        if !auth_method_configured(st, m) { return Err(format!("OPENWARP_AUTH_PROVIDERS enables {:?} but its credentials are not configured", m)); }
    }
    Ok(()) }
fn google_issuer() -> String { std::env::var("OPENWARP_GOOGLE_ISSUER").unwrap_or_else(|_| "https://accounts.google.com".into()) }
fn github_web() -> String { std::env::var("OPENWARP_GITHUB_WEB").unwrap_or_else(|_| "https://github.com".into()) }
fn github_api() -> String { std::env::var("OPENWARP_GITHUB_API").unwrap_or_else(|_| "https://api.github.com".into()) }
fn social_redirect(st: &S, h: &HeaderMap, provider: &str) -> String { format!("{}/api/auth/social/{}/callback", issuer(st, h), provider) }
async fn verify_id_token(id_token: &str, issuer: &str, audience: &str, jwks_uri: &str) -> Result<Value, String> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or("id_token has no kid")?;
    let jwks: Value = http_client().get(jwks_uri).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let jwk = jwks.get("keys").and_then(|v| v.as_array()).and_then(|ks| ks.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid))).ok_or("kid not found in JWKS")?;
    let dkey = jsonwebtoken::DecodingKey::from_rsa_components(jwk.get("n").and_then(|v| v.as_str()).unwrap_or(""), jwk.get("e").and_then(|v| v.as_str()).unwrap_or("")).map_err(|e| e.to_string())?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[audience]); validation.set_issuer(&[issuer]);
    let data = jsonwebtoken::decode::<Value>(id_token, &dkey, &validation).map_err(|e| e.to_string())?;
    Ok(data.claims) }
async fn google_identity(client_id: &str, client_secret: &str, redirect: &str, code: &str) -> Result<(String, String), String> {
    let issuer = google_issuer();
    let disc = oidc_discovery(&issuer).await.map_err(|(_, j)| j.to_string())?;
    let token_ep = disc.get("token_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    let jwks_uri = disc.get("jwks_uri").and_then(|v| v.as_str()).unwrap_or("");
    if !url_ok(token_ep) || !url_ok(jwks_uri) { return Err("Google discovery returned no usable endpoints".into()); }
    let tok: Value = http_client().post(token_ep)
        .form(&[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect), ("client_id", client_id), ("client_secret", client_secret)])
        .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let id_token = tok.get("id_token").and_then(|v| v.as_str()).ok_or("Google token response has no id_token")?;
    let claims = verify_id_token(id_token, &issuer, client_id, jwks_uri).await?;
    if claims.get("email_verified").and_then(|v| v.as_bool()) == Some(false) { return Err("Google account email is not verified".into()); }
    let email = claims.get("email").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    let subject = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if email.is_empty() || subject.is_empty() { return Err("Google id_token has no email or subject".into()); }
    Ok((subject, email)) }
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
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(uid), json!(email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
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
    let mut out = auth_settings(&st);
    out["signups"] = json!(if signups_open(&st) { "open" } else { "invite" });
    Ok(j(out)) }
async fn social_start(State(st): State<S>, h: HeaderMap, Path(provider): Path<String>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let (client_id, _) = social_provider(&provider).filter(|_| auth_enabled(&st, &provider)).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
    let redirect = social_redirect(&st, &h, &provider);
    let state = oc::random_token("sst");
    st.db.exec("INSERT INTO social_states(state,provider,created_at) VALUES(?,?,?)", &[json!(state), json!(&provider), json!(now())]).map_err(|e| bad(&e))?;
    let url = if provider == "google" {
        let disc = oidc_discovery(&google_issuer()).await?;
        let auth_ep = disc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
        if !url_ok(auth_ep) { return Err(bad("Google discovery returned no authorization_endpoint")); }
        format!("{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}", auth_ep, urlencode(&client_id), urlencode(&redirect), state)
    } else {
        format!("{}/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}", github_web(), urlencode(&client_id), urlencode(&redirect), state) };
    Ok(axum::response::Redirect::temporary(&url)) }
async fn social_callback(State(st): State<S>, h: HeaderMap, Path(provider): Path<String>, Query(q): Query<HashMap<String,String>>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let (client_id, client_secret) = social_provider(&provider).filter(|_| auth_enabled(&st, &provider)).ok_or_else(|| err(StatusCode::NOT_FOUND, "this sign-in provider is not configured on this instance"))?;
    let code = q.get("code").cloned().unwrap_or_default(); let state = q.get("state").cloned().unwrap_or_default();
    let row = st.db.one("SELECT provider,created_at FROM social_states WHERE state=?", &[json!(state)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    let _ = st.db.exec("DELETE FROM social_states WHERE state=?", &[json!(state)]);
    if db::s(&row, "provider") != provider || db::n(&row, "created_at") + 600 < now() { return Err(bad("invalid or expired state")); }
    if code.is_empty() { return Err(bad("missing authorization code")); }
    let redirect = social_redirect(&st, &h, &provider);
    let (subject, email) = if provider == "google" { google_identity(&client_id, &client_secret, &redirect, &code).await }
        else { github_identity(&client_id, &client_secret, &redirect, &code).await }.map_err(|e| bad(&e))?;
    let uid = resolve_social(&st, &provider, &subject, &email)?;
    // The provider proved the address, not possession of the account's second
    // factor, so MFA still applies to social sign-in.
    if mfa::required(&st, &uid) {
        let challenge = mfa::new_challenge(&st, &uid)?;
        return Ok(axum::response::Redirect::temporary(&format!("/#mfa={}", challenge))); }
    let token = make_session(&st, &uid)?;
    Ok(axum::response::Redirect::temporary(&format!("/#token={}", token))) }
async fn instance_info(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h)?;
    let mut auth = auth_settings(&st);
    auth["signups_open"] = json!(signups_open(&st));
    auth["signups_env_locked"] = json!(std::env::var("OPENWARP_SIGNUPS").is_ok());
    auth["instance_owner"] = json!(instance_owner(&st).as_deref() == Some(uid.as_str()));
    auth["mfa_email"] = json!(mfa::email_available());
    Ok(j(auth)) }
async fn set_auth_providers(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can change sign-in methods")); }
    if auth_env_lock().is_some() { return Err(err(StatusCode::CONFLICT, "OPENWARP_AUTH_PROVIDERS controls sign-in methods on this instance")); }
    let mut chosen: Vec<&str> = Vec::new();
    for method in AUTH_METHODS {
        let value = body.get(*method).and_then(|v| v.as_bool()).unwrap_or_else(|| auth_enabled(&st, method));
        if value {
            if !auth_method_configured(&st, method) { return Err(bad(&format!("{} sign-in is not configured; set its client credentials first", method))); }
            chosen.push(method);
        }
    }
    if chosen.is_empty() { return Err(bad("at least one sign-in method must stay enabled, or nobody could sign in")); }
    let cfg = json!({
        "password": chosen.contains(&"password"), "google": chosen.contains(&"google"),
        "github": chosen.contains(&"github"), "oidc": chosen.contains(&"oidc") });
    meta_set(&st, "auth_providers", &cfg.to_string());
    st.audit("", "", "", &uid, "instance.auth_providers", &chosen.join(","));
    Ok(j(auth_settings(&st))) }
async fn rewrap_env_keys(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can rewrap environment keys")); }
    let kms = st.kms.as_ref().ok_or_else(|| bad("no KMS is configured; environment keys are wrapped by the instance master"))?;
    let rows = st.db.query("SELECT id FROM envs WHERE env_key_wrapped<>''", &[]).map_err(|e| bad(&e))?;
    let mut rewrapped = 0;
    for r in &rows {
        let eid = db::s(r, "id");
        // env_key unwraps both legacy and KMS rows, so this also migrates a
        // deployment that enabled KMS after its data was created.
        if let Ok(key) = st.env_key(&eid) {
            let wrapped = kms.wrap(&key, &format!("env:{}", eid)).map_err(|e| bad(&format!("KMS could not wrap {}: {}", eid, e)))?;
            st.db.exec("UPDATE envs SET env_key_wrapped=? WHERE id=?", &[json!(wrapped), json!(&eid)]).map_err(|e| bad(&e))?;
            rewrapped += 1;
        }
    }
    st.audit("", "", "", &uid, "instance.rewrap_keys", &format!("{} environments, key {}", rewrapped, kms.key_id()));
    Ok(j(json!({"rewrapped": rewrapped, "key_id": kms.key_id()}))) }
async fn encrypt_metadata(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can migrate secret metadata")); }
    // Only managed environments have a server-side key; never touch E2E or
    // delegated rows, whose client-owned metadata cannot be rewritten here.
    let envs = st.db.query("SELECT id FROM envs WHERE env_key_wrapped<>'' AND mode='sse'", &[]).map_err(|e| bad(&e))?;
    let mut updated = 0;
    for e in &envs {
        let eid = db::s(e, "id");
        let key = match st.env_key(&eid) { Ok(k) => k, Err(_) => continue };
        let rows = st.db.query("SELECT id,path,tags,path_enc,tags_enc,key_enc FROM secrets WHERE env_id=?", &[json!(&eid)]).map_err(|e| bad(&e))?;
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
            st.db.exec("UPDATE secrets SET path='',path_enc=?,tags='',tags_enc=?,key_hash=?,key_index=? WHERE id=?",
                &[json!(path_enc), json!(tags_enc), json!(&kh), json!(&kh), json!(&sid)]).map_err(|e| bad(&e))?;
            updated += 1;
        }
    }
    st.audit("", "", "", &uid, "instance.encrypt_metadata", &format!("{} secrets", updated));
    Ok(j(json!({"updated": updated}))) }
async fn set_signups(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    if instance_owner(&st).as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN, "only the instance owner can change signup policy")); }
    if std::env::var("OPENWARP_SIGNUPS").is_ok() { return Err(err(StatusCode::CONFLICT, "OPENWARP_SIGNUPS controls signups on this instance")); }
    let open = body.get("open").and_then(|v| v.as_bool()).ok_or_else(|| bad("open must be a boolean"))?;
    meta_set(&st, "signups_open", if open { "1" } else { "0" });
    st.audit("", "", "", &uid, "instance.signups", if open { "open" } else { "invite" });
    Ok(j(json!({"signups_open": open}))) }

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


// ---------- customer-run sync runners (delegated environments) ----------
#[derive(Deserialize)] struct RunnerReq { name: String, public_key: String }
fn runner_auth(st: &S, h: &HeaderMap) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let token = bearer_token(h);
    if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "runner token required")); }
    let row = st.db.one("SELECT id,org_id FROM runners WHERE token_hash=?", &[json!(oc::hash_token(&token))]).map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid runner token"))?;
    Ok((db::s(&row, "id"), db::s(&row, "org_id"))) }
fn runner_for_env(st: &S, eid: &str) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let env = st.db.one("SELECT runner_id,mode FROM envs WHERE id=?", &[json!(eid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("env not found"))?;
    if db::s(&env, "mode") != "delegated" { return Err(bad("environment is not delegated")); }
    let rid = db::s(&env, "runner_id");
    let runner = st.db.one("SELECT pubkey FROM runners WHERE id=?", &[json!(&rid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("runner not found"))?;
    Ok((rid, db::s(&runner, "pubkey"))) }
fn seal_to_runner(st: &S, eid: &str, iid: &str, config: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    let (rid, pubkey) = runner_for_env(st, eid)?;
    // The sealed box has no AAD, so bind the payload to its integration inside
    // the plaintext and make the runner verify it before using the config.
    let envelope = json!({"context": format!("ow-integration|{}|{}", eid, iid), "config": config}).to_string();
    let sealed = oc::encrypt_to(&pubkey, envelope.as_bytes()).map_err(|e| bad(&e))?;
    Ok(format!("owrunner:{}:{}", rid, sealed)) }
fn enqueue_sync(st: &S, eid: &str, iid: &str, job_kind: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let (rid, _) = runner_for_env(st, eid)?;
    if st.db.one("SELECT id FROM sync_jobs WHERE integration_id=? AND status IN ('pending','claimed') AND kind=?", &[json!(iid), json!(job_kind)]).map_err(|e| bad(&e))?.is_some() { return Ok(()); }
    st.db.exec("INSERT INTO sync_jobs(id,env_id,integration_id,runner_id,kind,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(id()), json!(eid), json!(iid), json!(rid), json!(job_kind), json!(now())]).map_err(|e| bad(&e))?;
    Ok(()) }
async fn create_runner(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<RunnerReq>) -> Res {
    let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    let name = r.name.trim();
    if name.is_empty() { return Err(bad("runner name required")); }
    let raw = oc::unb64(&r.public_key).map_err(|_| bad("public_key must be base64 X25519"))?;
    if raw.len() != 32 { return Err(bad("public_key must decode to 32 bytes")); }
    let rid = id(); let token = oc::random_token("run");
    st.db.exec("INSERT INTO runners(id,org_id,name,pubkey,token_hash,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(&rid), json!(&oid), json!(name), json!(&r.public_key), json!(oc::hash_token(&token)), json!(now())]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "runner.create", name);
    Ok(j(json!({"id": rid, "name": name, "public_key": r.public_key, "token": token, "note": "token shown once; store it with the runner"}))) }
async fn list_runners(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    let rows = st.db.query("SELECT id,name,pubkey,created_at FROM runners WHERE org_id=?", &[json!(&oid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_runner(State(st): State<S>, h: HeaderMap, Path((oid, rid)): Path<(String, String)>) -> Res {
    let uid = st.token_user(&h)?; st.check_admin(&oid, &uid)?;
    if st.db.one("SELECT id FROM envs WHERE runner_id=? AND mode='delegated' LIMIT 1", &[json!(&rid)]).map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "this runner still owns a delegated environment; remove or migrate those environments first")); }
    let deleted = st.db.exec("DELETE FROM runners WHERE id=? AND org_id=?", &[json!(&rid), json!(&oid)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(err(StatusCode::NOT_FOUND, "runner not found")); }
    let _ = st.db.exec("DELETE FROM runner_env_keys WHERE runner_id=?", &[json!(&rid)]);
    let _ = st.db.exec("DELETE FROM sync_jobs WHERE runner_id=?", &[json!(&rid)]);
    st.audit(&oid, "", "", &uid, "runner.delete", &rid);
    Ok(j(json!({"deleted": rid}))) }
async fn runner_jobs(State(st): State<S>, h: HeaderMap) -> Res {
    let (rid, _) = runner_auth(&st, &h)?;
    // A runner that crashes after claiming a job must not strand it forever.
    let stale = now() - 600;
    let rows = st.db.query("SELECT * FROM sync_jobs WHERE runner_id=? AND (status='pending' OR (status='claimed' AND claimed_at<?)) ORDER BY created_at LIMIT 10", &[json!(&rid), json!(stale)]).map_err(|e| bad(&e))?;
    let mut jobs = Vec::new();
    for job in &rows {
        let jid = db::s(job, "id"); let claim = oc::random_token("job"); let claimed_at = now();
        if st.db.exec("UPDATE sync_jobs SET status='claimed',claimed_at=?,claim_id=? WHERE id=? AND (status='pending' OR (status='claimed' AND claimed_at<?))", &[json!(claimed_at), json!(&claim), json!(&jid), json!(stale)]).unwrap_or(0) == 0 { continue; }
        let eid = db::s(job, "env_id"); let iid = db::s(job, "integration_id");
        let fail = |msg: &str| { let _ = st.db.exec("UPDATE sync_jobs SET status='failed',detail=? WHERE id=? AND claim_id=?", &[json!(msg), json!(&jid), json!(&claim)]); };
        let env = match st.db.one("SELECT runner_id FROM envs WHERE id=?", &[json!(&eid)]) { Ok(Some(e)) => e, _ => { fail("environment no longer exists"); continue; } };
        if db::s(&env, "runner_id") != rid { fail("runner does not own this environment"); continue; }
        let wrapped = match st.db.one("SELECT wrapped_key FROM runner_env_keys WHERE runner_id=? AND env_id=?", &[json!(&rid), json!(&eid)]) { Ok(Some(w)) => db::s(&w, "wrapped_key"), _ => { fail("no wrapped environment key for this runner"); continue; } };
        let integ = match st.db.one("SELECT kind,config_enc FROM integrations WHERE id=?", &[json!(&iid)]) { Ok(Some(i)) => i, _ => { fail("integration no longer exists"); continue; } };
        // Sealed values are never readable, so a runner job must never carry them.
        let secrets = st.db.query("SELECT key_enc,value_enc,key_hash,path FROM secrets WHERE env_id=? AND deleted=0 AND secret_type<>'sealed'", &[json!(&eid)]).map_err(|e| bad(&e))?;
        let prev = st.db.query("SELECT remote_name FROM integration_sync_state WHERE integration_id=?", &[json!(&iid)]).unwrap_or_default();
        jobs.push(json!({
            "id": jid, "claim": claim, "env_id": eid, "integration_id": iid, "job_kind": db::s(job, "kind"),
            "kind": db::s(&integ, "kind"), "config_enc": db::s(&integ, "config_enc"), "wrapped_key": wrapped,
            "secrets": secrets.iter().map(db::obj).collect::<Vec<_>>(),
            "previous": prev.iter().map(|r| db::s(r, "remote_name")).collect::<Vec<_>>(),
        }));
    }
    Ok(j(json!({"jobs": jobs}))) }
#[derive(Deserialize)] struct ManagedSecret { name: String, #[serde(default)] value_hash: String }
#[derive(Deserialize)] struct JobResultReq { ok: bool, #[serde(default)] detail: String, #[serde(default)] managed: Vec<ManagedSecret>, #[serde(default)] claim: String }
async fn runner_job_result(State(st): State<S>, h: HeaderMap, Path(jid): Path<String>, Json(r): Json<JobResultReq>) -> Res {
    let (rid, _) = runner_auth(&st, &h)?;
    let job = st.db.one("SELECT * FROM sync_jobs WHERE id=? AND runner_id=?", &[json!(&jid), json!(&rid)]).map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "job not found"))?;
    if db::s(&job, "status") != "claimed" { return Err(err(StatusCode::CONFLICT, "job is not claimed by this runner")); }
    // The claim timestamp is the fencing token: a job reclaimed after the stale
    // window rejects the old runner's late result.
    let updated = st.db.exec("UPDATE sync_jobs SET status=?,detail=? WHERE id=? AND runner_id=? AND status='claimed' AND claim_id=?",
        &[json!(if r.ok { "done" } else { "failed" }), json!(&r.detail), json!(&jid), json!(&rid), json!(&r.claim)]).map_err(|e| bad(&e))?;
    if updated == 0 { return Err(err(StatusCode::CONFLICT, "this claim was superseded; refresh the job queue")); }
    let eid = db::s(&job, "env_id"); let iid = db::s(&job, "integration_id");
    if r.ok && db::s(&job, "kind") == "sync" && !r.managed.is_empty() {
        let _ = st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(&iid)]);
        for m in &r.managed { let _ = st.db.exec("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)", &[json!(&iid), json!(&m.name), json!(&m.value_hash)]); }
    }
    if let Ok((org, app)) = st.env_org_app(&eid) {
        st.audit(&org, &app, &eid, "runner", if r.ok { "integration.sync" } else { "integration.sync_failed" }, &format!("{} {}", iid, r.detail));
    }
    Ok(j(json!({"status": if r.ok { "done" } else { "failed" }}))) }

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
    let pid = id();
    st.db.exec("INSERT INTO proposals(id,env_id,author,payload_enc,created_at) VALUES(?,?,?,?,?)", &[json!(pid), json!(eid), json!(uid), json!(oc::encrypt_symmetric_aad(&key, &proposal_aad(&eid, &pid, "payload"), payload.as_bytes())), json!(now())]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"proposal.create",&pid); Ok(j(json!({"id": pid, "status": "pending"}))) }
async fn list_proposals(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:read")?;
    let rows = st.db.query("SELECT id,env_id,author,status,created_at,decided_by FROM proposals WHERE env_id=? ORDER BY created_at DESC", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn decide_proposal(State(st): State<S>, h: HeaderMap, Path((pid, action)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM proposals WHERE id=?", &[json!(pid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"proposal not found"))?;
    if db::s(&row,"status") != "pending" { return Err(bad("proposal already decided")); }
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid, &uid)?;
    st.check_admin(&org, &uid).map_err(|_| err(StatusCode::FORBIDDEN, "proposals need approval by an admin (not the author)"))?;
    if action == "approve" {
        let key = st.env_key(&eid)?; let plain = oc::decrypt_symmetric_compat(&key, &proposal_aad(&eid, &pid, "payload"), &db::s(&row,"payload_enc")).map_err(|e| bad(&e))?;
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
        let config_enc = oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "config"), json!({"connection":conn,"type":"postgres"}).to_string().as_bytes());
        st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,username,config_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), password.as_bytes())), json!(username), json!(config_enc), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
        return Ok(j(json!({"id": lid, "username": username, "password": password, "expires_at": now()+ttl, "type":"postgres"}))); }
    let value = oc::random_token("dyn");
    st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric_aad(&key, &lease_aad(&eid, &lid, "value"), value.as_bytes())), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": lid, "value": value, "expires_at": now()+ttl}))) }
async fn revoke_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM leases WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    let eid = db::s(&row,"env_id"); let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org, &uid, "leases:write")?; let key = st.env_key(&eid)?;
    if !db::s(&row,"config_enc").is_empty() { if let Ok(plain) = oc::decrypt_symmetric_compat(&key, &lease_aad(&eid, &lid, "config"), &db::s(&row,"config_enc")) { if let Ok(cfg) = serde_json::from_slice::<Value>(&plain) {
        if cfg.get("type").and_then(|v| v.as_str()) == Some("postgres") { let conn = cfg.get("connection").and_then(|v| v.as_str()).unwrap_or("").to_string(); let username = db::s(&row,"username");
            let _ = std::thread::spawn(move || { if let Ok(mut cl) = postgres::Client::connect(&conn, postgres::NoTls) { let _ = cl.execute(&format!("DROP ROLE IF EXISTS \"{}\"", username), &[]); } }).join(); } } } }
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
    let cid = id(); st.db.exec("INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,serial,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(cid), json!(oid), json!(r.name), json!(cert.pem()), json!(oc::encrypt_symmetric(&st.master, kp.serialize_pem().as_bytes())), json!(hex_encode(&serial_bytes)), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": cid, "certificate": cert.pem()}))) }
async fn issue_cert(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(caid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    st.check_admin(&db::s(&ca,"org_id"), &uid)?;
    let cn = body.get("cn").and_then(|v| v.as_str()).unwrap_or("service"); let days = body.get("days").and_then(|v| v.as_i64()).unwrap_or(365).clamp(1, 3650);
    let issuer_kp_pem = oc::decrypt_symmetric(&st.master, &db::s(&ca,"key_enc")).map_err(|e| bad(&e))?;
    let issuer_kp = rcgen::KeyPair::from_pem(&String::from_utf8_lossy(&issuer_kp_pem)).map_err(|e| bad(&e.to_string()))?;
    let issuer_params = {
        let mut p = ca_params(&db::s(&ca,"name"), true);
        if let Some(serial) = hex_decode(&db::s(&ca,"serial")) { p.serial_number = Some(rcgen::SerialNumber::from_slice(&serial)); }
        p };
    let issuer_cert = issuer_params.self_signed(&issuer_kp).map_err(|e| bad(&e.to_string()))?;
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
async fn list_certs(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(caid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?; st.require_org(&db::s(&ca,"org_id"),&uid)?;
    let rows = st.db.query("SELECT id,ca_id,cn,serial,revoked,expires_at,created_at FROM pki_certs WHERE ca_id=?", &[json!(caid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn revoke_cert(State(st): State<S>, h: HeaderMap, Path(cid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT ca_id FROM pki_certs WHERE id=?", &[json!(cid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"cert not found"))?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(db::s(&row,"ca_id"))]).map_err(|e| bad(&e))?; if let Some(ca)=ca { st.check_admin(&db::s(&ca,"org_id"),&uid)?; }
    st.db.exec("UPDATE pki_certs SET revoked=1 WHERE id=?", &[json!(cid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": cid}))) }


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
    let rows = st.db.query("SELECT id,app_id,env_id,name,kind,expires_at,created_at,created_by FROM tokens WHERE app_id=?", &[json!(aid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
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
    // Re-enrolling is equivalent to adding a factor to an account that already
    // has one, so it needs the password the user knows.
    mfa::reauth_add(&st, &uid, &body)?;
    let provided = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let secret_bytes: Vec<u8> = if provided.is_empty() { oc::random_key()[..20].to_vec() } else { let d = b32decode(provided); if d.len() < 10 { return Err(bad("provided TOTP secret must be base32, at least 10 bytes")); } d };
    let secret_b32 = b32encode(&secret_bytes);
    // Keep the new secret pending until a code proves it. A re-enrolment must
    // not disable the factor that is already protecting the account.
    meta_set(&st, &format!("totp_pending:{}", uid), &oc::encrypt_symmetric(&st.master, &secret_bytes));
    let codes = if mfa::recovery_count(&st, &uid) == 0 { mfa::issue_recovery_codes(&st, &uid) } else { Vec::new() };
    let email = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).map(|r| r.map(|x| db::s(&x,"email")).unwrap_or_default()).unwrap_or_default();
    Ok(j(json!({"secret": secret_b32, "otpauth_url": format!("otpauth://totp/OpenWarp:{}?secret={}&issuer=OpenWarp", email, secret_b32), "recovery_codes": codes, "note": "call POST /api/me/totp/verify {code} with a current TOTP code to enable"}))) }
async fn totp_verify(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    if !mfa::confirm_totp(&st, &uid, code) { return Err(err(StatusCode::UNAUTHORIZED, "invalid TOTP code")); }
    st.audit("", "", "", &uid, "auth.totp_enabled", "");
    Ok(j(json!({"enabled": true}))) }
async fn mfa_login(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(body): Json<Value>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let token = body.get("mfa_token").and_then(|v| v.as_str()).unwrap_or(""); let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let uid = mfa::challenge_user(&st, token).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid or expired MFA challenge"))?;
    // The password was already accepted upstream, so this step guards the second
    // factor itself: cap guesses per address and account.
    let key = format!("mfa:{}:{}", addr.ip(), uid);
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later")); }
    if !mfa::second_factor_ok(&st, &uid, code) { st.rate_fail(&key, 900); return Err(err(StatusCode::UNAUTHORIZED, "invalid MFA code")); }
    st.rate_clear(&key);
    mfa::consume_challenge(&st, token);
    st.audit("", "", "", &uid, "auth.mfa_login", "");
    let session = make_session(&st, &uid)?; let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap()); Ok((hdr, j(json!({"token": session, "user_id": uid})))) }


// ---------- log streams (T10) ----------
async fn create_stream(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    st.check_admin(&oid,&uid)?;
    let url = body.get("url").and_then(|v|v.as_str()).unwrap_or("");
    if !url_ok(url) { return Err(bad("log stream url must be http(s)")); }
    let secret = body.get("secret").and_then(|v|v.as_str()).unwrap_or("");
    let secret_enc = if secret.is_empty() { String::new() } else { oc::encrypt_symmetric(&st.master, secret.as_bytes()) };
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
async fn process_rotations(st: &S) {
    let _ = st.db.exec("DELETE FROM rate_limits WHERE window_start<?", &[json!(now() - 86400)]);
    let due = st.db.query("SELECT * FROM rotation_schedules WHERE enabled=1 AND next_run<=?", &[json!(now())]).unwrap_or_default();
    for r in &due {
        let id = db::s(r,"id"); let eid = db::s(r,"env_id"); let key_name = db::s(r,"key_name");
        let interval = db::n(r,"interval_secs").max(60); let old_next = db::n(r,"next_run");
        // Claim the slot atomically so two replicas cannot rotate the same key twice.
        let claimed = st.db.exec("UPDATE rotation_schedules SET next_run=? WHERE id=? AND next_run=?", &[json!(now()+interval), json!(&id), json!(old_next)]).unwrap_or(0);
        if claimed == 0 { continue; }
        let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(&eid)]).ok().flatten().map(|x| db::s(&x,"mode")).unwrap_or_default();
        if mode == "e2e" || mode == "delegated" { continue; }
        let path = { let p = db::s(r,"path"); if p.is_empty() { "/".to_string() } else { p } };
        let key = match st.env_key(&eid) { Ok(k) => k, Err(_) => continue };
        let khash = key_index(&key, &path, &key_name.to_uppercase());
        let legacy = oc::hash_token(&format!("{}:{}", path, key_name.to_uppercase()));
        let existing = st.db.one("SELECT secret_type FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(&eid), json!(&khash), json!(&legacy)]).ok().flatten();
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
        {
            let s = SecretIn{ key: key_name.clone(), value: oc::random_token("rot"), path: path.clone(), comment: "scheduled rotation".into(), tags: "".into(), secret_type: stype };
            if upsert_secret(st, &eid, &key, "rotation-scheduler", &s).is_ok() {
                if let Ok((org, app)) = st.env_org_app(&eid) { st.audit(&org,&app,&eid,"rotation-scheduler","secret.rotate",&key_name); }
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
const OAUTH_PASSKEY_JS: &str = r#"<script>
function b64uToBuf(s){var b=atob(s.replace(/-/g,'+').replace(/_/g,'/'));var u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}
function bufToB64u(x){var u=new Uint8Array(x),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
async function passkeySignIn(){var f=document.getElementById('mfaform');var t=f.querySelector('input[name=mfa_token]').value;try{
var r=await fetch('/api/auth/mfa/passkey/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({mfa_token:t})});
var d=await r.json();if(!r.ok)throw new Error(d.error||'passkey sign-in could not start');
var o=d.options.publicKey;o.challenge=b64uToBuf(o.challenge);if(o.allowCredentials)o.allowCredentials=o.allowCredentials.map(function(c){c.id=b64uToBuf(c.id);return c});
var a=await navigator.credentials.get({publicKey:o});
var body={mfa_token:t,credential:{id:a.id,rawId:bufToB64u(a.rawId),type:a.type,response:{clientDataJSON:bufToB64u(a.response.clientDataJSON),authenticatorData:bufToB64u(a.response.authenticatorData),signature:bufToB64u(a.response.signature),userHandle:a.response.userHandle?bufToB64u(a.response.userHandle):null}}};
var r2=await fetch('/api/auth/mfa/passkey/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
var d2=await r2.json();if(!r2.ok)throw new Error(d2.error||'passkey sign-in failed');
f.querySelector('input[name=mfa_token]').remove();var b=document.createElement('input');b.type='hidden';b.name='approve';b.value='1';f.appendChild(b);f.submit();
}catch(e){document.getElementById('mfaerr').textContent=e.message||String(e)}}
</script>"#;
fn consent_mfa_page(st: &S, uid: &str, form: &HashMap<String, String>, token: &str, message: &str) -> Response {
    let methods = mfa::methods(st, uid);
    // The token is only ever minted by this page after a password step, never
    // inherited from the authorize query string.
    let mut hidden = hidden_fields(form);
    hidden.push_str(&format!("<input type=hidden name=mfa_token value=\"{}\">", esc(token)));
    let mut buttons = String::new();
    if methods.contains(&"email") && mfa::email_available() {
        buttons.push_str("<button name=action value=send_email style=\"padding:10px 20px;margin-right:8px\">Email me a code</button>"); }
    if methods.contains(&"passkey") {
        buttons.push_str("<button type=button onclick=\"passkeySignIn()\" style=\"padding:10px 20px;margin-right:8px\">Use a passkey</button>"); }
    let note = if methods.contains(&"totp") { "Enter a code from your authenticator app, or a recovery code." }
        else if methods.contains(&"email") && mfa::email_available() { "Enter the code sent to your email, or a recovery code." }
        else if methods.contains(&"passkey") { "Use your passkey, or a recovery code." }
        else { "Enter a recovery code." };
    // The passkey script is only needed when a passkey exists; keep the page
    // otherwise under the stricter CSP.
    let page = format!("<!doctype html><html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Two-factor required</h1><p>{}</p><p style=\"color:#fb7185\" id=mfaerr>{}</p><form id=mfaform method=post action=\"/oauth/authorize/decision\">{}{}<input name=otp placeholder=\"code or recovery code\" autocomplete=one-time-code style=\"padding:8px\"><br><div style=\"margin-top:10px\">{}<button name=approve value=1 style=\"padding:10px 20px\">Continue</button></div></form>{}</body></html>",
        esc(note), esc(message), &hidden, &buttons, "", if methods.contains(&"passkey") { OAUTH_PASSKEY_JS } else { "" });
    let mut r = if methods.contains(&"passkey") { html_csp_with(OAUTH_MFA_CSP, page) } else { html_csp(page) };
    *r.status_mut() = StatusCode::UNAUTHORIZED; r }
fn oauth_error_page(status: StatusCode, msg: &str) -> Response {
    let mut r = html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>OAuth error</h1><p>{}</p></body></html>", esc(msg)));
    *r.status_mut() = status; r }
async fn oauth_authorize(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Response {
    if let Err(e) = authorize_params_ok(&st, &q) { return oauth_error_page(StatusCode::BAD_REQUEST, &e); }
    let hidden = hidden_fields(&q);
    let client = esc(q.get("client_id").map(|s| s.as_str()).unwrap_or(""));
    let scope = esc(q.get("scope").map(|s| s.as_str()).unwrap_or(""));
    if oauth_user(&st, &h).is_some() {
        return html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Authorize application</h1><p>Client: {}<br>Scopes: {}</p><form method=post action=\"/oauth/authorize/decision\">{}{}<button name=approve value=1 style=\"padding:10px 20px\">Approve</button> <button name=approve value=0 style=\"padding:10px 20px\">Deny</button></form></body></html>", client, scope, hidden, ""));
    }
    if !auth_enabled(&st, "password") {
        return oauth_error_page(StatusCode::FORBIDDEN, "Password sign-in is disabled on this instance. Sign in to the console with a configured provider, then open this link again."); }
    html_csp(format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Sign in to OpenWarp</h1><form method=post action=\"/oauth/authorize/decision\">{}<input name=email type=email placeholder=email required style=\"padding:8px\"><br><input name=password type=password placeholder=password required style=\"padding:8px\"><br><input name=otp placeholder=\"code if two-factor is enabled\" autocomplete=one-time-code style=\"padding:8px\"><br><button name=approve value=1 style=\"padding:10px 20px;margin-top:8px\">Sign in and approve</button></form></body></html>", hidden))
}
async fn oauth_decision(State(st): State<S>, h: HeaderMap, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, axum::extract::Form(form): axum::extract::Form<HashMap<String,String>>) -> Response {
    let (client_id, redirect, scope) = match authorize_params_ok(&st, &form) { Ok(x) => x, Err(e) => return oauth_error_page(StatusCode::BAD_REQUEST, &e) };
    let form_token = form.get("mfa_token").cloned().unwrap_or_default();
    let uid = if let Some(u) = oauth_user(&st, &h) { u }
    else if !form_token.is_empty() {
        let uid = match mfa::challenge_user(&st, &form_token) { Some(u) => u, None => return oauth_error_page(StatusCode::UNAUTHORIZED, "This two-factor challenge expired. Sign in again.") };
        if form.get("action").map(|s| s.as_str()) == Some("send_email") {
            let key = format!("email-mfa:{}:{}", addr.ip(), uid);
            if !st.rate_ok(&key, 3, 600) { return oauth_error_page(StatusCode::TOO_MANY_REQUESTS, "Too many codes requested. Try again later."); }
            st.rate_fail(&key, 600);
            if let Err((_, Json(v))) = mfa::send_login_code(&st, &uid).await {
                return consent_mfa_page(&st, &uid, &form, &form_token, v.get("error").and_then(|e| e.as_str()).unwrap_or("The code could not be sent.")); }
            return consent_mfa_page(&st, &uid, &form, &form_token, "A code is on its way to the account email."); }
        let key = format!("otp:{}:{}", addr.ip(), uid);
        if !st.rate_ok(&key, 5, 900) { return oauth_error_page(StatusCode::TOO_MANY_REQUESTS, "Too many failed two-factor attempts. Try again later."); }
        if !mfa::second_factor_ok(&st, &uid, form.get("otp").map(|s| s.as_str()).unwrap_or("")) {
            if !form.get("otp").map(|s| s.is_empty()).unwrap_or(true) { st.rate_fail(&key, 900); }
            return consent_mfa_page(&st, &uid, &form, &form_token, "That code was not accepted."); }
        st.rate_clear(&key);
        mfa::consume_challenge(&st, &form_token);
        uid }
    else {
        if !auth_enabled(&st, "password") { return oauth_error_page(StatusCode::FORBIDDEN, "Password sign-in is disabled on this instance."); }
        let email = form.get("email").cloned().unwrap_or_default(); let password = form.get("password").cloned().unwrap_or_default();
        let key = format!("oauth:{}:{}", addr.ip(), email.to_lowercase());
        if !st.rate_ok(&key, 5, 900) { return oauth_error_page(StatusCode::TOO_MANY_REQUESTS, "Too many failed sign-in attempts. Try again later."); }
        let row = match st.db.one("SELECT id,pass_hash,active FROM users WHERE email=?", &[json!(email.to_lowercase())]) { Ok(Some(r)) => r, _ => { st.rate_fail(&key, 900); return oauth_error_page(StatusCode::UNAUTHORIZED, "Invalid credentials."); } };
        if db::n(&row, "active") == 0 { return oauth_error_page(StatusCode::UNAUTHORIZED, "Account deactivated."); }
        if !oc::verify_password(&password, &db::s(&row, "pass_hash")) { st.rate_fail(&key, 900); return oauth_error_page(StatusCode::UNAUTHORIZED, "Invalid credentials."); }
        st.rate_clear(&key);
        let uid = db::s(&row, "id");
        mfa::note_password_login(&st, &uid);
        if mfa::required(&st, &uid) {
            let token = match mfa::new_challenge(&st, &uid) { Ok(t) => t, Err(_) => return oauth_error_page(StatusCode::INTERNAL_SERVER_ERROR, "Could not start two-factor verification.") };
            let otp = form.get("otp").map(|s| s.as_str()).unwrap_or("");
            if otp.is_empty() { return consent_mfa_page(&st, &uid, &form, &token, ""); }
            let key = format!("otp:{}:{}", addr.ip(), uid);
            if !st.rate_ok(&key, 5, 900) { return oauth_error_page(StatusCode::TOO_MANY_REQUESTS, "Too many failed two-factor attempts. Try again later."); }
            if !mfa::second_factor_ok(&st, &uid, otp) {
                st.rate_fail(&key, 900);
                return consent_mfa_page(&st, &uid, &form, &token, "That code was not accepted."); }
            st.rate_clear(&key);
            mfa::consume_challenge(&st, &token);
        }
        uid };
    if !st.db.one("SELECT active FROM users WHERE id=?", &[json!(uid)]).ok().flatten().map(|u| db::n(&u, "active") != 0).unwrap_or(true) { return oauth_error_page(StatusCode::UNAUTHORIZED, "Account deactivated."); }
    let state = form.get("state").cloned().unwrap_or_default();
    if form.get("approve").map(|s| s.as_str()) != Some("1") { return axum::response::Redirect::to(&format!("{}?error=access_denied&state={}", redirect, urlencode(&state))).into_response(); }
    let code = oc::random_token("code"); let resource = form.get("resource").cloned().unwrap_or_else(|| format!("{}/mcp", issuer(&st, &h)));
    if st.db.exec("INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(oc::hash_token(&code)), json!(client_id), json!(uid), json!(redirect), json!(form.get("code_challenge").cloned().unwrap_or_default()), json!(scope), json!(resource), json!(now()+300)]).is_err() { return oauth_error_page(StatusCode::INTERNAL_SERVER_ERROR, "Could not create an authorization code."); }
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
    let (master, kms) = load_root(&db).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    if verification_required() && std::env::var("OPENWARP_EMAIL_WEBHOOK").map(|v| v.trim().is_empty()).unwrap_or(true) {
        eprintln!("OPENWARP_REQUIRE_EMAIL_VERIFICATION is set but OPENWARP_EMAIL_WEBHOOK is not; verification links could not be delivered");
        std::process::exit(1);
    }
    #[cfg(feature = "redis-cache")]
    let redis_conn = std::env::var("REDIS_URL").ok().and_then(|u| redis::Client::open(u).ok()).and_then(|c| c.get_connection().ok());
    let pub_url = std::env::var("OPENWARP_PUBLIC_URL").unwrap_or_default();
    let state = Arc::new(AppState { db, db_url: db_url.clone(), pub_url, master, kms, #[cfg(feature = "redis-cache")] redis: std::sync::Mutex::new(redis_conn) });
    if let Err(e) = validate_auth_env(&state) { eprintln!("{}", e); std::process::exit(1); }
    { let st2 = state.clone(); tokio::spawn(async move { loop { tokio::time::sleep(std::time::Duration::from_secs(30)).await; process_rotations(&st2).await; } }); }
    let app = Router::new()
        .route("/", get(index)).route("/e2e.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("e2e.js")) }))
        .route("/metrics", get(metrics)).route("/lockbox/{lid}", get(lockbox_page))
        .route("/api/auth/providers", get(auth_providers)).route("/api/auth/accept-invite", post(accept_invite))
        .route("/api/auth/verify", get(verify_email)).route("/api/auth/forgot", post(forgot_password)).route("/api/auth/reset", post(reset_password)).route("/api/auth/resend-verification", post(resend_verification))
        .route("/api/auth/social/{provider}/start", get(social_start)).route("/api/auth/social/{provider}/callback", get(social_callback))
        .route("/api/instance", get(instance_info)).route("/api/instance/signups", put(set_signups)).route("/api/instance/auth", put(set_auth_providers)).route("/api/instance/rewrap", post(rewrap_env_keys)).route("/api/instance/encrypt-metadata", post(encrypt_metadata))
        .route("/health", get(health)).route("/.well-known/oauth-protected-resource", get(prm)).route("/.well-known/oauth-authorization-server", get(asm)).route("/oauth/register", post(oauth_register)).route("/oauth/authorize", get(oauth_authorize)).route("/oauth/authorize/decision", post(oauth_decision)).route("/oauth/token", post(oauth_token)).route("/oauth/revoke", post(oauth_revoke)).route("/mcp", post(mcp_post).get(mcp_get).delete(mcp_get))
        .route("/api/auth/register", post(register)).route("/api/auth/login", post(login)).route("/api/auth/logout", post(logout)).route("/api/me", get(me))
        .route("/api/orgs", get(list_orgs).post(create_org)).route("/api/orgs/{oid}", axum::routing::patch(update_org)).route("/api/orgs/{oid}/leave", post(leave_org)).route("/api/orgs/{oid}/transfer", post(transfer_org))
        .route("/api/orgs/{oid}/members", get(list_members).post(invite_member)).route("/api/orgs/{oid}/members/{uid}", axum::routing::patch(update_member_role).delete(remove_member)).route("/api/orgs/{oid}/apps", get(list_apps).post(create_app))
        .route("/api/orgs/{oid}/audit", get(audit_list)).route("/api/orgs/{oid}/roles", get(list_roles).post(create_role)).route("/api/orgs/{oid}/log-streams", get(list_streams).post(create_stream)).route("/api/orgs/{oid}/log-streams/deliveries", get(list_deliveries)).route("/api/orgs/{oid}/settings", get(get_org_settings).put(org_settings)).route("/api/orgs/{oid}/teams", get(list_teams).post(create_team))
        .route("/api/apps/{aid}", axum::routing::patch(update_app).delete(delete_app)).route("/api/apps/{aid}/envs", get(list_envs).post(create_env)).route("/api/apps/{aid}/envs/e2e", post(create_e2e_env)).route("/api/apps/{aid}/tokens", get(list_tokens).post(create_token)).route("/api/tokens/{tid}", delete(revoke_token)).route("/api/orgs/{oid}/identities", get(list_identities).post(create_identity)).route("/api/orgs/{oid}/identities/{iid}", delete(delete_identity)).route("/api/orgs/{oid}/identities/{iid}/rotate", post(rotate_identity)).route("/api/v1/machine/auth/universal/login", post(universal_login))
        .route("/api/orgs/{oid}/runners", get(list_runners).post(create_runner)).route("/api/orgs/{oid}/runners/{rid}", delete(delete_runner))
        .route("/api/runner/jobs", get(runner_jobs)).route("/api/runner/jobs/{jid}/result", post(runner_job_result))
        .route("/api/envs/{eid}", delete(delete_env).patch(update_env)).route("/api/envs/{eid}/policy", put(set_env_policy)).route("/api/envs/{eid}/clone", post(clone_env)).route("/api/envs/{eid}/compare", get(compare_envs))
        .route("/api/envs/{eid}/secrets", get(list_secrets).put(deploy_secrets)).route("/api/envs/{eid}/e2e/secrets", get(e2e_get).put(e2e_put)).route("/api/envs/{eid}/e2e/grant", post(e2e_grant)).route("/api/envs/{eid}/e2e/grants", get(e2e_grants)).route("/api/envs/{eid}/e2e/grants/{uid}", delete(e2e_revoke)).route("/api/envs/{eid}/e2e/meta", get(e2e_meta)).route("/api/envs/{eid}/e2e/rekey", post(e2e_rekey)).route("/api/users/lookup", get(user_lookup))
        .route("/api/envs/{eid}/export", get(export_env)).route("/api/envs/{eid}/import", post(deploy_secrets))
        .route("/api/envs/{eid}/integrations", get(list_integrations).post(create_integration))
        .route("/api/envs/{eid}/dynamic", get(list_leases).post(create_lease_v2)).route("/api/leases/{lid}", delete(revoke_lease)).route("/api/leases/{lid}/renew", post(renew_lease)).route("/api/envs/{eid}/rotations", get(list_rotations).post(create_rotation)).route("/api/rotations/{rid}", delete(delete_rotation)).route("/api/envs/{eid}/rotate", post(rotate_secret)).route("/api/envs/{eid}/restore-point", post(pitr))
        .route("/api/integrations/{iid}/sync", post(sync_integration)).route("/api/integrations/{iid}/test", post(test_integration)).route("/api/integrations/{iid}", axum::routing::patch(update_integration).delete(delete_integration))
        .route("/api/secrets/{sid}", delete(delete_secret)).route("/api/secrets/{sid}/history", get(history))
        .route("/api/secrets/{sid}/restore/{ver}", post(restore)).route("/api/secrets/{sid}/override", post(set_override))
        .route("/api/search", get(search)).route("/api/me/totp/setup", post(totp_setup)).route("/api/me/totp/verify", post(totp_verify)).route("/api/me/totp", delete(mfa::totp_disable))
        .route("/api/me/mfa", get(mfa::status)).route("/api/me/mfa/recovery-codes", post(mfa::recovery_regenerate))
        .route("/api/me/mfa/email/start", post(mfa::email_enroll_start)).route("/api/me/mfa/email/verify", post(mfa::email_enroll_verify)).route("/api/me/mfa/email", delete(mfa::email_disable))
        .route("/api/me/passkeys/start", post(mfa::passkey_register_start)).route("/api/me/passkeys/finish", post(mfa::passkey_register_finish)).route("/api/me/passkeys/{pid}", delete(mfa::passkey_delete))
        .route("/api/auth/mfa", post(mfa_login)).route("/api/auth/mfa/options", post(mfa::mfa_options)).route("/api/auth/mfa/email/send", post(mfa::email_login_send))
        .route("/api/auth/mfa/passkey/start", post(mfa::passkey_login_start)).route("/api/auth/mfa/passkey/finish", post(mfa::passkey_login_finish))
        .route("/api/envs/{eid}/proposals", get(list_proposals).post(create_proposal)).route("/api/proposals/{pid}/{action}", post(decide_proposal)).route("/api/envs/{eid}/access-requests", get(list_access_requests).post(request_access)).route("/api/access-requests/{rid}/{action}", post(decide_access)).route("/api/orgs/{oid}/pki/cas", post(create_ca)).route("/api/pki/cas/{caid}/issue", post(issue_cert)).route("/api/pki/cas/{caid}/certs", get(list_certs)).route("/api/pki/certs/{cid}/revoke", post(revoke_cert)).route("/scim/v2/Users", get(scim_list_users).post(scim_create_user)).route("/scim/v2/Users/{uid}", put(scim_put_user).patch(scim_patch_user).delete(scim_delete_user))
        .route("/scim/v2/Groups", get(scim_list_groups).post(scim_create_group)).route("/scim/v2/Groups/{tid}", get(scim_get_group).put(scim_put_group).patch(scim_patch_group).delete(scim_delete_group))
        .route("/scim/v2/ServiceProviderConfig", get(scim_service_config)).route("/scim/v2/ResourceTypes", get(scim_resource_types)).route("/scim/v2/Schemas", get(scim_schemas))
        .route("/api/auth/oidc/{oid}/start", get(oidc_start)).route("/api/auth/oidc/callback", get(oidc_callback)).route("/api/lockbox", post(create_lockbox)).route("/api/lockbox/{lid}", get(open_lockbox))
        .layer(axum::middleware::from_fn_with_state(state.clone(), oauth_scope_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(metrics_middleware))
        .layer(axum::middleware::from_fn(timeout_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state);
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    println!("openwarp listening on {} db={}", addr, db_url);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal()).await.unwrap();
}
fn load_root(db: &Db) -> Result<([u8;32], Option<kms::Kms>), String> {
    if let Some(kms) = kms::Kms::from_env()? {
        // The KMS-wrapped root in the database wins: a restarted instance must
        // keep using the same root to read data written before the restart.
        if let Ok(Some(r)) = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]) {
            let raw = kms.unwrap(&db::s(&r, "v"), "openwarp-root")?;
            // Finish the adoption cleanup if a previous boot crashed between
            // storing kms_root and deleting the plaintext master.
            let _ = db.exec("DELETE FROM meta WHERE k='master'", &[]);
            return Ok((raw.try_into().map_err(|_| "kms_root is not 32 bytes".to_string())?, Some(kms)));
        }
        // First KMS boot: adopt the stored master when there is one so old data
        // stays readable. If the environment also names a different master, stop
        // instead of wrapping the wrong root and rewrapping legacy env keys.
        let env_master: Option<[u8;32]> = match std::env::var("OPENWARP_MASTER_KEY") {
            Ok(v) => Some(oc::unb64(&v).map_err(|_| "OPENWARP_MASTER_KEY is not valid base64".to_string())?.try_into().map_err(|_| "OPENWARP_MASTER_KEY must decode to exactly 32 bytes".to_string())?),
            Err(_) => None };
        let stored_master: Option<[u8;32]> = match db.one("SELECT v FROM meta WHERE k='master'", &[]) {
            Ok(Some(r)) => Some(oc::unb64(&db::s(&r, "v")).map_err(|_| "stored master key is not base64".to_string())?.try_into().map_err(|_| "stored master key is not 32 bytes".to_string())?),
            _ => None };
        if let (Some(a), Some(b)) = (env_master, stored_master) { if a != b { return Err("OPENWARP_MASTER_KEY does not match the master key stored in this database; refusing to wrap the wrong root under KMS".into()); } }
        let master = env_master.or(stored_master).unwrap_or_else(oc::random_key);
        let wrapped = kms.wrap(&master, "openwarp-root")?;
        if db.exec("INSERT INTO meta(k,v) VALUES('kms_root',?)", &[json!(wrapped)]).is_err() {
            // Another replica won the race; read its root instead.
            if let Ok(Some(r)) = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]) {
                let raw = kms.unwrap(&db::s(&r, "v"), "openwarp-root")?;
                return Ok((raw.try_into().map_err(|_| "kms_root is not 32 bytes".to_string())?, Some(kms)));
            }
            return Err("could not store or read kms_root".into());
        }
        // The plaintext master row was only needed to adopt the old root. Once
        // the same root is wrapped by the KMS, remove the copy so the database
        // has no usable root key. Non-environment records decrypt with the
        // KMS-unwrapped root and need no re-encryption.
        let _ = db.exec("DELETE FROM meta WHERE k='master'", &[]);
        return Ok((master, Some(kms)));
    }
    Ok((load_master(db)?, None))
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

