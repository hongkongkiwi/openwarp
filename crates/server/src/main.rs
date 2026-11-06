mod db; mod integrations; mod ui;
use axum::{extract::{ConnectInfo, Path, Query, State}, http::{HeaderMap, StatusCode}, middleware::Next, response::{Html, IntoResponse, Response}, routing::{delete, get, post, put}, Json, Router};
use db::{Db, Row};
use openwarp_crypto as oc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

pub struct AppState {
    db: Db,
    db_url: String,
    pub_url: String,
    master: [u8; 32],
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
const OAUTH_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
fn html_csp(body: String) -> Response { let mut r = Html(body).into_response(); r.headers_mut().insert("content-security-policy", axum::http::HeaderValue::from_static(OAUTH_CSP)); r }
fn hidden_fields(form: &HashMap<String, String>) -> String { form.iter().filter(|(k, _)| k.as_str() != "otp").map(|(k, v)| format!("<input type=hidden name=\"{}\" value=\"{}\">", esc(k), esc(v))).collect() }
fn bearer_token(h: &HeaderMap) -> String { h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").strip_prefix("Bearer ").unwrap_or("").to_string() }
static LOGIN_FAILS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Vec<i64>>>> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
fn rate_allowed(key: &str) -> bool { let now = now(); let mut m = LOGIN_FAILS.lock().unwrap(); let len = { let e = m.entry(key.to_string()).or_default(); e.retain(|t| now - *t < 900); e.len() }; m.retain(|_, v| { v.retain(|t| now - *t < 900); !v.is_empty() }); len < 5 }
fn rate_fail(key: &str) { LOGIN_FAILS.lock().unwrap().entry(key.to_string()).or_default().push(now()); }
fn rate_clear(key: &str) { LOGIN_FAILS.lock().unwrap().remove(key); }
fn otp_ok(st: &S, uid: &str, code: &str) -> bool {
    if meta_get(st, &format!("totp_enabled:{}", uid)) != "1" { return true; }
    if code.is_empty() { return false; }
    if let Ok(secret) = oc::decrypt_symmetric(&st.master, &meta_get(st, &format!("totp_secret:{}", uid))) {
        let counter = (now() / 30) as u64;
        if [counter.wrapping_sub(1), counter, counter + 1].iter().any(|c| totp_code(&secret, *c) == code) { return true; }
    }
    let stored = meta_get(st, &format!("totp_recovery:{}", uid)); let hash = oc::hash_token(code);
    let mut list: Vec<String> = stored.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    if let Some(pos) = list.iter().position(|x| *x == hash) { list.remove(pos); meta_set(st, &format!("totp_recovery:{}", uid), &list.join(",")); return true; }
    false }

#[derive(Deserialize, Default)] struct AuthReq { email: String, password: String }
#[derive(Deserialize, Default)] struct NameReq { #[serde(default)] name: String, #[serde(default)] email: String, #[serde(default)] role: String, #[serde(default)] readme: String, #[serde(default)] env_id: String }
#[derive(Deserialize, Default, Clone)] struct SecretIn { key: String, value: String, #[serde(default = "def_path")] path: String, #[serde(default)] comment: String, #[serde(default)] tags: String, #[serde(default, rename = "type")] secret_type: String }
fn def_path() -> String { "/".into() }
#[derive(Deserialize, Default)] struct DeployReq { #[serde(default)] secrets: Vec<SecretIn>, #[serde(default)] text: String }

impl AppState {
    fn audit(&self, org: &str, app: &str, env: &str, actor: &str, action: &str, detail: &str) {
        // log streams (T10): persist delivery then send with retries in a thread
        if let Ok(streams) = self.db.query("SELECT id,url,secret FROM log_streams WHERE org_id=?", &[json!(org)]) { for srow in &streams {
            let did = id(); let payload = json!({"org":org,"app":app,"env":env,"actor":actor,"action":action,"detail":detail,"ts":now()}).to_string();
            let _ = self.db.exec("INSERT INTO log_deliveries(id,stream_id,event,payload,status,created_at) VALUES(?,?,?,?,'pending',?)", &[json!(did), json!(db::s(srow,"id")), json!(action), json!(payload), json!(now())]);
            let (url, secret, db_url) = (db::s(srow,"url"), db::s(srow,"secret"), self.db_url.clone());
            std::thread::spawn(move || { let mut status = "failed"; let mut attempts = 0;
                for i in 0..3 { attempts = i + 1; let mut req = reqwest::blocking::Client::new().post(&url).json(&serde_json::from_str::<Value>(&payload).unwrap_or(json!({})));
                    if !secret.is_empty() { req = req.header("X-OpenWarp-Signature", oc::hash_token(&format!("{}{}", secret, payload))); }
                    if let Ok(r) = req.send() { if r.status().is_success() { status = "delivered"; break; } } std::thread::sleep(std::time::Duration::from_millis(200)); }
                if let Ok(db2) = Db::open(&db_url) { let _ = db2.exec("UPDATE log_deliveries SET status=?,attempts=? WHERE id=?", &[json!(status), json!(attempts), json!(did)]); } });
        } }
        if let Ok(Some(wh)) = self.db.one("SELECT v FROM meta WHERE k=?", &[json!(format!("audit_webhook:{}", org))]) { let url = db::s(&wh, "v"); let payload = json!({"org":org,"app":app,"env":env,"actor":actor,"action":action,"detail":detail,"ts":now()}); std::thread::spawn(move || { let _ = reqwest::blocking::Client::new().post(&url).json(&payload).send(); }); }
        let _ = self.db.exec("INSERT INTO audit(id,org_id,app_id,env_id,actor,action,detail,created_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(id()), json!(org), json!(app), json!(env), json!(actor), json!(action), json!(detail), json!(now())]);
    }
    fn env_key(&self, env_id: &str) -> Result<[u8;32], (StatusCode, Json<Value>)> {
        let row = self.db.one("SELECT env_key_wrapped FROM envs WHERE id=?", &[json!(env_id)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "env not found"))?;
        let raw = oc::decrypt_symmetric(&self.master, &db::s(&row, "env_key_wrapped")).map_err(|e| bad(&e))?;
        raw.try_into().map_err(|_| bad("bad env key"))
    }
    fn token_user(&self, headers: &HeaderMap) -> Result<String, (StatusCode, Json<Value>)> {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        let token = auth.strip_prefix("Bearer ").unwrap_or("");
        if token.is_empty() { return Err(err(StatusCode::UNAUTHORIZED, "missing Bearer token")); }
        let hash = oc::hash_token(token);
        #[cfg(feature = "redis-cache")]
        if let Some(uid) = self.redis_get(&format!("sess:{}", hash)) { return Ok(uid); }
        // OAuth 2.1 access tokens (CLI / MCP clients)
        if let Some(row) = self.db.one("SELECT user_id FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?", &[json!(hash), json!(now())]).map_err(|e| bad(&e))? { return Ok(db::s(&row, "user_id")); }
        // service / personal access tokens
        if let Some(row) = self.db.one("SELECT created_by,kind,created_at FROM tokens WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))? {
            if db::s(&row, "kind") == "machine" && db::n(&row, "created_at") + 3600 < now() { return Err(err(StatusCode::UNAUTHORIZED, "machine token expired (1h TTL); login again via Universal Auth")); }
            let uid = db::s(&row, "created_by"); if !uid.is_empty() { return Ok(uid); }
        }
        let row = self.db.one("SELECT user_id,created_at FROM sessions WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
        if db::n(&row, "created_at") + 7 * 86400 < now() { let _ = self.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(hash)]); return Err(err(StatusCode::UNAUTHORIZED, "session expired (7d); login again")); }
        let uid = db::s(&row, "user_id");
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
    fn check_perm(&self, org: &str, user: &str, action: &str) -> Result<(), (StatusCode, Json<Value>)> {
        let role = self.require_org(org, user)?;
        if role == "owner" || role == "admin" || role == "developer" { return Ok(()); }
        // custom role: permissions matrix in roles table, e.g. ["secrets:write","secrets:read"] or ["*"]
        let row = self.db.one("SELECT permissions FROM roles WHERE org_id=? AND name=?", &[json!(org), json!(role)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN, "custom role not found"))?;
        let perms: Vec<String> = serde_json::from_str(&db::s(&row, "permissions")).unwrap_or_default();
        if perms.iter().any(|p| p == "*" || p == action) { Ok(()) } else { Err(err(StatusCode::FORBIDDEN, &format!("role {} lacks permission {}", role, action))) } }
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
        // env_members / app_members grant; org developers default read via app membership check fallback: allow org members (documented simplification, env_members narrows when present)
        let restricted = self.db.query("SELECT user_id FROM env_members WHERE env_id=?", &[json!(env_id)]).map_err(|e| bad(&e))?;
        if !restricted.is_empty() && !restricted.iter().any(|r| db::s(r, "user_id") == user) { return Err(err(StatusCode::FORBIDDEN, "no access to this environment")); }
        Ok((org, app))
    }
    fn decrypt_secret(&self, key: &[u8;32], row: &Row, user: &str) -> Value {
        let sid = db::s(row, "id");
        let mut value = oc::decrypt_symmetric(key, &db::s(row, "value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        if let Ok(Some(ov)) = self.db.one("SELECT value_enc FROM overrides WHERE secret_id=? AND user_id=?", &[json!(sid), json!(user)]) {
            if let Ok(b) = oc::decrypt_symmetric(key, &db::s(&ov, "value_enc")) { value = String::from_utf8_lossy(&b).into_owned(); }
        }
        let stype = db::s(row, "secret_type");
        json!({"id": sid, "key": oc::decrypt_symmetric(key, &db::s(row, "key_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            "value": if stype == "sealed" { Value::Null } else { json!(value) }, "path": db::s(row,"path"), "comment": oc::decrypt_symmetric(key, &db::s(row,"comment_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            "tags": db::s(row,"tags"), "type": stype, "version": db::n(row,"version"), "updated_at": db::n(row,"updated_at")})
    }
    #[allow(clippy::type_complexity)]
    fn list_secrets_decrypted(&self, env_id: &str, user: &str) -> Result<Vec<(String, String, Value)>, (StatusCode, Json<Value>)> {
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
}
fn resolve_refs(v: &str, by_path: &HashMap<String, String>, by_key: &HashMap<String, String>) -> String {
    let mut out = String::new(); let mut rest = v;
    while let Some(start) = rest.find("${") { out.push_str(&rest[..start]); let tail = &rest[start + 2..];
        match tail.find('}') { Some(end) => { let name = &tail[..end]; let val = by_path.get(name).or_else(|| by_key.get(name)).cloned().unwrap_or_else(|| format!("${{{}}}", name)); out.push_str(&val); rest = &tail[end + 1..]; } None => { out.push_str(&rest[start..]); return out; } } }
    out.push_str(rest); out
}

// ---------- auth ----------
async fn register(State(st): State<S>, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    if r.email.is_empty() || r.password.len() < 8 { return Err(bad("email and password (>=8 chars) required")); }
    let kp = oc::Keypair::generate();
    let wrapped = oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    let uid = id(); let hash = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(uid), json!(r.email.to_lowercase()), json!(hash), json!(kp.public), json!(wrapped), json!(now())]).map_err(|e| bad(&format!("register failed: {}", e)))?;
    let oid = id(); st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(oid), json!(format!("{}'s organisation", r.email)), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", &[json!(oid), json!(uid)]).map_err(|e| bad(&e))?;
    let token = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((hdr, j(json!({"token": token, "user_id": uid, "org_id": oid, "public_key": kp.public, "recovery_kit": kp.secret_b64()}))))
}
fn make_session(st: &S, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { let t = oc::random_token("ow"); st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&t)), json!(uid), json!(now())]).map_err(|e| bad(&e))?; Ok(t) }
async fn login(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<AuthReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let key = format!("login:{}:{}", addr.ip(), r.email.trim().to_lowercase());
    if !rate_allowed(&key) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later")); }
    let row = match st.db.one("SELECT * FROM users WHERE email=?", &[json!(r.email.trim().to_lowercase())]).map_err(|e| bad(&e))? { Some(x) => x, None => { rate_fail(&key); return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); } };
    if db::n(&row, "active") == 0 && row.contains_key("active") { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); }
    if !oc::verify_password(&r.password, &db::s(&row, "pass_hash")) { rate_fail(&key); return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    rate_clear(&key);
    let uid = db::s(&row, "id");
    if meta_get(&st, &format!("totp_enabled:{}", uid)) == "1" { let challenge = oc::random_token("mfa"); st.db.exec("INSERT INTO mfa_challenges(token,user_id,created_at) VALUES(?,?,?)", &[json!(challenge), json!(uid), json!(now())]).map_err(|e| bad(&e))?; return Ok((HeaderMap::new(), j(json!({"mfa_required": true, "mfa_token": challenge})))); }
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
async fn invite_member(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let role = st.require_org(&oid, &uid)?; if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "admin required")); }
    let target = st.db.one("SELECT id FROM users WHERE email=?", &[json!(r.email.to_lowercase())]).map_err(|e| bad(&e))?.ok_or_else(|| bad("user must register first"))?;
    let tid = db::s(&target, "id");
    if st.org_role(&oid, &tid).is_some() { return Err(err(StatusCode::CONFLICT, "user is already a member")); }
    let new_role = if r.role.trim().is_empty() { "developer".to_string() } else { r.role.trim().to_string() };
    if (new_role == "owner" || new_role == "admin") && role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can grant the owner or admin role")); }
    if new_role != "owner" && new_role != "admin" && new_role != "developer" && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(oid), json!(new_role)]).map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(oid), json!(tid), json!(new_role)]).map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "member.invite", &r.email); Ok(j(json!({"ok": true}))) }
async fn create_app(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let aid = id(); st.db.exec("INSERT INTO apps(id,org_id,name,readme,created_at) VALUES(?,?,?,?,?)", &[json!(aid), json!(oid), json!(r.name), json!(r.readme), json!(now())]).map_err(|e| bad(&e))?;
    for name in ["Development", "Staging", "Production"] { create_env_inner(&st, &aid, name)?; }
    st.audit(&oid, &aid, "", &uid, "app.create", &r.name); Ok(j(json!({"id": aid}))) }
fn create_env_inner(st: &S, app_id: &str, name: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let eid = id(); let key = oc::random_key(); let wrapped = oc::encrypt_symmetric(&st.master, &key);
    st.db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)", &[json!(eid), json!(app_id), json!(name), json!(wrapped), json!(now())]).map_err(|e| bad(&e))?; Ok(eid) }
async fn list_apps(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let rows = st.db.query("SELECT id,org_id,name,readme,created_at FROM apps WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"), &uid)?;
    if !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || r.name.is_empty() || r.name.len() > 32 { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    let eid = create_env_inner(&st, &aid, &r.name)?; Ok(j(json!({"id": eid}))) }
async fn list_envs(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"), &uid)?;
    let rows = st.db.query("SELECT id,app_id,name,created_at FROM envs WHERE app_id=? ORDER BY created_at", &[json!(aid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
    if st.org_role(&org, &uid).as_deref() != Some("owner") && st.org_role(&org, &uid).as_deref() != Some("admin") { return Err(err(StatusCode::FORBIDDEN, "admin required")); }
    st.db.exec("DELETE FROM secrets WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; st.db.exec("DELETE FROM envs WHERE id=?", &[json!(eid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &app, &eid, &uid, "env.delete", ""); Ok(j(json!({"ok": true}))) }
async fn list_members(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let rows = st.db.query("SELECT u.id AS id, u.email AS email, u.created_at AS created_at, m.role AS role FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? ORDER BY m.role, u.email", &[json!(oid)]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn remove_member(State(st): State<S>, h: HeaderMap, Path((oid, target)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let role = st.require_org(&oid, &uid)?; if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "admin required")); }
    if target == uid { return Err(bad("use another admin to remove yourself; leaving your own organisation is not supported")); }
    let target_role = st.org_role(&oid, &target).ok_or_else(|| err(StatusCode::NOT_FOUND, "member not found"))?;
    if target_role == "owner" && role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can remove an owner")); }
    let deleted = st.db.exec("DELETE FROM org_members WHERE org_id=? AND user_id=? AND (role<>'owner' OR (SELECT COUNT(*) FROM org_members WHERE org_id=? AND role='owner')>1)", &[json!(oid), json!(target), json!(oid)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(bad("cannot remove the last owner")); }
    st.audit(&oid, "", "", &uid, "member.remove", &target); Ok(j(json!({"ok": true}))) }
async fn update_app(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app, "org_id"); let role = st.require_org(&org, &uid)?;
    if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "admin required")); }
    if r.name.trim().is_empty() { return Err(bad("name required")); }
    st.db.exec("UPDATE apps SET name=? WHERE id=?", &[json!(r.name.trim()), json!(aid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &aid, "", &uid, "app.rename", &r.name); Ok(j(json!({"ok": true}))) }
async fn delete_app(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?;
    let org = db::s(&app, "org_id"); let role = st.require_org(&org, &uid)?;
    if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "admin required")); }
    for sql in [
        "DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?))",
        "DELETE FROM secrets WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM env_keys WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM leases WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM integrations WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM proposals WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM access_requests WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM rotation_schedules WHERE env_id IN (SELECT id FROM envs WHERE app_id=?)",
        "DELETE FROM envs WHERE app_id=?",
    ] { st.db.exec(sql, &[json!(aid)]).map_err(|e| bad(&e))?; }
    st.db.exec("DELETE FROM tokens WHERE app_id=?", &[json!(aid)]).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &aid, "", &uid, "app.delete", ""); Ok(j(json!({"ok": true}))) }
async fn update_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    if r.name.is_empty() || r.name.len() > 32 || !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { return Err(bad("env name must match ^[a-zA-Z0-9-_]{1,32}$")); }
    st.db.exec("UPDATE envs SET name=? WHERE id=?", &[json!(r.name), json!(eid)]).map_err(|e| bad(&e))?;
    st.audit(&org, &app, &eid, &uid, "env.rename", &r.name); Ok(j(json!({"ok": true}))) }

async fn list_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, app) = st.require_env(&eid, &uid)?;
    let items = st.list_secrets_decrypted(&eid, &uid)?; st.audit(&org, &app, &eid, &uid, "secret.list", &format!("{}", items.len()));
    Ok(j(json!({"secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
async fn deploy_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; let (org, app) = st.require_env(&eid, &uid)?; st.check_perm(&org, &uid, "secrets:write")?;
    let mut inputs = r.secrets.clone(); if inputs.is_empty() && !r.text.is_empty() { inputs = parse_env(&r.text); }
    let key = st.env_key(&eid)?; let mut count = 0;
    for s in &inputs { if s.key.trim().is_empty() { continue; } upsert_secret(&st, &eid, &key, &uid, s)?; count += 1; }
    st.audit(&org, &app, &eid, &uid, "secret.deploy", &format!("{} secrets", count));
    trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"deployed": count}))) }
fn upsert_secret(st: &S, eid: &str, key: &[u8;32], uid: &str, s: &SecretIn) -> Result<(), (StatusCode, Json<Value>)> {
    let kname = s.key.trim().to_uppercase(); let khash = oc::hash_token(&format!("{}:{}", s.path, kname));
    let existing = st.db.one("SELECT id,version,secret_type FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(khash)]).map_err(|e| bad(&e))?;
    let mut stype = if s.secret_type.is_empty() { "secret".to_string() } else { s.secret_type.clone() };
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
    st.db.exec("UPDATE secrets SET deleted=1,updated_at=? WHERE id=?", &[json!(now()), json!(sid)]).map_err(|e| bad(&e))?; st.audit(&org, &app, &eid, &uid, "secret.delete", &sid); Ok(j(json!({"ok": true}))) }
async fn history(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); st.require_env(&eid, &uid)?;
    let key = st.env_key(&eid)?; let sealed = st.db.one("SELECT secret_type FROM secrets WHERE id=?", &[json!(sid)]).map(|r| r.map(|x| db::s(&x,"secret_type") == "sealed").unwrap_or(false)).unwrap_or(false);
    let rows = st.db.query("SELECT * FROM secret_versions WHERE secret_id=? ORDER BY version DESC", &[json!(sid)]).map_err(|e| bad(&e))?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"version": db::n(r,"version"), "value": if sealed { "[SEALED]".to_string() } else { oc::decrypt_symmetric(&key,&db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() }, "created_at": db::n(r,"created_at"), "created_by": db::s(r,"created_by")})).collect();
    Ok(j(json!(items))) }
async fn restore(State(st): State<S>, h: HeaderMap, Path((sid, ver)): Path<(String, i64)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?;
    let v = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND version=?", &[json!(sid), json!(ver)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("version not found"))?;
    let cur = st.db.one("SELECT version FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?; let new_ver = cur.map(|r| db::n(&r,"version")).unwrap_or(0) + 1;
    st.db.exec("UPDATE secrets SET value_enc=?,comment_enc=?,version=?,deleted=0,updated_at=?,updated_by=? WHERE id=?", &[json!(db::s(&v,"value_enc")), json!(db::s(&v,"comment_enc")), json!(new_ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(new_ver), json!(db::s(&v,"key_enc")), json!(db::s(&v,"value_enc")), json!(db::s(&v,"comment_enc")), json!(db::s(&v,"secret_type")), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"secret.restore",&format!("{}->v{}",sid,ver)); Ok(j(json!({"ok":true,"version":new_ver}))) }
async fn set_override(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row,"env_id"); st.require_env(&eid,&uid)?;
    let key = st.env_key(&eid)?; let val = r.secrets.first().map(|s| s.value.clone()).unwrap_or_default();
    st.db.exec("INSERT INTO overrides(secret_id,user_id,value_enc) VALUES(?,?,?)", &[json!(sid), json!(uid), json!(oc::encrypt_symmetric(&key, val.as_bytes()))]).map_err(|e| bad(&e)).or_else(|_| st.db.exec("UPDATE overrides SET value_enc=? WHERE secret_id=? AND user_id=?", &[json!(oc::encrypt_symmetric(&key, val.as_bytes())), json!(sid), json!(uid)]).map_err(|e| bad(&e)))?; Ok(j(json!({"ok":true}))) }

async fn export_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.check_scope(&h, &eid)?; st.require_env(&eid,&uid)?;
    let items = st.list_secrets_decrypted(&eid,&uid)?; let text = items.iter().map(|(k,v,_)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n"); Ok(j(json!({"text": text, "secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
async fn search(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?; let needle = q.get("q").cloned().unwrap_or_default().to_uppercase();
    let orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).map_err(|e| bad(&e))?;
    let mut results = Vec::new();
    for o in &orgs { let apps = st.db.query("SELECT id,name FROM apps WHERE org_id=?", &[json!(db::s(o,"org_id"))]).map_err(|e| bad(&e))?;
        for a in &apps { let envs = st.db.query("SELECT id,name FROM envs WHERE app_id=?", &[json!(db::s(a,"id"))]).map_err(|e| bad(&e))?;
            for e in &envs { if let Ok(items) = st.list_secrets_decrypted(&db::s(e,"id"), &uid) { for (k,_,raw) in items { if needle.is_empty() || k.contains(&needle) { results.push(json!({"app": db::s(a,"name"), "env": db::s(e,"name"), "key": k, "path": raw["path"]})); } } } } } }
    Ok(j(json!({"results": results}))) }
async fn create_token(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    if let Ok(Some(scoped)) = st.db.one("SELECT env_id FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(&h)))]) { if !db::s(&scoped, "env_id").is_empty() { return Err(err(StatusCode::FORBIDDEN, "environment-scoped tokens cannot mint new tokens")); } }
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"),&uid)?;
    let token = oc::random_token("owp"); let tid = id();
    st.db.exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)", &[json!(tid), json!(db::s(&app,"org_id")), json!(aid), json!(r.env_id), json!(if r.name.is_empty(){"token".into()}else{r.name.clone()}), json!(oc::hash_token(&token)), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": tid, "token": token}))) }
async fn audit_list(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT * FROM audit WHERE org_id=? ORDER BY created_at DESC LIMIT 500", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn create_team(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
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
    let val = oc::decrypt_symmetric(&key, &db::s(&row,"value_enc")).map_err(|e| bad(&e))?;
    st.db.exec("DELETE FROM lockbox WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"value": String::from_utf8_lossy(&val)}))) }
async fn list_leases(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let key = st.env_key(&eid)?; let rows = st.db.query("SELECT * FROM leases WHERE env_id=? AND revoked=0 AND expires_at>?", &[json!(eid), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "value": oc::decrypt_symmetric(&key,&db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(), "expires_at": db::n(r,"expires_at")})).collect::<Vec<_>>()))) }

async fn create_integration(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or(""); if !integrations::KINDS.contains(&kind) { return Err(bad(&format!("unknown kind, supported: {:?}", integrations::KINDS))); }
    let config = body.get("config").cloned().unwrap_or(json!({})); let key = st.env_key(&eid)?;
    let iid = id(); st.db.exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES(?,?,?,?,?,?)", &[json!(iid), json!(eid), json!(kind), json!(body.get("name").and_then(|v| v.as_str()).unwrap_or(kind)), json!(oc::encrypt_symmetric(&key, config.to_string().as_bytes())), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": iid}))) }
async fn list_integrations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let rows = st.db.query("SELECT id,env_id,kind,name,created_at FROM integrations WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn sync_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?; let msg = sync_one(&st, &iid, &uid).await?; Ok(j(json!({"ok": true, "detail": msg}))) }
async fn test_integration(State(st): State<S>, h: HeaderMap, Path(iid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); st.require_env(&eid, &uid)?; let key = st.env_key(&eid)?;
    let config: Value = serde_json::from_slice(&oc::decrypt_symmetric(&key, &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    if db::s(&row, "kind") == "trigger" { let msg = integrations::trigger_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    if db::s(&row, "kind") == "instabox" { let msg = integrations::instabox_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    if db::s(&row, "kind") == "boat" { let msg = integrations::boat_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    if db::s(&row, "kind") == "daytona" { let msg = integrations::daytona_test(&config).await.map_err(|e| bad(&e))?; return Ok(j(json!({"ok": true, "detail": msg}))); }
    Ok(j(json!({"ok": true, "detail": format!("kind {} is configured; use Sync to verify against the live service", db::s(&row, "kind"))}))) }
async fn trigger_sync(st: &S, eid: &str, uid: &str) {
    if let Ok(rows) = st.db.query("SELECT id FROM integrations WHERE env_id=?", &[json!(eid)]) {
        for r in &rows { let _ = sync_one(st, &db::s(r, "id"), uid).await; }
    }
}
async fn sync_one(st: &S, iid: &str, uid: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM integrations WHERE id=?", &[json!(iid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("integration not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, uid)?;
    let key = st.env_key(&eid)?;
    let config: Value = serde_json::from_slice(&oc::decrypt_symmetric(&key, &db::s(&row, "config_enc")).map_err(|e| bad(&e))?).unwrap_or(json!({}));
    let items = st.list_secrets_decrypted(&eid, uid)?; let pairs: Vec<(String, String)> = items.iter().map(|(k, v, _)| (k.clone(), v.clone())).collect();
    let kind = db::s(&row, "kind");
    if matches!(kind.as_str(), "trigger" | "instabox" | "boat" | "daytona") {
        let prev_rows = st.db.query("SELECT remote_name FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]).map_err(|e| bad(&e))?;
        let prev: Vec<String> = prev_rows.iter().map(|r| db::s(r, "remote_name")).collect();
        let (msg, managed) = match kind.as_str() {
            "trigger" => integrations::trigger_sync(&config, &pairs, &prev).await,
            "instabox" => integrations::instabox_sync(&config, &pairs, &prev).await,
            "boat" => integrations::boat_sync(&config, &pairs, &prev).await,
            _ => integrations::daytona_sync(&config, &pairs, &prev).await,
        }.map_err(|e| bad(&e))?;
        let dry = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
        if !dry { let _ = st.db.exec("DELETE FROM integration_sync_state WHERE integration_id=?", &[json!(iid)]);
            for n in &managed { let hv = pairs.iter().find(|(k, _)| n.ends_with(k)).map(|(_, v)| oc::hash_token(v)).unwrap_or_default(); let _ = st.db.exec("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES(?,?,?)", &[json!(iid), json!(n), json!(hv)]); } }
        st.audit(&org, &app, &eid, uid, "integration.sync", &msg); return Ok(msg); }
    let msg = integrations::sync(&kind, &config, &pairs).await.map_err(|e| bad(&e))?;
    st.audit(&org, &app, &eid, uid, "integration.sync", &msg); Ok(msg)
}

async fn pitr(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid,&uid)?;
    let ts = body.get("timestamp").and_then(|v| v.as_i64()).unwrap_or_else(now);
    let rows = st.db.query("SELECT id FROM secrets WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; let mut restored = 0;
    for r in &rows { let sid = db::s(r,"id"); if let Ok(Some(v)) = st.db.one("SELECT * FROM secret_versions WHERE secret_id=? AND created_at<=? ORDER BY created_at DESC LIMIT 1", &[json!(sid), json!(ts)]) {
        let _ = st.db.exec("UPDATE secrets SET value_enc=?,deleted=0,updated_at=? WHERE id=?", &[json!(db::s(&v,"value_enc")), json!(now()), json!(sid)]); restored += 1; } }
    st.audit(&org,&app,&eid,&uid,"env.pitr",&format!("ts={} restored={}",ts,restored)); Ok(j(json!({"restored": restored}))) }


async fn org_settings(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    if st.require_org(&oid,&uid)? == "developer" { return Err(err(StatusCode::FORBIDDEN,"admin required")); }
    if let Some(v)=body.get("ip_allowlist").and_then(|x|x.as_str()) { st.db.exec("UPDATE orgs SET ip_allowlist=? WHERE id=?", &[json!(v), json!(oid)]).map_err(|e| bad(&e))?; }
    if let Some(v)=body.get("audit_webhook").and_then(|x|x.as_str()) { st.db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(format!("audit_webhook:{}",oid)), json!(v)]).map_err(|e| bad(&e)).or_else(|_| st.db.exec("UPDATE meta SET v=? WHERE k=?", &[json!(v), json!(format!("audit_webhook:{}",oid))]).map_err(|e| bad(&e)))?; }
    for (field, enc) in [("oidc_issuer", false), ("oidc_client_id", false), ("oidc_redirect_uri", false), ("oidc_client_secret", true)] {
        if let Some(v)=body.get(field).and_then(|x|x.as_str()) { let stored = if enc { oc::encrypt_symmetric(&st.master, v.as_bytes()) } else { v.to_string() };
            let k = format!("{}:{}", field, oid);
            if st.db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(k.clone()), json!(stored.clone())]).is_err() { let _ = st.db.exec("UPDATE meta SET v=? WHERE k=?", &[json!(stored), json!(k)]); } } }
    Ok(j(json!({"ok":true}))) }
async fn rotate_secret(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org,app)=st.require_env(&eid,&uid)?;
    let key_name = body.get("key").and_then(|v|v.as_str()).unwrap_or(""); let new_val = body.get("value").and_then(|v|v.as_str()).map(|s|s.to_string()).unwrap_or_else(|| oc::random_token("rot"));
    let key = st.env_key(&eid)?; let khash = oc::hash_token(&format!("/:{}", key_name.to_uppercase()));
    let row = st.db.one("SELECT id FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(khash)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found; create it first"))?;
    upsert_secret(&st,&eid,&key,&uid,&SecretIn{key:key_name.into(),value:new_val.clone(),path:"/".into(),comment:"auto-rotation".into(),tags:"".into(),secret_type:"secret".into()})?;
    st.audit(&org,&app,&eid,&uid,"secret.rotate",key_name); Ok(j(json!({"key":key_name,"value":new_val,"secret_id":db::s(&row,"id")}))) }
fn scim_org(st: &S, h: &HeaderMap, q: &HashMap<String, String>) -> Result<String, (StatusCode, Json<Value>)> {
    let uid = st.token_user(h)?;
    let oid = q.get("org_id").cloned().unwrap_or_default();
    if oid.is_empty() { return Err(bad("org_id query parameter required")); }
    let role = st.require_org(&oid, &uid)?;
    if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "SCIM requires admin of this organisation")); }
    Ok(oid) }
fn scim_member(st: &S, org: &str, user: &str) -> bool { st.db.one("SELECT user_id FROM org_members WHERE org_id=? AND user_id=?", &[json!(org), json!(user)]).ok().flatten().is_some() }
async fn scim_create_user(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>, Json(body): Json<Value>) -> Res {
    let org = scim_org(&st, &h, &q)?;
    let email = body.get("userName").and_then(|v| v.as_str()).unwrap_or(""); if email.is_empty() { return Err(bad("userName required")); }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("scim"); let nid = id();
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(nid), json!(email.to_lowercase()), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|_| bad("user exists"))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')", &[json!(org), json!(nid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id":nid,"userName":email,"active":true,"temp_password":pw}))) }
async fn scim_list_users(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res {
    let org = scim_org(&st, &h, &q)?;
    let rows = st.db.query("SELECT u.id AS id, u.email AS email FROM users u JOIN org_members m ON m.user_id=u.id WHERE m.org_id=? ORDER BY u.created_at", &[json!(org)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"Resources": rows.iter().map(|r| json!({"id":db::s(r,"id"),"userName":db::s(r,"email"),"active":true})).collect::<Vec<_>>(), "totalResults": rows.len()}))) }


async fn create_e2e_env(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"), &uid)?;
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
async fn e2e_put(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
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
async fn e2e_get(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid, &uid)?;
    let wrapped = st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN, "no wrapped env key for caller; ask a member to grant access"))?;
    let rows = st.db.query("SELECT id,path,key_enc,value_enc,version,updated_at FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1", &[json!(eid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"wrapped_key": db::s(&wrapped,"wrapped_key"), "secrets": rows.iter().map(db::obj).collect::<Vec<_>>()}))) }
async fn e2e_grant(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid, &uid)?;
    if st.db.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid), json!(uid)]).map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN, "caller has no env key to grant")); }
    let email = body.get("email").and_then(|v| v.as_str()).unwrap_or(""); let wrapped = body.get("wrapped_key").and_then(|v| v.as_str()).unwrap_or("");
    if email.is_empty() || wrapped.is_empty() { return Err(bad("email and wrapped_key (wrapped client-side for grantee) required")); }
    let target = st.db.one("SELECT id FROM users WHERE email=?", &[json!(email.to_lowercase())]).map_err(|e| bad(&e))?.ok_or_else(|| bad("user not found"))?;
    st.db.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(eid), json!(db::s(&target,"id")), json!(wrapped)]).map_err(|e| bad(&e))
        .or_else(|_| st.db.exec("UPDATE env_keys SET wrapped_key=? WHERE env_id=? AND user_id=?", &[json!(wrapped), json!(eid), json!(db::s(&target,"id"))]).map_err(|e| bad(&e)))?;
    Ok(j(json!({"ok": true}))) }
async fn user_lookup(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?;
    let email = q.get("email").cloned().unwrap_or_default();
    let target_pre = st.db.one("SELECT id FROM users WHERE email=?", &[json!(email.to_lowercase())]).map_err(|e| bad(&e))?;
    if let Some(tp) = &target_pre { let tid2 = db::s(tp, "id"); if tid2 != uid { let shared = st.db.query("SELECT a.org_id FROM org_members a JOIN org_members b ON b.org_id=a.org_id WHERE a.user_id=? AND b.user_id=?", &[json!(uid), json!(tid2)]).map_err(|e| bad(&e))?; if shared.is_empty() { return Err(err(StatusCode::FORBIDDEN, "target user shares no organisation with caller")); } } }
    let row = st.db.one("SELECT id,email,pubkey FROM users WHERE email=?", &[json!(email.to_lowercase())]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"user not found"))?;
    Ok(j(db::obj(&row))) }


fn meta_get(st: &S, k: &str) -> String { st.db.one("SELECT v FROM meta WHERE k=?", &[json!(k)]).ok().flatten().map(|r| db::s(&r,"v")).unwrap_or_default() }
async fn oidc_discovery(issuer: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    reqwest::get(&url).await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string())) }
async fn oidc_start(State(st): State<S>, Path(oid): Path<String>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)); let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)); let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid));
    if issuer.is_empty() || client_id.is_empty() || redirect_uri.is_empty() { return Err(bad("OIDC not configured for this org (set oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri via org settings)")); }
    let disc = oidc_discovery(&issuer).await?; let auth_ep = disc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    let state = oc::random_token("st"); let nonce = oc::random_token("n");
    st.db.exec("INSERT INTO oidc_states(state,org_id,created_at) VALUES(?,?,?)", &[json!(state), json!(oid), json!(now())]).map_err(|e| bad(&e))?;
    let url = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&nonce={}", auth_ep, urlencode(&client_id), urlencode(&redirect_uri), state, nonce);
    Ok(axum::response::Redirect::temporary(&url)) }
fn urlencode(s: &str) -> String { s.chars().map(|c| match c { 'A'..='Z'|'a'..='z'|'0'..='9'|'-'|'_'|'.'|'~' => c.to_string(), _ => format!("%{:02X}", c as u32) }).collect() }
#[derive(serde::Deserialize)] struct Claims { email: Option<String>, sub: String }
async fn oidc_callback(State(st): State<S>, Query(q): Query<HashMap<String,String>>) -> Result<axum::response::Redirect, (StatusCode, Json<Value>)> {
    let code = q.get("code").cloned().unwrap_or_default(); let state = q.get("state").cloned().unwrap_or_default();
    let srow = st.db.one("SELECT org_id FROM oidc_states WHERE state=?", &[json!(state)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid or expired state"))?;
    let oid = db::s(&srow, "org_id"); let _ = st.db.exec("DELETE FROM oidc_states WHERE state=?", &[json!(state)]);
    let issuer = meta_get(&st, &format!("oidc_issuer:{}", oid)); let client_id = meta_get(&st, &format!("oidc_client_id:{}", oid)); let redirect_uri = meta_get(&st, &format!("oidc_redirect_uri:{}", oid));
    let secret_enc = meta_get(&st, &format!("oidc_client_secret:{}", oid)); let client_secret = oc::decrypt_symmetric(&st.master, &secret_enc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let disc = oidc_discovery(&issuer).await?;
    let token_ep = disc.get("token_endpoint").and_then(|v| v.as_str()).unwrap_or(""); let jwks_uri = disc.get("jwks_uri").and_then(|v| v.as_str()).unwrap_or("");
    let client = reqwest::Client::new();
    let tok: Value = client.post(token_ep).form(&[("grant_type","authorization_code"),("code",&code),("redirect_uri",&redirect_uri),("client_id",&client_id),("client_secret",&client_secret)]).send().await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string()))?;
    let id_token = tok.get("id_token").and_then(|v| v.as_str()).ok_or_else(|| bad("token response has no id_token"))?;
    let header = jsonwebtoken::decode_header(id_token).map_err(|e| bad(&e.to_string()))?; let kid = header.kid.ok_or_else(|| bad("id_token has no kid"))?;
    let jwks: Value = client.get(jwks_uri).send().await.map_err(|e| bad(&e.to_string()))?.json().await.map_err(|e| bad(&e.to_string()))?;
    let jwk = jwks.get("keys").and_then(|v| v.as_array()).and_then(|ks| ks.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid))).ok_or_else(|| bad("kid not found in JWKS"))?;
    let dkey = jsonwebtoken::DecodingKey::from_rsa_components(jwk.get("n").and_then(|v| v.as_str()).unwrap_or(""), jwk.get("e").and_then(|v| v.as_str()).unwrap_or("")).map_err(|e| bad(&e.to_string()))?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&client_id]); validation.set_issuer(&[&issuer]);
    let data = jsonwebtoken::decode::<Claims>(id_token, &dkey, &validation).map_err(|e| bad(&format!("id_token verification failed: {}", e)))?;
    let email = data.claims.email.ok_or_else(|| bad("id_token has no email"))?.to_lowercase();
    let subject = data.claims.sub.clone(); let issuer_key = issuer.clone();
    let uid = if let Some(bound) = st.db.one("SELECT user_id FROM oidc_subjects WHERE issuer=? AND subject=?", &[json!(issuer_key), json!(subject)]).map_err(|e| bad(&e))? { db::s(&bound, "user_id") } else {
        if st.db.one("SELECT id FROM users WHERE email=?", &[json!(email)]).map_err(|e| bad(&e))?.is_some() { return Err(err(StatusCode::CONFLICT, "an account with this email already exists; sign in with your password, or ask an organisation admin to link this identity")); }
        let kp = oc::Keypair::generate(); let pw = oc::random_token("oidc"); let nid = id();
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(nid), json!(email), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO oidc_subjects(issuer,subject,user_id,created_at) VALUES(?,?,?,?)", &[json!(issuer_key), json!(subject), json!(nid), json!(now())]).map_err(|e| bad(&e))?;
        nid };
    if let Some(u) = st.db.one("SELECT active FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))? { if db::n(&u, "active") == 0 { return Err(err(StatusCode::UNAUTHORIZED, "account deactivated")); } }
    if st.org_role(&oid, &uid).is_none() { let _ = st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'developer')", &[json!(oid), json!(uid)]); }
    st.audit(&oid,"","",&uid,"auth.oidc_login",&format!("{} sub={}", email, data.claims.sub));
    let token = make_session(&st, &uid)?;
    Ok(axum::response::Redirect::temporary(&format!("/#token={}&org={}", token, oid))) }

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
    Ok(j(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": rows.iter().map(|r| scim_group_json(&st,r)).collect::<Vec<_>>(), "totalResults": rows.len()}))) }
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
    let caller_role = st.require_org(&oid, &uid)?; if caller_role != "owner" && caller_role != "admin" { return Err(err(StatusCode::FORBIDDEN, "admin required")); }
    let want = if r.role.trim().is_empty() { "developer".to_string() } else { r.role.trim().to_string() };
    if want == "owner" { return Err(bad("machine identities cannot hold the owner role")); }
    if want == "admin" && caller_role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only an owner can create an admin identity")); }
    if want != "developer" && want != "admin" && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(oid), json!(want)]).map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    let iid = id(); let client_id = oc::random_token("cid"); let client_secret = oc::random_token("csec");
    st.db.exec("INSERT INTO identities(id,org_id,name,role,created_at) VALUES(?,?,?,?,?)", &[json!(iid), json!(oid), json!(r.name), json!(want), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO identity_credentials(id,identity_id,client_id,secret_hash,created_at) VALUES(?,?,?,?,?)", &[json!(id()), json!(iid), json!(client_id), json!(oc::hash_token(&client_secret)), json!(now())]).map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"identity.create",&r.name);
    Ok(j(json!({"id": iid, "client_id": client_id, "client_secret": client_secret, "note": "client_secret shown once; POST /api/v1/machine/auth/universal/login {client_id, client_secret} for a 1h access token"}))) }
async fn list_identities(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid, &uid)?;
    let rows = st.db.query("SELECT id,org_id,name,role,created_at FROM identities WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn universal_login(State(st): State<S>, Json(body): Json<Value>) -> Res {
    let cid = body.get("client_id").and_then(|v| v.as_str()).unwrap_or(""); let secret = body.get("client_secret").and_then(|v| v.as_str()).unwrap_or("");
    let cred = st.db.one("SELECT identity_id FROM identity_credentials WHERE client_id=? AND secret_hash=?", &[json!(cid), json!(oc::hash_token(secret))]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid client credentials"))?;
    let iid = db::s(&cred, "identity_id"); let token = oc::random_token("owm");
    st.db.exec("INSERT INTO tokens(id,org_id,name,token_hash,kind,created_at,created_by) VALUES(?,?,?,?,?,?,?)", &[json!(id()), json!(""), json!("machine"), json!(oc::hash_token(&token)), json!("machine"), json!(now()), json!(iid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({"accessToken": token, "expiresIn": 3600, "tokenType": "Bearer", "identity_id": iid}))) }

// ---------- approval workflow: secret change proposals ----------
async fn create_proposal(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
    let key = st.env_key(&eid)?; let payload = serde_json::to_string(&r.secrets.iter().map(|s| json!({"key":s.key,"value":s.value,"path":s.path,"comment":s.comment,"tags":s.tags,"type":s.secret_type})).collect::<Vec<_>>()).unwrap();
    let pid = id(); st.db.exec("INSERT INTO proposals(id,env_id,author,payload_enc,created_at) VALUES(?,?,?,?,?)", &[json!(pid), json!(eid), json!(uid), json!(oc::encrypt_symmetric(&key, payload.as_bytes())), json!(now())]).map_err(|e| bad(&e))?;
    st.audit(&org,&app,&eid,&uid,"proposal.create",&pid); Ok(j(json!({"id": pid, "status": "pending"}))) }
async fn list_proposals(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid, &uid)?;
    let rows = st.db.query("SELECT id,env_id,author,status,created_at,decided_by FROM proposals WHERE env_id=? ORDER BY created_at DESC", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn decide_proposal(State(st): State<S>, h: HeaderMap, Path((pid, action)): Path<(String, String)>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM proposals WHERE id=?", &[json!(pid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"proposal not found"))?;
    if db::s(&row,"status") != "pending" { return Err(bad("proposal already decided")); }
    let eid = db::s(&row,"env_id"); let (org, app) = st.require_env(&eid, &uid)?;
    let role = st.org_role(&org, &uid).unwrap_or_default(); if role != "owner" && role != "admin" && db::s(&row,"author") == uid { return Err(err(StatusCode::FORBIDDEN, "proposals need approval by an admin or another member (not the author)")); }
    if role != "owner" && role != "admin" { return Err(err(StatusCode::FORBIDDEN, "admin approval required")); }
    if action == "approve" {
        let key = st.env_key(&eid)?; let plain = oc::decrypt_symmetric(&key, &db::s(&row,"payload_enc")).map_err(|e| bad(&e))?;
        let items: Vec<Value> = serde_json::from_slice(&plain).unwrap_or_default(); let mut count = 0;
        for it in &items { let s = SecretIn{ key: it["key"].as_str().unwrap_or("").into(), value: it["value"].as_str().unwrap_or("").into(), path: it["path"].as_str().unwrap_or("/").into(), comment: it["comment"].as_str().unwrap_or("").into(), tags: it["tags"].as_str().unwrap_or("").into(), secret_type: it["type"].as_str().unwrap_or("secret").into() };
            if !s.key.is_empty() { upsert_secret(&st, &eid, &key, &uid, &s)?; count += 1; } }
        st.db.exec("UPDATE proposals SET status='approved',decided_by=? WHERE id=?", &[json!(uid), json!(pid)]).map_err(|e| bad(&e))?;
        st.audit(&org,&app,&eid,&uid,"proposal.approve",&format!("{} applied {} secrets",pid,count)); trigger_sync(&st,&eid,&uid).await;
        Ok(j(json!({"status":"approved","applied":count})))
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
    if st.org_role(&org,&uid).as_deref() != Some("owner") && st.org_role(&org,&uid).as_deref() != Some("admin") { return Err(err(StatusCode::FORBIDDEN,"admin required")); }
    if action == "approve" { let _ = st.db.exec("INSERT INTO env_members(env_id,user_id) VALUES(?,?)", &[json!(eid), json!(db::s(&row,"user_id"))]);
        st.db.exec("UPDATE access_requests SET status='approved',decided_by=? WHERE id=?", &[json!(uid), json!(rid)]).map_err(|e| bad(&e))?; st.audit(&org,&app,&eid,&uid,"access.approve",&db::s(&row,"user_id")); Ok(j(json!({"status":"approved"})))
    } else { st.db.exec("UPDATE access_requests SET status='rejected',decided_by=? WHERE id=?", &[json!(uid), json!(rid)]).map_err(|e| bad(&e))?; Ok(j(json!({"status":"rejected"}))) } }

// ---------- dynamic Postgres secrets + PKI ----------
async fn create_lease_v2(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let key = st.env_key(&eid)?; let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("lease").to_string();
    let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600); let lid = id();
    let typ = body.get("type").and_then(|v| v.as_str()).unwrap_or("generic");
    if typ == "postgres" {
        let conn = body.get("config").and_then(|c| c.get("connection")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if conn.is_empty() { return Err(bad("postgres dynamic secret requires config.connection")); }
        let username = format!("dyn_{}", oc::random_token("").chars().take(12).collect::<String>().to_lowercase());
        let password = oc::random_token("dyn");
        let (u2,p2,c2) = (username.clone(), password.clone(), conn.clone()); let exp = ttl;
        let res = std::thread::spawn(move || { let mut cl = postgres::Client::connect(&c2, postgres::NoTls).map_err(|e| e.to_string())?;
            cl.execute(&format!("CREATE ROLE \"{}\" LOGIN PASSWORD '{}'", u2, p2), &[]).map_err(|e| e.to_string())?; let _ = exp; Ok::<(),String>(()) }).join().map_err(|_| bad("pg thread panicked"))?;
        res.map_err(|e: String| bad(&e))?;
        let config_enc = oc::encrypt_symmetric(&key, json!({"connection":conn,"type":"postgres"}).to_string().as_bytes());
        st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,username,config_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric(&key, password.as_bytes())), json!(username), json!(config_enc), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
        return Ok(j(json!({"id": lid, "username": username, "password": password, "expires_at": now()+ttl, "type":"postgres"}))); }
    let value = oc::random_token("dyn");
    st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(name), json!(oc::encrypt_symmetric(&key, value.as_bytes())), json!(now()+ttl), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": lid, "value": value, "expires_at": now()+ttl}))) }
async fn revoke_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT * FROM leases WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    let eid = db::s(&row,"env_id"); st.require_env(&eid,&uid)?; let key = st.env_key(&eid)?;
    if !db::s(&row,"config_enc").is_empty() { if let Ok(plain) = oc::decrypt_symmetric(&key, &db::s(&row,"config_enc")) { if let Ok(cfg) = serde_json::from_slice::<Value>(&plain) {
        if cfg.get("type").and_then(|v| v.as_str()) == Some("postgres") { let conn = cfg.get("connection").and_then(|v| v.as_str()).unwrap_or("").to_string(); let username = db::s(&row,"username");
            let _ = std::thread::spawn(move || { if let Ok(mut cl) = postgres::Client::connect(&conn, postgres::NoTls) { let _ = cl.execute(&format!("DROP ROLE IF EXISTS \"{}\"", username), &[]); } }).join(); } } } }
    st.db.exec("UPDATE leases SET revoked=1 WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": lid}))) }

fn ca_params(cn: &str, is_ca: bool) -> rcgen::CertificateParams {
    let mut p = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    if is_ca { p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained); p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign]; }
    else { p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature]; p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth, rcgen::ExtendedKeyUsagePurpose::ClientAuth]; }
    p }
async fn create_ca(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    if st.require_org(&oid,&uid)? == "developer" { return Err(err(StatusCode::FORBIDDEN,"admin required")); }
    let kp = rcgen::KeyPair::generate().map_err(|e| bad(&e.to_string()))?; let params = ca_params(if r.name.is_empty(){"OpenWarp CA"}else{&r.name}, true);
    let cert = params.self_signed(&kp).map_err(|e| bad(&e.to_string()))?;
    let cid = id(); st.db.exec("INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,created_at) VALUES(?,?,?,?,?,?)", &[json!(cid), json!(oid), json!(r.name), json!(cert.pem()), json!(oc::encrypt_symmetric(&st.master, kp.serialize_pem().as_bytes())), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": cid, "certificate": cert.pem()}))) }
async fn issue_cert(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let ca = st.db.one("SELECT * FROM pki_cas WHERE id=?", &[json!(caid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?;
    st.require_org(&db::s(&ca,"org_id"), &uid)?;
    let cn = body.get("cn").and_then(|v| v.as_str()).unwrap_or("service"); let days = body.get("days").and_then(|v| v.as_i64()).unwrap_or(365);
    let issuer_kp_pem = oc::decrypt_symmetric(&st.master, &db::s(&ca,"key_enc")).map_err(|e| bad(&e))?;
    let issuer_kp = rcgen::KeyPair::from_pem(&String::from_utf8_lossy(&issuer_kp_pem)).map_err(|e| bad(&e.to_string()))?;
    let issuer_params = ca_params(&db::s(&ca,"name"), true); let issuer_cert = issuer_params.self_signed(&issuer_kp).map_err(|e| bad(&e.to_string()))?;
    // NOTE: rcgen re-derives issuer cert from params; signing uses issuer cert+key pair as required by rcgen API.
    let leaf_kp = rcgen::KeyPair::generate().map_err(|e| bad(&e.to_string()))?;
    let mut leaf_params = ca_params(cn, false);
    if let Some(sans) = body.get("sans").and_then(|v| v.as_array()) { let names: Vec<String> = sans.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect(); if !names.is_empty() { leaf_params.subject_alt_names = names.iter().map(|n| rcgen::SanType::DnsName(n.clone().try_into().unwrap())).collect(); } }
    let leaf = leaf_params.signed_by(&leaf_kp, &issuer_cert, &issuer_kp).map_err(|e| bad(&e.to_string()))?;
    let cert_id = id(); let serial = format!("{:x}", now());
    st.db.exec("INSERT INTO pki_certs(id,ca_id,cn,cert_pem,serial,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(cert_id), json!(caid), json!(cn), json!(leaf.pem()), json!(serial), json!(now()+days*86400), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": cert_id, "certificate": leaf.pem(), "private_key": leaf_kp.serialize_pem(), "ca_certificate": db::s(&ca,"cert_pem")}))) }
async fn list_certs(State(st): State<S>, h: HeaderMap, Path(caid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(caid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"CA not found"))?; st.require_org(&db::s(&ca,"org_id"),&uid)?;
    let rows = st.db.query("SELECT id,ca_id,cn,serial,revoked,expires_at,created_at FROM pki_certs WHERE ca_id=?", &[json!(caid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn revoke_cert(State(st): State<S>, h: HeaderMap, Path(cid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT ca_id FROM pki_certs WHERE id=?", &[json!(cid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"cert not found"))?;
    let ca = st.db.one("SELECT org_id FROM pki_cas WHERE id=?", &[json!(db::s(&row,"ca_id"))]).map_err(|e| bad(&e))?; if let Some(ca)=ca { st.require_org(&db::s(&ca,"org_id"),&uid)?; }
    st.db.exec("UPDATE pki_certs SET revoked=1 WHERE id=?", &[json!(cid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": cid}))) }


// ---------- IP allowlist enforcement (T01) ----------
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let ip = ip.trim(); let cidr = cidr.trim(); if cidr.is_empty() { return false; }
    if !cidr.contains('/') { return ip == cidr; }
    let (net, bits) = cidr.split_once('/').unwrap(); let bits: u32 = bits.parse().unwrap_or(32);
    let parse = |s: &str| s.split('.').filter_map(|o| o.parse::<u32>().ok()).collect::<Vec<_>>();
    let (a, b) = (parse(ip), parse(net)); if a.len() != 4 || b.len() != 4 { return ip == net; }
    let to_u = |v: &Vec<u32>| (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) }; (to_u(&a) & mask) == (to_u(&b) & mask) }
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
    let forwarded = if trust_proxy { headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(|s| s.split(',').next().unwrap_or("").trim().to_string()) } else { None };
    let conn_ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string());
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
    if !path.starts_with("/api/") || path == "/api/auth/logout" { return next.run(req).await; }
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
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""); let token = auth.strip_prefix("Bearer ").unwrap_or("");
    let hash = oc::hash_token(token); let _ = st.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(hash)]);
    #[cfg(feature = "redis-cache")] st.redis_del(&format!("sess:{}", hash));
    Ok(j(json!({"ok": true}))) }
async fn list_tokens(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"),&uid)?;
    let rows = st.db.query("SELECT id,app_id,env_id,name,kind,created_at,created_by FROM tokens WHERE app_id=?", &[json!(aid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn revoke_token(State(st): State<S>, h: HeaderMap, Path(tid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT created_by,org_id FROM tokens WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"token not found"))?;
    if db::s(&row,"created_by") != uid && st.org_role(&db::s(&row,"org_id"),&uid).as_deref() != Some("owner") && st.org_role(&db::s(&row,"org_id"),&uid).as_deref() != Some("admin") { return Err(err(StatusCode::FORBIDDEN,"token owner or org admin required")); }
    st.db.exec("DELETE FROM tokens WHERE id=?", &[json!(tid)]).map_err(|e| bad(&e))?; Ok(j(json!({"revoked": tid}))) }


// ---------- custom RBAC roles (T07) ----------
async fn create_role(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    if st.require_org(&oid,&uid)? == "developer" { return Err(err(StatusCode::FORBIDDEN,"admin required")); }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(""); if name.is_empty() || ["owner","admin","developer"].contains(&name) { return Err(bad("role name required and cannot shadow managed roles")); }
    let perms = body.get("permissions").cloned().unwrap_or(json!([]));
    let rid = id(); st.db.exec("INSERT INTO roles(id,org_id,name,permissions) VALUES(?,?,?,?)", &[json!(rid), json!(oid), json!(name), json!(perms.to_string())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "name": name, "permissions": perms}))) }
async fn list_roles(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT id,name,permissions FROM roles WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?;
    let mut out: Vec<Value> = rows.iter().map(|r| json!({"id": db::s(r,"id"), "name": db::s(r,"name"), "permissions": serde_json::from_str::<Value>(&db::s(r,"permissions")).unwrap_or(json!([]))})).collect();
    for m in ["owner","admin","developer"] { out.push(json!({"name": m, "permissions": ["*"], "managed": true})); }
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
    let provided = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let secret_bytes: Vec<u8> = if provided.is_empty() { oc::random_key()[..20].to_vec() } else { let d = b32decode(provided); if d.len() < 10 { return Err(bad("provided TOTP secret must be base32, at least 10 bytes")); } d };
    let secret_b32 = b32encode(&secret_bytes);
    meta_set(&st, &format!("totp_secret:{}", uid), &oc::encrypt_symmetric(&st.master, &secret_bytes));
    meta_set(&st, &format!("totp_enabled:{}", uid), "0");
    let codes: Vec<String> = (0..8).map(|_| oc::random_token("rc")).collect();
    let hashed: Vec<String> = codes.iter().map(|c| oc::hash_token(c)).collect();
    meta_set(&st, &format!("totp_recovery:{}", uid), &hashed.join(","));
    let email = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).map(|r| r.map(|x| db::s(&x,"email")).unwrap_or_default()).unwrap_or_default(); let _ = &secret_bytes;
    Ok(j(json!({"secret": secret_b32, "otpauth_url": format!("otpauth://totp/OpenWarp:{}?secret={}&issuer=OpenWarp", email, secret_b32), "recovery_codes": codes, "note": "call POST /api/me/totp/verify {code} with a current TOTP code to enable"}))) }
async fn totp_verify(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let enc = meta_get(&st, &format!("totp_secret:{}", uid)); let secret = oc::decrypt_symmetric(&st.master, &enc).map_err(|_| bad("TOTP not set up"))?;
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or(""); let counter = (now() / 30) as u64;
    if ![counter.wrapping_sub(1), counter, counter + 1].iter().any(|c| totp_code(&secret, *c) == code) { return Err(err(StatusCode::UNAUTHORIZED, "invalid TOTP code")); }
    meta_set(&st, &format!("totp_enabled:{}", uid), "1"); Ok(j(json!({"enabled": true}))) }
async fn mfa_login(State(st): State<S>, Json(body): Json<Value>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let token = body.get("mfa_token").and_then(|v| v.as_str()).unwrap_or(""); let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let row = st.db.one("SELECT user_id,created_at FROM mfa_challenges WHERE token=?", &[json!(token)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid MFA challenge"))?;
    if db::n(&row,"created_at") + 300 < now() { return Err(err(StatusCode::UNAUTHORIZED, "MFA challenge expired")); }
    let uid = db::s(&row,"user_id");
    if !otp_ok(&st, &uid, code) { return Err(err(StatusCode::UNAUTHORIZED, "invalid MFA code")); }
    let _ = st.db.exec("DELETE FROM mfa_challenges WHERE token=?", &[json!(token)]);
    let session = make_session(&st, &uid)?; let mut hdr = HeaderMap::new(); hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap()); Ok((hdr, j(json!({"token": session, "user_id": uid})))) }


// ---------- log streams (T10) ----------
async fn create_stream(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    if st.require_org(&oid,&uid)? == "developer" { return Err(err(StatusCode::FORBIDDEN,"admin required")); }
    let sid = id(); st.db.exec("INSERT INTO log_streams(id,org_id,name,url,secret,created_at) VALUES(?,?,?,?,?,?)", &[json!(sid), json!(oid), json!(body.get("name").and_then(|v|v.as_str()).unwrap_or("stream")), json!(body.get("url").and_then(|v|v.as_str()).unwrap_or("")), json!(body.get("secret").and_then(|v|v.as_str()).unwrap_or("")), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": sid}))) }
async fn list_streams(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT id,org_id,name,url,created_at FROM log_streams WHERE org_id=?", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn list_deliveries(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_org(&oid,&uid)?;
    let rows = st.db.query("SELECT d.id,d.stream_id,d.event,d.status,d.attempts,d.created_at FROM log_deliveries d JOIN log_streams s ON s.id=d.stream_id WHERE s.org_id=? ORDER BY d.created_at DESC LIMIT 200", &[json!(oid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }

// ---------- lease renew + rotation schedules (T09) ----------
async fn renew_lease(State(st): State<S>, h: HeaderMap, Path(lid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id,revoked FROM leases WHERE id=?", &[json!(lid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"lease not found"))?;
    if db::n(&row,"revoked") == 1 { return Err(bad("lease revoked")); }
    st.require_env(&db::s(&row,"env_id"), &uid)?; let ttl = body.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
    st.db.exec("UPDATE leases SET expires_at=? WHERE id=?", &[json!(now()+ttl), json!(lid)]).map_err(|e| bad(&e))?; Ok(j(json!({"id": lid, "expires_at": now()+ttl}))) }
async fn create_rotation(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org, _) = st.require_env(&eid,&uid)?; st.check_perm(&org,&uid,"secrets:write")?;
    let key_name = body.get("key").and_then(|v| v.as_str()).unwrap_or(""); let interval = body.get("interval_secs").and_then(|v| v.as_i64()).unwrap_or(86400);
    if key_name.is_empty() || interval < 60 { return Err(bad("key and interval_secs (>=60) required")); }
    let rid = id(); st.db.exec("INSERT INTO rotation_schedules(id,env_id,key_name,interval_secs,next_run,created_at) VALUES(?,?,?,?,?,?)", &[json!(rid), json!(eid), json!(key_name.to_uppercase()), json!(interval), json!(now()+interval), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": rid, "next_run": now()+interval}))) }
async fn list_rotations(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let rows = st.db.query("SELECT * FROM rotation_schedules WHERE env_id=?", &[json!(eid)]).map_err(|e| bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn delete_rotation(State(st): State<S>, h: HeaderMap, Path(rid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM rotation_schedules WHERE id=?", &[json!(rid)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"schedule not found"))?;
    st.require_env(&db::s(&row,"env_id"),&uid)?; st.db.exec("DELETE FROM rotation_schedules WHERE id=?", &[json!(rid)]).map_err(|e| bad(&e))?; Ok(j(json!({"deleted": rid}))) }
fn process_rotations(st: &S) {
    let due = st.db.query("SELECT * FROM rotation_schedules WHERE enabled=1 AND next_run<=?", &[json!(now())]).unwrap_or_default();
    for r in &due { let eid = db::s(r,"env_id"); let key_name = db::s(r,"key_name");
        let mode = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).ok().flatten().map(|x| db::s(&x,"mode")).unwrap_or_default();
        if mode == "e2e" { let _ = st.db.exec("UPDATE rotation_schedules SET next_run=? WHERE id=?", &[json!(now()+db::n(r,"interval_secs")), json!(db::s(r,"id"))]); continue; }
        if let Ok(key) = st.env_key(&eid) { let s = SecretIn{ key: key_name.clone(), value: oc::random_token("rot"), path: "/".into(), comment: "scheduled rotation".into(), tags: "".into(), secret_type: "secret".into() };
            if upsert_secret(st, &eid, &key, "rotation-scheduler", &s).is_ok() { if let Ok((org, app)) = st.env_org_app(&eid) { st.audit(&org,&app,&eid,"rotation-scheduler","secret.rotate",&key_name); } } }
        let _ = st.db.exec("UPDATE rotation_schedules SET next_run=? WHERE id=?", &[json!(now()+db::n(r,"interval_secs")), json!(db::s(r,"id"))]); } }


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
fn authorize_params_ok(st: &S, q: &HashMap<String, String>) -> Result<(String, String, String), String> {
    let client_id = q.get("client_id").cloned().unwrap_or_default(); let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let client = st.db.one("SELECT redirect_uris FROM oauth_clients WHERE client_id=?", &[json!(client_id)]).ok().flatten().ok_or("unknown client_id")?;
    let uris: Vec<String> = serde_json::from_str(&db::s(&client, "redirect_uris")).unwrap_or_default();
    if !uris.iter().any(|u| u == &redirect) { return Err("redirect_uri does not exactly match a registered URI".into()); }
    if q.get("response_type").map(|s| s.as_str()) != Some("code") { return Err("response_type must be code".into()); }
    if q.get("code_challenge_method").map(|s| s.as_str()) != Some("S256") || q.get("code_challenge").map(|s| s.is_empty()).unwrap_or(true) { return Err("PKCE with S256 is required".into()); }
    Ok((client_id, redirect, q.get("scope").cloned().unwrap_or_else(|| "secrets:read".into()))) }
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
        if !rate_allowed(&key) { return (StatusCode::TOO_MANY_REQUESTS, "too many failed sign-in attempts; try again later").into_response(); }
        let row = match st.db.one("SELECT id,pass_hash,active FROM users WHERE email=?", &[json!(email.to_lowercase())]) { Ok(Some(r)) => r, _ => { rate_fail(&key); return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); } };
        if db::n(&row, "active") == 0 { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
        if !oc::verify_password(&password, &db::s(&row, "pass_hash")) { rate_fail(&key); return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(); }
        db::s(&row, "id") };
    if !st.db.one("SELECT active FROM users WHERE id=?", &[json!(uid)]).ok().flatten().map(|u| db::n(&u, "active") != 0).unwrap_or(true) { return (StatusCode::UNAUTHORIZED, "account deactivated").into_response(); }
    let otp_key = format!("otp:{}:{}", addr.ip(), uid);
    if !rate_allowed(&otp_key) { return (StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later").into_response(); }
    if !otp_ok(&st, &uid, form.get("otp").map(|s| s.as_str()).unwrap_or("")) {
        rate_fail(&otp_key);
        let page = format!("<html><body style=\"font-family:system-ui;background:#0b1020;color:#fff;padding:40px\"><h1>Two-factor required</h1><p>Enter the code from your authenticator app or a recovery code.</p><form method=post action=\"/oauth/authorize/decision\">{}<input name=otp placeholder=\"authenticator code\" autocomplete=one-time-code required><br><button name=approve value=1 style=\"padding:10px 20px;margin-top:8px\">Continue</button></form></body></html>", hidden_fields(&form));
        return (StatusCode::UNAUTHORIZED, html_csp(page)).into_response();
    }
    rate_clear(&otp_key);
    let state = form.get("state").cloned().unwrap_or_default();
    if form.get("approve").map(|s| s.as_str()) != Some("1") { return axum::response::Redirect::temporary(&format!("{}?error=access_denied&state={}", redirect, urlencode(&state))).into_response(); }
    let code = oc::random_token("code"); let resource = form.get("resource").cloned().unwrap_or_else(|| format!("{}/mcp", issuer(&st, &h)));
    if st.db.exec("INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?,?)", &[json!(oc::hash_token(&code)), json!(client_id), json!(uid), json!(redirect), json!(form.get("code_challenge").cloned().unwrap_or_default()), json!(scope), json!(resource), json!(now()+300)]).is_err() { return (StatusCode::INTERNAL_SERVER_ERROR, "could not create code").into_response(); }
    axum::response::Redirect::temporary(&format!("{}?code={}&state={}", redirect, code, urlencode(&state))).into_response() }
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
    if let Some(origin) = h.get("origin").and_then(|v| v.to_str().ok()) { let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !origin.contains(host) { return Err((StatusCode::FORBIDDEN, hdr, Json(json!({"error":"Origin does not match Host"})))); } }
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
fn env_scope_of(st: &S, h: &HeaderMap) -> String { st.db.one("SELECT env_id FROM tokens WHERE token_hash=?", &[json!(oc::hash_token(&bearer_token(h)))]).ok().flatten().map(|r| db::s(&r, "env_id")).unwrap_or_default() }
fn mcp_resources(st: &S, uid: &str, h: &HeaderMap) -> Result<Value, String> {
    let scoped = env_scope_of(st, h);
    let rows = st.db.query("SELECT e.id AS id, e.name AS name, a.name AS app FROM envs e JOIN apps a ON a.id=e.app_id JOIN org_members m ON m.org_id=a.org_id WHERE m.user_id=?", &[json!(uid)])?;
    Ok(json!({"resources": rows.iter().filter(|r| scoped.is_empty() || db::s(r,"id") == scoped).map(|r| json!({"uri": format!("openwarp://env/{}", db::s(r,"id")), "name": format!("{} / {}", db::s(r,"app"), db::s(r,"name")), "mimeType": "application/json"})).collect::<Vec<_>>()})) }
fn mcp_resource_read(st: &S, uid: &str, h: &HeaderMap, params: &Value) -> Result<Value, String> {
    let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or(""); let eid = uri.strip_prefix("openwarp://env/").ok_or("bad resource uri")?;
    st.check_scope(h, eid).map_err(|_| "forbidden".to_string())?;
    st.require_env(eid, uid).map_err(|_| "forbidden".to_string())?;
    let items = st.list_secrets_decrypted(eid, uid).map_err(|_| "read failed".to_string())?;
    let text = serde_json::to_string(&items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()).unwrap();
    Ok(json!({"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]})) }
async fn mcp_call(st: &S, uid: &str, h: &HeaderMap, params: &Value) -> Result<Value, String> {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or(""); let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let arg = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let text = |v: Value| json!({"content": [{"type":"text","text": v.to_string()}], "isError": false});
    let env_audit = |st: &S, eid: &str, action: &str, detail: &str| { if let Ok((org, app)) = st.env_org_app(eid) { st.audit(&org, &app, eid, uid, action, detail); } };
    let env_check = |eid: &str| -> Result<(), String> { st.check_scope(h, eid).map_err(|_| "forbidden".to_string())?; st.require_env(eid, uid).map_err(|_| "forbidden".to_string())?; Ok(()) };
    match name {
        "list_envs" => { let r = mcp_resources(st, uid, h)?; Ok(text(r)) }
        "list_secrets" => { let eid = arg("env_id"); env_check(&eid)?; let items = st.list_secrets_decrypted(&eid, uid).map_err(|_| "read failed".to_string())?; env_audit(st, &eid, "mcp.list_secrets", &format!("{}", items.len())); Ok(text(json!(items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()))) }
        "get_secret" => { let eid = arg("env_id"); let key = arg("key"); env_check(&eid)?; let items = st.list_secrets_decrypted(&eid, uid).map_err(|_| "read failed".to_string())?;
            let found = items.iter().find(|(k, _, _)| k == &key.to_uppercase()).map(|(_, v, _)| v.clone()).ok_or("secret not found")?; env_audit(st, &eid, "mcp.get_secret", &key); Ok(text(json!(found))) }
        "search_secrets" => { let q = arg("query").to_uppercase(); let res = mcp_resources(st, uid, h)?; let mut hits = Vec::new();
            for r in res["resources"].as_array().cloned().unwrap_or_default() { let eid = r["uri"].as_str().unwrap_or("").replace("openwarp://env/", ""); if let Ok(items) = st.list_secrets_decrypted(&eid, uid) { for (k, _, _) in items { if q.is_empty() || k.contains(&q) { hits.push(json!({"env_id": eid, "key": k})); } } } }
            Ok(text(json!(hits))) }
        "set_secret" => { let eid = arg("env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:write").map_err(|_| "forbidden".to_string())?;
            let key = st.env_key(&eid).map_err(|_| "env key failed".to_string())?; let s = SecretIn{ key: arg("key"), value: arg("value"), path: { let p = arg("path"); if p.is_empty() { "/".into() } else { p } }, comment: "via MCP".into(), tags: "".into(), secret_type: "secret".into() };
            upsert_secret(st, &eid, &key, uid, &s).map_err(|_| "write failed".to_string())?; env_audit(st, &eid, "mcp.set_secret", &s.key); Ok(text(json!({"ok": true}))) }
        "delete_secret" => { let eid = arg("env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:delete").map_err(|_| "forbidden".to_string())?;
            let items = st.list_secrets_decrypted(&eid, uid).map_err(|_| "read failed".to_string())?; let sid = items.iter().find(|(k, _, _)| k == &arg("key").to_uppercase()).map(|(_, _, raw)| raw["id"].as_str().unwrap_or("").to_string()).ok_or("secret not found")?;
            st.db.exec("UPDATE secrets SET deleted=1,updated_at=? WHERE id=?", &[json!(now()), json!(sid)])?; env_audit(st, &eid, "mcp.delete_secret", &arg("key")); Ok(text(json!({"ok": true}))) }
        "create_lease" => { let eid = arg("env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:write").map_err(|_| "forbidden".to_string())?; let key = st.env_key(&eid).map_err(|_| "env key failed".to_string())?;
            let value = oc::random_token("dyn"); let lid = id(); st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(arg("name")), json!(oc::encrypt_symmetric(&key, value.as_bytes())), json!(now()+3600), json!(now())])?;
            env_audit(st, &eid, "mcp.create_lease", &lid); Ok(text(json!({"id": lid, "value": value, "expires_at": now()+3600}))) }
        "sync_integration" => { let iid = arg("integration_id"); let row = st.db.one("SELECT env_id FROM integrations WHERE id=?", &[json!(iid)]).map_err(|_| "lookup failed".to_string())?.ok_or("integration not found")?; let eid = db::s(&row, "env_id"); env_check(&eid)?; let (org, _) = st.env_org_app(&eid).map_err(|_| "forbidden".to_string())?; st.check_perm(&org, uid, "secrets:write").map_err(|_| "forbidden".to_string())?;
            let msg = sync_one(st, &iid, uid).await.map_err(|_| "sync failed".to_string())?; Ok(text(json!(msg))) }
        _ => Err(format!("unknown tool: {}", name)),
    } }

async fn health() -> impl IntoResponse { Json(json!({"ok": true, "service": "openwarp"})) }

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://openwarp.db".into());
    let db = Db::open(&db_url).expect("open database (sqlite://file.db or postgres://...)");
    let master = load_master(&db).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    #[cfg(feature = "redis-cache")]
    let redis_conn = std::env::var("REDIS_URL").ok().and_then(|u| redis::Client::open(u).ok()).and_then(|c| c.get_connection().ok());
    let pub_url = std::env::var("OPENWARP_PUBLIC_URL").unwrap_or_default();
    let state = Arc::new(AppState { db, db_url: db_url.clone(), pub_url, master, #[cfg(feature = "redis-cache")] redis: std::sync::Mutex::new(redis_conn) });
    { let st2 = state.clone(); tokio::spawn(async move { loop { tokio::time::sleep(std::time::Duration::from_secs(30)).await; process_rotations(&st2); } }); }
    let app = Router::new()
        .route("/", get(|| async { Html(ui::INDEX) })).route("/e2e.js", get(|| async { ([(axum::http::header::CONTENT_TYPE, "application/javascript")], include_str!("e2e.js")) }))
        .route("/health", get(health)).route("/.well-known/oauth-protected-resource", get(prm)).route("/.well-known/oauth-authorization-server", get(asm)).route("/oauth/register", post(oauth_register)).route("/oauth/authorize", get(oauth_authorize)).route("/oauth/authorize/decision", post(oauth_decision)).route("/oauth/token", post(oauth_token)).route("/oauth/revoke", post(oauth_revoke)).route("/mcp", post(mcp_post).get(mcp_get).delete(mcp_get))
        .route("/api/auth/register", post(register)).route("/api/auth/login", post(login)).route("/api/auth/logout", post(logout)).route("/api/me", get(me))
        .route("/api/orgs", get(list_orgs).post(create_org))
        .route("/api/orgs/{oid}/members", get(list_members).post(invite_member)).route("/api/orgs/{oid}/members/{uid}", delete(remove_member)).route("/api/orgs/{oid}/apps", get(list_apps).post(create_app))
        .route("/api/orgs/{oid}/audit", get(audit_list)).route("/api/orgs/{oid}/roles", get(list_roles).post(create_role)).route("/api/orgs/{oid}/log-streams", get(list_streams).post(create_stream)).route("/api/orgs/{oid}/log-streams/deliveries", get(list_deliveries)).route("/api/orgs/{oid}/settings", put(org_settings)).route("/api/orgs/{oid}/teams", get(list_teams).post(create_team))
        .route("/api/apps/{aid}", axum::routing::patch(update_app).delete(delete_app)).route("/api/apps/{aid}/envs", get(list_envs).post(create_env)).route("/api/apps/{aid}/envs/e2e", post(create_e2e_env)).route("/api/apps/{aid}/tokens", get(list_tokens).post(create_token)).route("/api/tokens/{tid}", delete(revoke_token)).route("/api/orgs/{oid}/identities", get(list_identities).post(create_identity)).route("/api/v1/machine/auth/universal/login", post(universal_login))
        .route("/api/envs/{eid}", delete(delete_env).patch(update_env))
        .route("/api/envs/{eid}/secrets", get(list_secrets).put(deploy_secrets)).route("/api/envs/{eid}/e2e/secrets", get(e2e_get).put(e2e_put)).route("/api/envs/{eid}/e2e/grant", post(e2e_grant)).route("/api/users/lookup", get(user_lookup))
        .route("/api/envs/{eid}/export", get(export_env)).route("/api/envs/{eid}/import", post(deploy_secrets))
        .route("/api/envs/{eid}/integrations", get(list_integrations).post(create_integration))
        .route("/api/envs/{eid}/dynamic", get(list_leases).post(create_lease_v2)).route("/api/leases/{lid}", delete(revoke_lease)).route("/api/leases/{lid}/renew", post(renew_lease)).route("/api/envs/{eid}/rotations", get(list_rotations).post(create_rotation)).route("/api/rotations/{rid}", delete(delete_rotation)).route("/api/envs/{eid}/rotate", post(rotate_secret)).route("/api/envs/{eid}/restore-point", post(pitr))
        .route("/api/integrations/{iid}/sync", post(sync_integration)).route("/api/integrations/{iid}/test", post(test_integration))
        .route("/api/secrets/{sid}", delete(delete_secret)).route("/api/secrets/{sid}/history", get(history))
        .route("/api/secrets/{sid}/restore/{ver}", post(restore)).route("/api/secrets/{sid}/override", post(set_override))
        .route("/api/search", get(search)).route("/api/me/totp/setup", post(totp_setup)).route("/api/me/totp/verify", post(totp_verify)).route("/api/auth/mfa", post(mfa_login)).route("/api/envs/{eid}/proposals", get(list_proposals).post(create_proposal)).route("/api/proposals/{pid}/{action}", post(decide_proposal)).route("/api/envs/{eid}/access-requests", get(list_access_requests).post(request_access)).route("/api/access-requests/{rid}/{action}", post(decide_access)).route("/api/orgs/{oid}/pki/cas", post(create_ca)).route("/api/pki/cas/{caid}/issue", post(issue_cert)).route("/api/pki/cas/{caid}/certs", get(list_certs)).route("/api/pki/certs/{cid}/revoke", post(revoke_cert)).route("/scim/v2/Users", get(scim_list_users).post(scim_create_user)).route("/scim/v2/Users/{uid}", put(scim_put_user).patch(scim_patch_user).delete(scim_delete_user))
        .route("/scim/v2/Groups", get(scim_list_groups).post(scim_create_group)).route("/scim/v2/Groups/{tid}", get(scim_get_group).put(scim_put_group).patch(scim_patch_group).delete(scim_delete_group))
        .route("/api/auth/oidc/{oid}/start", get(oidc_start)).route("/api/auth/oidc/callback", get(oidc_callback)).route("/api/lockbox", post(create_lockbox)).route("/api/lockbox/{lid}", get(open_lockbox))
        .layer(axum::middleware::from_fn_with_state(state.clone(), oauth_scope_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_middleware))
        .with_state(state);
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    println!("openwarp listening on {} db={}", addr, db_url);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
fn load_master(db: &Db) -> Result<[u8;32], String> {
    if let Ok(v) = std::env::var("OPENWARP_MASTER_KEY") { if let Ok(b) = oc::unb64(&v) { if let Ok(k) = b.try_into() { return Ok(k); } } }
    if std::env::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) {
        return Err("OPENWARP_MASTER_KEY is required in production. If this database already has a generated key in the meta table, copy it into OPENWARP_MASTER_KEY, or start once with OPENWARP_ENV unset and set the key before going live.".into());
    }
    if let Ok(Some(r)) = db.one("SELECT v FROM meta WHERE k='master'", &[]) { if let Ok(b) = oc::unb64(&db::s(&r,"v")) { if let Ok(k) = b.try_into() { return Ok(k); } } }
    let k = oc::random_key(); let _ = db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&k))]);
    eprintln!("warning: OPENWARP_MASTER_KEY is not set; a generated key was stored in the database. Set OPENWARP_MASTER_KEY before production use.");
    Ok(k)
}

