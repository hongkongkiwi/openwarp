mod db; mod integrations; mod ui;
use axum::{extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, response::{Html, IntoResponse}, routing::{delete, get, post, put}, Json, Router};
use db::{Db, Row};
use openwarp_crypto as oc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

pub struct AppState {
    db: Db,
    master: [u8; 32],
    #[cfg(feature = "redis-cache")] redis: std::sync::Mutex<Option<redis::Connection>>,
}
type S = Arc<AppState>;
type Res = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) { (code, Json(json!({"error": msg}))) }
fn bad(msg: &str) -> (StatusCode, Json<Value>) { err(StatusCode::BAD_REQUEST, msg) }
fn now() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 }
fn id() -> String { oc::random_token("id").replace("id_", "") }
fn j(v: impl Into<Value>) -> Json<Value> { Json(v.into()) }

#[derive(Deserialize, Default)] struct AuthReq { email: String, password: String }
#[derive(Deserialize, Default)] struct NameReq { name: String, #[serde(default)] email: String, #[serde(default)] role: String, #[serde(default)] readme: String }
#[derive(Deserialize, Default, Clone)] struct SecretIn { key: String, value: String, #[serde(default = "def_path")] path: String, #[serde(default)] comment: String, #[serde(default)] tags: String, #[serde(default, rename = "type")] secret_type: String }
fn def_path() -> String { "/".into() }
#[derive(Deserialize, Default)] struct DeployReq { #[serde(default)] secrets: Vec<SecretIn>, #[serde(default)] text: String }

impl AppState {
    fn audit(&self, org: &str, app: &str, env: &str, actor: &str, action: &str, detail: &str) {
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
        // service / personal access tokens
        if let Some(row) = self.db.one("SELECT created_by FROM tokens WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))? {
            let uid = db::s(&row, "created_by"); if !uid.is_empty() { return Ok(uid); }
        }
        let row = self.db.one("SELECT user_id FROM sessions WHERE token_hash=?", &[json!(hash)]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
        let uid = db::s(&row, "user_id");
        #[cfg(feature = "redis-cache")] self.redis_set(&format!("sess:{}", hash), &uid);
        Ok(uid)
    }
    #[cfg(feature = "redis-cache")]
    fn redis_get(&self, k: &str) -> Option<String> { let mut g = self.redis.lock().unwrap(); let c = g.as_mut()?; redis::Commands::get(c, k).ok() }
    #[cfg(feature = "redis-cache")]
    fn redis_set(&self, k: &str, v: &str) { let mut g = self.redis.lock().unwrap(); if let Some(c) = g.as_mut() { let _: Result<(), _> = redis::Commands::set_ex(c, k, v, 3600u64); } }

    fn org_role(&self, org: &str, user: &str) -> Option<String> {
        self.db.one("SELECT role FROM org_members WHERE org_id=? AND user_id=?", &[json!(org), json!(user)]).ok().flatten().map(|r| db::s(&r, "role"))
    }
    fn require_org(&self, org: &str, user: &str) -> Result<String, (StatusCode, Json<Value>)> { self.org_role(org, user).ok_or_else(|| err(StatusCode::FORBIDDEN, "not an organisation member")) }
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
        for item in out.iter_mut() { for _ in 0..5 { let before = item.1.clone(); item.1 = resolve_refs(&item.1, &map, &by_key); if item.1 == before { break; } } item.2["value"] = json!(item.1); }
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
async fn register(State(st): State<S>, Json(r): Json<AuthReq>) -> Res {
    if r.email.is_empty() || r.password.len() < 8 { return Err(bad("email and password (>=8 chars) required")); }
    let kp = oc::Keypair::generate();
    let wrapped = oc::wrap_with_password(&r.password, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?;
    let uid = id(); let hash = oc::hash_password(&r.password).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(uid), json!(r.email.to_lowercase()), json!(hash), json!(kp.public), json!(wrapped), json!(now())]).map_err(|e| bad(&format!("register failed: {}", e)))?;
    let oid = id(); st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(oid), json!(format!("{}'s organisation", r.email)), json!(now())]).map_err(|e| bad(&e))?;
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", &[json!(oid), json!(uid)]).map_err(|e| bad(&e))?;
    let token = make_session(&st, &uid)?;
    Ok(j(json!({"token": token, "user_id": uid, "org_id": oid, "public_key": kp.public, "recovery_kit": kp.secret_b64()})))
}
fn make_session(st: &S, uid: &str) -> Result<String, (StatusCode, Json<Value>)> { let t = oc::random_token("ow"); st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&t)), json!(uid), json!(now())]).map_err(|e| bad(&e))?; Ok(t) }
async fn login(State(st): State<S>, Json(r): Json<AuthReq>) -> Res {
    let row = st.db.one("SELECT * FROM users WHERE email=?", &[json!(r.email.trim().to_lowercase())]).map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    if !oc::verify_password(&r.password, &db::s(&row, "pass_hash")) { return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials")); }
    let uid = db::s(&row, "id"); let token = make_session(&st, &uid)?;
    Ok(j(json!({"token": token, "user_id": uid, "public_key": db::s(&row, "pubkey")})))
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
    let new_role = if r.role.is_empty() { "developer".to_string() } else { r.role.clone() };
    st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(oid), json!(db::s(&target,"id")), json!(new_role)]).map_err(|e| bad(&e))?;
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

async fn list_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
    let items = st.list_secrets_decrypted(&eid, &uid)?; st.audit(&org, &app, &eid, &uid, "secret.list", &format!("{}", items.len()));
    Ok(j(json!({"secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
async fn deploy_secrets(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<DeployReq>) -> Res { let uid = st.token_user(&h)?; let (org, app) = st.require_env(&eid, &uid)?;
    let mut inputs = r.secrets.clone(); if inputs.is_empty() && !r.text.is_empty() { inputs = parse_env(&r.text); }
    let key = st.env_key(&eid)?; let mut count = 0;
    for s in &inputs { if s.key.trim().is_empty() { continue; } upsert_secret(&st, &eid, &key, &uid, s)?; count += 1; }
    st.audit(&org, &app, &eid, &uid, "secret.deploy", &format!("{} secrets", count));
    trigger_sync(&st, &eid, &uid).await; Ok(j(json!({"deployed": count}))) }
fn upsert_secret(st: &S, eid: &str, key: &[u8;32], uid: &str, s: &SecretIn) -> Result<(), (StatusCode, Json<Value>)> {
    let kname = s.key.trim().to_uppercase(); let khash = oc::hash_token(&format!("{}:{}", s.path, kname));
    let existing = st.db.one("SELECT id,version FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(khash)]).map_err(|e| bad(&e))?;
    let stype = if s.secret_type.is_empty() { "secret".to_string() } else { s.secret_type.clone() };
    if let Some(row) = existing { let sid = db::s(&row, "id"); let ver = db::n(&row, "version") + 1;
        st.db.exec("UPDATE secrets SET value_enc=?,comment_enc=?,tags=?,secret_type=?,version=?,updated_at=?,updated_by=? WHERE id=?", &[json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(s.tags), json!(stype), json!(ver), json!(now()), json!(uid), json!(sid)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(ver), json!(oc::encrypt_symmetric(key, kname.as_bytes())), json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    } else { let sid = id();
        st.db.exec("INSERT INTO secrets(id,env_id,path,key_enc,key_hash,value_enc,comment_enc,tags,secret_type,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)", &[json!(sid), json!(eid), json!(s.path), json!(oc::encrypt_symmetric(key, kname.as_bytes())), json!(khash), json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(s.tags), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
        st.db.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,created_at,created_by) VALUES(?,?,1,?,?,?,?,?,?)", &[json!(id()), json!(sid), json!(oc::encrypt_symmetric(key, kname.as_bytes())), json!(oc::encrypt_symmetric(key, s.value.as_bytes())), json!(oc::encrypt_symmetric(key, s.comment.as_bytes())), json!(stype), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
    } Ok(()) }
fn parse_env(text: &str) -> Vec<SecretIn> { let mut out = Vec::new(); let mut pending_comment = String::new();
    for line in text.lines() { let l = line.trim(); if l.is_empty() { continue; } if l.starts_with('#') { pending_comment = l.trim_start_matches('#').trim().to_string(); continue; }
        if let Some((k, v)) = l.trim_start_matches("export ").split_once('=') { out.push(SecretIn{ key: k.trim().to_string(), value: v.trim().trim_matches('"').trim_matches('\'').to_string(), path: "/".into(), comment: pending_comment.clone(), tags: "".into(), secret_type: "".into() }); pending_comment.clear(); } } out }
async fn delete_secret(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?;
    let eid = db::s(&row, "env_id"); let (org, app) = st.require_env(&eid, &uid)?;
    st.db.exec("UPDATE secrets SET deleted=1,updated_at=? WHERE id=?", &[json!(now()), json!(sid)]).map_err(|e| bad(&e))?; st.audit(&org, &app, &eid, &uid, "secret.delete", &sid); Ok(j(json!({"ok": true}))) }
async fn history(State(st): State<S>, h: HeaderMap, Path(sid): Path<String>) -> Res { let uid = st.token_user(&h)?;
    let row = st.db.one("SELECT env_id FROM secrets WHERE id=?", &[json!(sid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?; let eid = db::s(&row, "env_id"); st.require_env(&eid, &uid)?;
    let key = st.env_key(&eid)?; let rows = st.db.query("SELECT * FROM secret_versions WHERE secret_id=? ORDER BY version DESC", &[json!(sid)]).map_err(|e| bad(&e))?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"version": db::n(r,"version"), "value": oc::decrypt_symmetric(&key,&db::s(r,"value_enc")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(), "created_at": db::n(r,"created_at"), "created_by": db::s(r,"created_by")})).collect();
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

async fn export_env(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let items = st.list_secrets_decrypted(&eid,&uid)?; let text = items.iter().map(|(k,v,_)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n"); Ok(j(json!({"text": text, "secrets": items.iter().map(|x| x.2.clone()).collect::<Vec<_>>()}))) }
async fn search(State(st): State<S>, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res { let uid = st.token_user(&h)?; let needle = q.get("q").cloned().unwrap_or_default().to_uppercase();
    let orgs = st.db.query("SELECT org_id FROM org_members WHERE user_id=?", &[json!(uid)]).map_err(|e| bad(&e))?;
    let mut results = Vec::new();
    for o in &orgs { let apps = st.db.query("SELECT id,name FROM apps WHERE org_id=?", &[json!(db::s(o,"org_id"))]).map_err(|e| bad(&e))?;
        for a in &apps { let envs = st.db.query("SELECT id,name FROM envs WHERE app_id=?", &[json!(db::s(a,"id"))]).map_err(|e| bad(&e))?;
            for e in &envs { if let Ok(items) = st.list_secrets_decrypted(&db::s(e,"id"), &uid) { for (k,_,raw) in items { if needle.is_empty() || k.contains(&needle) { results.push(json!({"app": db::s(a,"name"), "env": db::s(e,"name"), "key": k, "path": raw["path"]})); } } } } } }
    Ok(j(json!({"results": results}))) }
async fn create_token(State(st): State<S>, h: HeaderMap, Path(aid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?;
    let app = st.db.one("SELECT org_id FROM apps WHERE id=?", &[json!(aid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("app not found"))?; st.require_org(&db::s(&app,"org_id"),&uid)?;
    let token = oc::random_token("owp"); let tid = id();
    st.db.exec("INSERT INTO tokens(id,org_id,app_id,name,token_hash,created_at,created_by) VALUES(?,?,?,?,?,?,?)", &[json!(tid), json!(db::s(&app,"org_id")), json!(aid), json!(if r.name.is_empty(){"token".into()}else{r.name.clone()}), json!(oc::hash_token(&token)), json!(now()), json!(uid)]).map_err(|e| bad(&e))?;
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
async fn create_lease(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(r): Json<NameReq>) -> Res { let uid = st.token_user(&h)?; st.require_env(&eid,&uid)?;
    let key = st.env_key(&eid)?; let value = oc::random_token("dyn"); let lid = id();
    st.db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(lid), json!(eid), json!(if r.name.is_empty(){"lease".into()}else{r.name}), json!(oc::encrypt_symmetric(&key, value.as_bytes())), json!(now()+3600), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"id": lid, "value": value, "expires_at": now()+3600}))) }
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
    let msg = integrations::sync(&db::s(&row, "kind"), &config, &pairs).await.map_err(|e| bad(&e))?;
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
    if let Some(v)=body.get("oidc_issuer").and_then(|x|x.as_str()) { let _ = st.db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(format!("oidc_issuer:{}",oid)), json!(v)]); }
    Ok(j(json!({"ok":true}))) }
async fn rotate_secret(State(st): State<S>, h: HeaderMap, Path(eid): Path<String>, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let (org,app)=st.require_env(&eid,&uid)?;
    let key_name = body.get("key").and_then(|v|v.as_str()).unwrap_or(""); let new_val = body.get("value").and_then(|v|v.as_str()).map(|s|s.to_string()).unwrap_or_else(|| oc::random_token("rot"));
    let key = st.env_key(&eid)?; let khash = oc::hash_token(&format!("/:{}", key_name.to_uppercase()));
    let row = st.db.one("SELECT id FROM secrets WHERE env_id=? AND key_hash=? AND deleted=0", &[json!(eid), json!(khash)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found; create it first"))?;
    upsert_secret(&st,&eid,&key,&uid,&SecretIn{key:key_name.into(),value:new_val.clone(),path:"/".into(),comment:"auto-rotation".into(),tags:"".into(),secret_type:"secret".into()})?;
    st.audit(&org,&app,&eid,&uid,"secret.rotate",key_name); Ok(j(json!({"key":key_name,"value":new_val,"secret_id":db::s(&row,"id")}))) }
async fn scim_create_user(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res { let uid = st.token_user(&h)?; let _=uid;
    let email = body.get("userName").and_then(|v|v.as_str()).unwrap_or(""); if email.is_empty() { return Err(bad("userName required")); }
    let kp = oc::Keypair::generate(); let pw = oc::random_token("scim"); let nid = id();
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)", &[json!(nid), json!(email.to_lowercase()), json!(oc::hash_password(&pw).map_err(|e| bad(&e))?), json!(kp.public), json!(oc::wrap_with_password(&pw, kp.secret_b64().as_bytes()).map_err(|e| bad(&e))?), json!(now())]).map_err(|_| bad("user exists"))?;
    Ok(j(json!({"id":nid,"userName":email,"active":true,"temp_password":pw}))) }
async fn scim_list_users(State(st): State<S>, h: HeaderMap) -> Res { let uid = st.token_user(&h)?; let _=uid;
    let rows = st.db.query("SELECT id,email FROM users ORDER BY created_at", &[]).map_err(|e| bad(&e))?;
    Ok(j(json!({"Resources": rows.iter().map(|r| json!({"id":db::s(r,"id"),"userName":db::s(r,"email"),"active":true})).collect::<Vec<_>>(), "totalResults": rows.len()}))) }

async fn health() -> impl IntoResponse { Json(json!({"ok": true, "service": "openwarp"})) }

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://openwarp.db".into());
    let db = Db::open(&db_url).expect("open database (sqlite://file.db or postgres://...)");
    let master = load_master(&db);
    #[cfg(feature = "redis-cache")]
    let redis_conn = std::env::var("REDIS_URL").ok().and_then(|u| redis::Client::open(u).ok()).and_then(|c| c.get_connection().ok());
    let state = Arc::new(AppState { db, master, #[cfg(feature = "redis-cache")] redis: std::sync::Mutex::new(redis_conn) });
    let app = Router::new()
        .route("/", get(|| async { Html(ui::INDEX) }))
        .route("/health", get(health))
        .route("/api/auth/register", post(register)).route("/api/auth/login", post(login)).route("/api/me", get(me))
        .route("/api/orgs", get(list_orgs).post(create_org))
        .route("/api/orgs/{oid}/members", post(invite_member)).route("/api/orgs/{oid}/apps", get(list_apps).post(create_app))
        .route("/api/orgs/{oid}/audit", get(audit_list)).route("/api/orgs/{oid}/settings", put(org_settings)).route("/api/orgs/{oid}/teams", get(list_teams).post(create_team))
        .route("/api/apps/{aid}/envs", get(list_envs).post(create_env)).route("/api/apps/{aid}/tokens", post(create_token))
        .route("/api/envs/{eid}", delete(delete_env))
        .route("/api/envs/{eid}/secrets", get(list_secrets).put(deploy_secrets))
        .route("/api/envs/{eid}/export", get(export_env)).route("/api/envs/{eid}/import", post(deploy_secrets))
        .route("/api/envs/{eid}/integrations", get(list_integrations).post(create_integration))
        .route("/api/envs/{eid}/dynamic", get(list_leases).post(create_lease)).route("/api/envs/{eid}/rotate", post(rotate_secret)).route("/api/envs/{eid}/restore-point", post(pitr))
        .route("/api/integrations/{iid}/sync", post(sync_integration))
        .route("/api/secrets/{sid}", delete(delete_secret)).route("/api/secrets/{sid}/history", get(history))
        .route("/api/secrets/{sid}/restore/{ver}", post(restore)).route("/api/secrets/{sid}/override", post(set_override))
        .route("/api/search", get(search)).route("/scim/v2/Users", get(scim_list_users).post(scim_create_user)).route("/api/lockbox", post(create_lockbox)).route("/api/lockbox/{lid}", get(open_lockbox))
        .with_state(state);
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    println!("openwarp listening on {} db={}", addr, db_url);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
fn load_master(db: &Db) -> [u8;32] {
    if let Ok(v) = std::env::var("OPENWARP_MASTER_KEY") { if let Ok(b) = oc::unb64(&v) { if let Ok(k) = b.try_into() { return k; } } }
    if let Ok(Some(r)) = db.one("SELECT v FROM meta WHERE k='master'", &[]) { if let Ok(b) = oc::unb64(&db::s(&r,"v")) { if let Ok(k) = b.try_into() { return k; } } }
    let k = oc::random_key(); let _ = db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&k))]); k
}

