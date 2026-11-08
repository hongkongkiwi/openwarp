use super::*;

#[cfg(not(target_arch = "wasm32"))]
pub(super) type Lifecycle = tokio::sync::RwLock<()>;
#[cfg(target_arch = "wasm32")]
#[derive(Default)]
pub(super) struct Lifecycle;
#[cfg(target_arch = "wasm32")]
impl Lifecycle { pub async fn read(&self) {} }
const ROOT: &str = "transit:root-generation";
type Statement = (String, Vec<Value>, Option<u64>);
fn conflict() -> (StatusCode, Json<Value>) { err(StatusCode::CONFLICT, "transit key lifecycle changed; retry with the current master key") }
fn tx_error(e: String) -> (StatusCode, Json<Value>) { if e.contains("unavailable on Workers") { err(StatusCode::NOT_IMPLEMENTED, "atomic transit mutation unavailable on Workers") } else { conflict() } }
fn fingerprint(key: &[u8;32]) -> String { hmac_hex(key, b"openwarp:transit:root:v1") }
fn generation(key: &[u8;32]) -> String { format!("{}:{}", fingerprint(key), id()) }
fn wrap_aad(org: &str, kid: &str, version: i64) -> Vec<u8> { json!(["openwarp:transit:wrap:v1",org,kid,version]).to_string().into_bytes() }
fn content_aad(org: &str, kid: &str, version: i64, context: &str) -> Vec<u8> { json!(["openwarp:transit:content:v1",org,kid,version,context]).to_string().into_bytes() }
pub(super) async fn root(st: &S, master: &[u8;32]) -> Result<String, (StatusCode, Json<Value>)> {
    let sql = "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO NOTHING";
    #[cfg(not(target_arch = "wasm32"))]
    let sql = if st.db.backend()==db::Backend::Mysql { "INSERT INTO meta(k,v) VALUES(?,?) ON DUPLICATE KEY UPDATE k=k" } else { sql };
    st.db.exec(sql, &[json!(ROOT),json!(generation(master))]).await.map_err(|e| bad(&e))?;
    let r = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(ROOT)]).await.map_err(|e| bad(&e))?.ok_or_else(conflict)?;
    let value = db::s(&r,"v");
    if value.split(':').next() != Some(fingerprint(master).as_str()) { return Err(conflict()); }
    Ok(value)
}
pub(super) fn fence(expected: &str, master: &[u8;32]) -> Statement {
    ("UPDATE meta SET v=? WHERE k=? AND v=?".into(),vec![json!(generation(master)),json!(ROOT),json!(expected)],Some(1))
}
#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn rotation(st: &S, old: &[u8;32], new: &[u8;32], expected: &str) -> Result<Vec<Statement>, (StatusCode, Json<Value>)> {
    let rows = st.db.query("SELECT key_id,org_id,version,key_enc FROM transit_versions", &[]).await.map_err(|e| bad(&e))?;
    let mut statements = vec![fence(expected,new)];
    for r in rows {
        let org = db::s(&r,"org_id"); let kid = db::s(&r,"key_id"); let version = db::n(&r,"version"); let wrapped = db::s(&r,"key_enc");
        let aad = wrap_aad(&org,&kid,version);
        let raw = oc::decrypt_symmetric_aad(old,&aad,&wrapped).map_err(|_| bad("transit key cannot be unwrapped; refusing master rotation"))?;
        if raw.len()!=32 { return Err(bad("invalid transit key; refusing master rotation")); }
        statements.push(("UPDATE transit_versions SET key_enc=? WHERE key_id=? AND org_id=? AND version=? AND key_enc=?".into(),vec![json!(oc::encrypt_symmetric_aad(new,&aad,&raw)),json!(kid),json!(org),json!(version),json!(wrapped)],Some(1)));
    }
    Ok(statements)
}
async fn authorize(st: &S, h: &HeaderMap, org: &str, action: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let uid = st.token_user(h).await?;
    if !env_scope_of(st,h).await.is_empty() { return Err(err(StatusCode::FORBIDDEN,"environment credentials cannot use transit")); }
    credential_scope(st,h,org,action).await?;
    st.check_perm(org,&uid,action).await?;
    if action=="transit:manage" { st.check_admin(org,&uid).await?; }
    Ok(uid)
}
pub(super) async fn scope(st: &S, h: &HeaderMap, path: &str, method: &str) -> Result<bool, (StatusCode, Json<Value>)> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.len()<6 || parts[1]!="api" || parts[2]!="orgs" || parts[4]!="transit" || parts[5]!="keys" { return Ok(false); }
    let action = match (method,parts.get(7).copied()) { ("POST",Some("encrypt"))=>"transit:encrypt", ("POST",Some("decrypt"))=>"transit:decrypt", ("POST",Some("rewrap"))=>"transit:rewrap", _=>"transit:manage" };
    credential_scope(st,h,parts[3],action).await?;
    Ok(true)
}
async fn credential_scope(st: &S, h: &HeaderMap, org: &str, action: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let token = bearer_token(h); if token.is_empty() { return Ok(()); }
    let hash = oc::hash_token(&token);
    if let Some(r) = st.db.one("SELECT scope FROM oauth_tokens WHERE token_hash=?", &[json!(hash)]).await.map_err(|e| bad(&e))? {
        if !db::s(&r,"scope").split_whitespace().any(|s| s==action) { return Err(err(StatusCode::FORBIDDEN,"OAuth token lacks explicit transit scope")); }
    } else if let Some(r) = st.db.one("SELECT env_id,org_id,scopes FROM tokens WHERE token_hash=?", &[json!(hash)]).await.map_err(|e| bad(&e))? {
        if !db::s(&r,"env_id").is_empty() || (!db::s(&r,"org_id").is_empty() && db::s(&r,"org_id")!=org) || !db::s(&r,"scopes").split_whitespace().any(|s| s==action) { return Err(err(StatusCode::FORBIDDEN,"token lacks explicit transit scope")); }
    }
    Ok(())
}
pub(super) async fn list(State(st): State<S>, h: HeaderMap, Path(org): Path<String>) -> Res {
    authorize(&st,&h,&org,"transit:manage").await?;
    let rows = st.db.query("SELECT id,name,current_version FROM transit_keys WHERE org_id=? ORDER BY name", &[json!(org)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>())))
}
pub(super) async fn create(State(st): State<S>, h: HeaderMap, Path(org): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = authorize(&st,&h,&org,"transit:manage").await?;
    let name = body["name"].as_str().unwrap_or(""); if !valid_secret_key(name) { return Err(bad("name must be 1-128 ASCII letters, digits, underscore, hyphen or dot")); }
    let _lifecycle = st.transit_lifecycle.read().await; let master = st.master(); let expected = root(&st,&master).await?;
    let kid = id(); let key = oc::random_key();
    let statements = vec![fence(&expected,&master),
        ("INSERT INTO transit_keys(id,org_id,name,current_version) VALUES(?,?,?,1)".into(),vec![json!(kid),json!(org),json!(name)],Some(1)),
        ("INSERT INTO transit_versions(key_id,org_id,version,key_enc) VALUES(?,?,1,?)".into(),vec![json!(kid),json!(org),json!(oc::encrypt_symmetric_aad(&master,&wrap_aad(&org,&kid,1),&key))],Some(1))];
    st.db.checked_batch(&statements,false).await.map_err(tx_error)?;
    st.audit(&org,"","",&uid,"transit.create",&format!("{} version=1",kid)).await;
    Ok(j(json!({"id":kid,"name":name,"current_version":1})))
}
async fn metadata(st: &S, org: &str, kid: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    st.db.one("SELECT id,current_version FROM transit_keys WHERE id=? AND org_id=?", &[json!(kid),json!(org)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN,"transit key unavailable in workspace"))
}
async fn key(st: &S, master: &[u8;32], org: &str, kid: &str, version: i64) -> Result<[u8;32], (StatusCode, Json<Value>)> {
    let r = st.db.one("SELECT key_enc FROM transit_versions WHERE key_id=? AND org_id=? AND version=?", &[json!(kid),json!(org),json!(version)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("invalid transit ciphertext version"))?;
    oc::decrypt_symmetric_aad(master,&wrap_aad(org,kid,version),&db::s(&r,"key_enc")).map_err(|_| conflict())?.try_into().map_err(|_| conflict())
}
pub(super) async fn rotate(State(st): State<S>, h: HeaderMap, Path((org,kid)): Path<(String,String)>) -> Res {
    let uid = authorize(&st,&h,&org,"transit:manage").await?;
    let _lifecycle = st.transit_lifecycle.read().await; let master = st.master(); let expected = root(&st,&master).await?;
    let row = metadata(&st,&org,&kid).await?; let old = db::n(&row,"current_version"); let version = old.checked_add(1).ok_or_else(conflict)?;
    let statements = vec![fence(&expected,&master),
        ("UPDATE transit_keys SET current_version=? WHERE id=? AND org_id=? AND current_version=?".into(),vec![json!(version),json!(kid),json!(org),json!(old)],Some(1)),
        ("INSERT INTO transit_versions(key_id,org_id,version,key_enc) VALUES(?,?,?,?)".into(),vec![json!(kid),json!(org),json!(version),json!(oc::encrypt_symmetric_aad(&master,&wrap_aad(&org,&kid,version),&oc::random_key()))],Some(1))];
    st.db.checked_batch(&statements,false).await.map_err(tx_error)?;
    st.audit(&org,"","",&uid,"transit.rotate",&format!("{} version={}",kid,version)).await;
    Ok(j(json!({"id":kid,"current_version":version})))
}
#[derive(serde::Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { org: String, key: String, version: i64, payload: String }
fn encrypt(key: &[u8;32], org: &str, kid: &str, version: i64, context: &str, raw: &[u8]) -> String {
    let envelope = Envelope { org: org.into(), key: kid.into(), version, payload: oc::encrypt_symmetric_aad(key,&content_aad(org,kid,version,context),raw) };
    format!("owt1:{}",oc::b64(&serde_json::to_vec(&envelope).expect("transit envelope serialization")))
}
pub(super) async fn operate(State(st): State<S>, h: HeaderMap, Path((org,kid,action)): Path<(String,String,String)>, Json(body): Json<Value>) -> Res {
    let permission = match action.as_str() { "encrypt"=>"transit:encrypt", "decrypt"=>"transit:decrypt", "rewrap"=>"transit:rewrap", _=>return Err(bad("invalid transit operation")) };
    let uid = authorize(&st,&h,&org,permission).await?;
    let context = body["context"].as_str().ok_or_else(|| bad("context is required"))?; if context.len()>1024 { return Err(bad("context exceeds 1024 bytes")); }
    let _lifecycle = st.transit_lifecycle.read().await; let master = st.master(); let expected = root(&st,&master).await?;
    let row = metadata(&st,&org,&kid).await?; let latest = db::n(&row,"current_version");
    let (raw,version) = if action=="encrypt" {
        let encoded = body["plaintext"].as_str().ok_or_else(|| bad("base64 plaintext required"))?;
        if encoded.len()>1398104 { return Err(bad("plaintext exceeds 1MiB")); }
        let raw = oc::unb64(encoded).map_err(|_| bad("invalid base64 plaintext"))?; if raw.len()>1048576 { return Err(bad("plaintext exceeds 1MiB")); } (raw,latest)
    } else {
        let encoded = body["ciphertext"].as_str().ok_or_else(|| bad("ciphertext required"))?;
        if encoded.len()>2000000 { return Err(bad("ciphertext too large")); }
        let bytes = oc::unb64(encoded.strip_prefix("owt1:").ok_or_else(|| bad("invalid transit ciphertext"))?).map_err(|_| bad("invalid transit ciphertext"))?;
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| bad("invalid transit ciphertext"))?;
        if encoded!=format!("owt1:{}",oc::b64(&serde_json::to_vec(&envelope).map_err(|_| bad("invalid transit ciphertext"))?)) || envelope.org!=org || envelope.key!=kid || envelope.version<1 { return Err(bad("invalid transit ciphertext")); }
        let oldkey = key(&st,&master,&org,&kid,envelope.version).await?;
        let raw = oc::decrypt_symmetric_aad(&oldkey,&content_aad(&org,&kid,envelope.version,context),&envelope.payload).map_err(|_| bad("invalid transit ciphertext or context"))?;
        if raw.len()>1048576 { return Err(bad("plaintext exceeds 1MiB")); } (raw,envelope.version)
    };
    let output_version = if action=="decrypt" { version } else { latest };
    let result = if action=="decrypt" { json!({"plaintext":oc::b64(&raw),"version":version}) } else {
        let key = key(&st,&master,&org,&kid,latest).await?;
        json!({"ciphertext":encrypt(&key,&org,&kid,latest,context,&raw),"version":latest})
    };
    // A different replica may have rotated the root while this operation was reading.
    let current = st.db.one("SELECT v FROM meta WHERE k=?", &[json!(ROOT)]).await.map_err(|e| bad(&e))?.ok_or_else(conflict)?;
    if db::s(&current,"v")!=expected { return Err(conflict()); }
    st.audit(&org,"","",&uid,&format!("transit.{}",action),&format!("{} version={}",kid,output_version)).await;
    Ok(j(result))
}
