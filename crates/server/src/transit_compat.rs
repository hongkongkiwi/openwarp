use super::*;

fn wrapping_aad(org: &str, kid: &str) -> Vec<u8> { json!(["openwarp-transit-wrap-v1",org,kid]).to_string().into_bytes() }
fn aad(org: &str, kid: &str, version: i64, context: &str) -> Vec<u8> { json!(["openwarp-transit-v1",org,kid,version,context]).to_string().into_bytes() }
async fn authorize(st: &S, h: &HeaderMap, oid: &str, action: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let uid = st.token_user(h).await?;
    let scoped = env_scope_of(st, h).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "credential scope unavailable"))?;
    if !scoped.is_empty() { return Err(err(StatusCode::FORBIDDEN,"environment credentials cannot access transit")); }
    st.check_perm(oid,&uid,action).await?; Ok(uid)
}
async fn row(st: &S, oid: &str, kid: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    st.db.one("SELECT * FROM compat_transit_keys WHERE id=? AND org_id=?", &[json!(kid),json!(oid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("transit key not found"))
}
fn unwrap(st: &S, r: &Row) -> Result<[u8;32], (StatusCode, Json<Value>)> {
    oc::decrypt_symmetric_aad(&st.master(), &wrapping_aad(&db::s(r,"org_id"),&db::s(r,"id")), &db::s(r,"wrapping_key")).map_err(|_| bad("transit wrapping key unavailable"))?.try_into().map_err(|_| bad("invalid transit wrapping key"))
}
async fn version(st: &S, kid: &str, v: Option<i64>) -> Result<Row, (StatusCode, Json<Value>)> {
    let sql = if v.is_some() { "SELECT * FROM compat_transit_versions WHERE key_id=? AND version=?" } else { "SELECT * FROM compat_transit_versions WHERE key_id=? ORDER BY version DESC LIMIT 1" };
    let mut params = vec![json!(kid)]; if let Some(v) = v { params.push(json!(v)); }
    st.db.one(sql,&params).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("transit version not found"))
}
async fn add_version(st: &S, oid: &str, kid: &str, wrap: &[u8;32]) -> Result<i64, (StatusCode, Json<Value>)> {
    for _ in 0..8 {
        let latest = st.db.one("SELECT MAX(version) AS v FROM compat_transit_versions WHERE key_id=?", &[json!(kid)]).await.map_err(|e| bad(&e))?;
        let v = latest.map(|r| db::n(&r,"v")).unwrap_or(0)+1;
        let enc = oc::encrypt_symmetric_aad(wrap,&aad(oid,kid,v,"key"),&oc::random_key());
        match st.db.exec("INSERT INTO compat_transit_versions(key_id,version,key_enc,created_at) VALUES(?,?,?,?)", &[json!(kid),json!(v),json!(enc),json!(now())]).await {
            Ok(_) => return Ok(v),
            Err(e) => { if st.db.one("SELECT version FROM compat_transit_versions WHERE key_id=? AND version=?", &[json!(kid),json!(v)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad(&e)); } }
        }
    }
    Err(err(StatusCode::CONFLICT,"concurrent transit rotation; retry"))
}
pub(super) async fn create(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = authorize(&st,&h,&oid,"transit:manage").await?;
    #[cfg(not(target_arch="wasm32"))] let _guard=st.transit_gate.lock().await;
    let name = body["name"].as_str().unwrap_or(""); if name.is_empty() || name.len()>128 || name.chars().any(char::is_control) { return Err(bad("name must contain 1-128 printable bytes")); }
    let kid = id(); let wrap = oc::random_key();
    let enc = oc::encrypt_symmetric_aad(&st.master(),&wrapping_aad(&oid,&kid),&wrap);
    let initial = oc::encrypt_symmetric_aad(&wrap,&aad(&oid,&kid,1,"key"),&oc::random_key());
    // The key and its first version are one atomic write: a failed version
    // insert must not reserve the name or leave an unusable key behind.
    st.db.batch(&[
        ("INSERT INTO compat_transit_keys(id,org_id,name,wrapping_key,created_at) VALUES(?,?,?,?,?)".into(), vec![json!(&kid),json!(&oid),json!(&name),json!(&enc),json!(now())]),
        ("INSERT INTO compat_transit_versions(key_id,version,key_enc,created_at) VALUES(?,?,?,?)".into(), vec![json!(&kid),json!(1),json!(&initial),json!(now())]),
    ]).await.map_err(|_| bad("transit key name already exists or storage unavailable"))?;
    st.audit(&oid,"","",&uid,"transit.create",&kid).await;
    Ok(j(json!({"id":kid,"name":name,"key_version":1})))
}
pub(super) async fn list(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    authorize(&st,&h,&oid,"transit:manage").await?;
    let rows = st.db.query("SELECT id,name,created_at FROM compat_transit_keys WHERE org_id=? ORDER BY name", &[json!(oid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>())))
}
pub(super) async fn rotate(State(st): State<S>, h: HeaderMap, Path((oid,kid)): Path<(String,String)>) -> Res {
    let uid = authorize(&st,&h,&oid,"transit:manage").await?;
    #[cfg(not(target_arch="wasm32"))] let _guard=st.transit_gate.lock().await;
    let r = row(&st,&oid,&kid).await?; let wrap = unwrap(&st,&r)?; let v = add_version(&st,&oid,&kid,&wrap).await?;
    st.audit(&oid,"","",&uid,"transit.rotate",&kid).await; Ok(j(json!({"id":kid,"key_version":v})))
}
fn context(body: &Value) -> Result<&str, (StatusCode, Json<Value>)> {
    let c = match body.get("context") { None => "", Some(v) => v.as_str().ok_or_else(|| bad("context must be a string"))? };
    if c.len()>1024 { return Err(bad("context exceeds 1024 bytes")); } Ok(c)
}
fn key(wrap: &[u8;32], oid: &str, kid: &str, r: &Row) -> Result<[u8;32], (StatusCode, Json<Value>)> {
    oc::decrypt_symmetric_aad(wrap,&aad(oid,kid,db::n(r,"version"),"key"),&db::s(r,"key_enc")).map_err(|_| bad("invalid transit key"))?.try_into().map_err(|_| bad("invalid transit key"))
}
async fn seal(st: &S, oid: &str, kid: &str, wrap: &[u8;32], plain: &[u8], c: &str) -> Res {
    let r = version(st,kid,None).await?; let v = db::n(&r,"version");
    let ciphertext = format!("owtransit:v1:{}:{}",v,oc::encrypt_symmetric_aad(&key(wrap,oid,kid,&r)?,&aad(oid,kid,v,c),plain));
    Ok(j(json!({"ciphertext":ciphertext,"key_version":v})))
}
async fn open(st: &S, oid: &str, kid: &str, wrap: &[u8;32], body: &Value, c: &str) -> Result<Vec<u8>, (StatusCode, Json<Value>)> {
    let raw = body["ciphertext"].as_str().ok_or_else(|| bad("ciphertext required"))?;
    if raw.len()>1_400_000 { return Err(bad("ciphertext too large")); }
    let (v,payload) = raw.strip_prefix("owtransit:v1:").and_then(|s| s.split_once(':')).ok_or_else(|| bad("invalid transit ciphertext"))?;
    let v: i64 = v.parse().map_err(|_| bad("invalid transit version"))?;
    let r = version(st,kid,Some(v)).await?;
    let plain = oc::decrypt_symmetric_aad(&key(wrap,oid,kid,&r)?,&aad(oid,kid,v,c),payload).map_err(|_| bad("transit authentication failed"))?;
    if plain.len()>1024*1024 { return Err(bad("payload exceeds 1 MiB")); } Ok(plain)
}
pub(super) async fn encrypt(State(st): State<S>, h: HeaderMap, Path((oid,kid)): Path<(String,String)>, Json(body): Json<Value>) -> Res {
    authorize(&st,&h,&oid,"transit:encrypt").await?; #[cfg(not(target_arch="wasm32"))] let _guard=st.transit_gate.lock().await; let c = context(&body)?;
    let raw = body["plaintext"].as_str().ok_or_else(|| bad("base64 plaintext required"))?;
    if raw.len()>1_398_104 { return Err(bad("payload exceeds 1 MiB")); }
    let plain = oc::unb64(raw).map_err(|_| bad("invalid base64 plaintext"))?; if plain.len()>1024*1024 { return Err(bad("payload exceeds 1 MiB")); }
    let r = row(&st,&oid,&kid).await?; seal(&st,&oid,&kid,&unwrap(&st,&r)?,&plain,c).await
}
pub(super) async fn decrypt(State(st): State<S>, h: HeaderMap, Path((oid,kid)): Path<(String,String)>, Json(body): Json<Value>) -> Res {
    authorize(&st,&h,&oid,"transit:decrypt").await?; #[cfg(not(target_arch="wasm32"))] let _guard=st.transit_gate.lock().await; let c = context(&body)?; let r = row(&st,&oid,&kid).await?;
    let plain = open(&st,&oid,&kid,&unwrap(&st,&r)?,&body,c).await?; Ok(j(json!({"plaintext":oc::b64(&plain)})))
}
pub(super) async fn rewrap(State(st): State<S>, h: HeaderMap, Path((oid,kid)): Path<(String,String)>, Json(body): Json<Value>) -> Res {
    authorize(&st,&h,&oid,"transit:decrypt").await?; authorize(&st,&h,&oid,"transit:encrypt").await?;
    #[cfg(not(target_arch="wasm32"))] let _guard=st.transit_gate.lock().await;
    let c = context(&body)?; let r = row(&st,&oid,&kid).await?; let wrap = unwrap(&st,&r)?;
    let plain = open(&st,&oid,&kid,&wrap,&body,c).await?; seal(&st,&oid,&kid,&wrap,&plain,c).await
}
#[cfg(not(target_arch="wasm32"))]
pub(super) async fn rewrap_master(st: &S, old: &[u8;32], new: &[u8;32]) -> Result<Vec<(String,String)>, (StatusCode, Json<Value>)> {
    let rows = st.db.query("SELECT * FROM compat_transit_keys",&[]).await.map_err(|e| bad(&e))?;
    let mut out = Vec::new(); for r in rows {
        let kid = db::s(&r,"id"); let a = wrapping_aad(&db::s(&r,"org_id"),&kid);
        let plain = oc::decrypt_symmetric_aad(old,&a,&db::s(&r,"wrapping_key")).map_err(|_| bad("transit wrapping key unavailable; refusing root rotation"))?;
        out.push((kid,oc::encrypt_symmetric_aad(new,&a,&plain)));
    } Ok(out)
}
