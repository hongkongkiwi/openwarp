use super::*;
use axum::{body::to_bytes, extract::Request};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

type Result<T> = std::result::Result<T, StatusCode>;
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Service { name: String, env_id: String, kind: String, credential_secret_id: String, enabled: bool, policy: Policy, #[serde(default, skip_serializing_if="Option::is_none")] expected_revision: Option<i64> }
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Policy { allowed_member_ids: Vec<String>, auth: Auth, #[serde(default, skip_serializing_if="Vec::is_empty")] operations: Vec<Capability>, #[serde(default, skip_serializing_if="Option::is_none")] endpoint: Option<String>, #[serde(default, skip_serializing_if="Vec::is_empty")] tools: Vec<Capability> }
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Auth { #[serde(rename="type")] kind: String }
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Capability { id: String, #[serde(default, skip_serializing_if="Option::is_none")] url: Option<String>, #[serde(default, skip_serializing_if="Option::is_none")] method: Option<String>, #[serde(default, skip_serializing_if="Option::is_none")] name: Option<String>, privileged: bool, input_schema: Value, #[serde(default)] response_fields: BTreeMap<String,String> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue { service_id: String, subject_user_id: String, capabilities: Vec<String>, #[serde(default)] approved_privileged_capabilities: Vec<String>, #[serde(default="ttl")] ttl_seconds: i64 }
fn ttl() -> i64 { 300 }
fn invalid() -> StatusCode { StatusCode::BAD_REQUEST }
fn unavailable<T>(_: T) -> StatusCode { StatusCode::SERVICE_UNAVAILABLE }
fn response(status: StatusCode, value: Value) -> Response { (status, [("cache-control", "no-store")], Json(value)).into_response() }
pub(super) fn failure(status: StatusCode, rid: &str) -> Response {
    let code = match status.as_u16() { 400=>"invalid_request",401=>"invalid_session",403=>"forbidden",404=>"not_found",409=>"conflict",413=>"payload_too_large",415=>"unsupported_media_type",501=>"native_only",502=>"upstream_failed",504=>"timeout",_=>"unavailable" };
    response(status,json!({"error":code,"request_id":rid})) }
fn object_keys(v: &Value, keys: &[&str]) -> bool { v.as_object().is_some_and(|o| o.keys().all(|k| keys.contains(&k.as_str()))) }
fn label(s: &str) -> bool { !s.is_empty() && s.len()<=128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) }
fn unique(v: &[String]) -> bool { v.len()<=32 && v.iter().all(|s| label(s)) && v.iter().collect::<HashSet<_>>().len()==v.len() }
fn destination(s: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(s).map_err(|_| invalid())?;
    let host=u.host_str().ok_or_else(invalid)?;
    if u.scheme()!="https" || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() || u.port_or_known_default()!=Some(443) || host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') || !host.contains('.') || host.ends_with('.') || host.split('.').any(|p| p.is_empty() || p.starts_with('-') || p.ends_with('-') || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'-')) || ["localhost","local","internal","test","invalid","onion"].iter().any(|suffix| host==*suffix || host.ends_with(&format!(".{suffix}"))) { return Err(invalid()); }
    Ok(u) }
fn integer(v: &Value) -> Option<i128> { v.as_i64().map(i128::from).or_else(|| v.as_u64().map(i128::from)) }
fn safe_number(v: &Value) -> bool { integer(v).is_none_or(|n| n.abs()<=9007199254740992) }
fn schema(v: &Value) -> Result<()> {
    if !object_keys(v,&["type","properties","required","additionalProperties"]) || v["type"]!="object" || v["additionalProperties"]!=false { return Err(invalid()); }
    let props=v["properties"].as_object().ok_or_else(invalid)?; if props.len()>32 { return Err(invalid()); }
    for (name,p) in props {
        if !label(name) || !object_keys(p,&["type","maxLength","minimum","maximum"]) { return Err(invalid()); }
        match p["type"].as_str() {
            Some("string") => { if p.get("minimum").is_some() || p.get("maximum").is_some() || p.get("maxLength").is_some_and(|n| n.as_u64().is_none_or(|n| n>4096)) { return Err(invalid()); } },
            Some("integer") => { if p.get("maxLength").is_some() || ["minimum","maximum"].iter().any(|k| p.get(*k).is_some_and(|n| integer(n).is_none())) || matches!((integer(&p["minimum"]),integer(&p["maximum"])),(Some(a),Some(b)) if a>b) { return Err(invalid()); } },
            Some("number") => { if p.get("maxLength").is_some() || ["minimum","maximum"].iter().any(|k| p.get(*k).is_some_and(|n| n.as_f64().is_none() || !safe_number(n))) || matches!((p["minimum"].as_f64(),p["maximum"].as_f64()),(Some(a),Some(b)) if a>b) { return Err(invalid()); } },
            Some("boolean"|"null") => { if p.as_object().is_none_or(|o| o.len()!=1) { return Err(invalid()); } },
            _ => return Err(invalid()),
        }
    }
    if let Some(required)=v.get("required") { let a=required.as_array().ok_or_else(invalid)?; let mut names=HashSet::new(); for n in a { let n=n.as_str().ok_or_else(invalid)?; if !props.contains_key(n) || !names.insert(n) { return Err(invalid()); } } }
    Ok(()) }
fn arguments(s: &Value, v: &Value) -> Result<()> {
    let a=v.as_object().ok_or_else(invalid)?; let props=s["properties"].as_object().ok_or_else(invalid)?;
    if s["required"].as_array().is_some_and(|r| r.iter().any(|k| !a.contains_key(k.as_str().unwrap_or("")))) { return Err(invalid()); }
    for (k,v) in a { let p=props.get(k).ok_or_else(invalid)?; let valid=match p["type"].as_str() {
        Some("string")=>v.as_str().is_some_and(|x| x.chars().count()<=p["maxLength"].as_u64().unwrap_or(4096) as usize),
        Some("number")=>v.is_number() && safe_number(v), Some("integer")=>integer(v).is_some(), Some("boolean")=>v.is_boolean(),Some("null")=>v.is_null(),_=>false };
        let out_of_bounds=if p["type"]=="integer" { integer(v).is_some_and(|n| integer(&p["minimum"]).is_some_and(|m| n<m) || integer(&p["maximum"]).is_some_and(|m| n>m)) } else { v.as_f64().is_some_and(|n| p["minimum"].as_f64().is_some_and(|m| n<m) || p["maximum"].as_f64().is_some_and(|m| n>m)) };
        if !valid || out_of_bounds { return Err(invalid()); }
    } Ok(()) }
impl Service {
    fn caps(&self) -> &[Capability] { if self.kind=="http" { &self.policy.operations } else { &self.policy.tools } }
    fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len()>128 || !unique(&self.policy.allowed_member_ids) || self.policy.auth.kind!="bearer" { return Err(invalid()); }
        match self.kind.as_str() {
            "http" if self.policy.endpoint.is_none() && self.policy.tools.is_empty()=>(),
            "mcp" if self.policy.operations.is_empty()=>{ destination(self.policy.endpoint.as_deref().ok_or_else(invalid)?)?; },
            _=>return Err(invalid()),
        }
        let caps=self.caps(); if caps.len()>32 || caps.iter().map(|c| &c.id).collect::<HashSet<_>>().len()!=caps.len() { return Err(invalid()); }
        for c in caps {
            if !label(&c.id) || c.response_fields.len()>32 { return Err(invalid()); }
            if self.kind=="http" { destination(c.url.as_deref().ok_or_else(invalid)?)?; if c.name.is_some() || !matches!(c.method.as_deref(),Some("GET"|"POST")) { return Err(invalid()); } }
            else if c.url.is_some() || c.method.is_some() || !c.name.as_deref().is_some_and(label) { return Err(invalid()); }
            schema(&c.input_schema)?;
            if c.method.as_deref()==Some("GET") && c.input_schema["properties"].as_object().is_none_or(|p| !p.is_empty()) { return Err(invalid()); }
            for (k,p) in &c.response_fields { if !label(k) || !p.starts_with('/') || p.len()>512 || p.split('~').skip(1).any(|s| !s.starts_with('0') && !s.starts_with('1')) { return Err(invalid()); } }
        } Ok(()) }
}
async fn human(st: &S, h: &HeaderMap, mutation: bool) -> Result<String> {
    if h.get_all("authorization").iter().count()>1 || cookie_val(h,"ow_session").starts_with("owb_") { return Err(StatusCode::UNAUTHORIZED); }
    let raw=if h.contains_key("authorization") { let a=bearer_token(h); if a.is_empty() { return Err(StatusCode::UNAUTHORIZED); } a } else { if mutation && !h.get("origin").and_then(|v| v.to_str().ok()).is_some_and(|o| origin_matches(st,h,o)) { return Err(StatusCode::FORBIDDEN); } cookie_val(h,"ow_session") };
    if raw.is_empty() || raw.starts_with("owb_") { return Err(StatusCode::UNAUTHORIZED); }
    let r=st.db.one("SELECT s.user_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.created_at>? AND u.active=1 AND u.email_verified=1",&[json!(oc::hash_token(&raw)),json!(now()-7*86400)]).await.map_err(unavailable)?.ok_or(StatusCode::FORBIDDEN)?;
    Ok(db::s(&r,"user_id")) }
async fn authority(st: &S, oid: &str, uid: &str, env: Option<&str>) -> Result<()> {
    st.check_admin(oid,uid).await.map_err(|_| StatusCode::FORBIDDEN)?;
    if let Some(env)=env { let (org,_)=st.require_env(env,uid).await.map_err(|_| StatusCode::FORBIDDEN)?; if org!=oid { return Err(StatusCode::NOT_FOUND); } } Ok(()) }
async fn history_authority(st: &S, oid: &str, uid: &str, env: &str) -> Result<()> {
    authority(st,oid,uid,None).await?;
    if st.db.one("SELECT id FROM envs WHERE id=?",&[json!(env)]).await.map_err(unavailable)?.is_some() { authority(st,oid,uid,Some(env)).await?; } Ok(()) }
async fn credential_row(st: &S, s: &Service) -> Result<Row> {
    let e=st.db.one("SELECT mode FROM envs WHERE id=?",&[json!(&s.env_id)]).await.map_err(unavailable)?.ok_or(StatusCode::CONFLICT)?;
    if db::s(&e,"mode")!="sse" { return Err(StatusCode::CONFLICT); }
    let r=st.db.one("SELECT * FROM secrets WHERE id=? AND env_id=? AND deleted=0 AND secret_type='secret'",&[json!(&s.credential_secret_id),json!(&s.env_id)]).await.map_err(unavailable)?.ok_or(StatusCode::CONFLICT)?; Ok(r) }
async fn subject(st: &S, oid: &str, s: &Service, uid: &str) -> Result<()> {
    if !s.policy.allowed_member_ids.iter().any(|u| u==uid) { return Err(StatusCode::FORBIDDEN); }
    let u=st.db.one("SELECT id FROM users WHERE id=? AND active=1 AND email_verified=1",&[json!(uid)]).await.map_err(unavailable)?;
    if u.is_none() { return Err(StatusCode::FORBIDDEN); }
    st.check_perm(oid,uid,"broker:use").await.map_err(|_| StatusCode::FORBIDDEN)?;
    let (org,_)=st.require_env(&s.env_id,uid).await.map_err(|_| StatusCode::FORBIDDEN)?; if org!=oid { return Err(StatusCode::FORBIDDEN); }
    st.check_secret_path(&s.credential_secret_id,uid,"read").await.map_err(|_| StatusCode::FORBIDDEN)?; Ok(()) }
async fn load_service(st: &S, oid: &str, sid: &str) -> Result<(Row,Service)> {
    let r=st.db.one("SELECT * FROM broker_services WHERE id=? AND org_id=?",&[json!(sid),json!(oid)]).await.map_err(unavailable)?.ok_or(StatusCode::NOT_FOUND)?;
    let s=serde_json::from_str(&db::s(&r,"config")).map_err(unavailable)?; Ok((r,s)) }
fn service_view(r: &Row, s: &Service) -> Value { let mut v=serde_json::to_value(s).unwrap_or(Value::Null); v["id"]=json!(db::s(r,"id")); v["revision"]=json!(db::n(r,"revision")); v }
async fn payload(req: Request, limit: usize) -> Result<Value> {
    if req.headers().get("content-type").and_then(|v| v.to_str().ok()).is_none_or(|s| s.split(';').next()!=Some("application/json")) { return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE); }
    let bytes=to_bytes(req.into_body(),limit).await.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?; serde_json::from_slice(&bytes).map_err(|_| invalid()) }
// The service config JSON is not portable SQL, so the env-to-app mapping is
// resolved here and the returned statement dies inside the emergency batch.
// Read failures propagate: a lockdown must not succeed while its broker
// revocation silently went uncomputed.
pub(super) async fn lockdown_statement(st:&S,oid:&str,app:Option<&str>) -> std::result::Result<Option<(String,Vec<Value>)>,(reqwest::StatusCode,axum::Json<Value>)> {
    let rows=st.db.query("SELECT id,config FROM broker_services WHERE org_id=?",&[json!(&oid)])   .await.map_err(|e| (unavailable(e), axum::Json(Value::Null)))?;
    let mut sids=Vec::new();
    for r in &rows {
        let env=serde_json::from_str::<Value>(&db::s(r,"config")).map_err(|_| (reqwest::StatusCode::SERVICE_UNAVAILABLE, axum::Json(Value::Null)))?.get("env_id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_default();
        if env.is_empty() { continue; }
        let hit=st.db.one(&format!("SELECT 1 FROM envs e JOIN apps a ON a.id=e.app_id WHERE e.id=? AND {}=?",if app.is_some() { "a.id" } else { "a.org_id" }),&[json!(&env),json!(app.unwrap_or(oid))]).await.map_err(|e| (unavailable(e), axum::Json(Value::Null)))?;
        if hit.is_some() { sids.push(db::s(r,"id")); } }
    if sids.is_empty() { return Ok(None); }
    let mut args:Vec<Value>=sids.iter().map(|s| json!(s)).collect(); args.insert(0,json!(&oid));
    Ok(Some((format!("DELETE FROM broker_sessions WHERE org_id=? AND service_id IN ({})",vec!["?";sids.len()].join(",")),args))) }
pub(super) fn routes() -> Router<S> {    Router::new().route("/api/orgs/{oid}/broker/services",get(services).post(create_service))
        .route("/api/orgs/{oid}/broker/services/{sid}",put(update_service).delete(delete_service))
        .route("/api/orgs/{oid}/broker/sessions",get(sessions).post(issue))
        .route("/api/orgs/{oid}/broker/sessions/{sid}",delete(revoke))
        .route("/api/orgs/{oid}/broker/audit",get(audit))
        .route("/api/broker/http",post(execute_http)).route("/api/broker/mcp",post(execute_mcp)) }
async fn services(State(st): State<S>, Path(oid): Path<String>, h: HeaderMap) -> Response {
    let rid=id(); let result=async { let uid=human(&st,&h,false).await?; authority(&st,&oid,&uid,None).await?;
        let rows=st.db.query("SELECT * FROM broker_services WHERE org_id=? ORDER BY id LIMIT 1000",&[json!(&oid)]).await.map_err(unavailable)?; let mut out=Vec::new();
        for r in rows { let s:Service=serde_json::from_str(&db::s(&r,"config")).map_err(unavailable)?; history_authority(&st,&oid,&uid,&s.env_id).await?; out.push(service_view(&r,&s)); } Ok(json!(out)) }.await;
    match result { Ok(v)=>response(StatusCode::OK,v),Err(e)=>failure(e,&rid) } }
async fn save(st: &S, oid: &str, sid: Option<&str>, req: Request) -> Result<Value> {
    let uid=human(st,req.headers(),true).await?; authority(st,oid,&uid,None).await?;
    let mut s:Service=serde_json::from_value(payload(req,64*1024).await?).map_err(|_| invalid())?; s.validate()?;
    authority(st,oid,&uid,Some(&s.env_id)).await?; credential_row(st,&s).await?;
    let revision=if let Some(sid)=sid { let (_,old)=load_service(st,oid,sid).await?; authority(st,oid,&uid,Some(&old.env_id)).await?; let revision=s.expected_revision.ok_or(StatusCode::CONFLICT)?; if revision<1 { return Err(StatusCode::CONFLICT); } revision } else { if s.expected_revision.is_some() { return Err(invalid()); } 0 };
    s.expected_revision=None; let config=serde_json::to_string(&s).map_err(unavailable)?;
    let sid=sid.map(str::to_owned).unwrap_or_else(id);
    let n=if revision==0 { if sid.is_empty() { return Err(invalid()); } st.db.exec("INSERT INTO broker_services(id,org_id,revision,config,created_at) VALUES(?,?,1,?,?)",&[json!(&sid),json!(oid),json!(&config),json!(now())]).await.map_err(unavailable)? }
        else { st.db.exec("UPDATE broker_services SET revision=revision+1,config=? WHERE id=? AND org_id=? AND revision=?",&[json!(config),json!(&sid),json!(oid),json!(revision)]).await.map_err(unavailable)? };
    if n!=1 { return Err(StatusCode::CONFLICT); } let (r,s)=load_service(st,oid,&sid).await?; Ok(service_view(&r,&s)) }
async fn create_service(State(st): State<S>,Path(oid): Path<String>,req: Request) -> Response { let rid=id(); match save(&st,&oid,None,req).await { Ok(v)=>response(StatusCode::CREATED,v),Err(e)=>failure(e,&rid) } }
async fn update_service(State(st): State<S>,Path((oid,sid)): Path<(String,String)>,req: Request) -> Response { let rid=id(); match save(&st,&oid,Some(&sid),req).await { Ok(v)=>response(StatusCode::OK,v),Err(e)=>failure(e,&rid) } }
async fn delete_service(State(st): State<S>,Path((oid,sid)): Path<(String,String)>,h: HeaderMap) -> Response {
    let rid=id(); let result=async { let uid=human(&st,&h,true).await?; let (r,mut s)=load_service(&st,&oid,&sid).await?; history_authority(&st,&oid,&uid,&s.env_id).await?; s.enabled=false;
        let n=st.db.exec("UPDATE broker_services SET config=?,revision=revision+1 WHERE id=? AND org_id=? AND revision=?",&[json!(serde_json::to_string(&s).map_err(unavailable)?),json!(&sid),json!(&oid),json!(db::n(&r,"revision"))]).await.map_err(unavailable)?; if n!=1 { return Err(StatusCode::CONFLICT); } Ok(()) }.await;
    match result { Ok(())=>response(StatusCode::NO_CONTENT,Value::Null),Err(e)=>failure(e,&rid) } }
async fn issue(State(st): State<S>,Path(oid): Path<String>,req: Request) -> Response {
    let rid=id();
    #[cfg(target_arch="wasm32")]
    { let _=(st,oid,req); failure(StatusCode::NOT_IMPLEMENTED,&rid) }
    #[cfg(not(target_arch="wasm32"))]
    { let result=async { let uid=human(&st,req.headers(),true).await?; authority(&st,&oid,&uid,None).await?;
        let q:Issue=serde_json::from_value(payload(req,32*1024).await?).map_err(|_| invalid())?;
        if !(1..=900).contains(&q.ttl_seconds) || !unique(&q.capabilities) || q.capabilities.is_empty() || !unique(&q.approved_privileged_capabilities) { return Err(invalid()); }
        let (r,s)=load_service(&st,&oid,&q.service_id).await?; if !s.enabled { return Err(StatusCode::FORBIDDEN); }
        authority(&st,&oid,&uid,Some(&s.env_id)).await?; subject(&st,&oid,&s,&q.subject_user_id).await?; credential_row(&st,&s).await?;
        for c in &q.capabilities { let cap=s.caps().iter().find(|cap| &cap.id==c).ok_or(StatusCode::FORBIDDEN)?; if cap.privileged && !q.approved_privileged_capabilities.contains(c) { return Err(StatusCode::FORBIDDEN); } }
        if q.approved_privileged_capabilities.iter().any(|c| !q.capabilities.contains(c) || !s.caps().iter().any(|cap| &cap.id==c && cap.privileged)) { return Err(invalid()); }
        let token=oc::random_token("owb"); let sid=id(); let expires=now()+q.ttl_seconds;
        // The guard repeats the lockdown check inside the write batch: an
        // emergency lockdown landing between authority and commit must abort
        // the insert, or a token could outlive the lockdown that deleted the
        // sessions before it.
        st.db.batch_checked(&[
            ("UPDATE orgs SET emergency_locked=emergency_locked WHERE id=? AND emergency_locked=0".into(), vec![json!(&oid)]),
            ("INSERT INTO broker_sessions(id,token_hash,org_id,service_id,revision,subject_user_id,issuer_user_id,capabilities,approvals,expires_at,revoked,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,?)".into(), vec![json!(&sid),json!(oc::hash_token(&token)),json!(&oid),json!(&q.service_id),json!(db::n(&r,"revision")),json!(&q.subject_user_id),json!(&uid),json!(serde_json::to_string(&q.capabilities).map_err(unavailable)?),json!(serde_json::to_string(&q.approved_privileged_capabilities).map_err(unavailable)?),json!(expires),json!(now())]),
        ], &[0]).await.map_err(|_| StatusCode::CONFLICT)?;
        Ok(json!({"id":sid,"token":token,"expires_at":expires,"service_id":q.service_id,"capabilities":q.capabilities})) }.await;
        match result { Ok(v)=>response(StatusCode::CREATED,v),Err(e)=>failure(e,&rid) } }
}
async fn sessions(State(st): State<S>,Path(oid): Path<String>,h: HeaderMap) -> Response {
    let rid=id(); let result=async { let uid=human(&st,&h,false).await?; authority(&st,&oid,&uid,None).await?;
        let rows=st.db.query("SELECT id,service_id,subject_user_id,issuer_user_id,expires_at,revoked FROM broker_sessions WHERE org_id=? ORDER BY created_at DESC LIMIT 1000",&[json!(&oid)]).await.map_err(unavailable)?;
        for r in &rows { let (_,s)=load_service(&st,&oid,&db::s(r,"service_id")).await?; history_authority(&st,&oid,&uid,&s.env_id).await?; } Ok(json!(rows)) }.await;
    match result { Ok(v)=>response(StatusCode::OK,v),Err(e)=>failure(e,&rid) } }
async fn revoke(State(st): State<S>,Path((oid,sid)): Path<(String,String)>,h: HeaderMap) -> Response {
    let rid=id(); let result=async { let uid=human(&st,&h,true).await?; authority(&st,&oid,&uid,None).await?;
        let r=st.db.one("SELECT service_id FROM broker_sessions WHERE id=? AND org_id=?",&[json!(&sid),json!(&oid)]).await.map_err(unavailable)?.ok_or(StatusCode::NOT_FOUND)?;
        let (_,s)=load_service(&st,&oid,&db::s(&r,"service_id")).await?; history_authority(&st,&oid,&uid,&s.env_id).await?;
        st.db.exec("UPDATE broker_sessions SET revoked=1 WHERE id=? AND org_id=?",&[json!(&sid),json!(&oid)]).await.map_err(unavailable)?; Ok(()) }.await;
    match result { Ok(())=>response(StatusCode::NO_CONTENT,Value::Null),Err(e)=>failure(e,&rid) } }
async fn audit(State(st): State<S>,Path(oid): Path<String>,h: HeaderMap) -> Response {
    let rid=id(); let result=async { let uid=human(&st,&h,false).await?; authority(&st,&oid,&uid,None).await?;
        let rows=st.db.query("SELECT * FROM broker_audit WHERE org_id=? ORDER BY created_at DESC LIMIT 1000",&[json!(&oid)]).await.map_err(unavailable)?;
        for r in &rows { history_authority(&st,&oid,&uid,&db::s(r,"env_id")).await?; } Ok(json!(rows)) }.await;
    match result { Ok(v)=>response(StatusCode::OK,v),Err(e)=>failure(e,&rid) } }

#[cfg(not(target_arch="wasm32"))]
mod native {
    use super::*;
    use std::{net::{IpAddr,SocketAddr}, time::{Duration,Instant}};
    #[cfg(test)] tokio::task_local! { static TEST_CLIENT: reqwest::Client; }
    #[cfg(test)] pub(super) async fn with_test_client<F: std::future::Future>(client:reqwest::Client,future:F)->F::Output { TEST_CLIENT.scope(client,future).await }
    pub(super) fn public_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v)=>{ let n=u32::from(v); ![(0,8),(0x0a000000,8),(0x64400000,10),(0x7f000000,8),(0xa9fe0000,16),(0xac100000,12),(0xc0000000,24),(0xc0000200,24),(0xc0586300,24),(0xc0a80000,16),(0xc6120000,15),(0xc6336400,24),(0xcb007100,24),(0xe0000000,3)].iter().any(|&(base,bits)| n>>(32-bits)==base>>(32-bits)) },
            IpAddr::V6(v)=>{ let n=u128::from(v); n>>125==1 && ![(0x20010000u128<<96,23),(0x20010db8u128<<96,32),(0x20020000u128<<96,16),(0x3fff0000u128<<96,20)].iter().any(|&(base,bits)| n>>(128-bits)==base>>(128-bits)) },
        }
    }
    async fn client(url: &str) -> Result<reqwest::Client> {
        let u=destination(url)?;
        #[cfg(test)] if let Ok(c)=TEST_CLIENT.try_with(Clone::clone) { return Ok(c); }
        let host=u.host_str().ok_or(StatusCode::BAD_GATEWAY)?;
        let addresses:Vec<SocketAddr>=tokio::net::lookup_host((host,443)).await.map_err(|_| StatusCode::BAD_GATEWAY)?.collect();
        if addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip())) { return Err(StatusCode::BAD_GATEWAY); }
        reqwest::Client::builder().https_only(true).no_proxy().redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).no_gzip().no_brotli().no_deflate().no_zstd().timeout(Duration::from_secs(15)).resolve_to_addrs(host,&addresses).build().map_err(|_| StatusCode::BAD_GATEWAY)
    }
    async fn send(c:&reqwest::Client,url:&str,method:&str,args:&Value,key:&str,session:Option<&str>,notification:bool) -> Result<(Value,Option<String>)> {
        // The Streamable HTTP transport requires clients to advertise both
        // media types; a conformant server may answer 406 to a JSON-only Accept.
        let mut request=c.request(if method=="GET" { reqwest::Method::GET } else { reqwest::Method::POST },url).bearer_auth(key).header("accept","application/json, text/event-stream").header("mcp-protocol-version","2025-06-18");
        if method=="POST" { request=request.json(args); }
        if let Some(s)=session { request=request.header("mcp-session-id",s); }
        let mut r=request.send().await.map_err(|e| if e.is_timeout() { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY })?;
        if !r.status().is_success() || r.headers().contains_key("content-encoding") { return Err(StatusCode::BAD_GATEWAY); }
        if !notification && r.headers().get("content-type").and_then(|v| v.to_str().ok()).is_none_or(|v| v.split(';').next()!=Some("application/json")) { return Err(StatusCode::BAD_GATEWAY); }
        let session=r.headers().get("mcp-session-id").map(|v| v.to_str().map(str::to_owned).map_err(|_| StatusCode::BAD_GATEWAY)).transpose()?;
        if session.as_ref().is_some_and(|s| s.len()>1024 || s.is_empty() || !s.bytes().all(|b| b.is_ascii_graphic())) { return Err(StatusCode::BAD_GATEWAY); }
        let mut body=Vec::new(); while let Some(chunk)=r.chunk().await.map_err(|_| StatusCode::BAD_GATEWAY)? { if chunk.len()>256*1024-body.len() { return Err(StatusCode::BAD_GATEWAY); } body.extend_from_slice(&chunk); }
        if notification { return Ok((Value::Null,session)); }
        Ok((serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_GATEWAY)?,session))
    }
    async fn ip_allowed(st:&S,oid:&str,h:&HeaderMap,peer:PeerAddr) -> Result<()> {
        let mut ip=peer.0.to_string();
        if crate::envcfg::var("OPENWARP_TRUST_PROXY").is_ok_and(|v| v=="1") && crate::envcfg::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1/32,::1".into()).split(',').any(|c| ip_in_cidr(&ip,c)) {
            if let Some(f)=h.get("x-forwarded-for").and_then(|v| v.to_str().ok()) { ip=f.split(',').next().unwrap_or("").trim().into(); }
        }
        let r=st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?",&[json!(oid)]).await.map_err(unavailable)?.ok_or(StatusCode::FORBIDDEN)?;
        let list=db::s(&r,"ip_allowlist"); if ip.parse::<IpAddr>().is_err() || (!list.trim().is_empty() && !list.split(',').any(|c| ip_in_cidr(&ip,c))) { return Err(StatusCode::FORBIDDEN); } Ok(())
    }
    struct Session { row:Row, service:Service, caps:Vec<String>, approvals:Vec<String> }
    async fn session(st:&S,h:&HeaderMap,peer:PeerAddr) -> Result<Session> {
        if h.contains_key("cookie") || h.get_all("authorization").iter().count()!=1 { return Err(StatusCode::UNAUTHORIZED); }
        let token=bearer_token(h); if !token.starts_with("owb_") { return Err(StatusCode::UNAUTHORIZED); }
        let row=st.db.one("SELECT * FROM broker_sessions WHERE token_hash=? AND revoked=0 AND expires_at>?",&[json!(oc::hash_token(&token)),json!(now())]).await.map_err(unavailable)?.ok_or(StatusCode::UNAUTHORIZED)?;
        let oid=db::s(&row,"org_id"); let (r,s)=load_service(st,&oid,&db::s(&row,"service_id")).await.map_err(|e| if e==StatusCode::NOT_FOUND { StatusCode::UNAUTHORIZED } else { e })?;
        if !s.enabled || db::n(&r,"revision")!=db::n(&row,"revision") { return Err(StatusCode::UNAUTHORIZED); }
        let issuer=db::s(&row,"issuer_user_id"); if st.db.one("SELECT id FROM users WHERE id=? AND active=1 AND email_verified=1",&[json!(&issuer)]).await.map_err(unavailable)?.is_none() { return Err(StatusCode::FORBIDDEN); }
        authority(st,&oid,&issuer,Some(&s.env_id)).await?;
        // A live delegation carries the issuer's authority: once the issuer
        // becomes path-restricted, outstanding sessions must stop executing.
        if st.restricted_principal(&issuer).await.map_err(|e| e.0)? { return Err(StatusCode::FORBIDDEN); }
        subject(st,&oid,&s,&db::s(&row,"subject_user_id")).await?; ip_allowed(st,&oid,h,peer).await?; credential_row(st,&s).await?;
        let caps=serde_json::from_str(&db::s(&row,"capabilities")).map_err(unavailable)?; let approvals=serde_json::from_str(&db::s(&row,"approvals")).map_err(unavailable)?;
        Ok(Session {row,service:s,caps,approvals})
    }
    fn project(c:&Capability,v:&Value,key:&str) -> Result<Value> {
        let mut out=serde_json::Map::new(); for (k,p) in &c.response_fields { let value=v.pointer(p).ok_or(StatusCode::BAD_GATEWAY)?;
            if value.is_array() || value.is_object() || value.as_str().is_some_and(|s| s.len()>4096 || s.contains(key)) { return Err(StatusCode::BAD_GATEWAY); } out.insert(k.clone(),value.clone()); }
        let v=Value::Object(out); if serde_json::to_vec(&v).map_err(unavailable)?.len()>64*1024 { return Err(StatusCode::BAD_GATEWAY); } Ok(v)
    }
    async fn run(st:&S,h:&HeaderMap,peer:PeerAddr,s:&Session,c:&Capability,args:&Value,rid:&str) -> Result<Value> {
        let started=Instant::now(); let oid=db::s(&s.row,"org_id");
        let (_,app)=st.env_org_app(&s.service.env_id).await.map_err(unavailable)?;
        st.audited_batch(&[("INSERT INTO broker_audit(id,org_id,env_id,service_id,session_id,subject_user_id,issuer_user_id,capability,decision,status,duration_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?,0,0,?)".into(),vec![json!(rid),json!(&oid),json!(&s.service.env_id),json!(db::s(&s.row,"service_id")),json!(db::s(&s.row,"id")),json!(db::s(&s.row,"subject_user_id")),json!(db::s(&s.row,"issuer_user_id")),json!(&c.id),json!("attempt"),json!(now())])],&[0],[&oid,&app,&s.service.env_id,&db::s(&s.row,"subject_user_id"),"broker.invoke",rid]).await.map_err(unavailable)?;
        let result=tokio::time::timeout(Duration::from_secs(15),async {
            session(st,h,peer).await?;
            let row=credential_row(st,&s.service).await?; let envkey=st.env_key(&s.service.env_id).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let bytes=decrypt_secret_value(&envkey,&s.service.env_id,&s.service.credential_secret_id,"value",db::n(&row,"version"),&db::s(&row,"value_enc")).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let key=String::from_utf8(bytes).map_err(|_| StatusCode::CONFLICT)?; if key.is_empty() || key.len()>8192 || !key.bytes().all(|b| b.is_ascii_graphic()) { return Err(StatusCode::CONFLICT); }
            let url=if s.service.kind=="http" { c.url.as_deref() } else { s.service.policy.endpoint.as_deref() }.ok_or(StatusCode::BAD_GATEWAY)?;
            let client=client(url).await?;
            session(st,h,peer).await?;
            let value=if s.service.kind=="http" { send(&client,url,c.method.as_deref().unwrap_or("POST"),args,&key,None,false).await?.0 }
            else {
                let (init,session_id)=send(&client,url,"POST",&json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"openwarp-broker","version":"1"}}}),&key,None,false).await?;
                if init["jsonrpc"]!="2.0" || init["id"]!=0 || init.get("error").is_some() || init["result"]["protocolVersion"]!="2025-06-18" { return Err(StatusCode::BAD_GATEWAY); }
                send(&client,url,"POST",&json!({"jsonrpc":"2.0","method":"notifications/initialized"}),&key,session_id.as_deref(),true).await?;
                session(st,h,peer).await?;
                let (reply,_)=send(&client,url,"POST",&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":c.name,"arguments":args}}),&key,session_id.as_deref(),false).await?;
                if reply["jsonrpc"]!="2.0" || reply["id"]!=1 || reply.get("error").is_some() || reply["result"]["isError"]==true || !reply["result"]["structuredContent"].is_object() { return Err(StatusCode::BAD_GATEWAY); } reply["result"]["structuredContent"].clone()
            };
            let out=project(c,&value,&key)?; session(st,h,peer).await?; Ok(out)
        }).await.unwrap_or(Err(StatusCode::GATEWAY_TIMEOUT));
        let status=result.as_ref().map(|_|200).unwrap_or_else(|e| e.as_u16());
        let n=st.db.exec("UPDATE broker_audit SET decision=?,status=?,duration_ms=? WHERE id=? AND decision='attempt'",&[json!(if result.is_ok() {"success"} else {"denied"}),json!(status),json!(started.elapsed().as_millis().min(i64::MAX as u128) as i64),json!(rid)]).await.map_err(unavailable)?; if n!=1 { return Err(StatusCode::SERVICE_UNAVAILABLE); }
        if result.is_ok() { if let Err(e)=session(st,h,peer).await { let n=st.db.exec("UPDATE broker_audit SET decision='denied',status=? WHERE id=?",&[json!(e.as_u16()),json!(rid)]).await.map_err(unavailable)?; if n!=1 { return Err(StatusCode::SERVICE_UNAVAILABLE); } return Err(e); } } result
    }
    async fn denied(st:&S,s:&Session,rid:&str,status:StatusCode) -> Result<()> {
        let sql="INSERT INTO broker_audit(id,org_id,env_id,service_id,session_id,subject_user_id,issuer_user_id,capability,decision,status,duration_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT(id) DO NOTHING";
        let sql=if st.db.backend()==db::Backend::Mysql { "INSERT INTO broker_audit(id,org_id,env_id,service_id,session_id,subject_user_id,issuer_user_id,capability,decision,status,duration_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,?) ON DUPLICATE KEY UPDATE id=VALUES(id)" } else { sql };
        st.db.exec(sql,&[json!(rid),json!(db::s(&s.row,"org_id")),json!(&s.service.env_id),json!(db::s(&s.row,"service_id")),json!(db::s(&s.row,"id")),json!(db::s(&s.row,"subject_user_id")),json!(db::s(&s.row,"issuer_user_id")),json!("request"),json!("denied"),json!(status.as_u16()),json!(now())]).await.map_err(unavailable)?; Ok(())
    }
    pub(super) async fn execute(st:S,peer:PeerAddr,req:Request,mcp:bool,rid:&str) -> Response {
        let h=req.headers().clone(); let s=match session(&st,&h,peer).await { Ok(s)=>s,Err(e)=>return failure(e,rid) };
        let body=match payload(req,32*1024).await { Ok(v)=>v,Err(e)=>return failure(denied(&st,&s,rid,e).await.err().unwrap_or(e),rid) };
        let rpc_id=body.get("id").cloned().unwrap_or(Value::Null);
        let result=async {
            let (operation,args)=if mcp {
                if !object_keys(&body,&["jsonrpc","id","method","params"]) || body["jsonrpc"]!="2.0" || !(rpc_id.is_null() || rpc_id.is_string() || rpc_id.is_i64() || rpc_id.is_u64()) { return Err(invalid()); }
                let params=body.get("params").cloned().unwrap_or(json!({}));
                match body["method"].as_str() {
                    Some("ping") if params==json!({})=>return Ok(json!({})),
                    Some("initialize")=>{ if !object_keys(&params,&["protocolVersion","capabilities","clientInfo"]) || params["protocolVersion"]!="2025-06-18" { return Err(invalid()); } return Ok(json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"openwarp-broker","version":"1"}})); },
                    Some("notifications/initialized") if params==json!({}) && body.get("id").is_none()=>return Ok(Value::Null),
                    Some("tools/list") if params==json!({})=>{ let tools:Vec<Value>=s.service.caps().iter().filter(|c| s.caps.contains(&c.id) && (!c.privileged || s.approvals.contains(&c.id))).map(|c| json!({"name":c.id,"inputSchema":c.input_schema})).collect(); return Ok(json!({"tools":tools})); },
                    Some("tools/call")=>{ if !object_keys(&params,&["name","arguments"]) { return Err(invalid()); } (params["name"].as_str().ok_or_else(invalid)?.to_owned(),params.get("arguments").cloned().unwrap_or(json!({}))) },
                    _=>return Err(StatusCode::FORBIDDEN),
                }
            } else { if !object_keys(&body,&["operation","arguments"]) { return Err(invalid()); } (body["operation"].as_str().ok_or_else(invalid)?.to_owned(),body["arguments"].clone()) };
            if (!mcp && s.service.kind!="http") || (mcp && s.service.kind!="mcp") { return Err(StatusCode::FORBIDDEN); }
            let c=s.service.caps().iter().find(|c| c.id==operation && s.caps.contains(&c.id)).ok_or(StatusCode::FORBIDDEN)?;
            if c.privileged && !s.approvals.contains(&c.id) { return Err(StatusCode::FORBIDDEN); } arguments(&c.input_schema,&args)?;
            let data=run(&st,&h,peer,&s,c,&args,rid).await?;
            if mcp { Ok(json!({"structuredContent":data,"content":[{"type":"text","text":serde_json::to_string(&data).map_err(unavailable)?}]})) } else { Ok(json!({"request_id":rid,"data":data})) }
        }.await;
        let result=match result { Err(e)=>match denied(&st,&s,rid,e).await { Ok(())=>Err(e),Err(audit)=>Err(audit) },ok=>ok };
        match result { Ok(v) if mcp && body["method"]=="notifications/initialized"=>response(StatusCode::ACCEPTED,v),Ok(v) if mcp=>response(StatusCode::OK,json!({"jsonrpc":"2.0","id":rpc_id,"result":v})),Ok(v)=>response(StatusCode::OK,v),Err(e) if mcp && matches!(e.as_u16(),502|504)=>response(StatusCode::OK,json!({"jsonrpc":"2.0","id":rpc_id,"error":{"code":-32000,"message":"upstream_failed","data":{"request_id":rid}}})),Err(e)=>failure(e,rid) }
    }
    #[cfg(test)]
    mod address_tests {
        use super::*;
        #[test] fn special_addresses_denied() { for ip in ["127.0.0.1","10.1.1.1","100.64.0.1","169.254.169.254","192.0.2.1","198.18.0.1","224.1.1.1","::1","::ffff:8.8.8.8","64:ff9b::808:808","2001:db8::1","2002:808:808::1","fc00::1","fe80::1"] { assert!(!public_ip(ip.parse().unwrap()),"{ip}"); } for ip in ["8.8.8.8","1.1.1.1","2606:4700:4700::1111"] { assert!(public_ip(ip.parse().unwrap()),"{ip}"); } }
    }
}
#[cfg(all(test,not(target_arch="wasm32")))]
pub(super) async fn with_test_client<F: std::future::Future>(client:reqwest::Client,future:F)->F::Output { native::with_test_client(client,future).await }
async fn execute_http(State(st):State<S>,peer:PeerAddr,req:Request) -> Response { execute(st,peer,req,false).await }
async fn execute_mcp(State(st):State<S>,peer:PeerAddr,req:Request) -> Response { execute(st,peer,req,true).await }
async fn execute(st:S,peer:PeerAddr,req:Request,mcp:bool) -> Response {
    let rid=id();
    #[cfg(target_arch="wasm32")] { let _=(st,peer,req,mcp); failure(StatusCode::NOT_IMPLEMENTED,&rid) }
    #[cfg(not(target_arch="wasm32"))] { native::execute(st,peer,req,mcp,&rid).await }
}
#[cfg(all(test,not(target_arch="wasm32")))]
#[path="broker_tests.rs"] mod tests;
