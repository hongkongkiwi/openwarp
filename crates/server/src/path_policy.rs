use super::*;
#[derive(serde::Deserialize, serde::Serialize)]
struct Rule { prefix: String, capabilities: Vec<String> }
fn canonical(p: &str) -> bool {
    !p.is_empty() && p.len()<=256 && p.starts_with('/') && p.ends_with('/') && !p.contains("//") && !p.contains('%') && !p.contains('\\') && !p.chars().any(char::is_control) && !p.split('/').any(|s| s=="." || s=="..")
}
async fn owner(st: &S, h: &HeaderMap, eid: &str) -> Result<String,(StatusCode,Json<Value>)> {
    let uid=st.token_user(h).await?; st.check_scope(h,eid).await?; let (oid,_)=st.require_env(eid,&uid).await?;
    if st.require_org(&oid,&uid).await?!="owner" { return Err(err(StatusCode::FORBIDDEN,"workspace owner required")); } Ok(uid)
}
pub(super) async fn put(State(st): State<S>, h: HeaderMap, Path((eid,role)): Path<(String,String)>, Json(b): Json<Value>) -> Res {
    owner(&st,&h,&eid).await?;
    if role=="owner" || role.is_empty() || role.len()>128 { return Err(bad("owner cannot have a path policy")); }
    let mode=st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("environment not found"))?;
    if db::s(&mode,"mode")!="sse" { return Err(bad("path policies require an explicit SSE environment")); }
    let rules: Vec<Rule>=serde_json::from_value(b["rules"].clone()).map_err(|_| bad("rules array required"))?;
    if rules.len()>256 || rules.iter().any(|r| !canonical(&r.prefix) || r.capabilities.is_empty() || r.capabilities.iter().any(|c| !matches!(c.as_str(),"read"|"write"|"delete"))) { return Err(bad("invalid canonical prefix or capabilities")); }
    let raw=serde_json::to_string(&rules).map_err(|_| bad("invalid rules"))?;
    let sql = "INSERT INTO path_policies(env_id,role,rules) VALUES(?,?,?) ON CONFLICT(env_id,role) DO UPDATE SET rules=excluded.rules";
    #[cfg(not(target_arch = "wasm32"))]
    let sql = if st.db.backend() == db::Backend::Mysql { "INSERT INTO path_policies(env_id,role,rules) VALUES(?,?,?) ON DUPLICATE KEY UPDATE rules=VALUES(rules)" } else { sql };
    st.db.exec(sql, &[json!(eid),json!(role),json!(raw)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"rules":rules})))
}
pub(super) async fn get(State(st): State<S>, h: HeaderMap, Path((eid,role)): Path<(String,String)>) -> Res {
    owner(&st,&h,&eid).await?; let r=st.db.one("SELECT rules FROM path_policies WHERE env_id=? AND role=?", &[json!(eid),json!(role)]).await.map_err(|e| bad(&e))?;
    match r { None=>Ok(j(Value::Null)),Some(r)=>Ok(j(json!({"rules":serde_json::from_str::<Value>(&db::s(&r,"rules")).map_err(|_| bad("stored policy invalid"))?}))) }
}
pub(super) async fn delete(State(st): State<S>, h: HeaderMap, Path((eid,role)): Path<(String,String)>) -> Res {
    owner(&st,&h,&eid).await?; st.db.exec("DELETE FROM path_policies WHERE env_id=? AND role=?", &[json!(eid),json!(role)]).await.map_err(|e| bad(&e))?; Ok(j(json!({"ok":true})))
}
impl AppState {
    async fn path_rules(&self,eid: &str,uid: &str) -> Result<Option<Vec<Rule>>,(StatusCode,Json<Value>)> {
        let (oid,_)=self.env_org_app(eid).await?; let role=self.require_org(&oid,uid).await?;
        if role=="owner" { return Ok(None); }
        let row=self.db.one("SELECT rules FROM path_policies WHERE env_id=? AND role=?", &[json!(eid),json!(role)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE,"path policy unavailable"))?;
        row.map(|r| serde_json::from_str::<Vec<Rule>>(&db::s(&r,"rules")).map_err(|_| err(StatusCode::FORBIDDEN,"stored path policy invalid"))).transpose()
    }
    pub(super) async fn path_allowed(&self,eid: &str,uid: &str,path: &str,action: &str) -> Result<bool,(StatusCode,Json<Value>)> {
        let Some(rules)=self.path_rules(eid,uid).await? else { return Ok(true) };
        Ok(canonical(path) && rules.iter().any(|r| canonical(&r.prefix) && path.starts_with(&r.prefix) && r.capabilities.iter().any(|c| c==action)))
    }
    pub(super) async fn check_path(&self,eid: &str,uid: &str,path: &str,action: &str) -> Result<(),(StatusCode,Json<Value>)> {
        if self.path_allowed(eid,uid,path,action).await? { Ok(()) } else { Err(err(StatusCode::FORBIDDEN,"path policy denies this operation")) }
    }
    pub(super) async fn restricted_env(&self,eid: &str,uid: &str) -> Result<bool,(StatusCode,Json<Value>)> { Ok(self.path_rules(eid,uid).await?.is_some()) }
    pub(super) async fn restricted_principal(&self,uid: &str) -> Result<bool,(StatusCode,Json<Value>)> {
        let rows=self.db.query("SELECT p.role AS policy_role,m.role AS principal_role FROM path_policies p JOIN envs e ON e.id=p.env_id JOIN apps a ON a.id=e.app_id JOIN org_members m ON m.org_id=a.org_id WHERE m.user_id=? UNION ALL SELECT p.role AS policy_role,i.role AS principal_role FROM path_policies p JOIN envs e ON e.id=p.env_id JOIN apps a ON a.id=e.app_id JOIN identities i ON i.org_id=a.org_id WHERE i.id=?", &[json!(uid),json!(uid)]).await.map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE,"path policies unavailable"))?;
        Ok(rows.iter().any(|r| db::s(r,"principal_role")!="owner" && db::s(r,"policy_role")==db::s(r,"principal_role")))
    }
    pub(super) fn stored_path(&self,key: &[u8;32],r: &Row) -> Result<String,(StatusCode,Json<Value>)> {
        if db::s(r,"path_enc").is_empty() { return Ok(db::s(r,"path")); }
        let raw=oc::decrypt_symmetric_compat(key,&secret_aad(&db::s(r,"env_id"),&db::s(r,"id"),"path"),&db::s(r,"path_enc")).map_err(|_| err(StatusCode::FORBIDDEN,"secret path authentication failed"))?;
        String::from_utf8(raw).map_err(|_| err(StatusCode::FORBIDDEN,"invalid secret path"))
    }
    pub(super) async fn check_secret_path(&self,sid: &str,uid: &str,action: &str) -> Result<(),(StatusCode,Json<Value>)> {
        let r=self.db.one("SELECT * FROM secrets WHERE id=?", &[json!(sid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("secret not found"))?;
        let eid=db::s(&r,"env_id"); if !self.restricted_env(&eid,uid).await? { return Ok(()); }
        let key=self.env_key(&eid).await?; let path=self.stored_path(&key,&r)?; self.check_path(&eid,uid,&path,action).await
    }
}
// Exact matched routes make every new unmediated API denied until explicitly reviewed.
pub(super) async fn middleware(State(st): State<S>, req: axum::extract::Request, next: Next) -> Response {
    let path=req.uri().path();
    let route=req.extensions().get::<axum::extract::MatchedPath>().map(|p| p.as_str()).unwrap_or("");
    // Runner and wrapping credentials have separate authenticators.
    if matches!((req.method().as_str(),route),("GET","/api/runner/jobs")|("POST","/api/runner/jobs/{jid}/result")|("GET","/api/unwrap")|("POST","/api/unwrap")) { return next.run(req).await; }
    if !path.starts_with("/api/") && !path.starts_with("/scim/") && path!="/mcp" { return next.run(req).await; }
    let uid=match st.token_user(req.headers()).await { Ok(u)=>u,Err(e)=> { if bearer_token(req.headers()).is_empty() && cookie_val(req.headers(),"ow_session").is_empty() { return next.run(req).await; } return e.into_response(); } };
    let restricted=match st.restricted_principal(&uid).await { Ok(v)=>v,Err(e)=>return e.into_response() };
    if !restricted { return next.run(req).await; }
    let route=req.extensions().get::<axum::extract::MatchedPath>().map(|p| p.as_str()).unwrap_or("");
    let method=req.method().as_str();
    let allowed=matches!((method,route),
        ("POST","/mcp") | ("GET","/api/me") | ("POST","/api/auth/logout") |
        ("GET","/api/orgs") | ("GET","/api/orgs/{oid}/apps") | ("GET","/api/apps/{aid}/envs") |
        ("GET","/api/envs/{eid}/meta") | ("GET","/api/envs/{eid}/secrets") | ("PUT","/api/envs/{eid}/secrets") |
        ("POST","/api/envs/{eid}/import") | ("GET","/api/envs/{eid}/export") | ("GET","/api/envs/{eid}/scan") |
        ("POST","/api/envs/{eid}/secrets/reuse-check") | ("GET","/api/search") |
        ("DELETE","/api/secrets/{sid}") | ("GET","/api/secrets/{sid}/history") |
        ("POST","/api/secrets/{sid}/restore/{ver}") | ("GET","/api/secrets/{sid}/override") | ("POST","/api/secrets/{sid}/override") | ("DELETE","/api/secrets/{sid}/override"));
    if !allowed { return err(StatusCode::FORBIDDEN,"path-restricted principals cannot use this operation").into_response(); }
    next.run(req).await
}
