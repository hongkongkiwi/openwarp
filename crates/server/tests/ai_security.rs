// Security regressions use disposable databases and fake loopback inference only.
use axum::{body::{to_bytes, Body}, extract::State, http::{Method, Request}, routing::post, Json, Router};
use openwarp_server::{clock, db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OWNER: &str = "ow_fake_security_owner";
const CUSTOM: &str = "ow_fake_security_custom";
const IMPORT_VALUE: &str = "ZmFrZVNlY3JldENyZWRlbnRpYWw";

struct Resp { status:u16, text:String, body:Value }
impl Resp { fn ok(&self) { assert!((200..300).contains(&self.status),"expected success, got {} {}",self.status,self.text); } }
struct Fixture { state:S, app:Router, app_id:String, env:String, restricted:String, _lock:tokio::sync::MutexGuard<'static,()> }
impl Fixture {
    async fn new() -> Self {
        let lock=TEST_LOCK.lock().await;
        let db=Db::open_memory().await.expect("private migrated database"); let (live,_)=tokio::sync::broadcast::channel(16);
        let state=new_state(db,"sqlite::memory:".into(),"security-fixture".into(),"http://127.0.0.1:8080".into(),[29;32],live,#[cfg(feature="redis-cache")] None);
        for (uid,token,role) in [("owner",OWNER,"owner"),("custom",CUSTOM,"investigator")] {
            state.db().exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,'unused','unused','unused',?,1)",&[json!(uid),json!(format!("{}@ai-security.test.invalid",uid)),json!(clock::now())]).await.unwrap();
            state.db().exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",&[json!(openwarp_crypto::hash_token(token)),json!(uid),json!(clock::now())]).await.unwrap();
            if uid=="owner" { state.db().exec("INSERT INTO orgs(id,name,created_at) VALUES('org','security',?)",&[json!(clock::now())]).await.unwrap(); }
            state.db().exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org',?,?)",&[json!(uid),json!(role)]).await.unwrap();
        }
        state.db().exec("INSERT INTO roles(id,org_id,name,permissions) VALUES('investigator','org','investigator',?)",&[json!(json!(["org:admin","secrets:read"]).to_string())]).await.unwrap();
        let mut f=Self { app:router(state.clone()),state,app_id:String::new(),env:String::new(),restricted:String::new(),_lock:lock };
        for (token,uid) in [(OWNER,"owner"),(CUSTOM,"custom")] { let me=f.call(Method::GET,"/api/me",token,None).await; me.ok(); assert_eq!(me.body["id"],uid); }
        let app=f.call(Method::POST,"/api/orgs/org/apps",OWNER,Some(json!({"name":"security"}))).await; app.ok(); f.app_id=app.body["id"].as_str().unwrap().into();
        let envs=f.call(Method::GET,&format!("/api/apps/{}/envs",f.app_id),OWNER,None).await; envs.ok();
        f.env=envs.body[0]["id"].as_str().unwrap().into(); f.restricted=envs.body[1]["id"].as_str().unwrap().into();
        f.call(Method::PUT,&format!("/api/envs/{}/policy",f.restricted),OWNER,Some(json!({"restricted":true}))).await.ok();
        f.call(Method::GET,&format!("/api/envs/{}/secrets",f.env),CUSTOM,None).await.ok();
        let denied=f.call(Method::GET,&format!("/api/envs/{}/secrets",f.restricted),CUSTOM,None).await;
        assert_eq!(denied.status,403,"custom org:admin permission must not bypass restricted environment policy: {}",denied.text);
        f
    }
    async fn call(&self,method:Method,path:&str,token:&str,body:Option<Value>) -> Resp {
        let mut req=Request::builder().method(method).uri(path).header("authorization",format!("Bearer {}",token)).extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127,0,0,1],43212))));
        let body=if let Some(v)=body { req=req.header("content-type","application/json"); Body::from(v.to_string()) } else { Body::empty() };
        let response=self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap(); let status=response.status().as_u16();
        let text=String::from_utf8(to_bytes(response.into_body(),2*1024*1024).await.unwrap().to_vec()).unwrap();
        Resp { status,body:serde_json::from_str(&text).unwrap_or(Value::Null),text }
    }
    async fn enable(&self,endpoint:&str) {
        self.call(Method::PUT,"/api/orgs/org/ai/settings",OWNER,Some(json!({"enabled":true,"endpoint":endpoint,"model":"fake-model","allow_metadata":true}))).await.ok();
    }
    async fn chat(&self,token:&str,body:Value) -> Resp { self.call(Method::POST,"/api/orgs/org/ai/chat",token,Some(body)).await }
    async fn findings(&self) -> Resp { let r=self.call(Method::GET,"/api/orgs/org/ai/findings",OWNER,None).await; r.ok(); r }
    async fn restricted_burst(&self) -> String {
        // A fixed timestamp avoids splitting the burst at a ten-minute boundary.
        let at=clock::now();
        for i in 0..20 {
            self.state.db().exec("INSERT INTO ai_activity(id,org_id,app_id,env_id,actor,credential,action,resource,count,created_at) VALUES(?,'org',?,?,'owner','fake-burst-credential','secret.list','',1,?)",&[json!(format!("restricted-event-{}",i)),json!(self.app_id),json!(self.restricted),json!(at)]).await.unwrap();
        }
        let r=self.findings().await;
        let burst=r.body["findings"].as_array().unwrap().iter().find(|v| v["rule"]=="read_export_burst" && v["evidence"].as_array().unwrap().iter().any(|e| e["env_id"]==self.restricted)).expect("restricted read burst must produce real nested evidence");
        assert_eq!(burst["evidence"].as_array().unwrap().len(),20);
        burst["id"].as_str().unwrap().into()
    }
}

struct Endpoints(Option<String>);
impl Endpoints { fn set(endpoint:&str) -> Self { let old=std::env::var("OPENWARP_AI_ENDPOINTS").ok(); std::env::set_var("OPENWARP_AI_ENDPOINTS",json!([endpoint]).to_string()); Self(old) } }
impl Drop for Endpoints { fn drop(&mut self) { match &self.0 { Some(v)=>std::env::set_var("OPENWARP_AI_ENDPOINTS",v),None=>std::env::remove_var("OPENWARP_AI_ENDPOINTS") } } }
type Captures=Arc<Mutex<Vec<Value>>>;
struct Provider { endpoint:String, captured:Captures, task:tokio::task::JoinHandle<()> }
impl Drop for Provider { fn drop(&mut self) { self.task.abort(); } }
impl Provider {
    async fn new() -> Self {
        async fn complete(State(captured):State<Captures>,Json(body):Json<Value>) -> Json<Value> {
            captured.lock().unwrap().push(body);
            Json(json!({"choices":[{"message":{"content":"Fake security answer."}}]}))
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let endpoint=format!("http://{}/v1/chat/completions",listener.local_addr().unwrap());
        let captured=Arc::new(Mutex::new(Vec::new())); let app=Router::new().route("/v1/chat/completions",post(complete)).with_state(captured.clone());
        let task=tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); }); Self { endpoint,captured,task }
    }
    fn count(&self) -> usize { self.captured.lock().unwrap().len() }
    fn clear(&self) { self.captured.lock().unwrap().clear(); }
    fn contexts(&self) -> Vec<Value> { self.captured.lock().unwrap().iter().map(|v| serde_json::from_str::<Value>(v["messages"][1]["content"].as_str().expect("user message")).expect("structured model context")["context"].clone()).collect() }
    fn excludes_restricted(&self,env:&str) {
        for context in self.contexts() { let text=context.to_string(); assert!(!text.contains(env) && !text.contains("restricted-event-"),"restricted environment evidence reached provider before authorization"); }
    }
}

#[tokio::test]
async fn multiline_quoted_import_never_discloses_assignment_shaped_value() {
    let f=Fixture::new().await; let p=Provider::new().await; let _operator=Endpoints::set(&p.endpoint); f.enable(&p.endpoint).await;
    f.chat(OWNER,json!({"task":"import","message":"Organize imported names","env_id":f.env,"import_text":"export PUBLIC_NAME=\"fake-single-line-value\"\nOTHER_NAME=fake-other-value"})).await.ok();
    assert_eq!(p.count(),1); let context=p.contexts().remove(0); assert_eq!(context["import_keys"],json!(["PUBLIC_NAME","OTHER_NAME"]));
    for marker in ["fake-single-line-value","fake-other-value"] { assert!(!context.to_string().contains(marker)); }
    p.clear();
    let r=f.chat(OWNER,json!({"task":"import","message":"Organize imported names","env_id":f.env,"import_text":format!("PRIVATE_BLOB=\"\n{}=\n\"\nPUBLIC_NAME=harmless",IMPORT_VALUE)})).await;
    assert!([200,400].contains(&r.status),"multiline import must be safely parsed or rejected, got {} {}",r.status,r.text);
    if r.status==400 { assert_eq!(p.count(),0,"unsupported multiline input must be rejected before inference"); }
    else { assert_eq!(p.count(),1); }
    for context in p.contexts() { assert!(!context.to_string().contains(IMPORT_VALUE),"quoted multiline secret fragment was parsed as a key and disclosed to provider"); }
}

#[tokio::test]
async fn incident_filters_restricted_timeline_before_inference() {
    let f=Fixture::new().await; let p=Provider::new().await; let _operator=Endpoints::set(&p.endpoint); f.enable(&p.endpoint).await;
    f.restricted_burst().await;
    let request=json!({"task":"incident","message":"Review activity","env_id":f.env});
    let mut owner_request=request.clone(); owner_request["env_id"]=json!(f.restricted);
    f.chat(OWNER,owner_request).await.ok(); assert_eq!(p.count(),1);
    assert!(p.contexts()[0]["timeline"].as_array().unwrap().iter().any(|e| e["env_id"]==f.restricted),"owner control must observe fixture evidence"); p.clear();
    let r=f.chat(CUSTOM,request).await;
    assert!([200,400,403].contains(&r.status),"expected filtered response or policy denial, got {} {}",r.status,r.text);
    p.excludes_restricted(&f.restricted);
}

#[tokio::test]
async fn explanation_filters_nested_restricted_finding_before_inference() {
    let f=Fixture::new().await; let p=Provider::new().await; let _operator=Endpoints::set(&p.endpoint); f.enable(&p.endpoint).await;
    let finding=f.restricted_burst().await;
    let request=json!({"task":"explain","message":"Explain this finding","env_id":f.env,"finding_id":finding});
    let mut owner_request=request.clone(); owner_request["env_id"]=json!(f.restricted);
    f.chat(OWNER,owner_request).await.ok(); assert_eq!(p.count(),1);
    assert!(p.contexts()[0]["finding"]["evidence"].as_array().unwrap().iter().any(|e| e["env_id"]==f.restricted),"owner control must observe nested finding evidence"); p.clear();
    let r=f.chat(CUSTOM,request).await;
    assert!([200,400,403].contains(&r.status),"expected sanitized explanation or policy denial, got {} {}",r.status,r.text);
    p.excludes_restricted(&f.restricted);
}

#[tokio::test]
async fn previous_day_active_inference_blocks_today_until_lease_expires() {
    let f=Fixture::new().await; let p=Provider::new().await; let _operator=Endpoints::set(&p.endpoint); f.enable(&p.endpoint).await;
    let request=json!({"message":"Find configuration names","env_id":f.env}); f.chat(OWNER,request.clone()).await.ok(); assert_eq!(p.count(),1); p.clear();
    let now=clock::now(); let previous_day=now/86400-1;
    // Seed both lease representations so the same cross-day contract survives migration.
    seed_active_claim(&f,previous_day,now+45).await;
    let r=f.chat(OWNER,request.clone()).await;
    assert_eq!((r.status,p.count()),(429,0),"previous-day active request must block before provider contact; response {}",r.text);
    f.state.db().exec("UPDATE ai_usage SET active_until=? WHERE org_id='org'",&[json!(now-1)]).await.unwrap();
    f.state.db().exec("UPDATE instance_leases SET expires_at=? WHERE name='ai-inference:org'",&[json!(now-1)]).await.unwrap();
    f.chat(OWNER,request).await.ok(); assert_eq!(p.count(),1,"expired lease must allow inference without carrying yesterday's budget forward");
}
async fn seed_active_claim(f:&Fixture,day:i64,until:i64) {
    f.state.db().exec("INSERT INTO ai_usage(org_id,day,requests,units,active_until,claim) VALUES('org',?,1,1,?,'held')",&[json!(day),json!(until)]).await.unwrap();
    f.state.db().exec("INSERT INTO instance_leases(name,owner,expires_at) VALUES('ai-inference:org','held',?) ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at",&[json!(until)]).await.unwrap();
}

#[tokio::test]
async fn expiry_resource_cap_reports_incomplete_coverage_or_includes_every_resource() {
    let f=Fixture::new().await;
    let empty=f.findings().await; assert_eq!(empty.body["coverage"]["truncated"],false); assert_eq!(empty.body["findings"],json!([]));
    let now=clock::now();
    for i in 0..51 {
        f.state.db().exec("INSERT INTO tokens(id,org_id,env_id,name,token_hash,role,expires_at,created_at,created_by) VALUES(?,'org',?,?,'fake-unused-hash','developer',?,?,'owner')",&[json!(format!("expiry-token-{:02}",i)),json!(f.env),json!(format!("fake-token-{}",i)),json!(now+3600+i),json!(now)]).await.unwrap();
    }
    let r=f.findings().await; let findings=r.body["findings"].as_array().unwrap();
    let represented=|id:&str| findings.iter().any(|v| v["rule"]=="expiring_token" && v["evidence"].as_array().unwrap().iter().any(|e| e["id"]==id));
    assert!(represented("expiry-token-00"),"expiry rule must operate on seeded resources");
    assert!(represented("expiry-token-50") || r.body["coverage"]["truncated"]==true,"51st expiring token omitted without coverage.truncated=true (returned {} findings)",findings.len());
}

#[tokio::test]
async fn final_findings_cap_reports_incomplete_coverage_when_history_is_omitted() {
    let f=Fixture::new().await; let now=clock::now();
    f.state.db().exec("INSERT INTO tokens(id,org_id,env_id,name,token_hash,expires_at,created_at) VALUES('fresh-expiry','org',?,'fake-current-token','fake-unused-hash',?,?)",&[json!(f.env),json!(now+3600),json!(now)]).await.unwrap();
    for i in 0..200 {
        let id=format!("history-finding-{:03}",i);
        let finding=json!({"id":id,"rule":"expiring_token","severity":"low","title":"Fake historical expiry","rationale":"Fixture history","evidence":[{"id":format!("history-token-{}",i),"action":"expiring_token","env_id":f.env,"created_at":now-3600}],"status":"open","exception_until":0,"maintenance_note":""});
        f.state.db().exec("INSERT INTO ai_finding_history(org_id,finding_id,finding,first_seen,last_seen) VALUES('org',?,?,?,?)",&[json!(id),json!(finding.to_string()),json!(now-1000),json!(now-i)]).await.unwrap();
    }
    let r=f.findings().await; let findings=r.body["findings"].as_array().unwrap();
    assert!(findings.iter().any(|v| v["id"]=="history-finding-000" && v["historical"]==true),"recent persisted history must remain visible");
    assert!(findings.iter().any(|v| v["rule"]=="expiring_token" && v["evidence"].as_array().unwrap().iter().any(|e| e["id"]=="fresh-expiry")),"current resource finding must remain visible alongside history");
    assert!(findings.iter().any(|v| v["id"]=="history-finding-199") || r.body["coverage"]["truncated"]==true,"persisted finding omitted by final result cap without coverage.truncated=true (returned {} findings)",findings.len());
}
