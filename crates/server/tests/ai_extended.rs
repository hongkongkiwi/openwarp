// Extended AI safety checks use disposable state and loopback providers only.
use axum::{body::{to_bytes, Body}, extract::State, http::{HeaderMap, Method, Request, StatusCode}, response::{IntoResponse, Response}, routing::post, Json, Router};
use openwarp_server::{clock, db::Db, new_state, process_maintenance, router, S};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, Semaphore};
use tower::ServiceExt;

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SESSION: &str = "ow_fake_extended_session";
const KEY: &str = "fake-extended-provider-key";
const PRIVATE: &str = "fake-extended-private-value";

struct Resp { status: u16, body: Value, text: String }
impl Resp {
    fn ok(&self) { assert!((200..300).contains(&self.status), "expected success, got {} {}", self.status, self.text); }
    fn rejected(&self) { assert!((400..600).contains(&self.status), "expected rejection, got {} {}", self.status, self.text); }
}
struct Fixture { state: S, app: Router, env: String, _lock: tokio::sync::MutexGuard<'static, ()> }
impl Fixture {
    async fn new() -> Self {
        let lock=TEST_LOCK.lock().await;
        let db=Db::open_memory().await.unwrap(); let (live,_)=tokio::sync::broadcast::channel(16);
        let state=new_state(db,"sqlite::memory:".into(),"extended-fixture".into(),"http://127.0.0.1:8080".into(),[23;32],live,#[cfg(feature="redis-cache")] None);
        state.db().exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','extended@test.invalid','unused','unused','unused',?,1)",&[json!(clock::now())]).await.unwrap();
        state.db().exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)",&[json!(openwarp_crypto::hash_token(SESSION)),json!(clock::now())]).await.unwrap();
        state.db().exec("INSERT INTO orgs(id,name,created_at) VALUES('org','extended',?)",&[json!(clock::now())]).await.unwrap();
        state.db().exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')",&[]).await.unwrap();
        let mut f=Self { app:router(state.clone()),state,env:String::new(),_lock:lock };
        let me=f.call(Method::GET,"/api/me",None).await; me.ok(); assert_eq!(me.body["id"],"owner");
        let app=f.call(Method::POST,"/api/orgs/org/apps",Some(json!({"name":"extended"}))).await; app.ok();
        let envs=f.call(Method::GET,&format!("/api/apps/{}/envs",app.body["id"].as_str().unwrap()),None).await; envs.ok();
        f.env=envs.body[0]["id"].as_str().unwrap().into(); f
    }
    async fn call(&self, method:Method, path:&str, body:Option<Value>) -> Resp {
        let mut req=Request::builder().method(method).uri(path).header("authorization",format!("Bearer {}",SESSION)).extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127,0,0,1],43211))));
        let body=if let Some(v)=body { req=req.header("content-type","application/json"); Body::from(v.to_string()) } else { Body::empty() };
        let response=self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap(); let status=response.status().as_u16();
        let text=String::from_utf8(to_bytes(response.into_body(),2*1024*1024).await.unwrap().to_vec()).unwrap();
        Resp { status,body:serde_json::from_str(&text).unwrap_or(Value::Null),text }
    }
    async fn settings(&self, body:Value) -> Resp { self.call(Method::PUT,"/api/orgs/org/ai/settings",Some(body)).await }
    async fn enable(&self, endpoint:&str) { self.settings(json!({"enabled":true,"endpoint":endpoint,"model":"fake-model","allow_metadata":true,"allow_actions":true})).await.ok(); }
    async fn chat(&self) -> Resp { self.call(Method::POST,"/api/orgs/org/ai/chat",Some(json!({"message":"Find configuration names","env_id":self.env}))).await }
    async fn get(&self, suffix:&str) -> Resp { self.call(Method::GET,&format!("/api/orgs/org/ai/{}",suffix),None).await }
}
struct Endpoints(Option<String>);
impl Endpoints { fn set(urls:Value) -> Self { let old=std::env::var("OPENWARP_AI_ENDPOINTS").ok(); std::env::set_var("OPENWARP_AI_ENDPOINTS",urls.to_string()); Self(old) } }
impl Drop for Endpoints { fn drop(&mut self) { match &self.0 { Some(v)=>std::env::set_var("OPENWARP_AI_ENDPOINTS",v),None=>std::env::remove_var("OPENWARP_AI_ENDPOINTS") } } }

#[derive(Clone)]
enum Reply { Success, Redirect(String), Oversized, Blocked }
struct ProviderState { reply:Reply, captured:Mutex<Vec<(HeaderMap,Value)>>, arrived:Notify, release:Semaphore }
struct Provider { endpoint:String, state:Arc<ProviderState>, task:tokio::task::JoinHandle<()> }
impl Drop for Provider { fn drop(&mut self) { self.task.abort(); } }
impl Provider {
    async fn new(reply:Reply) -> Self {
        async fn complete(State(st):State<Arc<ProviderState>>,headers:HeaderMap,Json(body):Json<Value>) -> Response {
            st.captured.lock().unwrap().push((headers,body)); st.arrived.notify_one();
            match &st.reply {
                Reply::Redirect(target)=>(StatusCode::TEMPORARY_REDIRECT,[("location",target.as_str())],"redirect").into_response(),
                Reply::Oversized=>Json(json!({"choices":[{"message":{"content":"OVERSIZED_SENTINEL".repeat(65536)}}]})).into_response(),
                Reply::Success|Reply::Blocked=>{
                    if matches!(st.reply,Reply::Blocked) { let permit=st.release.acquire().await.unwrap(); permit.forget(); }
                    Json(json!({"choices":[{"message":{"content":"Fake provider answer."}}]})).into_response()
                },
            }
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let endpoint=format!("http://{}/v1/chat/completions",listener.local_addr().unwrap());
        let state=Arc::new(ProviderState { reply,captured:Mutex::new(Vec::new()),arrived:Notify::new(),release:Semaphore::new(0) });
        let app=Router::new().route("/v1/chat/completions",post(complete)).with_state(state.clone());
        let task=tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); }); Self { endpoint,state,task }
    }
    fn count(&self) -> usize { self.state.captured.lock().unwrap().len() }
}

#[tokio::test]
async fn endpoint_change_drops_old_key_and_keyless_local_inference_succeeds() {
    let f=Fixture::new().await; let first=Provider::new(Reply::Success).await; let second=Provider::new(Reply::Success).await;
    let _operator=Endpoints::set(json!([first.endpoint,second.endpoint]));
    f.enable(&first.endpoint).await; f.settings(json!({"api_key":KEY})).await.ok(); f.chat().await.ok();
    assert_eq!(first.state.captured.lock().unwrap()[0].0.get("authorization").unwrap(),format!("Bearer {}",KEY).as_str());
    let changed=f.settings(json!({"endpoint":second.endpoint})).await; changed.ok(); assert_eq!(changed.body["has_api_key"],false); assert!(!changed.text.contains(KEY));
    f.chat().await.ok(); assert!(second.state.captured.lock().unwrap()[0].0.get("authorization").is_none(),"old endpoint credential must not reach new destination");
    f.settings(json!({"endpoint":first.endpoint,"api_key":"fake-replacement"})).await.ok(); f.chat().await.ok();
    assert_eq!(first.state.captured.lock().unwrap()[1].0.get("authorization").unwrap(),"Bearer fake-replacement");
}

#[tokio::test]
async fn redirects_never_reach_target_and_oversized_provider_responses_are_rejected() {
    let f=Fixture::new().await; let target=Provider::new(Reply::Success).await; let redirect=Provider::new(Reply::Redirect(target.endpoint.clone())).await; let huge=Provider::new(Reply::Oversized).await;
    let _operator=Endpoints::set(json!([redirect.endpoint,target.endpoint,huge.endpoint]));
    f.enable(&redirect.endpoint).await; f.settings(json!({"api_key":KEY})).await.ok();
    let r=f.chat().await; r.rejected(); assert_eq!(r.status,502); assert!(!r.text.contains(KEY));
    assert_eq!(redirect.count(),1); assert_eq!(target.count(),0,"even an independently allowlisted redirect target must not receive the request or key");
    f.settings(json!({"endpoint":huge.endpoint})).await.ok();
    let r=f.chat().await; r.rejected(); assert_eq!(r.status,502); assert!(r.text.len()<8192,"error must not echo oversized body"); assert!(!r.text.contains("OVERSIZED_SENTINEL"));
    assert_eq!(huge.count(),1);
}

#[tokio::test]
async fn concurrent_inference_and_daily_request_budget_fail_before_outbound_call() {
    let f=Fixture::new().await; let p=Provider::new(Reply::Blocked).await; let _operator=Endpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint).await; f.settings(json!({"request_limit":2})).await.ok();
    let (first,second)=tokio::join!(f.chat(),async {
        tokio::time::timeout(std::time::Duration::from_secs(5),p.state.arrived.notified()).await.expect("first request reached mock");
        let second=f.chat().await; p.state.release.add_permits(1); second
    });
    first.ok(); assert_eq!(second.status,429,"workspace permits only one active inference"); assert_eq!(p.count(),1);
    p.state.release.add_permits(1); f.chat().await.ok(); assert_eq!(p.count(),2,"rejected concurrent request must not consume a daily request slot");
    assert_eq!(f.chat().await.status,429); assert_eq!(p.count(),2,"daily limit denial must precede provider request");
}

#[tokio::test]
async fn reservation_unit_budget_rejects_large_question_without_contacting_provider() {
    let f=Fixture::new().await; let p=Provider::new(Reply::Success).await; let _operator=Endpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint).await; f.settings(json!({"token_limit":1024,"max_output_tokens":64})).await.ok();
    let r=f.call(Method::POST,"/api/orgs/org/ai/chat",Some(json!({"message":"q".repeat(2000),"env_id":f.env}))).await;
    assert_eq!(r.status,429,"request bytes already exceed conservative daily reservation budget"); assert_eq!(p.count(),0);
}

#[tokio::test]
async fn local_value_matching_needs_opt_in_excludes_sealed_values_and_never_infers() {
    let f=Fixture::new().await; let p=Provider::new(Reply::Success).await; let _operator=Endpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint).await; f.settings(json!({"allow_metadata":false})).await.ok();
    f.call(Method::PUT,&format!("/api/envs/{}/secrets",f.env),Some(json!({"secrets":[{"key":"REGULAR","value":PRIVATE},{"key":"SEALED","value":PRIVATE,"type":"sealed"}]}))).await.ok();
    let request=json!({"env_id":f.env,"query":PRIVATE});
    assert_eq!(f.call(Method::POST,"/api/orgs/org/ai/local-search",Some(request.clone())).await.status,403);
    f.settings(json!({"allow_local_search":true})).await.ok();
    let r=f.call(Method::POST,"/api/orgs/org/ai/local-search",Some(request.clone())).await; r.ok(); assert_eq!(r.body["results"].as_array().unwrap().len(),1); assert_eq!(r.body["results"][0]["key"],"REGULAR");
    assert!(!r.text.contains(PRIVATE)); assert!(r.body["results"][0].get("value").is_none());
    f.settings(json!({"allow_local_search":false})).await.ok(); assert_eq!(f.call(Method::POST,"/api/orgs/org/ai/local-search",Some(request)).await.status,403);
    assert_eq!(p.count(),0);
}

#[tokio::test]
async fn integration_plans_only_create_drafts_and_expired_plans_have_no_effects() {
    let f=Fixture::new().await; f.settings(json!({"enabled":true,"allow_actions":true})).await.ok();
    let operations=json!([{"kind":"draft_integration","env_id":f.env,"provider_kind":"webhook","name":"Unconfigured fake draft"}]);
    let plan=f.call(Method::POST,"/api/orgs/org/ai/plans",Some(json!({"operations":operations}))).await; plan.ok();
    let live_path=format!("/api/envs/{}/integrations",f.env);
    let live=f.call(Method::GET,&live_path,None).await; live.ok(); assert_eq!(live.body,json!([]));
    assert_eq!(f.get("drafts").await.body["drafts"],json!([]),"planning creates neither a live integration nor a draft");
    let execute=format!("/api/orgs/org/ai/plans/{}/execute",plan.body["id"].as_str().unwrap());
    f.call(Method::POST,&execute,Some(json!({"confirm":true}))).await.ok();
    let drafts=f.get("drafts").await; drafts.ok(); assert_eq!(drafts.body["drafts"].as_array().unwrap().len(),1); assert_eq!(drafts.body["drafts"][0]["provider_kind"],"webhook");
    assert_eq!(f.call(Method::GET,&live_path,None).await.body,json!([]),"confirming a draft must never activate an integration");
    let plan=f.call(Method::POST,"/api/orgs/org/ai/plans",Some(json!({"operations":[{"kind":"create_folder","env_id":f.env,"path":"/expired-never-created"}]}))).await; plan.ok();
    f.state.db().exec("UPDATE ai_plans SET expires_at=? WHERE id=?",&[json!(clock::now()-1),plan.body["id"].clone()]).await.unwrap();
    let r=f.call(Method::POST,&format!("/api/orgs/org/ai/plans/{}/execute",plan.body["id"].as_str().unwrap()),Some(json!({"confirm":true}))).await; r.rejected(); assert!((400..500).contains(&r.status));
    let folders=f.call(Method::GET,&format!("/api/envs/{}/folders",f.env),None).await; folders.ok(); assert_eq!(folders.body["folders"],json!([]));
}

#[tokio::test]
async fn findings_have_stable_persisted_evidence_and_acknowledgement_exception_state() {
    let f=Fixture::new().await; f.settings(json!({"monitoring_enabled":true})).await.ok();
    for _ in 0..21 { f.call(Method::GET,&format!("/api/envs/{}/secrets",f.env),None).await.ok(); }
    f.state.db().exec("INSERT INTO audit(id,org_id,actor,action,detail,created_at) VALUES('raw-private','org','owner','secret.list',?,?)",&[json!(PRIVATE),json!(clock::now())]).await.unwrap();
    let initial=f.get("findings").await; initial.ok();
    let burst=initial.body["findings"].as_array().unwrap().iter().find(|v| v["rule"]=="read_export_burst").expect("real read burst produces a finding");
    let id=burst["id"].as_str().unwrap().to_string(); assert!(!id.is_empty()); assert!(burst["evidence"].as_array().unwrap().len()>=20);
    for event in burst["evidence"].as_array().unwrap() { assert!(event.get("detail").is_none()); assert!(event.get("credential").is_none()); assert_eq!(event["action"],"secret.list"); }
    assert!(!initial.text.contains(PRIVATE)); assert!(!initial.text.contains(SESSION));
    let again=f.get("findings").await; again.ok(); assert!(again.body["findings"].as_array().unwrap().iter().any(|v| v["id"]==id));
    let path=format!("/api/orgs/org/ai/findings/{}",id);
    f.call(Method::PUT,&path,Some(json!({"status":"acknowledged"}))).await.ok();
    let ack=f.get("findings").await; ack.ok(); assert_eq!(ack.body["findings"].as_array().unwrap().iter().find(|v| v["id"]==id).unwrap()["status"],"acknowledged");
    let expires=clock::now()+3600;
    f.call(Method::PUT,&path,Some(json!({"status":"exception","exception_until":expires,"maintenance_note":"fake planned investigation"}))).await.ok();
    let except=f.get("findings").await; except.ok(); let finding=except.body["findings"].as_array().unwrap().iter().find(|v| v["id"]==id).unwrap(); assert_eq!(finding["status"],"exception"); assert_eq!(finding["exception_until"],expires);
    process_maintenance(&f.state).await;
    f.state.db().exec("UPDATE ai_activity SET created_at=? WHERE org_id='org'",&[json!(clock::now()-1200)]).await.unwrap();
    let history=f.get("findings").await; history.ok(); let persisted=history.body["findings"].as_array().unwrap().iter().find(|v| v["id"]==id).expect("finding survives burst window in monitoring history"); assert_eq!(persisted["status"],"exception"); assert!(!history.text.contains(PRIVATE));
    f.state.db().exec("UPDATE ai_finding_states SET exception_until=? WHERE org_id='org' AND finding_id=?",&[json!(clock::now()-1),json!(id)]).await.unwrap();
    let reopened=f.get("findings").await; reopened.ok(); assert_eq!(reopened.body["findings"].as_array().unwrap().iter().find(|v| v["id"]==id).unwrap()["status"],"open");
}
