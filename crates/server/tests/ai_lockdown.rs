// AI lockdown boundaries: workspace and project emergency lockdowns halt AI
// settings, context, search, chat, plans and folders without any provider call,
// and restoration resumes them. Background monitoring must pause too.
use axum::{body::{to_bytes, Body}, extract::State, http::{HeaderMap, Method, Request}, routing::post, Json, Router};
use openwarp_server::{clock, db::{self, Db}, new_state, process_maintenance, router, S};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OWNER: &str = "ow_ai_lock_owner";
const MEMBER: &str = "ow_ai_lock_member";
const ADMIN: &str = "ow_ai_lock_admin";
const OUTSIDER: &str = "ow_ai_lock_outsider";
const AI_KEY: &str = "fake-ai-provider-key-write-only";

struct Resp { status: u16, text: String, body: Value }
impl Resp {
    fn ok(&self) { assert!((200..300).contains(&self.status), "expected success, got {} {}", self.status, self.text); }
    fn locked(&self) { assert_eq!(self.status, 403, "expected 403 lockdown, got {} {}", self.status, self.text); }
}

struct Fixture {
    app: Router, app_id: String, env: String,
    _lock: tokio::sync::MutexGuard<'static, ()>,
}
impl Fixture {
    async fn new() -> Self {
        let lock = TEST_LOCK.lock().await;
        let db = Db::open_memory().await.expect("private migrated database");
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "ai-lockdown".into(), "http://127.0.0.1:8080".into(), [17; 32], live, #[cfg(feature = "redis-cache")] None);
        for (uid, token) in [("owner", OWNER), ("member", MEMBER), ("admin", ADMIN), ("outsider", OUTSIDER)] {
            state.db().exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,'unused','unused','unused',?,1)", &[json!(uid), json!(format!("{}@ai-lockdown.invalid", uid)), json!(clock::now())]).await.unwrap();
            state.db().exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(openwarp_crypto::hash_token(token)), json!(uid), json!(clock::now())]).await.unwrap();
        }
        for org in ["org-a", "org-b"] {
            state.db().exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(org), json!(org), json!(clock::now())]).await.unwrap();
        }
        for (org, uid, role) in [("org-a", "owner", "owner"), ("org-a", "member", "developer"), ("org-a", "admin", "admin"), ("org-b", "owner", "owner"), ("org-b", "outsider", "owner")] {
            state.db().exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(org), json!(uid), json!(role)]).await.unwrap();
        }
        let app = router(state.clone());
        let mut f = Self { app, app_id: String::new(), env: String::new(), _lock: lock };
        let me = f.call(Method::GET, "/api/me", OWNER, None).await;
        me.ok(); assert_eq!(me.body["id"], "owner", "seeded session must authenticate on an existing route");
        let a = f.call(Method::POST, "/api/orgs/org-a/apps", OWNER, Some(json!({"name":"ai-lockdown"}))).await;
        a.ok(); f.app_id = a.body["id"].as_str().unwrap().into();
        let envs = f.call(Method::GET, &format!("/api/apps/{}/envs", f.app_id), OWNER, None).await;
        envs.ok(); f.env = envs.body[0]["id"].as_str().unwrap().into();
        f
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        self.request(method, path, if token.is_empty() { None } else { Some(("authorization", format!("Bearer {}", token))) }, body).await
    }
    async fn cookie(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        self.request(method, path, if token.is_empty() { None } else { Some(("cookie", format!("ow_session={}", token))) }, body).await
    }
    async fn request(&self, method: Method, path: &str, auth: Option<(&str, String)>, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(path).extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 43220))));
        if let Some((key, value)) = auth { req = req.header(key, value); }
        let body = match body { Some(b) => { req = req.header("content-type", "application/json"); Body::from(b.to_string()) }, None => Body::empty() };
        let response = self.app.clone().oneshot(req.body(body).unwrap()).await.expect("router request");
        let status = response.status().as_u16();
        let text = String::from_utf8(to_bytes(response.into_body(), 2 * 1024 * 1024).await.unwrap().to_vec()).unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body }
    }
    async fn settings(&self, body: Value) -> Resp { self.call(Method::PUT, "/api/orgs/org-a/ai/settings", OWNER, Some(body)).await }
    async fn enable(&self, endpoint: &str, metadata: bool, actions: bool) {
        let r = self.settings(json!({"enabled":true,"endpoint":endpoint,"model":"fake-model","api_key":AI_KEY,"allow_metadata":metadata,"allow_actions":actions})).await;
        r.ok(); assert!(!r.text.contains(AI_KEY), "settings write response leaked provider key");
    }
    fn operations(&self, path: &str) -> Value { json!([{"kind":"create_folder","env_id":self.env,"path":path}]) }
    async fn plan(&self, token: &str, path: &str) -> String {
        let ops = self.operations(path);
        let r = self.call(Method::POST, "/api/orgs/org-a/ai/plans", token, Some(json!({"operations":ops}))).await;
        r.ok(); assert_eq!(r.body["status"], "pending"); assert_eq!(r.body["operations"], ops);
        r.body["id"].as_str().expect("plan id").into()
    }
    async fn execute(&self, org: &str, plan: &str, token: &str, body: Value) -> Resp {
        self.call(Method::POST, &format!("/api/orgs/{}/ai/plans/{}/execute", org, plan), token, Some(body)).await
    }
    async fn folders(&self) -> Value {
        let r = self.call(Method::GET, &format!("/api/envs/{}/folders", self.env), OWNER, None).await;
        r.ok(); r.body
    }
    async fn lock_org(&self, locked: bool) {
        let r = self.cookie(Method::PUT, "/api/orgs/org-a/emergency", OWNER, Some(json!({"locked":locked}))).await;
        r.ok(); assert_eq!(r.body["locked"], json!(locked), "workspace emergency transition");
    }
    async fn lock_app(&self, app: &str, locked: bool) {
        let r = self.cookie(Method::PUT, &format!("/api/apps/{}/emergency", app), OWNER, Some(json!({"locked":locked}))).await;
        r.ok(); assert_eq!(r.body["locked"], json!(locked), "project emergency transition");
    }
}

struct OperatorEndpoints(Option<String>);
impl OperatorEndpoints {
    fn set(endpoints: Value) -> Self {
        let old = std::env::var("OPENWARP_AI_ENDPOINTS").ok();
        std::env::set_var("OPENWARP_AI_ENDPOINTS", endpoints.to_string()); Self(old)
    }
}
impl Drop for OperatorEndpoints {
    fn drop(&mut self) { match &self.0 { Some(v) => std::env::set_var("OPENWARP_AI_ENDPOINTS", v), None => std::env::remove_var("OPENWARP_AI_ENDPOINTS") } }
}

type Captures = Arc<Mutex<Vec<(HeaderMap, Value)>>>;
struct Provider { endpoint: String, requests: Captures, task: tokio::task::JoinHandle<()> }
impl Drop for Provider { fn drop(&mut self) { self.task.abort(); } }
impl Provider {
    async fn new() -> Self {
        async fn complete(State(capture): State<Captures>, h: HeaderMap, Json(body): Json<Value>) -> Json<Value> {
            capture.lock().unwrap().push((h, body));
            Json(json!({"id":"fake-completion","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Fixture metadata only."},"finish_reason":"stop"}]}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/chat/completions", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route("/v1/chat/completions", post(complete)).with_state(requests.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { endpoint, requests, task }
    }
}

async fn reset_monitoring(st: &S) {
    st.db().exec("DELETE FROM instance_leases WHERE name='ai-monitoring'", &[]).await.unwrap();
    st.db().exec("DELETE FROM meta WHERE k='ai:monitoring_cursor'", &[]).await.unwrap();
}
async fn background(st: &S, org: &str) -> Option<String> {
    st.db().one("SELECT v FROM meta WHERE k=?", &[json!(format!("ai:background:{}", org))]).await.unwrap().map(|r| db::s(&r, "v"))
}

#[tokio::test]
async fn workspace_lockdown_blocks_ai_and_folders_then_restores() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint, true, true).await;
    f.call(Method::POST, "/api/orgs/org-a/ai/chat", OWNER, Some(json!({"message":"Find MATCH","env_id":f.env}))).await.ok();
    assert_eq!(p.requests.lock().unwrap().len(), 1, "baseline inference must reach the fake provider");
    f.lock_org(true).await;
    for (method, path, body) in [
        (Method::GET, "/api/orgs/org-a/ai/settings".to_string(), None),
        (Method::GET, "/api/orgs/org-a/ai/context".to_string(), None),
        (Method::GET, "/api/orgs/org-a/ai/search?q=MATCH".to_string(), None),
        (Method::POST, "/api/orgs/org-a/ai/chat".to_string(), Some(json!({"message":"Find MATCH","env_id":f.env}))),
        (Method::POST, "/api/orgs/org-a/ai/plans".to_string(), Some(json!({"operations":f.operations("/locked")}))),
        (Method::GET, "/api/orgs/org-a/ai/findings".to_string(), None),
    ] {
        f.call(method.clone(), &path, OWNER, body.clone()).await.locked();
        f.cookie(method, &path, OWNER, body).await.locked();
    }
    f.call(Method::GET, &format!("/api/envs/{}/folders", f.env), OWNER, None).await.locked();
    f.cookie(Method::GET, &format!("/api/envs/{}/folders", f.env), OWNER, None).await.locked();
    assert_eq!(p.requests.lock().unwrap().len(), 1, "lockdown must precede any outbound inference request");
    f.call(Method::GET, "/api/orgs/org-b/ai/settings", OWNER, None).await.ok();
    f.lock_org(false).await;
    f.call(Method::POST, "/api/orgs/org-a/ai/chat", OWNER, Some(json!({"message":"Find MATCH","env_id":f.env}))).await.ok();
    assert_eq!(p.requests.lock().unwrap().len(), 2, "restoration must resume inference");
}

#[tokio::test]
async fn project_lockdown_blocks_org_ai_and_its_folders_without_provider_calls() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint, true, true).await;
    let a = f.call(Method::POST, "/api/orgs/org-a/apps", OWNER, Some(json!({"name":"sibling"}))).await;
    a.ok(); let sibling_app = a.body["id"].as_str().unwrap().to_string();
    let envs = f.call(Method::GET, &format!("/api/apps/{}/envs", sibling_app), OWNER, None).await;
    envs.ok(); let sibling_env = envs.body[0]["id"].as_str().unwrap().to_string();
    f.lock_app(&f.app_id, true).await;
    // A single locked project halts the whole workspace's AI surface.
    f.call(Method::POST, "/api/orgs/org-a/ai/chat", OWNER, Some(json!({"message":"Find MATCH","env_id":f.env}))).await.locked();
    f.call(Method::GET, "/api/orgs/org-a/ai/settings", OWNER, None).await.locked();
    // The locked project's folders are halted, but a sibling project stays available.
    f.call(Method::GET, &format!("/api/envs/{}/folders", f.env), OWNER, None).await.locked();
    f.cookie(Method::GET, &format!("/api/envs/{}/folders", f.env), OWNER, None).await.locked();
    f.call(Method::GET, &format!("/api/envs/{}/folders", sibling_env), OWNER, None).await.ok();
    assert!(p.requests.lock().unwrap().is_empty(), "project lockdown must precede inference");
    f.lock_app(&f.app_id, false).await;
    f.call(Method::POST, "/api/orgs/org-a/ai/chat", OWNER, Some(json!({"message":"Find MATCH","env_id":f.env}))).await.ok();
    assert_eq!(p.requests.lock().unwrap().len(), 1, "restoration must resume inference");
}

#[tokio::test]
async fn preexisting_plan_cannot_execute_while_locked_and_completes_after_restore() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint, false, true).await;
    let pid = f.plan(OWNER, "/lockdown-folder").await;
    let before = f.folders().await;
    assert!(!before.to_string().contains("/lockdown-folder"), "planning must not mutate folders");
    f.lock_org(true).await;
    f.execute("org-a", &pid, OWNER, json!({"confirm":true})).await.locked();
    f.lock_org(false).await;
    let after = f.folders().await;
    assert!(!after.to_string().contains("/lockdown-folder"), "a blocked execute must not persist a folder");
    f.execute("org-a", &pid, OWNER, json!({"confirm":true})).await.ok();
    let done = f.folders().await;
    assert!(done.to_string().contains("/lockdown-folder"), "restoration must let the preexisting plan complete");
}

#[tokio::test]
async fn background_maintenance_skips_locked_workspace_and_locked_project() {
    let _lock = TEST_LOCK.lock().await;
    let db = Db::open_memory().await.unwrap();
    let (live, _) = tokio::sync::broadcast::channel(16);
    let st = new_state(db, "sqlite::memory:".into(), "ai-maintenance".into(), "http://127.0.0.1:8080".into(), [17; 32], live, #[cfg(feature = "redis-cache")] None);
    st.db().exec("INSERT INTO orgs(id,name,created_at) VALUES('org-a','org-a',?)", &[json!(clock::now())]).await.unwrap();
    st.db().exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app-a','org-a','app-a',?)", &[json!(clock::now())]).await.unwrap();
    st.db().exec("INSERT INTO ai_settings(org_id,settings,key_enc,updated_at) VALUES('org-a',?,'',?)", &[json!(r#"{"monitoring_enabled":true}"#), json!(clock::now())]).await.unwrap();
    process_maintenance(&st).await;
    let first = background(&st, "org-a").await.expect("unlocked monitoring must record a timestamp");
    assert!(first.parse::<i64>().is_ok(), "unlocked timestamp must be numeric: {}", first);
    // Workspace lockdown must pause the background timestamp.
    st.db().exec("UPDATE orgs SET emergency_locked=1 WHERE id='org-a'", &[]).await.unwrap();
    st.db().exec("UPDATE meta SET v='777' WHERE k='ai:background:org-a'", &[]).await.unwrap();
    reset_monitoring(&st).await;
    process_maintenance(&st).await;
    assert_eq!(background(&st, "org-a").await.as_deref(), Some("777"), "workspace lockdown must pause background monitoring");
    // A single locked project must also pause it.
    st.db().exec("UPDATE orgs SET emergency_locked=0 WHERE id='org-a'", &[]).await.unwrap();
    st.db().exec("UPDATE apps SET emergency_locked=1 WHERE id='app-a'", &[]).await.unwrap();
    reset_monitoring(&st).await;
    process_maintenance(&st).await;
    assert_eq!(background(&st, "org-a").await.as_deref(), Some("777"), "any locked project must pause background monitoring");
    // Full restoration must resume it.
    st.db().exec("UPDATE apps SET emergency_locked=0 WHERE id='app-a'", &[]).await.unwrap();
    reset_monitoring(&st).await;
    process_maintenance(&st).await;
    let restored = background(&st, "org-a").await.expect("restored monitoring must record a timestamp");
    assert!(restored.parse::<i64>().is_ok() && restored != "777", "restoration must resume background monitoring: {}", restored);
}
