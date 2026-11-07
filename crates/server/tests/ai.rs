// AI boundaries use fake data and an in-process router, never a live provider.
use axum::{body::{to_bytes, Body}, extract::State, http::{HeaderMap, Method, Request}, routing::post, Json, Router};
use openwarp_server::{clock, db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OWNER: &str = "ow_fake_ai_owner";
const MEMBER: &str = "ow_fake_ai_member";
const ADMIN: &str = "ow_fake_ai_admin";
const OUTSIDER: &str = "ow_fake_ai_outsider";
const VALUE: &str = "fake-stored-value-never-in-ai-context";
const COMMENT: &str = "fake-private-comment-never-in-ai-context";
const CONFIG: &str = "fake-integration-credential-never-in-ai-context";
const AI_KEY: &str = "fake-ai-provider-key-write-only";

struct Resp { status: u16, text: String, body: Value }
impl Resp {
    fn ok(&self) { assert!((200..300).contains(&self.status), "expected success, got {} {}", self.status, self.text); }
    fn denied(&self) { assert!([401, 403].contains(&self.status), "expected authentication/policy denial, got {} {}", self.status, self.text); }
    fn rejected(&self) { assert!((400..500).contains(&self.status), "expected client error, got {} {}", self.status, self.text); }
}

struct Fixture {
    app: Router, state: S, app_id: String, env: String, restricted: String, foreign_env: String,
    _lock: tokio::sync::MutexGuard<'static, ()>,
}
impl Fixture {
    async fn new() -> Self {
        let lock = TEST_LOCK.lock().await;
        let db = Db::open_memory().await.expect("private migrated database");
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "ai-test".into(), "http://127.0.0.1:8080".into(), [17; 32], live, #[cfg(feature = "redis-cache")] None);
        for (uid, token) in [("owner", OWNER), ("member", MEMBER), ("admin", ADMIN), ("outsider", OUTSIDER)] {
            state.db().exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,'unused','unused','unused',?,1)", &[json!(uid), json!(format!("{}@ai.test.invalid", uid)), json!(clock::now())]).await.unwrap();
            state.db().exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(openwarp_crypto::hash_token(token)), json!(uid), json!(clock::now())]).await.unwrap();
        }
        for org in ["org-a", "org-b"] {
            state.db().exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(org), json!(org), json!(clock::now())]).await.unwrap();
        }
        for (org, uid, role) in [("org-a", "owner", "owner"), ("org-a", "member", "developer"), ("org-a", "admin", "admin"), ("org-b", "owner", "owner"), ("org-b", "outsider", "owner")] {
            state.db().exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(org), json!(uid), json!(role)]).await.unwrap();
        }
        let app = router(state.clone());
        let mut f = Self { app, state, app_id: String::new(), env: String::new(), restricted: String::new(), foreign_env: String::new(), _lock: lock };
        let me = f.call(Method::GET, "/api/me", OWNER, None).await;
        me.ok(); assert_eq!(me.body["id"], "owner", "seeded session must authenticate on an existing route");
        let a = f.call(Method::POST, "/api/orgs/org-a/apps", OWNER, Some(json!({"name":"ai-fixture"}))).await;
        a.ok(); f.app_id = a.body["id"].as_str().unwrap().into();
        let envs = f.call(Method::GET, &format!("/api/apps/{}/envs", f.app_id), OWNER, None).await;
        envs.ok(); f.env = envs.body[0]["id"].as_str().unwrap().into(); f.restricted = envs.body[1]["id"].as_str().unwrap().into();
        let a = f.call(Method::POST, "/api/orgs/org-b/apps", OWNER, Some(json!({"name":"foreign-fixture"}))).await;
        a.ok(); let envs = f.call(Method::GET, &format!("/api/apps/{}/envs", a.body["id"].as_str().unwrap()), OWNER, None).await;
        envs.ok(); f.foreign_env = envs.body[0]["id"].as_str().unwrap().into();
        let r = f.call(Method::PUT, &format!("/api/envs/{}/policy", f.restricted), OWNER, Some(json!({"restricted":true}))).await;
        r.ok();
        f.call(Method::GET, &format!("/api/envs/{}/secrets", f.env), MEMBER, None).await.ok();
        f.call(Method::GET, &format!("/api/envs/{}/secrets", f.restricted), MEMBER, None).await.denied();
        f
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        self.request(method, path, if token.is_empty() { None } else { Some(("authorization", format!("Bearer {}", token))) }, body).await
    }
    async fn request(&self, method: Method, path: &str, auth: Option<(&str, String)>, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(path).extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 43210))));
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
    async fn secret(&self, env: &str, key: &str) {
        self.call(Method::PUT, &format!("/api/envs/{}/secrets", env), OWNER, Some(json!({"secrets":[{"key":key,"value":VALUE,"comment":COMMENT,"path":"/fixture"}]}))).await.ok();
    }
    fn operations(&self, path: &str) -> Value { json!([{"kind":"create_folder","env_id":self.env,"path":path}]) }
    async fn plan(&self, token: &str, path: &str) -> String {
        let ops = self.operations(path);
        let r = self.call(Method::POST, "/api/orgs/org-a/ai/plans", token, Some(json!({"operations":ops}))).await;
        r.ok(); assert_eq!(r.body["status"], "pending"); assert_eq!(r.body["operations"], ops);
        assert!(r.body["expires_at"].as_i64().expect("Unix expiry") > clock::now(), "new plan already expired");
        r.body["id"].as_str().expect("plan id").into()
    }
    async fn execute(&self, org: &str, plan: &str, token: &str, body: Value) -> Resp {
        self.call(Method::POST, &format!("/api/orgs/{}/ai/plans/{}/execute", org, plan), token, Some(body)).await
    }
    async fn folders(&self) -> Value {
        let r = self.call(Method::GET, &format!("/api/envs/{}/folders", self.env), OWNER, None).await;
        r.ok(); r.body
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

fn metadata_only(value: &Value) {
    match value {
        Value::Object(map) => for (key, v) in map {
            assert!(!["value", "value_enc", "comment", "comment_enc", "config", "config_enc", "wrapped_key", "env_key_wrapped"].contains(&key.as_str()), "AI metadata contains forbidden field {}", key);
            metadata_only(v);
        },
        Value::Array(values) => for v in values { metadata_only(v); },
        _ => (),
    }
    let text = value.to_string();
    for marker in [VALUE, COMMENT, CONFIG, AI_KEY] { assert!(!text.contains(marker), "AI response/context contains stored private data"); }
}

#[tokio::test]
async fn fixture_authenticates_existing_routes_and_enforces_environment_policy() {
    let f = Fixture::new().await;
    f.request(Method::GET, "/api/me", Some(("cookie", format!("ow_session={}", OWNER))), None).await.ok();
    f.call(Method::GET, "/api/me", "", None).await.denied();
    f.call(Method::GET, "/api/orgs/org-a/apps", OUTSIDER, None).await.denied();
}

#[tokio::test]
async fn ai_defaults_opt_out_and_local_findings_remain_admin_only() {
    let f = Fixture::new().await;
    let r = f.call(Method::GET, "/api/orgs/org-a/ai/settings", OWNER, None).await;
    r.ok();
    for field in ["enabled", "allow_metadata", "allow_actions"] { assert_eq!(r.body[field], false, "{} must default off", field); }
    assert!(r.body.get("api_key").is_none(), "provider key is write-only");
    f.request(Method::GET, "/api/orgs/org-a/ai/settings", Some(("cookie", format!("ow_session={}", OWNER))), None).await.ok();
    f.call(Method::GET, "/api/orgs/org-a/ai/search?q=MATCH", OWNER, None).await.denied();
    f.call(Method::POST, "/api/orgs/org-a/ai/chat", OWNER, Some(json!({"message":"Find MATCH"}))).await.denied();
    f.call(Method::POST, "/api/orgs/org-a/ai/plans", OWNER, Some(json!({"operations":f.operations("/disabled")}))).await.denied();
    let findings = f.call(Method::GET, "/api/orgs/org-a/ai/findings", OWNER, None).await;
    findings.ok(); metadata_only(&findings.body);
    f.call(Method::GET, "/api/orgs/org-a/ai/findings", MEMBER, None).await.denied();
    f.call(Method::GET, "/api/orgs/org-a/ai/findings", OUTSIDER, None).await.denied();
}

#[tokio::test]
async fn settings_require_admin_exact_operator_endpoint_and_never_return_api_key() {
    let f = Fixture::new().await;
    let provider = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([provider.endpoint]));
    for endpoint in [format!("{}/extra", provider.endpoint), format!("{}?redirect=elsewhere", provider.endpoint), "http://127.0.0.1:1/v1/chat/completions".into()] {
        let r = f.settings(json!({"enabled":true,"endpoint":endpoint,"model":"fake-model","api_key":AI_KEY})).await;
        r.rejected(); assert_ne!(r.status, 404, "settings route missing"); assert!(!r.text.contains(AI_KEY));
    }
    f.call(Method::PUT, "/api/orgs/org-a/ai/settings", MEMBER, Some(json!({"enabled":true,"endpoint":provider.endpoint,"model":"fake-model"}))).await.denied();
    f.enable(&provider.endpoint, false, false).await;
    let r = f.call(Method::GET, "/api/orgs/org-a/ai/settings", MEMBER, None).await;
    r.ok(); assert_eq!(r.body["endpoint"], provider.endpoint); assert_eq!(r.body["model"], "fake-model");
    assert_eq!(r.body["allow_metadata"], false); assert_eq!(r.body["allow_actions"], false);
    assert!(r.body.get("api_key").is_none()); assert!(!r.text.contains(AI_KEY));
    f.call(Method::GET, "/api/orgs/org-a/ai/settings", OUTSIDER, None).await.denied();
    f.call(Method::POST, "/api/orgs/org-a/ai/chat", OWNER, Some(json!({"message":"hello"}))).await.denied();
    f.call(Method::POST, "/api/orgs/org-a/ai/plans", OWNER, Some(json!({"operations":f.operations("/no-consent")}))).await.denied();
    assert!(provider.requests.lock().unwrap().is_empty(), "metadata consent gate must precede outbound request");
}

#[tokio::test]
async fn all_ai_routes_reject_service_machine_and_oauth_credentials() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint, true, true).await;
    for (token, kind) in [("ow_fake_ai_service", "service"), ("ow_fake_ai_machine", "machine")] {
        f.state.db().exec("INSERT INTO tokens(id,org_id,name,token_hash,role,created_at,created_by,kind) VALUES(?, 'org-a', ?, ?, 'admin', ?, 'owner', ?)", &[json!(kind), json!(kind), json!(openwarp_crypto::hash_token(token)), json!(clock::now()), json!(kind)]).await.unwrap();
    }
    let oauth = "ow_fake_ai_oauth";
    f.state.db().exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,kind,expires_at,created_at) VALUES(?,'fake-client','owner','*','access',?,?)", &[json!(openwarp_crypto::hash_token(oauth)), json!(clock::now()+3600), json!(clock::now())]).await.unwrap();
    let pid = f.plan(OWNER, "/session-only").await;
    for token in ["", "ow_fake_ai_service", "ow_fake_ai_machine", oauth] {
        if !token.is_empty() { f.call(Method::GET, "/api/me", token, None).await.ok(); }
        for (method, path, body) in [
            (Method::GET, "/api/orgs/org-a/ai/settings".to_string(), None),
            (Method::PUT, "/api/orgs/org-a/ai/settings".into(), Some(json!({"enabled":true,"endpoint":p.endpoint,"model":"fake-model"}))),
            (Method::GET, "/api/orgs/org-a/ai/search?q=MATCH".into(), None),
            (Method::POST, "/api/orgs/org-a/ai/chat".into(), Some(json!({"message":"hello"}))),
            (Method::GET, "/api/orgs/org-a/ai/findings".into(), None),
            (Method::POST, "/api/orgs/org-a/ai/plans".into(), Some(json!({"operations":f.operations("/token-denied")}))),
            (Method::POST, format!("/api/orgs/org-a/ai/plans/{}/execute", pid), Some(json!({"confirm":true}))),
        ] { f.call(method, &path, token, body).await.denied(); }
    }
    assert!(p.requests.lock().unwrap().is_empty());
    f.execute("org-a", &pid, OWNER, json!({"confirm":true})).await.ok();
}

#[tokio::test]
async fn search_and_chat_include_only_authorized_sse_metadata() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.secret(&f.env, "MATCH_PUBLIC").await;
    f.secret(&f.restricted, "MATCH_RESTRICTED").await;
    f.secret(&f.foreign_env, "MATCH_FOREIGN").await;
    for mode in ["e2e", "delegated"] {
        f.state.db().exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,'',?,?)", &[json!(mode), json!(f.app_id), json!(mode), json!(mode), json!(clock::now())]).await.unwrap();
        f.state.db().exec("INSERT INTO secrets(id,env_id,path,key_enc,key_hash,value_enc,e2e,updated_at) VALUES(?,?,?,'opaque-client-key',?,'opaque-client-value',1,?)", &[json!(format!("secret-{}", mode)), json!(mode), json!(format!("/MATCH_{}", mode)), json!(mode), json!(clock::now())]).await.unwrap();
    }
    let config = f.call(Method::POST, &format!("/api/envs/{}/integrations", f.env), OWNER, Some(json!({"kind":"webhook","name":"fake","config":{"url":p.endpoint,"token":CONFIG}}))).await;
    config.ok();
    f.enable(&p.endpoint, true, false).await;
    for (token, expected) in [(MEMBER, vec!["MATCH_PUBLIC"]), (OWNER, vec!["MATCH_PUBLIC", "MATCH_RESTRICTED"])] {
        let r = f.call(Method::GET, "/api/orgs/org-a/ai/search?q=MATCH", token, None).await;
        r.ok(); metadata_only(&r.body);
        let results = r.body["results"].as_array().expect("metadata result list");
        let mut keys: Vec<&str> = results.iter().map(|v| v["key"].as_str().unwrap()).collect(); keys.sort_unstable();
        assert_eq!(keys, expected, "workspace, restricted, and encryption-mode filters");
        for result in results {
            assert!(!result["id"].as_str().unwrap().is_empty()); assert_eq!(result["app_id"], f.app_id);
            assert_eq!(result["path"], "/fixture"); assert!(result["env_id"] == f.env || result["env_id"] == f.restricted);
        }
    }
    f.call(Method::GET, "/api/orgs/org-a/ai/search?q=MATCH", OUTSIDER, None).await.denied();
    for env in [&f.restricted, &f.foreign_env] {
        f.call(Method::POST, "/api/orgs/org-a/ai/chat", MEMBER, Some(json!({"message":"Find MATCH","env_id":env}))).await.denied();
    }
    assert!(p.requests.lock().unwrap().is_empty(), "unauthorized env must not reach provider");
    let r = f.call(Method::POST, "/api/orgs/org-a/ai/chat", MEMBER, Some(json!({"message":"Find MATCH","env_id":f.env}))).await;
    r.ok(); metadata_only(&r.body);
    let captured = p.requests.lock().unwrap(); assert_eq!(captured.len(), 1, "must use fake provider");
    let (headers, body) = &captured[0];
    assert_eq!(headers.get("authorization").unwrap(), format!("Bearer {}", AI_KEY).as_str());
    assert_eq!(body["model"], "fake-model"); metadata_only(body);
    let text = body.to_string(); assert!(text.contains("MATCH_PUBLIC"), "authorized metadata must reach provider");
    for marker in ["MATCH_RESTRICTED", "MATCH_FOREIGN", "/MATCH_e2e", "/MATCH_delegated", "opaque-client-value"] { assert!(!text.contains(marker), "provider received excluded metadata"); }
}

#[tokio::test]
async fn plans_bind_stored_operations_actor_org_confirmation_and_one_time_claim() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint, false, true).await;
    for env in [&f.restricted, &f.foreign_env] {
        f.call(Method::POST, "/api/orgs/org-a/ai/plans", MEMBER, Some(json!({"operations":[{"kind":"create_folder","env_id":env,"path":"/denied"}]}))).await.denied();
    }
    let pid = f.plan(OWNER, "/confirmed-only").await;
    let before = f.folders().await;
    assert!(!before.to_string().contains("/confirmed-only"), "planning must not mutate folders");
    f.execute("org-a", &pid, ADMIN, json!({"confirm":true})).await.rejected();
    f.execute("org-b", &pid, OWNER, json!({"confirm":true})).await.rejected();
    for body in [json!({}), json!({"confirm":false}), json!({"confirm":true,"operations":f.operations("/tampered")}), json!({"confirm":true,"unexpected":true})] {
        f.execute("org-a", &pid, OWNER, body).await.rejected();
        assert_eq!(f.folders().await, before, "rejected execute body must not mutate");
    }
    let (first, second) = tokio::join!(f.execute("org-a", &pid, OWNER, json!({"confirm":true})), f.execute("org-a", &pid, OWNER, json!({"confirm":true})));
    assert_eq!([&first, &second].iter().filter(|r| (200..300).contains(&r.status)).count(), 1, "exactly one concurrent execute must claim the plan: {} / {}", first.status, second.status);
    if first.status >= 400 { first.rejected(); } else { second.rejected(); }
    let after = f.folders().await;
    assert!(after.to_string().contains("/confirmed-only")); assert!(!after.to_string().contains("/tampered"));
    f.execute("org-a", &pid, OWNER, json!({"confirm":true})).await.rejected();
    assert_eq!(f.folders().await, after, "replay must not mutate");
    assert!(p.requests.lock().unwrap().is_empty(), "explicit plans need no model call");
}

#[tokio::test]
async fn execute_rechecks_action_consent_environment_policy_and_current_permissions() {
    let f = Fixture::new().await;
    let p = Provider::new().await;
    let _operator = OperatorEndpoints::set(json!([p.endpoint]));
    f.enable(&p.endpoint, false, true).await;
    for (case, path) in [("consent", "/revoked-consent"), ("disabled", "/revoked-enabled"), ("policy", "/revoked-env"), ("role", "/revoked-role"), ("membership", "/revoked-member")] {
        let pid = f.plan(MEMBER, path).await;
        let before = f.folders().await;
        match case {
            "consent" => f.settings(json!({"allow_actions":false})).await.ok(),
            "disabled" => f.settings(json!({"enabled":false})).await.ok(),
            "policy" => f.call(Method::PUT, &format!("/api/envs/{}/policy", f.env), OWNER, Some(json!({"restricted":true}))).await.ok(),
            "role" => {
                f.call(Method::POST, "/api/orgs/org-a/roles", OWNER, Some(json!({"name":"ai-reader","permissions":["secrets:read"]}))).await.ok();
                f.call(Method::PATCH, "/api/orgs/org-a/members/member", OWNER, Some(json!({"role":"ai-reader"}))).await.ok();
            },
            "membership" => f.call(Method::DELETE, "/api/orgs/org-a/members/member", OWNER, None).await.ok(),
            _ => unreachable!(),
        }
        f.execute("org-a", &pid, MEMBER, json!({"confirm":true})).await.denied();
        assert_eq!(f.folders().await, before, "revoked execution must not persist a folder");
        match case {
            "consent" | "disabled" => f.enable(&p.endpoint, false, true).await,
            "policy" => f.call(Method::PUT, &format!("/api/envs/{}/policy", f.env), OWNER, Some(json!({"restricted":false}))).await.ok(),
            "role" => {
                f.call(Method::POST, "/api/orgs/org-a/ai/plans", MEMBER, Some(json!({"operations":f.operations("/reader-denied")}))).await.denied();
                f.call(Method::PATCH, "/api/orgs/org-a/members/member", OWNER, Some(json!({"role":"developer"}))).await.ok();
            },
            _ => (),
        }
    }
}
