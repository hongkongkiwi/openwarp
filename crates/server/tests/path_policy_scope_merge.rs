use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const PATH: &str = "/api/envs/env/path-policy/developer";
const SESSION: &str = "path-policy-owner-session";
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn policy() -> Value { json!({"rules":[{"prefix":"/restricted/","capabilities":["read"]}]}) }
fn replacement() -> Value { json!({"rules":[{"prefix":"/","capabilities":["read","write","delete"]}]}) }
struct Reply { status: u16, body: Value }
impl Reply {
    fn ok(self) -> Value { assert_eq!(self.status, 200, "HTTP {}: {}", self.status, self.body); self.body }
}
struct Fixture { state: S, app: Router }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','path-policy@test.invalid','unused','unused','unused',?,1)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token(SESSION)), json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','app',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES('env','app','env',?,'sse',?)", &[json!(oc::encrypt_symmetric(&[7;32], &[8;32])), json!(now())]).await.unwrap();
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "tests".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature = "redis-cache")] None);
        let app = router(state.clone());
        Self { state, app }
    }
    async fn credential(&self, kind: &str, scope: &str) -> String {
        let token = format!("path-policy-{}-{}", kind, scope.replace(' ', "-"));
        if kind == "oauth" {
            self.state.db().exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,expires_at,created_at,resource) VALUES(?,'path-policy-test','owner',?,?,?,'https://openwarp.test')", &[json!(oc::hash_token(&token)), json!(scope), json!(now()+300), json!(now())]).await.unwrap();
        } else {
            assert_eq!(kind, "service");
            self.state.db().exec("INSERT INTO tokens(id,org_id,name,token_hash,scopes,created_at,created_by) VALUES(?,'org',?,?,?,?,'owner')", &[json!(&token), json!(&token), json!(oc::hash_token(&token)), json!(scope), json!(now())]).await.unwrap();
        }
        token
    }
    async fn call(&self, method: &str, token: Option<&str>, body: Option<Value>) -> Reply {
        let mut request = Request::builder().method(method).uri(PATH).extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])));
        request = if let Some(token) = token { request.header("authorization", format!("Bearer {}", token)) }
            else { request.header("cookie", format!("ow_session={}", SESSION)) };
        let body = if let Some(body) = body { request = request.header("content-type", "application/json"); Body::from(body.to_string()) } else { Body::empty() };
        let response = self.app.clone().oneshot(request.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
        Reply { status, body }
    }
    async fn stored(&self) -> Value {
        let row = self.state.db().one("SELECT rules FROM path_policies WHERE env_id='env' AND role='developer'", &[]).await.unwrap();
        row.map(|r| json!({"rules":serde_json::from_str::<Value>(r["rules"].as_str().unwrap()).unwrap()})).unwrap_or(Value::Null)
    }
}

async fn allowed_crud(kind: Option<&str>) {
    let f = Fixture::new().await;
    let token = match kind { Some(kind) => Some(f.credential(kind, "org:admin secrets:read secrets:write").await), None => None };
    let token = token.as_deref();
    assert_eq!(f.call("PUT", token, Some(policy())).await.ok(), policy());
    assert_eq!(f.stored().await, policy());
    assert_eq!(f.call("GET", token, None).await.ok(), policy());
    assert_eq!(f.call("PUT", token, Some(replacement())).await.ok(), replacement());
    assert_eq!(f.stored().await, replacement());
    assert_eq!(f.call("DELETE", token, None).await.ok(), json!({"ok":true}));
    assert_eq!(f.stored().await, Value::Null);
    assert_eq!(f.call("GET", token, None).await.ok(), Value::Null);
}

async fn denied_without_admin(kind: &str, method: &str) {
    let f = Fixture::new().await;
    let mut violations = Vec::new();
    // Read/write consent also catches GET escaping through the inherited read gate.
    for scope in ["secrets:write", "secrets:read secrets:write"] {
        assert_eq!(f.call("PUT", None, Some(policy())).await.ok(), policy());
        let before = f.stored().await;
        assert_eq!(before, policy());
        let token = f.credential(kind, scope).await;
        let body = if method == "PUT" { Some(replacement()) } else { None };
        let response = f.call(method, Some(&token), body).await;
        if response.status != 403 {
            violations.push(format!("{} {} with {:?} returned {}, expected 403: {}", kind, method, scope, response.status, response.body));
        }
        let after = f.stored().await;
        if after != before { violations.push(format!("{} {} with {:?} changed policy: {} -> {}", kind, method, scope, before, after)); }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[tokio::test]
async fn owner_browser_session_can_manage_path_policy() { allowed_crud(None).await; }
#[tokio::test]
async fn owner_oauth_with_org_admin_can_manage_path_policy() { allowed_crud(Some("oauth")).await; }
#[tokio::test]
async fn owner_service_with_org_admin_can_manage_path_policy() { allowed_crud(Some("service")).await; }
#[tokio::test]
async fn owner_oauth_without_org_admin_cannot_get_path_policy() { denied_without_admin("oauth", "GET").await; }
#[tokio::test]
async fn owner_oauth_without_org_admin_cannot_put_path_policy() { denied_without_admin("oauth", "PUT").await; }
#[tokio::test]
async fn owner_oauth_without_org_admin_cannot_delete_path_policy() { denied_without_admin("oauth", "DELETE").await; }
#[tokio::test]
async fn owner_service_without_org_admin_cannot_get_path_policy() { denied_without_admin("service", "GET").await; }
#[tokio::test]
async fn owner_service_without_org_admin_cannot_put_path_policy() { denied_without_admin("service", "PUT").await; }
#[tokio::test]
async fn owner_service_without_org_admin_cannot_delete_path_policy() { denied_without_admin("service", "DELETE").await; }
