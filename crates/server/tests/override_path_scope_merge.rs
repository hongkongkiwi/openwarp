use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
struct Reply { status: u16, body: Value }
impl Reply { fn ok(self) -> Value { assert_eq!(self.status, 200, "HTTP {}: {}", self.status, self.body); self.body } }
struct Fixture { state: S, app: Router, team: String, other: String }
impl Fixture {
    async fn new(role: &str, capabilities: &[&str]) -> Self {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',?)", &[json!(now())]).await.unwrap();
        for (uid, role) in [("owner", "owner"), ("reader", role)] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,'unused','unused','unused',?,1)", &[json!(uid), json!(format!("{}@override-path.invalid", uid)), json!(now())]).await.unwrap();
            db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org',?,?)", &[json!(uid), json!(role)]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&format!("override-path-{}", uid))), json!(uid), json!(now())]).await.unwrap();
        }
        db.exec("INSERT INTO roles(id,org_id,name,permissions) VALUES('reader-role','org','reader',?)", &[json!(json!(["secrets:read"]).to_string())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','app',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES('env','app','env',?,'sse',?)", &[json!(oc::encrypt_symmetric(&[7;32], &[8;32])), json!(now())]).await.unwrap();
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "tests".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature = "redis-cache")] None);
        let app = router(state.clone());
        let mut f = Self { state, app, team: String::new(), other: String::new() };
        f.call("PUT", "/api/envs/env/secrets", "owner", Some(json!({"secrets":[{"key":"TEAM","value":"shared-team","path":"/team/"},{"key":"OTHER","value":"shared-other","path":"/other/"}]}))).await.ok();
        let listed = f.call("GET", "/api/envs/env/secrets", "owner", None).await.ok();
        for item in listed["secrets"].as_array().unwrap() {
            let sid = item["id"].as_str().unwrap().to_string();
            if item["key"] == "TEAM" { f.team = sid.clone(); } else if item["key"] == "OTHER" { f.other = sid.clone(); }
            let aad = format!("ow-secret:v2|env|{}|override:reader", sid);
            let encrypted = oc::encrypt_symmetric_aad(&[8;32], aad.as_bytes(), b"reader-personal");
            f.state.db().exec("INSERT INTO overrides(secret_id,user_id,value_enc) VALUES(?,'reader',?)", &[json!(sid), json!(encrypted)]).await.unwrap();
        }
        assert!(!f.team.is_empty() && !f.other.is_empty());
        // Validate the seeded ciphertext and both direct-ID routes before applying policy.
        for sid in [&f.team, &f.other] {
            assert_eq!(f.call("GET", &format!("/api/secrets/{}/override", sid), "reader", None).await.ok()["value"], "reader-personal");
        }
        f.call("PUT", &format!("/api/envs/env/path-policy/{}", role), "owner", Some(json!({"rules":[{"prefix":"/team/","capabilities":capabilities}]}))).await.ok();
        f
    }
    async fn call(&self, method: &str, path: &str, uid: &str, body: Option<Value>) -> Reply {
        let mut request = Request::builder().method(method).uri(path)
            .extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])))
            .header("cookie", format!("ow_session=override-path-{}", uid));
        let body = if let Some(body) = body { request = request.header("content-type", "application/json"); Body::from(body.to_string()) } else { Body::empty() };
        let response = self.app.clone().oneshot(request.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        Reply { status, body: serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))) }
    }
    async fn stored(&self, sid: &str) -> Option<Value> {
        self.state.db().one("SELECT value_enc FROM overrides WHERE secret_id=? AND user_id='reader'", &[json!(sid)]).await.unwrap().map(|r| r["value_enc"].clone())
    }
}

#[tokio::test]
async fn restricted_reader_can_get_own_override_on_readable_path() {
    let f = Fixture::new("reader", &["read"]).await;
    let body = f.call("GET", &format!("/api/secrets/{}/override", f.team), "reader", None).await.ok();
    assert_eq!(body["key"], "TEAM"); assert_eq!(body["value"], "reader-personal");
}

#[tokio::test]
async fn restricted_reader_can_delete_own_override_on_readable_path_without_shared_write() {
    let f = Fixture::new("reader", &["read"]).await;
    let other_before = f.stored(&f.other).await;
    assert_eq!(f.call("DELETE", &format!("/api/secrets/{}/override", f.team), "reader", None).await.ok()["deleted"], true);
    assert_eq!(f.stored(&f.team).await, None);
    assert_eq!(f.stored(&f.other).await, other_before);
    let listed = f.call("GET", "/api/envs/env/secrets", "reader", None).await.ok();
    assert_eq!(listed["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(listed["secrets"][0]["value"], "shared-team");
}

async fn forbidden_id(method: &str) {
    let f = Fixture::new("developer", &["read"]).await;
    let before = f.stored(&f.other).await;
    assert!(before.is_some());
    let response = f.call(method, &format!("/api/secrets/{}/override", f.other), "reader", None).await;
    let after = f.stored(&f.other).await;
    assert_eq!(after, before, "forbidden direct-ID request must preserve personal override");
    assert_eq!(response.status, 403, "{} forbidden path: {}", method, response.body);
}
#[tokio::test]
async fn restricted_principal_cannot_get_forbidden_override_by_id() { forbidden_id("GET").await; }
#[tokio::test]
async fn restricted_principal_cannot_delete_forbidden_override_by_id() { forbidden_id("DELETE").await; }

async fn set_override(role: &str, capabilities: &[&str], allowed: bool) {
    let f = Fixture::new(role, capabilities).await;
    let before = f.stored(&f.team).await;
    let response = f.call("POST", &format!("/api/secrets/{}/override", f.team), "reader", Some(json!({"secrets":[{"key":"TEAM","value":"replacement-personal"}]}))).await;
    if allowed {
        response.ok();
        let stored = f.stored(&f.team).await.unwrap();
        assert_ne!(Some(stored.clone()), before);
        let aad = format!("ow-secret:v2|env|{}|override:reader", f.team);
        assert_eq!(oc::decrypt_symmetric_aad(&[8;32], aad.as_bytes(), stored.as_str().unwrap()).unwrap(), b"replacement-personal");
        let body = f.call("GET", &format!("/api/secrets/{}/override", f.team), "owner", None).await;
        assert_eq!(body.status, 404, "override belongs only to reader");
    } else {
        assert_eq!(f.stored(&f.team).await, before, "rejected set must preserve personal override");
        assert_eq!(response.status, 403, "restricted override set: {}", response.body);
    }
}
#[tokio::test]
async fn restricted_developer_cannot_set_override_without_path_write() { set_override("developer", &["read"], false).await; }
#[tokio::test]
async fn restricted_reader_cannot_set_override_even_with_path_write() { set_override("reader", &["read","write"], false).await; }
#[tokio::test]
async fn restricted_developer_can_set_override_with_path_write() { set_override("developer", &["read","write"], true).await; }
