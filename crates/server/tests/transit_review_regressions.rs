use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

struct Reply { status: u16, body: Value, text: String }
impl Reply {
    fn forbidden(self) { assert_eq!(self.status, 403, "HTTP {}: {}", self.status, self.text); }
}

struct Fixture { app: Router, state: S }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("org"), json!("org"), json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','owner@test.invalid','unused','unused','unused',?,1)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token("owner")), json!("owner"), json!(now())]).await.unwrap();
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "tests".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature = "redis-cache")] None);
        let app = router(state.clone());
        Self { app, state }
    }
    async fn call(&self, method: &str, path: &str, user: &str, body: Option<Value>) -> Reply {
        let mut req = Request::builder().method(method).uri(path)
            .extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127, 0, 0, 1])));
        if !user.is_empty() { req = req.header("authorization", format!("Bearer {}", user)); }
        let body = if let Some(body) = body { req = req.header("content-type", "application/json"); Body::from(body.to_string()) } else { Body::empty() };
        let response = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let text = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await.unwrap().to_vec()).unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Reply { status, body, text }
    }
    async fn create_key(&self, name: &str) -> Reply {
        self.call("POST", "/api/orgs/org/transit/keys", "owner", Some(json!({"name": name}))).await
    }
    async fn transit_key_count(&self, name: &str) -> usize {
        self.state.db().query("SELECT id FROM transit_keys WHERE org_id='org' AND name=?", &[json!(name)]).await.unwrap().len()
    }
}

#[tokio::test]
async fn transit_create_rolls_back_key_and_name_when_first_version_insert_fails() {
    let f = Fixture::new().await;
    let control = f.create_key("control").await;
    assert_eq!(control.status, 200, "control create: {}", control.text);
    assert_eq!(control.body["key_version"].as_i64(), Some(1));
    assert_eq!(f.transit_key_count("control").await, 1);
    let duplicate = f.create_key("control").await;
    assert_eq!(duplicate.status, 400, "duplicate name should be rejected: {}", duplicate.text);
    assert_eq!(f.transit_key_count("control").await, 1, "duplicate create added a second row");
    // Simulate a storage failure in the second insert: transit_keys commits first, then this aborts the first transit_versions row.
    f.state.db().exec("CREATE TRIGGER block_transit_versions BEFORE INSERT ON transit_versions BEGIN SELECT RAISE(ABORT, 'forced transit version failure'); END", &[]).await.unwrap();
    let failed = f.create_key("rollback-me").await;
    assert_eq!(failed.status, 400, "blocked create should fail: {}", failed.text);
    assert_eq!(f.transit_key_count("rollback-me").await, 0, "failed create left an orphan transit key");
    f.state.db().exec("DROP TRIGGER block_transit_versions", &[]).await.unwrap();
    let retried = f.create_key("rollback-me").await;
    assert_eq!(retried.status, 200, "name still reserved after failed create: {}", retried.text);
    assert_eq!(f.transit_key_count("rollback-me").await, 1);
}

#[tokio::test]
async fn transit_create_seeds_a_usable_first_version_and_enforces_name_uniqueness() {
    let f = Fixture::new().await;
    let created = f.create_key("payload").await;
    assert_eq!(created.status, 200, "{}", created.text);
    let kid = created.body["id"].as_str().expect("created key id").to_string();
    assert_eq!(created.body["key_version"].as_i64(), Some(1));
    let base = format!("/api/orgs/org/transit/keys/{}", kid);
    let plaintext = oc::b64(b"first version roundtrip");
    let sealed = f.call("POST", &format!("{}/encrypt", base), "owner", Some(json!({"plaintext": plaintext, "context": "ctx"}))).await;
    assert_eq!(sealed.status, 200, "{}", sealed.text);
    let opened = f.call("POST", &format!("{}/decrypt", base), "owner", Some(json!({"ciphertext": sealed.body["ciphertext"], "context": "ctx"}))).await;
    assert_eq!(opened.status, 200, "{}", opened.text);
    assert_eq!(opened.body["plaintext"], plaintext);
    let duplicate = f.create_key("payload").await;
    assert_eq!(duplicate.status, 400, "duplicate name should be rejected: {}", duplicate.text);
    assert_eq!(f.transit_key_count("payload").await, 1);
    let list = f.call("GET", "/api/orgs/org/transit/keys", "owner", None).await;
    assert_eq!(list.status, 200, "{}", list.text);
    let names: Vec<&str> = list.body.as_array().unwrap().iter().map(|k| k["name"].as_str().unwrap()).collect();
    assert_eq!(names.iter().filter(|n| **n == "payload").count(), 1);
}

#[tokio::test]
async fn environment_scoped_tokens_are_denied_transit_even_with_transit_scope() {
    let f = Fixture::new().await;
    // A credential scoped to an environment must never reach transit, even when
    // its scopes field would otherwise authorise transit:manage.
    f.state.db().exec("INSERT INTO tokens(id,org_id,env_id,name,token_hash,scopes,created_at,created_by) VALUES('scoped','org','env','scoped',?,'transit:manage',?,'owner')", &[json!(oc::hash_token("scoped")), json!(now())]).await.unwrap();
    f.call("POST", "/api/orgs/org/transit/keys", "scoped", Some(json!({"name": "denied"}))).await.forbidden();
    f.call("GET", "/api/orgs/org/transit/keys", "scoped", None).await.forbidden();
    assert_eq!(f.transit_key_count("denied").await, 0, "env-scoped credential created a transit key");
}
