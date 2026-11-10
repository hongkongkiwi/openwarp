// Outbox atomicity. A secret mutation, its audit row and its fan-out event must
// commit or roll back together. The current handlers commit the secret write
// with batch_checked and then append the audit row, audit head and event in
// separate statements, so a failed audit write leaves the secret committed with
// no audit trail. These tests inject a SQLite trigger that fails the audit
// INSERT and assert the whole deploy (business row, audit head, event) rolls
// back. The fan-out payload must stay metadata-only: names and actions, never a
// secret value.

use openwarp_server::db::{n, s, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use openwarp_crypto as oc;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "outbox-session";
const ORG: &str = "outbox-org";
const USER: &str = "outbox-user";
const APP: &str = "outbox-app";
const ENV: &str = "outbox-env";
const HOOK: &str = "outbox-hook";

async fn fixture(with_hook: bool) -> (S, [u8; 32]) {
    let db = Db::open_memory().await.unwrap();
    let master = oc::random_key();
    let (live, _) = tokio::sync::broadcast::channel(8);
    let state = new_state(db, String::new(), "outbox".into(), "https://example.invalid".into(), master, live, #[cfg(feature = "redis-cache")] None);
    let t = openwarp_server::clock::now();
    let env_key = oc::random_key();
    let wrapped = oc::encrypt_symmetric(&master, &env_key);
    let db = state.db();
    db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(USER), json!("outbox@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
    db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(ORG), json!("outbox"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
    db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(APP), json!(ORG), json!("outbox"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)",
        &[json!(ENV), json!(APP), json!("dev"), json!(wrapped), json!(t)]).await.unwrap();
    db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
    if with_hook {
        db.exec("INSERT INTO webhook_subscriptions(id,org_id,app_id,name,url,events,enabled,secret_enc,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            &[json!(HOOK), json!(ORG), json!(""), json!("outbox"), json!("https://example.invalid/never"),
              json!(r#"["secret.deploy"]"#), json!(1), json!("dummy"), json!(1), json!(t), json!(t)]).await.unwrap();
    }
    (state, master)
}

async fn call(state: &S, method: &str, uri: &str, body: Option<Value>) -> (u16, Value) {
    let mut b = axum::http::Request::builder().method(method).uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    if body.is_some() { b = b.header("content-type", "application/json"); }
    let mut req = match body {
        Some(v) => b.body(axum::body::Body::from(v.to_string())).unwrap(),
        None => b.body(axum::body::Body::empty()).unwrap(),
    };
    req.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
    let resp = router(state.to_owned()).oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn count(db: &Db, sql: &str, params: &[Value]) -> i64 {
    db.one(sql, params).await.unwrap().map(|r| n(&r, "n")).unwrap_or(0)
}

async fn head_seq(db: &Db) -> i64 {
    db.one("SELECT seq FROM audit_heads WHERE org_id=?", &[json!(ORG)]).await.unwrap()
        .map(|r| n(&r, "seq")).unwrap_or(0)
}

fn deploy_body(key: &str, value: &str) -> Value {
    json!({"secrets": [{"key": key, "value": value, "path": "/"}]})
}

#[tokio::test]
async fn audit_write_failure_rolls_back_secret_deploy() {
    let (state, _) = fixture(false).await;

    // Sanity: the deploy path commits business + audit before the trigger.
    let (s1, b1) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("FIRST", "first-value"))).await;
    assert_eq!(s1, 200, "baseline deploy failed: {b1}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM secrets WHERE env_id=?", &[json!(ENV)]).await, 1);
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='secret.deploy'", &[json!(ORG)]).await, 1);
    assert_eq!(head_seq(state.db()).await, 1);

    // Fail every subsequent audit INSERT.
    state.db().exec("CREATE TRIGGER outbox_fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END", &[]).await.unwrap();

    let (s2, b2) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("SECOND", "second-value"))).await;
    assert!(s2 >= 400, "deploy must fail when its audit write fails; got {s2}: {b2}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM secrets WHERE env_id=?", &[json!(ENV)]).await, 1,
        "the failed deploy must not commit its secret; SECOND leaked through");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='secret.deploy'", &[json!(ORG)]).await, 1,
        "the failed deploy must not append an audit row");
    assert_eq!(head_seq(state.db()).await, 1, "the failed deploy must not advance the audit head");
}

#[tokio::test]
async fn deploy_commits_secret_audit_and_metadata_only_event() {
    let (state, _) = fixture(true).await;

    let (status, body) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("API_KEY", "SUPERSECRETVALUE"))).await;
    assert_eq!(status, 200, "deploy failed: {body}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM secrets WHERE env_id=?", &[json!(ENV)]).await, 1);
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='secret.deploy'", &[json!(ORG)]).await, 1);
    assert_eq!(head_seq(state.db()).await, 1);

    let payload = s(&state.db().one("SELECT payload FROM webhook_deliveries WHERE webhook_id=?", &[json!(HOOK)]).await.unwrap().unwrap(), "payload");
    let event: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(event["type"], json!("secret.deploy"));
    assert!(!payload.contains("SUPERSECRETVALUE"), "fan-out payload leaked the secret value");
    assert!(!payload.contains("API_KEY"), "fan-out payload leaked the secret key");
}

#[tokio::test]
async fn audit_write_failure_rolls_back_secret_delete() {
    let (state, _) = fixture(false).await;

    let (s1, _) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("KEEP", "keep-value"))).await;
    assert_eq!(s1, 200);
    let sid = s(&state.db().one("SELECT id FROM secrets WHERE env_id=?", &[json!(ENV)]).await.unwrap().unwrap(), "id");

    state.db().exec("CREATE TRIGGER outbox_fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END", &[]).await.unwrap();

    let (s2, b2) = call(&state, "DELETE", &format!("/api/secrets/{sid}"), None).await;
    assert!(s2 >= 400, "delete must fail when its audit write fails; got {s2}: {b2}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM secrets WHERE id=? AND deleted=0", &[json!(sid)]).await, 1,
        "the failed delete must not tombstone the secret");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='secret.delete'", &[json!(ORG)]).await, 0);
}
