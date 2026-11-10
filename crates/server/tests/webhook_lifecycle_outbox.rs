// Outbox atomicity for webhook management. create, update, delete and rotate
// (outgoing) plus reauthorize (incoming) must commit their mutation, audit row
// and fan-out event atomically: if the audit write fails, the whole operation
// rolls back and the endpoint fails. These tests inject a SQLite trigger that
// aborts the audit INSERT and assert the subscription state, audit trail and
// outbox stay unchanged while the response is a failure. Signing keys are
// server-generated dummies; no provider credentials are used.

use openwarp_server::db::{n, s, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use openwarp_crypto as oc;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "lifecycle-session";
const TOKEN2: &str = "lifecycle-session-2";
const ORG: &str = "lifecycle-org";
const USER: &str = "lifecycle-user";
const APP: &str = "lifecycle-app";
const ENV: &str = "lifecycle-env";
const INTEGRATION: &str = "lifecycle-integration";

async fn fixture(with_integration: bool) -> S {
    let db = Db::open_memory().await.unwrap();
    let master = oc::random_key();
    let (live, _) = tokio::sync::broadcast::channel(8);
    let state = new_state(db, String::new(), "lifecycle".into(), "https://example.invalid".into(), master, live, #[cfg(feature = "redis-cache")] None);
    let t = openwarp_server::clock::now();
    let env_key = oc::random_key();
    let wrapped = oc::encrypt_symmetric(&master, &env_key);
    let db = state.db();
    db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(USER), json!("lifecycle@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
    db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(ORG), json!("lifecycle"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
    db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(APP), json!(ORG), json!("lifecycle"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)",
        &[json!(ENV), json!(APP), json!("dev"), json!(wrapped), json!(t)]).await.unwrap();
    db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
    if with_integration {
        db.exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES(?,?,?,?,?,?)",
            &[json!(INTEGRATION), json!(ENV), json!("webhook"), json!("dummy target"), json!("dummy"), json!(t)]).await.unwrap();
    }
    state
}

async fn call(state: &S, token: &str, method: &str, uri: &str, body: Option<Value>) -> (u16, Value) {
    let mut b = axum::http::Request::builder().method(method).uri(uri)
        .header("authorization", format!("Bearer {token}"));
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

async fn fail_audit(state: &S) {
    state.db().exec("CREATE TRIGGER lifecycle_fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END", &[]).await.unwrap();
}

fn outgoing_body() -> Value { json!({"url":"https://example.invalid/hook","events":["secret.deploy"],"enabled":true}) }

#[tokio::test]
async fn audit_failure_rolls_back_outgoing_create() {
    let state = fixture(false).await;

    // Positive control: the create endpoint is valid and commits a subscription.
    let (s1, b1) = call(&state, TOKEN, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(outgoing_body())).await;
    assert_eq!(s1, 200, "baseline create failed: {b1}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_subscriptions WHERE org_id=?", &[json!(ORG)]).await, 1);

    fail_audit(&state).await;

    let (s2, b2) = call(&state, TOKEN, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(outgoing_body())).await;
    assert!(s2 >= 400, "create must fail when its audit write fails; got {s2}: {b2}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_subscriptions WHERE org_id=?", &[json!(ORG)]).await, 1,
        "the failed create must not commit its subscription");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='webhook.create'", &[json!(ORG)]).await, 1,
        "the failed create must not append a webhook.create audit row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 0, "outbox must stay empty");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets", &[]).await, 0, "outbox targets must stay empty");
}

#[tokio::test]
async fn audit_failure_rolls_back_outgoing_update() {
    let state = fixture(false).await;
    let (s1, b1) = call(&state, TOKEN, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(outgoing_body())).await;
    assert_eq!(s1, 200, "{b1}");
    let wid = s(&state.db().one("SELECT id FROM webhook_subscriptions WHERE org_id=?", &[json!(ORG)]).await.unwrap().unwrap(), "id");

    // Positive control: update works and advances the version before the trigger.
    let (s2, b2) = call(&state, TOKEN, "PATCH", &format!("/api/webhooks/{wid}"), Some(json!({"name":"control-rename"}))).await;
    assert_eq!(s2, 200, "baseline update failed: {b2}");

    fail_audit(&state).await;

    let (s3, b3) = call(&state, TOKEN, "PATCH", &format!("/api/webhooks/{wid}"), Some(json!({"name":"must-not-land"}))).await;
    assert!(s3 >= 400, "update must fail when its audit write fails; got {s3}: {b3}");
    let row = state.db().one("SELECT name,version FROM webhook_subscriptions WHERE id=?", &[json!(wid)]).await.unwrap().unwrap();
    assert_eq!(s(&row, "name"), "control-rename", "the failed update must not rename the subscription");
    assert_eq!(n(&row, "version"), 2, "the failed update must not advance the version");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='webhook.update'", &[json!(ORG)]).await, 1,
        "the failed update must not append a webhook.update audit row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 0, "outbox must stay empty");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets", &[]).await, 0, "outbox targets must stay empty");
}

#[tokio::test]
async fn audit_failure_rolls_back_outgoing_delete() {
    let state = fixture(false).await;
    for _ in 0..2 {
        let (s, b) = call(&state, TOKEN, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(outgoing_body())).await;
        assert_eq!(s, 200, "{b}");
    }
    let ids: Vec<String> = state.db().query("SELECT id FROM webhook_subscriptions WHERE org_id=?", &[json!(ORG)]).await.unwrap()
        .iter().map(|r| s(r, "id")).collect();

    // Positive control: delete works before the trigger.
    let (d1, b1) = call(&state, TOKEN, "DELETE", &format!("/api/webhooks/{}", ids[0]), None).await;
    assert_eq!(d1, 200, "baseline delete failed: {b1}");

    fail_audit(&state).await;

    let (d2, b2) = call(&state, TOKEN, "DELETE", &format!("/api/webhooks/{}", ids[1]), None).await;
    assert!(d2 >= 400, "delete must fail when its audit write fails; got {d2}: {b2}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_subscriptions WHERE id=?", &[json!(ids[1])]).await, 1,
        "the failed delete must not remove the subscription");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='webhook.delete'", &[json!(ORG)]).await, 1,
        "the failed delete must not append a webhook.delete audit row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 0, "outbox must stay empty");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets", &[]).await, 0, "outbox targets must stay empty");
}

#[tokio::test]
async fn audit_failure_rolls_back_outgoing_rotate() {
    let state = fixture(false).await;
    let (s1, b1) = call(&state, TOKEN, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(outgoing_body())).await;
    assert_eq!(s1, 200, "{b1}");
    let wid = s(&state.db().one("SELECT id FROM webhook_subscriptions WHERE org_id=?", &[json!(ORG)]).await.unwrap().unwrap(), "id");

    // Positive control: rotate works and replaces the key before the trigger.
    let (s2, b2) = call(&state, TOKEN, "POST", &format!("/api/webhooks/{wid}/rotate"), None).await;
    assert_eq!(s2, 200, "baseline rotate failed: {b2}");
    let key_after_control = s(&state.db().one("SELECT secret_enc FROM webhook_subscriptions WHERE id=?", &[json!(wid)]).await.unwrap().unwrap(), "secret_enc");

    fail_audit(&state).await;

    let (s3, b3) = call(&state, TOKEN, "POST", &format!("/api/webhooks/{wid}/rotate"), None).await;
    assert!(s3 >= 400, "rotate must fail when its audit write fails; got {s3}: {b3}");
    let row = state.db().one("SELECT secret_enc,version FROM webhook_subscriptions WHERE id=?", &[json!(wid)]).await.unwrap().unwrap();
    assert_eq!(s(&row, "secret_enc"), key_after_control, "the failed rotate must not replace the signing key");
    assert_eq!(n(&row, "version"), 2, "the failed rotate must not advance the version");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='webhook.rotate'", &[json!(ORG)]).await, 1,
        "the failed rotate must not append a webhook.rotate audit row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 0, "outbox must stay empty");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets", &[]).await, 0, "outbox targets must stay empty");
}

#[tokio::test]
async fn audit_failure_rolls_back_incoming_reauthorize() {
    let state = fixture(true).await;
    let t = openwarp_server::clock::now();
    state.db().exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(TOKEN2)), json!(USER), json!(t)]).await.unwrap();

    // Positive control: the incoming create and reauthorize endpoints are valid.
    let (s1, b1) = call(&state, TOKEN, "POST", &format!("/api/integrations/{INTEGRATION}/webhooks"), Some(json!({"name":"trigger","enabled":true}))).await;
    assert_eq!(s1, 200, "baseline incoming create failed: {b1}");
    let wid = b1["id"].as_str().expect("incoming webhook id").to_string();
    let (s2, b2) = call(&state, TOKEN2, "POST", &format!("/api/incoming-webhooks/{wid}/reauthorize"), None).await;
    assert_eq!(s2, 200, "baseline reauthorize failed: {b2}");
    let hash_after_control = s(&state.db().one("SELECT credential_hash FROM incoming_webhooks WHERE id=?", &[json!(wid)]).await.unwrap().unwrap(), "credential_hash");

    // A pending receipt makes the reauthorize cancellation observable.
    state.db().exec("INSERT INTO webhook_receipts(id,webhook_id,message_id,body_hash,version,status,source_ip,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?,?,?)",
        &[json!("seed-receipt"), json!(wid), json!("seed-message"), json!("seed-hash"), json!(2), json!("127.0.0.1"), json!(t), json!(t), json!(t)]).await.unwrap();

    fail_audit(&state).await;

    let (s3, b3) = call(&state, TOKEN, "POST", &format!("/api/incoming-webhooks/{wid}/reauthorize"), None).await;
    assert!(s3 >= 400, "reauthorize must fail when its audit write fails; got {s3}: {b3}");
    let row = state.db().one("SELECT credential_hash,version FROM incoming_webhooks WHERE id=?", &[json!(wid)]).await.unwrap().unwrap();
    assert_eq!(s(&row, "credential_hash"), hash_after_control, "the failed reauthorize must not rebind the creator credential");
    assert_eq!(n(&row, "version"), 2, "the failed reauthorize must not advance the version");
    let receipt = state.db().one("SELECT status,error_code FROM webhook_receipts WHERE id=?", &[json!("seed-receipt")]).await.unwrap().unwrap();
    assert_eq!(s(&receipt, "status"), "pending", "the failed reauthorize must not cancel pending receipts");
    assert_eq!(s(&receipt, "error_code"), "", "the failed reauthorize must not mark receipts reauthorized");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='incoming_webhook.reauthorize'", &[json!(ORG)]).await, 1,
        "the failed reauthorize must not append an incoming_webhook.reauthorize audit row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 0, "outbox must stay empty");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets", &[]).await, 0, "outbox targets must stay empty");
}
