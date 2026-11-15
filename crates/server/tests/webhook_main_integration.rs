#![cfg(feature = "transit")]

// Transit and change request integration with the outbox/epoch write path,
// exercised through the public routes. These tests pin three invariants: a
// master rotation rewraps every transit version in place so existing
// ciphertext still decrypts and new encryptions stay under control; a replica
// still holding the old master fails closed with epoch_stale and writes no
// transit rows; and an audit admission failure rolls the business rows back
// instead of committing them without a trail.

use openwarp_server::db::{n, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use openwarp_crypto as oc;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "webhook-main-session";
const ORG: &str = "webhook-main-org";
const USER: &str = "webhook-main-user";
const APP: &str = "webhook-main-app";
const ENV: &str = "webhook-main-env";

async fn isolated_mail_child(name: &str) -> bool {
    const MARKER: &str = "OPENWARP_WEBHOOK_MAIN_MAIL_CHILD";
    if let Ok(selected) = std::env::var(MARKER) { assert_eq!(selected, name, "isolated child must run exactly its selected test"); return false; }
    let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let incoming = messages.clone();
    let relay = axum::Router::new().route("/mail", axum::routing::post(move |axum::Json(mail): axum::Json<Value>| {
        let messages = incoming.clone(); async move { messages.lock().unwrap().push(mail); axum::Json(json!({})) }
    }).get(move || { let messages = messages.clone(); async move { axum::Json(messages.lock().unwrap().clone()) } }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("private mail relay");
    let mail_url = format!("http://{}/mail", listener.local_addr().unwrap());
    struct Relay(tokio::task::JoinHandle<()>);
    impl Drop for Relay { fn drop(&mut self) { self.0.abort(); } }
    let _relay = Relay(tokio::spawn(async move { axum::serve(listener, relay).await.unwrap(); }));
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
    child.args(["--exact", name, "--test-threads=1"]).env_clear().env(MARKER, name)
        .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", mail_url)
        .env("NO_PROXY", "127.0.0.1,localhost").kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(120), child.output()).await
        .expect("bounded isolated webhook integration test").expect("run isolated webhook integration test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "isolated webhook integration assertions failed: {stdout}\n{}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;") && stdout.contains(&format!("test {name} ... ok")), "isolated child must execute exactly one passing test");
    true
}

async fn rotation_proof(state: &S) -> String {
    let url = std::env::var("OPENWARP_EMAIL_WEBHOOK").expect("child-only mail relay");
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(5)).build().unwrap();
    let before: Vec<Value> = client.get(&url).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    let (status, started) = call(state, "POST", "/api/auth/step-up/start", Some(json!({"risk":"very_risky"}))).await;
    assert_eq!(status, 200, "start rotation verification: {}", started["error"]);
    assert_eq!(started["email_sent"], true);
    let messages: Vec<Value> = client.get(&url).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    assert_eq!(messages.len(), before.len() + 1, "one fresh rotation verification email must be delivered");
    let mail = messages.last().unwrap();
    assert_eq!(mail["to"], "webhook-main@test.invalid");
    assert_eq!(mail["subject"], "Your OpenWarp verification code");
    let code = mail["text"].as_str().unwrap().split(|c: char| !c.is_ascii_digit()).find(|part| part.len() == 6).expect("delivered six-digit code");
    let (status, verified) = call(state, "POST", "/api/auth/step-up/verify", Some(json!({"challenge":started["challenge"],"email_code":code}))).await;
    assert_eq!(status, 200, "verify delivered rotation code: {}", verified["error"]);
    verified["token"].as_str().expect("authentic rotation grant").to_string()
}

async fn call(state: &S, method: &str, uri: &str, body: Option<Value>) -> (u16, Value) { call_with_grant(state, method, uri, body, None).await }

async fn call_with_grant(state: &S, method: &str, uri: &str, body: Option<Value>, grant: Option<&str>) -> (u16, Value) {
    let mut b = axum::http::Request::builder().method(method).uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    if let Some(grant) = grant { b = b.header("x-openwarp-step-up", grant); }
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

fn assert_epoch_stale(status: u16, body: &Value, what: &str) {
    assert_eq!(status, 503, "{what} must fail closed with 503; got {status}: {body}");
    assert!(body.to_string().contains("epoch_stale"), "{what} must carry epoch_stale; got {body}");
}

async fn seed_owner(db: &Db, master: &[u8; 32], with_env: bool) {
    let t = openwarp_server::clock::now();
    db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(USER), json!("webhook-main@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
    db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(ORG), json!("webhook-main"), json!(t)]).await.unwrap();
    // Transit and change-request routes require a workspace feature grant on
    // top of the compiled feature.
    db.exec("INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,?,?)",
        &[json!(ORG), json!("transit change-requests"), json!(USER), json!(t)]).await.unwrap();
    db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
    db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(APP), json!(ORG), json!("webhook-main"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
    db.exec("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(USER)]).await.unwrap();
    if with_env {
        let env_key = oc::random_key();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)",
            &[json!(ENV), json!(APP), json!("dev"), json!(oc::encrypt_symmetric(master, &env_key)), json!(t)]).await.unwrap();
    }
}

async fn single(with_env: bool) -> S {
    let db = Db::open_memory().await.unwrap();
    let master = oc::random_key();
    let (live, _) = tokio::sync::broadcast::channel(8);
    let state = new_state(db, String::new(), "webhook-main".into(), "https://example.invalid".into(), master, live, #[cfg(feature = "redis-cache")] None);
    seed_owner(state.db(), &master, with_env).await;
    state
}

async fn transit_key(state: &S, name: &str) -> String {
    let (s, b) = call(state, "POST", &format!("/api/orgs/{ORG}/transit/keys"), Some(json!({"name": name}))).await;
    assert_eq!(s, 200, "transit key create failed: {b}");
    let kid = b["id"].as_str().expect("transit key create must return an id").to_string();
    assert!(!kid.is_empty());
    kid
}

async fn transit_op(state: &S, kid: &str, action: &str, body: Value) -> (u16, Value) {
    call(state, "POST", &format!("/api/orgs/{ORG}/transit/keys/{kid}/{action}"), Some(body)).await
}

fn change_body() -> Value {
    json!({"title":"Atomic rollout","changes":[{"env_id":ENV,"secrets":[{"key":"API_KEY","value":"reviewed-value","path":"/"}],"deletes":[]}]})
}

struct Rotated {
    dir: std::path::PathBuf,
    stale: Option<S>,
    fresh: Option<S>,
    new: [u8; 32],
}

impl Rotated {
    fn stale(&self) -> &S { self.stale.as_ref().unwrap() }
    fn fresh(&self) -> &S { self.fresh.as_ref().unwrap() }

    async fn seed() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-webhook-main-{}-{}", std::process::id(), oc::random_token("fixture")));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}/main.db", dir.display());
        let db_stale = Db::open(&url).await.unwrap();
        let db_fresh = Db::open(&url).await.unwrap();
        let old = oc::random_key();
        let new = oc::random_key();
        let (live_stale, _) = tokio::sync::broadcast::channel(8);
        let (live_fresh, _) = tokio::sync::broadcast::channel(8);
        let stale = new_state(db_stale, String::new(), "webhook-main-stale".into(), "https://example.invalid".into(), old, live_stale, #[cfg(feature = "redis-cache")] None);
        let fresh = new_state(db_fresh, String::new(), "webhook-main-fresh".into(), "https://example.invalid".into(), old, live_fresh, #[cfg(feature = "redis-cache")] None);
        seed_owner(fresh.db(), &old, false).await;

        // Seed the shared epoch row through a legitimate webhook creation, which
        // records the current master fingerprint in webhook_serialization.
        let (status, body) = call(&fresh, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(json!({"url": "https://example.invalid/hook"}))).await;
        assert_eq!(status, 200, "webhook seed failed: {body}");

        Rotated { dir, stale: Some(stale), fresh: Some(fresh), new }
    }

    async fn rotate(&self) {
        let proof = rotation_proof(self.fresh()).await;
        let (status, body) = call_with_grant(self.fresh(), "POST", "/api/instance/rotate-master", Some(json!({"new_key": oc::b64(&self.new)})), Some(&proof)).await;
        assert_eq!(status, 200, "master rotation failed: {body}");
        assert_eq!(body["ok"], json!(true), "rotation response: {body}");
    }
}

impl Drop for Rotated {
    fn drop(&mut self) {
        drop(self.stale.take().unwrap());
        drop(self.fresh.take().unwrap());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn transit_key_encrypt_decrypt_survives_master_rotation() {
    if isolated_mail_child("transit_key_encrypt_decrypt_survives_master_rotation").await { return; }
    let r = Rotated::seed().await;
    let kid = transit_key(r.fresh(), "payments.primary").await;
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM transit_keys WHERE org_id=?", &[json!(ORG)]).await, 1);
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM transit_versions WHERE org_id=?", &[json!(ORG)]).await, 1);

    let plain = oc::b64(b"rotation fixture payload");
    let input = json!({"plaintext": plain, "context": "payment:fixture"});
    let (s, enc) = transit_op(r.fresh(), &kid, "encrypt", input.clone()).await;
    assert_eq!(s, 200, "encrypt failed: {enc}");
    assert_eq!(enc["version"], json!(1));
    let ciphertext = enc["ciphertext"].as_str().expect("encrypt must return ciphertext").to_string();
    assert!(ciphertext.starts_with("owt1:"), "transit ciphertext must carry the owt1 envelope");

    let old_envelope = json!({"ciphertext": ciphertext, "context": "payment:fixture"});
    let (s, dec) = transit_op(r.fresh(), &kid, "decrypt", old_envelope.clone()).await;
    assert_eq!(s, 200, "decrypt before rotation failed: {dec}");
    assert_eq!(dec["plaintext"], json!(plain));

    r.rotate().await;

    // The pre-rotation ciphertext still decrypts: rotation rewrapped the transit
    // version in place rather than invalidating it.
    let (s, dec) = transit_op(r.fresh(), &kid, "decrypt", old_envelope).await;
    assert_eq!(s, 200, "decrypt after rotation failed: {dec}");
    assert_eq!(dec["plaintext"], json!(plain));

    // New encryption control under the rewrapped key still round-trips.
    let (s, enc2) = transit_op(r.fresh(), &kid, "encrypt", input).await;
    assert_eq!(s, 200, "encrypt after rotation failed: {enc2}");
    assert_eq!(enc2["version"], json!(1));
    let cipher2 = enc2["ciphertext"].as_str().expect("post-rotation encrypt must return ciphertext").to_string();
    let (s, dec2) = transit_op(r.fresh(), &kid, "decrypt", json!({"ciphertext": cipher2, "context": "payment:fixture"})).await;
    assert_eq!(s, 200, "decrypt of post-rotation ciphertext failed: {dec2}");
    assert_eq!(dec2["plaintext"], json!(plain));

    // Rotation rewrapped the one version, never duplicated or dropped it.
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM transit_versions WHERE org_id=?", &[json!(ORG)]).await, 1);
}

#[tokio::test]
async fn stale_replica_transit_create_fails_closed_after_master_rotation() {
    if isolated_mail_child("stale_replica_transit_create_fails_closed_after_master_rotation").await { return; }
    let r = Rotated::seed().await;

    // Control: the fresh replica creates a key before rotation.
    let _ = transit_key(r.fresh(), "fresh.primary").await;
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM transit_keys WHERE org_id=?", &[json!(ORG)]).await, 1);
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM transit_versions WHERE org_id=?", &[json!(ORG)]).await, 1);

    r.rotate().await;

    // The fresh replica still creates keys under the new master.
    let _ = transit_key(r.fresh(), "fresh.secondary").await;
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM transit_keys WHERE org_id=?", &[json!(ORG)]).await, 2);

    // The stale replica must fail closed with epoch_stale and write nothing.
    let (s, b) = call(r.stale(), "POST", &format!("/api/orgs/{ORG}/transit/keys"), Some(json!({"name": "stale.primary"}))).await;
    assert_epoch_stale(s, &b, "stale transit key create");
    assert_eq!(count(r.stale().db(), "SELECT COUNT(*) AS n FROM transit_keys WHERE org_id=?", &[json!(ORG)]).await, 2,
        "stale transit key create must not persist a key row");
    assert_eq!(count(r.stale().db(), "SELECT COUNT(*) AS n FROM transit_versions WHERE org_id=?", &[json!(ORG)]).await, 2,
        "stale transit key create must not persist a version row");
}

#[tokio::test]
async fn audit_write_failure_rolls_back_transit_key_create() {
    let state = single(false).await;

    // Baseline: a key create commits key + version + audit together.
    let _ = transit_key(&state, "first.primary").await;
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM transit_keys WHERE org_id=?", &[json!(ORG)]).await, 1);
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM transit_versions WHERE org_id=?", &[json!(ORG)]).await, 1);

    // Fail every subsequent audit INSERT.
    state.db().exec("CREATE TRIGGER wm_fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END", &[]).await.unwrap();

    let (s, b) = call(&state, "POST", &format!("/api/orgs/{ORG}/transit/keys"), Some(json!({"name": "second.primary"}))).await;
    assert!(s >= 400, "transit key create must fail when its audit write fails; got {s}: {b}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM transit_keys WHERE org_id=?", &[json!(ORG)]).await, 1,
        "the failed create must not persist a key row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM transit_versions WHERE org_id=?", &[json!(ORG)]).await, 1,
        "the failed create must not persist a version row");
}

#[tokio::test]
async fn audit_write_failure_rolls_back_change_request_create() {
    let state = single(true).await;

    // Baseline: a valid change request persists request + env snapshot + audit.
    let (s, b) = call(&state, "POST", &format!("/api/orgs/{ORG}/change-requests"), Some(change_body())).await;
    assert_eq!(s, 200, "baseline change request create failed: {b}");
    assert_eq!(b["revision"], json!(1));
    assert_eq!(b["status"], json!("pending"));
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM change_requests WHERE org_id=?", &[json!(ORG)]).await, 1);
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM change_request_envs", &[]).await, 1);

    // Fail every subsequent audit INSERT.
    state.db().exec("CREATE TRIGGER wm_fail_audit_cr BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END", &[]).await.unwrap();

    let (s2, b2) = call(&state, "POST", &format!("/api/orgs/{ORG}/change-requests"), Some(change_body())).await;
    assert!(s2 >= 400, "change request create must fail when its audit write fails; got {s2}: {b2}");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM change_requests WHERE org_id=?", &[json!(ORG)]).await, 1,
        "the failed create must not persist a request row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM change_request_envs", &[]).await, 1,
        "the failed create must not persist an env snapshot");
}
