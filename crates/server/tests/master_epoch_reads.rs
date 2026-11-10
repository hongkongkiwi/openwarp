// Master epoch read fencing. A master rotation advances the shared epoch
// fingerprint in webhook_serialization; a replica still holding the old master
// is stale and must fail closed on reads instead of enqueuing a webhook
// delivery or receipt it can no longer sign or decrypt, or reporting a bogus
// invalid-code verdict for a TOTP secret it cannot decrypt. These tests build
// two AppStates over one file-backed SQLite database (the stale and fresh
// replicas), rotate through the real /api/instance/rotate-master handler, then
// drive each replica's public routes. No concurrency or timing: the two states
// are the two sides of the rotation boundary, which is deterministic.

use base64ct::{Base64, Encoding};
use hmac::Mac;
use openwarp_crypto as oc;
use openwarp_server::db::{n, s as db_string, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "epoch-session";
const ORG: &str = "epoch-org";
const USER: &str = "epoch-user";
const APP: &str = "epoch-app";

struct Rotated {
    dir: std::path::PathBuf,
    stale: Option<S>,
    fresh: Option<S>,
    new: [u8; 32],
    hook: String,
}

impl Rotated {
    fn stale(&self) -> &S { self.stale.as_ref().unwrap() }
    fn fresh(&self) -> &S { self.fresh.as_ref().unwrap() }

    async fn seed() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-master-epoch-reads-{}-{}", std::process::id(), oc::random_token("fixture")));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}/epoch.db", dir.display());
        let db_stale = Db::open(&url).await.unwrap();
        let db_fresh = Db::open(&url).await.unwrap();
        let old = oc::random_key();
        let new = oc::random_key();
        let (live_stale, _) = tokio::sync::broadcast::channel(8);
        let (live_fresh, _) = tokio::sync::broadcast::channel(8);
        let stale = new_state(db_stale, String::new(), "epoch-stale".into(), "https://example.invalid".into(), old, live_stale, #[cfg(feature = "redis-cache")] None);
        let fresh = new_state(db_fresh, String::new(), "epoch-fresh".into(), "https://example.invalid".into(), old, live_fresh, #[cfg(feature = "redis-cache")] None);

        let t = openwarp_server::clock::now();
        let db = fresh.db();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
            &[json!(USER), json!("epoch@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(ORG), json!("epoch"), json!(t)]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(APP), json!(ORG), json!("epoch"), json!(t)]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
            &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(USER)]).await.unwrap();

        // Seed the shared epoch row through a legitimate webhook creation, which
        // records the current master fingerprint in webhook_serialization.
        let (status, body) = call(&fresh, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(json!({"url": "https://example.invalid/hook"}))).await;
        assert_eq!(status, 200, "webhook seed failed: {body}");
        let hook = body["id"].as_str().unwrap().to_string();

        Rotated { dir, stale: Some(stale), fresh: Some(fresh), new, hook }
    }

    async fn rotate(&self) {
        let (status, body) = call(self.fresh(), "POST", "/api/instance/rotate-master", Some(json!({"new_key": oc::b64(&self.new)}))).await;
        assert_eq!(status, 200, "master rotation failed: {body}");
        assert_eq!(body["ok"], json!(true), "rotation response: {body}");
    }
}

impl Drop for Rotated {
    fn drop(&mut self) {
        // Close the SQLite connections before unlinking so WAL/SHM files are
        // released rather than recreated by a closing connection.
        drop(self.stale.take().unwrap());
        drop(self.fresh.take().unwrap());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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

async fn signed(state: &S, wid: &str, secret: &str, mid: &str, body: &[u8]) -> (u16, Value) {
    let key = Base64::decode_vec(secret.strip_prefix("whsec_").expect("whsec prefix")).expect("base64 signing key");
    assert_eq!(key.len(), 32, "signing key must be 32 bytes");
    let ts = openwarp_server::clock::now();
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
    mac.update(format!("{mid}.{ts}.").as_bytes());
    mac.update(body);
    let sig = format!("v1,{}", Base64::encode_string(&mac.finalize().into_bytes()));
    let mut req = axum::http::Request::builder().method("POST").uri(format!("/hooks/integrations/{wid}"))
        .header("content-type", "application/json")
        .header("webhook-id", mid)
        .header("webhook-timestamp", ts.to_string())
        .header("webhook-signature", sig)
        .body(axum::body::Body::from(body.to_vec())).unwrap();
    req.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
    let resp = router(state.to_owned()).oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

async fn count(db: &Db, sql: &str, params: &[Value]) -> i64 {
    db.one(sql, params).await.unwrap().map(|r| n(&r, "n")).unwrap_or(0)
}

async fn meta_value(db: &Db, k: &str) -> String {
    db_string(&db.one("SELECT v FROM meta WHERE k=?", &[json!(k)]).await.unwrap().unwrap(), "v")
}

fn assert_epoch_stale(status: u16, body: &Value, what: &str) {
    assert_eq!(status, 503, "{what} must fail closed with 503; got {status}: {body}");
    assert!(body.to_string().contains("epoch_stale"), "{what} must carry epoch_stale; got {body}");
}

#[tokio::test]
async fn stale_replica_outgoing_webhook_test_fails_closed_without_queue_admission() {
    let r = Rotated::seed().await;
    let wid = r.hook.clone();
    r.rotate().await;

    const DELIV: &str = "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id=?";
    let after_rotate = count(r.fresh().db(), DELIV, &[json!(&wid)]).await;

    // The fresh replica can issue a test delivery under the new master.
    let (s, b) = call(r.fresh(), "POST", &format!("/api/webhooks/{wid}/test"), None).await;
    assert_eq!(s, 200, "fresh replica could not issue a test delivery: {b}");
    assert_eq!(count(r.fresh().db(), DELIV, &[json!(&wid)]).await, after_rotate + 1, "fresh test must enqueue exactly one delivery");

    // The stale replica must fail closed and admit nothing to the queue.
    let (s, b) = call(r.stale(), "POST", &format!("/api/webhooks/{wid}/test"), None).await;
    assert_epoch_stale(s, &b, "stale outgoing webhook test");
    assert_eq!(count(r.fresh().db(), DELIV, &[json!(&wid)]).await, after_rotate + 1, "stale outgoing test must not enqueue a delivery");
}

#[tokio::test]
async fn stale_replica_correctly_signed_incoming_accept_fails_closed_without_queue_admission() {
    let r = Rotated::seed().await;

    // A real incoming webhook needs an SSE environment and an integration.
    let (s, b) = call(r.fresh(), "POST", &format!("/api/apps/{APP}/envs"), Some(json!({"name": "hook-env"}))).await;
    assert_eq!(s, 200, "environment creation failed: {b}");
    let eid = b["id"].as_str().unwrap().to_string();
    let (s, b) = call(r.fresh(), "POST", &format!("/api/envs/{eid}/integrations"), Some(json!({"kind": "webhook", "name": "dummy"}))).await;
    assert_eq!(s, 200, "integration creation failed: {b}");
    let iid = b["id"].as_str().unwrap().to_string();
    let (s, b) = call(r.fresh(), "POST", &format!("/api/integrations/{iid}/webhooks"), Some(json!({"name": "trigger", "enabled": true}))).await;
    assert_eq!(s, 200, "incoming webhook creation failed: {b}");
    let hid = b["id"].as_str().unwrap().to_string();
    let secret = b["secret"].as_str().unwrap().to_string();

    r.rotate().await;

    const RCPT: &str = "SELECT COUNT(*) AS n FROM webhook_receipts WHERE webhook_id=?";
    let after_rotate = count(r.fresh().db(), RCPT, &[json!(&hid)]).await;

    // A correctly signed request on the fresh replica is admitted.
    let (s, b) = signed(r.fresh(), &hid, &secret, "fresh-message-1", b"{}").await;
    assert_eq!(s, 202, "fresh replica rejected a correctly signed accept: {b}");
    assert_eq!(count(r.fresh().db(), RCPT, &[json!(&hid)]).await, after_rotate + 1, "fresh accept must enqueue exactly one receipt");

    // The same correctly signed request on the stale replica must fail closed
    // as epoch_stale, before signature verification or queue admission.
    let (s, b) = signed(r.stale(), &hid, &secret, "stale-message-1", b"{}").await;
    assert_epoch_stale(s, &b, "stale incoming accept");
    assert_eq!(count(r.fresh().db(), RCPT, &[json!(&hid)]).await, after_rotate + 1, "stale accept must not enqueue a receipt");
}

#[tokio::test]
async fn stale_replica_totp_verify_fails_closed_not_invalid_code() {
    let r = Rotated::seed().await;

    // Start a real TOTP enrollment on the fresh replica before the rotation so
    // a pending secret exists that the stale replica cannot decrypt.
    let (s, b) = call(r.fresh(), "POST", "/api/me/totp/setup", Some(json!({}))).await;
    assert_eq!(s, 200, "TOTP setup failed: {b}");

    r.rotate().await;

    let pending_key = format!("totp_pending:{USER}");
    let before = meta_value(r.fresh().db(), &pending_key).await;

    // Fresh control: the route is reachable and decrypts the pending secret,
    // rejecting a wrong code as an invalid code.
    let (s, b) = call(r.fresh(), "POST", "/api/me/totp/verify", Some(json!({"code": "000000"}))).await;
    assert_eq!(s, 401, "fresh replica should reject a wrong TOTP code: {b}");
    assert!(b.to_string().contains("invalid TOTP code"), "fresh response should name the invalid code: {b}");

    // The stale replica holds the old master and cannot decrypt the rewrapped
    // pending secret; it must fail closed with epoch_stale, not pass the bogus
    // invalid-code verdict, and must not touch the pending blob.
    let (s, b) = call(r.stale(), "POST", "/api/me/totp/verify", Some(json!({"code": "000000"}))).await;
    assert_epoch_stale(s, &b, "stale TOTP verify");
    assert_eq!(meta_value(r.fresh().db(), &pending_key).await, before, "stale TOTP verify must not replace the pending secret");
}
