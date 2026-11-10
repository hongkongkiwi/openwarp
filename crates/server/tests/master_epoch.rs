#![cfg(feature = "ssh-ca")]

// Master epoch fencing. A master rotation rewraps every master-encrypted blob
// in one database transaction and advances the shared epoch fingerprint in
// webhook_serialization. A replica that still holds the old master in memory is
// stale: it must fail closed with epoch_stale instead of writing ciphertext the
// new master cannot decrypt. These tests build two AppStates over one
// file-backed SQLite database (the stale replica and the fresh replica), rotate
// through the real /api/instance/rotate-master handler, then drive the stale
// replica's public routes. No concurrency or timing: the two states are the two
// sides of the rotation boundary, which is deterministic.

use openwarp_server::db::{n, s as db_string, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use openwarp_crypto as oc;
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
    old: [u8; 32],
    new: [u8; 32],
}

impl Rotated {
    fn stale(&self) -> &S { self.stale.as_ref().unwrap() }
    fn fresh(&self) -> &S { self.fresh.as_ref().unwrap() }

    async fn seed() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-master-epoch-{}-{}", std::process::id(), oc::random_token("fixture")));
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
        // SSH CA and PKI routes require workspace grants on top of compiled features.
        db.exec("INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,?,?)",
            &[json!(ORG), json!("ssh-ca pki"), json!(USER), json!(t)]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(APP), json!(ORG), json!("epoch"), json!(t)]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
            &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(USER)]).await.unwrap();

        // Seed the shared epoch row through a legitimate webhook creation, which
        // records the current master fingerprint in webhook_serialization.
        let (status, body) = call(&fresh, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(json!({"url": "https://example.invalid/hook"}))).await;
        assert_eq!(status, 200, "webhook seed failed: {body}");

        Rotated { dir, stale: Some(stale), fresh: Some(fresh), old, new }
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

async fn count(db: &Db, sql: &str, params: &[Value]) -> i64 {
    db.one(sql, params).await.unwrap().map(|r| n(&r, "n")).unwrap_or(0)
}

fn assert_epoch_stale(status: u16, body: &Value, what: &str) {
    assert_eq!(status, 503, "{what} must fail closed with 503; got {status}: {body}");
    assert!(body.to_string().contains("epoch_stale"), "{what} must carry epoch_stale; got {body}");
}

#[tokio::test]
async fn stale_replica_env_write_and_read_fail_closed_after_master_rotation() {
    let r = Rotated::seed().await;
    r.rotate().await;

    // The fresh replica still writes and reads under the new master.
    let (s, b) = call(r.fresh(), "POST", &format!("/api/apps/{APP}/envs"), Some(json!({"name": "fresh-env"}))).await;
    assert_eq!(s, 200, "fresh replica could not create an environment: {b}");
    let eid = b["id"].as_str().unwrap().to_string();
    let wrapped = db_string(&r.fresh().db().one("SELECT env_key_wrapped FROM envs WHERE id=?", &[json!(&eid)]).await.unwrap().unwrap(), "env_key_wrapped");
    assert_eq!(oc::decrypt_symmetric(&r.new, &wrapped).unwrap().len(), 32, "fresh environment must be wrapped by the new master");
    assert!(oc::decrypt_symmetric(&r.old, &wrapped).is_err(), "fresh environment must not be wrapped by the old master");
    let (s, b) = call(r.fresh(), "GET", &format!("/api/envs/{eid}/secrets"), None).await;
    assert_eq!(s, 200, "fresh replica could not read the environment after rotation: {b}");

    // The stale replica must fail closed on both write and read, writing nothing.
    let (s, b) = call(r.stale(), "POST", &format!("/api/apps/{APP}/envs"), Some(json!({"name": "stale-env"}))).await;
    assert_epoch_stale(s, &b, "stale environment write");
    assert_eq!(count(r.stale().db(), "SELECT COUNT(*) AS n FROM envs WHERE app_id=? AND name=?", &[json!(APP), json!("stale-env")]).await, 0,
        "stale environment write must not persist a row");

    let (s, b) = call(r.stale(), "GET", &format!("/api/envs/{eid}/secrets"), None).await;
    assert_epoch_stale(s, &b, "stale environment read");
}

#[tokio::test]
async fn stale_replica_ssh_ca_write_fails_closed_after_master_rotation() {
    let r = Rotated::seed().await;
    r.rotate().await;

    // The fresh replica can mint an SSH CA under the new master.
    let (s, b) = call(r.fresh(), "POST", &format!("/api/orgs/{ORG}/ssh/cas"), Some(json!({"name": "fresh-ca"}))).await;
    assert_eq!(s, 200, "fresh replica could not create an SSH CA: {b}");
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM pki_cas WHERE org_id=?", &[json!(ORG)]).await, 1);

    // The stale replica must fail closed and write no CA row.
    let (s, b) = call(r.stale(), "POST", &format!("/api/orgs/{ORG}/ssh/cas"), Some(json!({"name": "stale-ca"}))).await;
    assert_epoch_stale(s, &b, "stale SSH CA write");
    assert_eq!(count(r.stale().db(), "SELECT COUNT(*) AS n FROM pki_cas WHERE org_id=?", &[json!(ORG)]).await, 1,
        "stale SSH CA write must not persist a row");
}

#[tokio::test]
async fn stale_replica_totp_enrollment_fails_closed_after_master_rotation() {
    let r = Rotated::seed().await;
    r.rotate().await;

    // The fresh replica can start TOTP enrollment under the new master.
    let (s, b) = call(r.fresh(), "POST", "/api/me/totp/setup", Some(json!({}))).await;
    assert_eq!(s, 200, "fresh replica could not start TOTP enrollment: {b}");
    let pending_key = format!("totp_pending:{}", USER);
    let before = db_string(&r.fresh().db().one("SELECT v FROM meta WHERE k=?", &[json!(&pending_key)]).await.unwrap().unwrap(), "v");
    assert_eq!(oc::decrypt_symmetric(&r.new, &before).unwrap().len(), 20, "fresh pending secret must be wrapped by the new master");

    // The stale replica must fail closed and must not replace the pending secret.
    let (s, b) = call(r.stale(), "POST", "/api/me/totp/setup", Some(json!({}))).await;
    assert_epoch_stale(s, &b, "stale TOTP enrollment");
    let after = db_string(&r.stale().db().one("SELECT v FROM meta WHERE k=?", &[json!(&pending_key)]).await.unwrap().unwrap(), "v");
    assert_eq!(after, before, "stale TOTP enrollment must not replace the pending secret");
    assert_eq!(oc::decrypt_symmetric(&r.new, &after).unwrap().len(), 20, "pending secret must remain wrapped by the new master");
}
