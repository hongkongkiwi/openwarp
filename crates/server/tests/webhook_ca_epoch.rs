#![cfg(feature = "pki")]

// Master epoch fencing for the PKI CA write paths. Every route that persists
// master-encrypted key material must fail closed with epoch_stale on a replica
// still holding the pre-rotation master: an intermediate CA private key and the
// pre-issuance hook secret are both rewrapped by a rotation, so a stale write
// either lands as ciphertext the current master cannot decrypt or breaks the
// next rotation outright. These tests build two AppStates over one file-backed
// SQLite database (the stale replica and the fresh replica), rotate through the
// real /api/instance/rotate-master handler, then drive the stale replica's
// public routes. No concurrency or timing: the two states are the two sides of
// the rotation boundary, which is deterministic.

use openwarp_server::db::{n, s as db_string, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use openwarp_crypto as oc;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "ca-epoch-session";
const ORG: &str = "ca-epoch-org";
const USER: &str = "ca-epoch-user";
const HOOK_URL: &str = "https://example.invalid/hook";

struct Rotated {
    dir: std::path::PathBuf,
    stale: Option<S>,
    fresh: Option<S>,
    old: [u8; 32],
    new: [u8; 32],
    root: String,
}

impl Rotated {
    fn stale(&self) -> &S { self.stale.as_ref().unwrap() }
    fn fresh(&self) -> &S { self.fresh.as_ref().unwrap() }

    async fn seed() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-ca-epoch-{}-{}", std::process::id(), oc::random_token("fixture")));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}/epoch.db", dir.display());
        let db_stale = Db::open(&url).await.unwrap();
        let db_fresh = Db::open(&url).await.unwrap();
        let old = oc::random_key();
        let new = oc::random_key();
        let (live_stale, _) = tokio::sync::broadcast::channel(8);
        let (live_fresh, _) = tokio::sync::broadcast::channel(8);
        let stale = new_state(db_stale, String::new(), "ca-epoch-stale".into(), "https://example.invalid".into(), old, live_stale, #[cfg(feature = "redis-cache")] None);
        let fresh = new_state(db_fresh, String::new(), "ca-epoch-fresh".into(), "https://example.invalid".into(), old, live_fresh, #[cfg(feature = "redis-cache")] None);

        let t = openwarp_server::clock::now();
        let db = fresh.db();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
            &[json!(USER), json!("ca-epoch@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(ORG), json!("ca-epoch"), json!(t)]).await.unwrap();
        // The CA routes require a workspace pki grant on top of the compiled feature.
        db.exec("INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,?,?)",
            &[json!(ORG), json!("pki"), json!(USER), json!(t)]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
            &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(USER)]).await.unwrap();

        // Seed the shared epoch row through a legitimate webhook creation, which
        // records the current master fingerprint in webhook_serialization.
        let (status, body) = call(&fresh, "POST", &format!("/api/orgs/{ORG}/webhooks"), Some(json!({"url": HOOK_URL}))).await;
        assert_eq!(status, 200, "webhook seed failed: {body}");

        // A root CA that exists across the rotation, created through the real
        // route before the master changes.
        let (status, body) = call(&fresh, "POST", &format!("/api/orgs/{ORG}/pki/cas"), Some(json!({"name": "epoch-root"}))).await;
        assert_eq!(status, 200, "root CA seed failed: {body}");
        let root = body["id"].as_str().unwrap().to_string();

        Rotated { dir, stale: Some(stale), fresh: Some(fresh), old, new, root }
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
async fn stale_replica_intermediate_ca_write_fails_closed_after_master_rotation() {
    let r = Rotated::seed().await;
    r.rotate().await;

    // The fresh replica signs an intermediate under the new master.
    let (s, b) = call(r.fresh(), "POST", &format!("/api/orgs/{ORG}/pki/cas"), Some(json!({"name": "fresh-intermediate", "parent_id": r.root}))).await;
    assert_eq!(s, 200, "fresh replica could not create an intermediate CA: {b}");
    assert_eq!(b["kind"], json!("intermediate"), "fresh creation must report the intermediate kind: {b}");
    let fresh_id = b["id"].as_str().unwrap().to_string();
    let enc = db_string(&r.fresh().db().one("SELECT key_enc FROM pki_cas WHERE id=?", &[json!(&fresh_id)]).await.unwrap().unwrap(), "key_enc");
    assert!(oc::decrypt_symmetric(&r.new, &enc).is_ok(), "fresh intermediate key must be wrapped by the new master");
    assert!(oc::decrypt_symmetric(&r.old, &enc).is_err(), "fresh intermediate key must not be wrapped by the old master");

    // The stale replica must fail closed and write no CA row.
    let (s, b) = call(r.stale(), "POST", &format!("/api/orgs/{ORG}/pki/cas"), Some(json!({"name": "stale-intermediate", "parent_id": r.root}))).await;
    assert_epoch_stale(s, &b, "stale intermediate CA write");
    assert_eq!(count(r.stale().db(), "SELECT COUNT(*) AS n FROM pki_cas WHERE org_id=? AND kind='x509' AND name=?", &[json!(ORG), json!("stale-intermediate")]).await, 0,
        "stale intermediate CA write must not persist a row");
    assert_eq!(count(r.stale().db(), "SELECT COUNT(*) AS n FROM pki_cas WHERE org_id=? AND ca_kind='intermediate'", &[json!(ORG)]).await, 1,
        "only the fresh intermediate may exist");
}

#[tokio::test]
async fn stale_replica_ca_hook_secret_write_fails_closed_after_master_rotation() {
    let r = Rotated::seed().await;
    r.rotate().await;

    // The fresh replica stores the hook secret wrapped by the new master.
    let (s, b) = call(r.fresh(), "PUT", &format!("/api/pki/cas/{}/hook", r.root), Some(json!({"url": HOOK_URL, "secret": "fresh-hook-secret"}))).await;
    assert_eq!(s, 200, "fresh replica could not configure the CA hook: {b}");
    assert_eq!(b["secret_set"], json!(true), "fresh hook response: {b}");
    let fresh_row = r.fresh().db().one("SELECT hook_url,hook_secret_enc FROM pki_cas WHERE id=?", &[json!(&r.root)]).await.unwrap().unwrap();
    let before = db_string(&fresh_row, "hook_secret_enc");
    assert_eq!(oc::decrypt_symmetric(&r.new, &before).unwrap(), b"fresh-hook-secret".to_vec(), "fresh hook secret must be wrapped by the new master");
    assert!(oc::decrypt_symmetric(&r.old, &before).is_err(), "fresh hook secret must not be wrapped by the old master");

    // The stale replica must fail closed and must not replace the ciphertext.
    let (s, b) = call(r.stale(), "PUT", &format!("/api/pki/cas/{}/hook", r.root), Some(json!({"url": "https://example.invalid/stale-hook", "secret": "stale-hook-secret"}))).await;
    assert_epoch_stale(s, &b, "stale CA hook secret write");
    let stale_row = r.stale().db().one("SELECT hook_url,hook_secret_enc FROM pki_cas WHERE id=?", &[json!(&r.root)]).await.unwrap().unwrap();
    let after = db_string(&stale_row, "hook_secret_enc");
    assert_eq!(after, before, "stale CA hook write must not replace the stored ciphertext");
    assert_eq!(oc::decrypt_symmetric(&r.new, &after).unwrap(), b"fresh-hook-secret".to_vec(), "hook secret must remain wrapped by the new master");
    assert_eq!(db_string(&stale_row, "hook_url"), HOOK_URL, "stale CA hook write must not replace the stored url");
}
