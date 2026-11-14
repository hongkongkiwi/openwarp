#![cfg(not(target_arch = "wasm32"))]

use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{clock::now, db::{self, Db, Row}, install_kms, new_state, process_rotations, router, seed_epoch, verify_master, PeerAddr, S};
use serde_json::{json, Value};
use tower::ServiceExt;

const MASTER: [u8; 32] = [83; 32];
const SESSION: &str = "pr32-disposable-receipt-owner";
const OWNER: &str = "receipt-owner";
const APP: &str = "receipt-app";
const DELETED_ENV: &str = "receipt-deleted-env";
const LIVE_ENV: &str = "receipt-live-env";

struct Token { id: String, value: String }
struct Fixture { st: S, app: Router }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.expect("migrate private in-memory database");
        seed_epoch(&db, &MASTER).await.expect("initialize matching instance key epoch");
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,?,'','',?,1,1)",
            &[json!(OWNER), json!("receipt-owner@example.invalid"), json!("unused-password-hash"), json!(now())]).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('receipt-org','receipt-workspace',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('receipt-org',?,'owner')", &[json!(OWNER)]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(SESSION)), json!(OWNER), json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,'receipt-org','receipt-application',?)", &[json!(APP), json!(now())]).await.unwrap();
        for (env, name) in [(DELETED_ENV, "Deleted"), (LIVE_ENV, "Live")] {
            db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,?,'sse',?)",
                &[json!(env), json!(APP), json!(name), json!(oc::encrypt_symmetric(&MASTER, &[84; 32])), json!(now())]).await.unwrap();
        }
        for (key, value) in [
            ("master", oc::b64(&MASTER)),
            ("master_key_check", oc::encrypt_symmetric(&MASTER, b"openwarp-master-key-v1")),
            ("instance_owner", OWNER.to_string()),
        ] { db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(key), json!(value)]).await.unwrap(); }
        verify_master(&db, &MASTER).await.expect("fixture root decrypts the persisted inventory");
        let (live, _) = tokio::sync::broadcast::channel(16);
        let st = new_state(db, String::new(), "receipt-expiry-fixture".into(), "https://openwarp.test.invalid".into(), MASTER, live,
            #[cfg(feature = "redis-cache")] None);
        install_kms(&st, None);
        Self { app: router(st.clone()), st }
    }
    async fn call(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = Request::builder().method(method).uri(path).header("authorization", format!("Bearer {token}"));
        if body.is_some() { request = request.header("content-type", "application/json"); }
        let mut request = request.body(body.map(|v| Body::from(v.to_string())).unwrap_or_else(Body::empty)).unwrap();
        request.extensions_mut().insert(PeerAddr("192.0.2.10".parse().unwrap()));
        let response = self.app.clone().oneshot(request).await.expect("in-process API request");
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 65536).await.expect("API response body");
        (status, serde_json::from_slice(&bytes).expect("JSON API response"))
    }
    async fn mint(&self, env: &str) -> Token {
        let (status, body) = self.call("POST", &format!("/api/apps/{APP}/tokens"), SESSION,
            Some(json!({"name":"receipt-expiry-reader","env_id":env,"expires_in":86400,"scopes":"secrets:read"}))).await;
        assert_eq!(status, 200, "owner without TOTP can mint an ordinary environment token");
        Token { id: body["id"].as_str().expect("token id").into(), value: body["token"].as_str().expect("new credential").into() }
    }
    async fn delete(&self) {
        let (status, body) = self.call("DELETE", &format!("/api/envs/{DELETED_ENV}"), SESSION, None).await;
        assert_eq!(status, 200, "real environment deletion needs no step-up for an owner without TOTP");
        assert_eq!(body, json!({"ok":true}));
        assert!(self.st.db().one("SELECT id FROM envs WHERE id=?", &[json!(DELETED_ENV)]).await.unwrap().is_none(), "source environment must actually be deleted");
    }
    async fn receipt(&self, token: &Token) -> Option<Row> {
        self.st.db().one("SELECT * FROM deleted_env_receipts WHERE token_id=?", &[json!(&token.id)]).await.expect("inspect private receipt retention")
    }
    async fn terminal(&self, token: &Token) {
        assert_eq!(self.call("GET", "/api/me", &token.value, None).await, (200, json!({"env_scope":DELETED_ENV})));
        assert_eq!(self.call("GET", &format!("/api/envs/{DELETED_ENV}/meta"), &token.value, None).await,
            (200, json!({"id":DELETED_ENV,"name":"Deleted","app":"receipt-application","workspace":"receipt-workspace"})), "receipt retains exactly the four naming fields");
        assert_eq!(self.call("GET", &format!("/api/envs/{DELETED_ENV}/export?base=1"), &token.value, None).await,
            (404, json!({"error":"environment deleted","code":"environment_deleted"})));
    }
}

#[tokio::test]
async fn maintenance_physically_removes_expired_deleted_environment_receipts() {
    let f = Fixture::new().await;
    let token = f.mint(DELETED_ENV).await;
    assert_eq!(f.call("GET", "/api/me", &token.value, None).await.0, 200, "ordinary token authenticates before deletion");
    f.delete().await;
    f.terminal(&token).await;
    assert!(f.st.db().one("SELECT id FROM tokens WHERE id=? OR token_hash=?", &[json!(&token.id), json!(oc::hash_token(&token.value))]).await.unwrap().is_none(), "deletion removes the ordinary credential, not just its admission");
    assert!(f.receipt(&token).await.is_some(), "real deletion must create the receipt before time advances");
    assert_eq!(f.st.db().exec("UPDATE deleted_env_receipts SET expires_at=? WHERE token_id=?", &[json!(now()-86400), json!(&token.id)]).await.unwrap(), 1);
    for path in ["/api/me".to_string(), format!("/api/envs/{DELETED_ENV}/meta"), format!("/api/envs/{DELETED_ENV}/export?base=1")] {
        let (status, body) = f.call("GET", &path, &token.value, None).await;
        assert_eq!(status, 401, "expired receipt is already denied before maintenance");
        assert_ne!(body["code"], "environment_deleted", "expired receipt cannot disclose the deletion signal");
    }
    assert!(f.receipt(&token).await.is_some(), "admission expiry alone is not physical retention cleanup");
    process_rotations(&f.st).await;
    assert!(f.receipt(&token).await.is_none(), "maintenance must physically remove the expired receipt and its retained naming snapshot");
    process_rotations(&f.st).await;
    assert!(f.receipt(&token).await.is_none(), "repeated maintenance must not recreate expired receipts");
    assert_eq!(f.call("GET", "/api/me", &token.value, None).await.0, 401, "purging must not revive ordinary authentication");
}

#[tokio::test]
async fn maintenance_preserves_future_receipt_metadata_root_state_and_live_authentication() {
    let f = Fixture::new().await;
    let receipt = f.mint(DELETED_ENV).await;
    let live = f.mint(LIVE_ENV).await;
    f.delete().await;
    f.terminal(&receipt).await;
    let before = f.receipt(&receipt).await.expect("future receipt created by real deletion");
    assert!(db::n(&before, "expires_at") > now()+3600, "positive control must remain safely unexpired");
    let metadata = f.st.db().query("SELECT k,v FROM meta ORDER BY k", &[]).await.unwrap();
    let epoch = f.st.db().query("SELECT * FROM webhook_serialization", &[]).await.unwrap();
    for _ in 0..2 {
        process_rotations(&f.st).await;
        assert!(f.receipt(&receipt).await.as_ref() == Some(&before), "maintenance must preserve every field of an unexpired receipt");
        f.terminal(&receipt).await;
        assert!(f.st.db().query("SELECT k,v FROM meta ORDER BY k", &[]).await.unwrap() == metadata, "receipt cleanup must not change instance or root metadata");
        assert!(f.st.db().query("SELECT * FROM webhook_serialization", &[]).await.unwrap() == epoch, "receipt cleanup must not advance the instance key epoch");
        verify_master(f.st.db(), &MASTER).await.expect("maintenance preserves the root-encrypted inventory");
        assert!(f.st.db().one("SELECT id FROM tokens WHERE id=?", &[json!(&live.id)]).await.unwrap().is_some(), "cleanup must retain the active ordinary credential");
        let (status, me) = f.call("GET", "/api/me", &live.value, None).await;
        assert_eq!(status, 200, "active ordinary environment token still authenticates");
        assert_eq!(me["id"], OWNER);
        assert_eq!(me["env_scope"], LIVE_ENV);
        let (status, env) = f.call("GET", &format!("/api/envs/{LIVE_ENV}/meta"), &live.value, None).await;
        assert_eq!(status, 200, "active token keeps its normal environment read authority");
        assert_eq!(env["name"], "Live");
        assert!(env["policy"].is_object(), "ordinary metadata is not replaced by a terminal receipt");
    }
}
