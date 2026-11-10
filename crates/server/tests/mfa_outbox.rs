// MFA durable-factor atomicity. Enrolling, removing or regenerating a second
// factor mutates durable account state (meta keys, passkey rows) and then calls
// st.audit, whose audit row, audit head and outbox event commit in one
// transaction. The mutation currently happens first, outside that transaction,
// so a failed audit write leaves the factor changed with no audit trail. These
// tests inject a SQLite trigger that fails the audit INSERT and assert the
// durable factor state, audit head and outbox all stay put, and that the
// handler surfaces the failure as a non-2xx response instead of pretending
// success.
//
// confirm_totp resets totp_last to "0" as part of enrollment promotion, so that
// reset rolls back with totp_secret/enabled/pending. The login path (totp_ok,
// otp_ok) advancing totp_last after consuming a code, and recovery_ok removing
// a consumed recovery code, are consumptive security state and stay independent
// of this rollback; those paths are not exercised here.

use openwarp_server::db::{n, s, Db};
use openwarp_server::mfa;
use openwarp_server::{new_state, router, PeerAddr, S};
use openwarp_crypto as oc;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "mfa-outbox-session";
const USER: &str = "mfa-outbox-user";
// RFC 6238 test secret: 20 ASCII bytes, base32-encoded, at least 10 bytes once
// decoded so the server accepts it.
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SECRET_BYTES: &[u8] = b"12345678901234567890";

async fn fixture() -> (S, [u8; 32]) {
    let db = Db::open_memory().await.unwrap();
    let master = oc::random_key();
    let (live, _) = tokio::sync::broadcast::channel(8);
    let state = new_state(db, String::new(), "mfa-outbox".into(), "https://example.invalid".into(), master, live, #[cfg(feature = "redis-cache")] None);
    let t = openwarp_server::clock::now();
    // A social-created account: no pass_hash and no password_known meta, so
    // reauth_add / reauth_remove are no-ops. That isolates the durable-state
    // audit atomicity under test from the password reauth step.
    state.db().exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(USER), json!("mfa-outbox@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
    state.db().exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
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

async fn meta_val(db: &Db, key: &str) -> String {
    db.one("SELECT v FROM meta WHERE k=?", &[json!(key)]).await.unwrap().map(|r| s(&r, "v")).unwrap_or_default()
}

async fn audit_count(db: &Db, action: &str) -> i64 {
    db.one("SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action=?", &[json!(""), json!(action)]).await.unwrap()
        .map(|r| n(&r, "n")).unwrap_or(0)
}

async fn head_seq(db: &Db) -> i64 {
    db.one("SELECT seq FROM audit_heads WHERE org_id=?", &[json!("")]).await.unwrap()
        .map(|r| n(&r, "seq")).unwrap_or(0)
}

async fn outbox_count(db: &Db) -> i64 {
    db.one("SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await.unwrap()
        .map(|r| n(&r, "n")).unwrap_or(0)
}

async fn install_audit_fault(state: &S) {
    state.db().exec("CREATE TRIGGER mfa_fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END", &[]).await.unwrap();
}

// Mirrors the server's TOTP truncation so the test produces a code the same
// window will accept.
fn totp_code(secret: &[u8], counter: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type H = Hmac<Sha1>;
    let mut m = H::new_from_slice(secret).unwrap();
    m.update(&counter.to_be_bytes());
    let hash = m.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize;
    let code = ((hash[off] as u32 & 0x7f) << 24) | ((hash[off + 1] as u32) << 16) | ((hash[off + 2] as u32) << 8) | hash[off + 3] as u32;
    format!("{:06}", code % 1_000_000)
}

async fn enroll_totp(state: &S) {
    let (s1, b1) = call(state, "POST", "/api/me/totp/setup", Some(json!({"secret": SECRET_B32}))).await;
    assert_eq!(s1, 200, "totp setup failed: {b1}");
    let counter = (openwarp_server::clock::now() / 30) as u64;
    let code = totp_code(SECRET_BYTES, counter);
    let (s2, b2) = call(state, "POST", "/api/me/totp/verify", Some(json!({"code": code}))).await;
    assert_eq!(s2, 200, "totp verify failed: {b2}");
    assert!(mfa::totp_enabled(state, USER).await, "fixture: TOTP did not enable");
}

#[tokio::test]
async fn audit_write_failure_rolls_back_totp_enrollment() {
    let (state, _) = fixture().await;

    // Real setup establishes a pending secret and recovery codes, but the
    // factor must stay pending until verify proves the code.
    let (s1, b1) = call(&state, "POST", "/api/me/totp/setup", Some(json!({"secret": SECRET_B32}))).await;
    assert_eq!(s1, 200, "totp setup failed: {b1}");
    assert!(!meta_val(state.db(), &format!("totp_pending:{USER}")).await.is_empty(), "fixture: pending secret not stored");
    assert_eq!(meta_val(state.db(), &format!("totp_enabled:{USER}")).await, "", "fixture: TOTP enabled before verify");

    install_audit_fault(&state).await;

    let counter = (openwarp_server::clock::now() / 30) as u64;
    let code = totp_code(SECRET_BYTES, counter);
    let (s2, b2) = call(&state, "POST", "/api/me/totp/verify", Some(json!({"code": code}))).await;
    // A failed audit write must surface as a non-2xx response, not pretend success.
    assert!(s2 >= 400, "verify must fail when its audit write fails; got {s2}: {b2}");

    assert_eq!(meta_val(state.db(), &format!("totp_enabled:{USER}")).await, "",
        "TOTP must stay disabled when its audit write fails");
    assert_eq!(meta_val(state.db(), &format!("totp_secret:{USER}")).await, "",
        "the pending secret must not be promoted when the audit write fails");
    assert!(!meta_val(state.db(), &format!("totp_pending:{USER}")).await.is_empty(),
        "the pending secret must remain when the audit write fails");
    assert_eq!(meta_val(state.db(), &format!("totp_last:{USER}")).await, "",
        "the enrollment replay reset must roll back when the audit write fails");
    assert_eq!(audit_count(state.db(), "auth.totp_enabled").await, 0,
        "the failed enrollment must not append an audit row");
    assert_eq!(head_seq(state.db()).await, 0, "the failed enrollment must not advance the audit head");
    assert_eq!(outbox_count(state.db()).await, 0, "the failed enrollment must not enqueue an outbox event");
}

#[tokio::test]
async fn audit_write_failure_rolls_back_totp_disable() {
    let (state, _) = fixture().await;
    enroll_totp(&state).await;

    let secret_before = meta_val(state.db(), &format!("totp_secret:{USER}")).await;
    let recovery_before = meta_val(state.db(), &format!("totp_recovery:{USER}")).await;
    assert!(!secret_before.is_empty(), "fixture: enabled TOTP has no secret");
    assert!(!recovery_before.is_empty(), "fixture: enabled TOTP has no recovery codes");
    let head_before = head_seq(state.db()).await;

    install_audit_fault(&state).await;

    let (s2, b2) = call(&state, "DELETE", "/api/me/totp", Some(json!({}))).await;
    assert!(s2 >= 400, "totp disable must fail when its audit write fails; got {s2}: {b2}");

    assert!(mfa::totp_enabled(&state, USER).await,
        "TOTP must stay enabled when its audit write fails");
    assert_eq!(meta_val(state.db(), &format!("totp_secret:{USER}")).await, secret_before,
        "the TOTP secret must survive a failed disable");
    assert_eq!(meta_val(state.db(), &format!("totp_recovery:{USER}")).await, recovery_before,
        "recovery codes must survive a failed disable");
    assert_eq!(audit_count(state.db(), "auth.totp_disabled").await, 0,
        "the failed disable must not append an audit row");
    assert_eq!(head_seq(state.db()).await, head_before, "the failed disable must not advance the audit head");
    assert_eq!(outbox_count(state.db()).await, 0, "the failed disable must not enqueue an outbox event");
}

#[tokio::test]
async fn audit_write_failure_rolls_back_recovery_regeneration() {
    let (state, _) = fixture().await;

    // Setup alone issues recovery codes; regenerating must not replace them when
    // the audit write fails.
    let (s1, b1) = call(&state, "POST", "/api/me/totp/setup", Some(json!({"secret": SECRET_B32}))).await;
    assert_eq!(s1, 200, "totp setup failed: {b1}");
    let recovery_before = meta_val(state.db(), &format!("totp_recovery:{USER}")).await;
    assert!(!recovery_before.is_empty(), "fixture: setup issued no recovery codes");

    install_audit_fault(&state).await;

    let (s2, b2) = call(&state, "POST", "/api/me/mfa/recovery-codes", Some(json!({}))).await;
    assert!(s2 >= 400, "recovery regeneration must fail when its audit write fails; got {s2}: {b2}");

    assert_eq!(meta_val(state.db(), &format!("totp_recovery:{USER}")).await, recovery_before,
        "recovery codes must not be replaced when the audit write fails");
    assert_eq!(audit_count(state.db(), "auth.recovery_codes_regenerated").await, 0,
        "the failed regeneration must not append an audit row");
    assert_eq!(head_seq(state.db()).await, 0, "the failed regeneration must not advance the audit head");
    assert_eq!(outbox_count(state.db()).await, 0, "the failed regeneration must not enqueue an outbox event");
}
