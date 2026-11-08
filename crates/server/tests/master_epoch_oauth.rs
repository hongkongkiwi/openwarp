// Master epoch read fencing for the OAuth authorization-decision path. A v2
// sign-in proves possession of the account auth key with an HMAC over a
// challenge; the decision handler decrypts that auth key with the instance
// master. After a master rotation a stale replica would decrypt the rewrapped
// auth_key_enc with the old master and return a bogus 500 instead of failing
// closed with epoch_stale, and must not consume the challenge. Two AppStates
// share one file-backed SQLite database; the fresh replica rotates through the
// real handler and then each replica drives POST /oauth/authorize/decision
// with a real registered client and a correctly computed proof.

use hmac::Mac;
use openwarp_crypto as oc;
use openwarp_server::db::{n, Db};
use openwarp_server::{new_state, router, PeerAddr, S};
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "epoch-oauth-session";
const USER: &str = "epoch-oauth-user";
const EMAIL: &str = "epoch-v2@test.invalid";
const REDIRECT: &str = "http://127.0.0.1:8917/callback";

struct Rotated {
    dir: std::path::PathBuf,
    stale: Option<S>,
    fresh: Option<S>,
    new: [u8; 32],
    auth_key: [u8; 32],
}

impl Rotated {
    fn stale(&self) -> &S { self.stale.as_ref().unwrap() }
    fn fresh(&self) -> &S { self.fresh.as_ref().unwrap() }

    async fn seed() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-master-epoch-oauth-{}-{}", std::process::id(), oc::random_token("fixture")));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}/epoch.db", dir.display());
        let db_stale = Db::open(&url).await.unwrap();
        let db_fresh = Db::open(&url).await.unwrap();
        let old = oc::random_key();
        let new = oc::random_key();
        let auth_key = oc::random_key();
        let (live_stale, _) = tokio::sync::broadcast::channel(8);
        let (live_fresh, _) = tokio::sync::broadcast::channel(8);
        let stale = new_state(db_stale, String::new(), "epoch-stale".into(), "https://example.invalid".into(), old, live_stale, #[cfg(feature = "redis-cache")] None);
        let fresh = new_state(db_fresh, String::new(), "epoch-fresh".into(), "https://example.invalid".into(), old, live_fresh, #[cfg(feature = "redis-cache")] None);

        let t = openwarp_server::clock::now();
        let aad = format!("auth-key|{USER}").into_bytes();
        let auth_key_enc = oc::encrypt_symmetric_aad(&old, &aad, &auth_key);
        let iterations: i64 = 600_000;
        let db = fresh.db();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,auth_version,kdf_salt,kdf_iterations,kdf_algo,auth_key_enc,active,email_verified) VALUES(?,?,?,?,?,?,2,?,?,?,?,1,1)",
            &[json!(USER), json!(EMAIL), json!(""), json!(oc::b64(&oc::random_key())), json!("owv2:epoch"), json!(t), json!(oc::b64(&oc::random_key()[..16])), json!(iterations), json!("pbkdf2-sha256"), json!(auth_key_enc)]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
            &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(USER)]).await.unwrap();

        Rotated { dir, stale: Some(stale), fresh: Some(fresh), new, auth_key }
    }

    async fn rotate(&self) {
        let (status, body) = call(self.fresh(), "POST", "/api/instance/rotate-master", Some(json!({"new_key": oc::b64(&self.new)}))).await;
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

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

async fn decision(state: &S, form: &[(&str, &str)]) -> (u16, String, Option<String>) {
    let body = form.iter().map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v))).collect::<Vec<_>>().join("&");
    let mut req = axum::http::Request::builder().method("POST").uri("/oauth/authorize/decision")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body)).unwrap();
    req.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
    let resp = router(state.to_owned()).oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let location = resp.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned(), location)
}

async fn count(db: &Db, sql: &str, params: &[Value]) -> i64 {
    db.one(sql, params).await.unwrap().map(|r| n(&r, "n")).unwrap_or(0)
}

async fn seed_challenge(db: &Db, cid: &str, challenge: &str) {
    db.exec("INSERT INTO auth_challenges(id_hash,user_id,challenge,created_at) VALUES(?,?,?,?)",
        &[json!(oc::hash_token(cid)), json!(USER), json!(challenge), json!(openwarp_server::clock::now())]).await.unwrap();
}

fn proof_for(auth_key: &[u8; 32], challenge: &str, cid: &str) -> String {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(auth_key).unwrap();
    mac.update(format!("{challenge}|{cid}").as_bytes());
    hex(&mac.finalize().into_bytes())
}

#[tokio::test]
async fn stale_replica_oauth_v2_proof_fails_closed_without_consuming_challenge() {
    let r = Rotated::seed().await;

    // Register a real client, then create the v2 proof challenge rows.
    let (s, b) = call(r.fresh(), "POST", "/oauth/register", Some(json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "scope": "secrets:read"}))).await;
    assert_eq!(s, 201, "oauth client registration failed: {b}");
    let client_id = b["client_id"].as_str().unwrap().to_string();

    let fresh_cid = oc::random_token("ch");
    let fresh_challenge = oc::random_token("chal");
    seed_challenge(r.fresh().db(), &fresh_cid, &fresh_challenge).await;

    r.rotate().await;

    let fresh_proof = proof_for(&r.auth_key, &fresh_challenge, &fresh_cid);
    let fresh_form = vec![
        ("client_id", client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "secrets:read"),
        ("code_challenge", "epoch-challenge"),
        ("code_challenge_method", "S256"),
        ("email", EMAIL),
        ("challenge_id", fresh_cid.as_str()),
        ("proof", fresh_proof.as_str()),
        ("approve", "1"),
        ("state", "epoch"),
    ];
    let (status, body, location) = decision(r.fresh(), &fresh_form).await;
    assert_eq!(status, 303, "fresh replica should issue an authorization code: {body}");
    assert!(location.as_deref().map(|l| l.contains("code=")).unwrap_or(false), "fresh redirect must carry a code: {location:?}");
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id=?", &[json!(USER)]).await, 0,
        "fresh proof must consume its challenge");

    // A second challenge for the stale replica, whose old master can no longer
    // decrypt the rewrapped auth_key_enc.
    let stale_cid = oc::random_token("ch");
    let stale_challenge = oc::random_token("chal");
    seed_challenge(r.fresh().db(), &stale_cid, &stale_challenge).await;

    let stale_proof = proof_for(&r.auth_key, &stale_challenge, &stale_cid);
    let stale_form = vec![
        ("client_id", client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "secrets:read"),
        ("code_challenge", "epoch-challenge"),
        ("code_challenge_method", "S256"),
        ("email", EMAIL),
        ("challenge_id", stale_cid.as_str()),
        ("proof", stale_proof.as_str()),
        ("approve", "1"),
        ("state", "epoch"),
    ];
    let (status, body, _) = decision(r.stale(), &stale_form).await;
    assert_eq!(status, 503, "stale OAuth v2 proof must fail closed with 503, not a bogus decrypt failure; got {status}: {body}");
    assert!(body.contains("epoch_stale"), "stale OAuth v2 proof must carry epoch_stale; got {body}");
    assert_eq!(count(r.fresh().db(), "SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id=?", &[json!(USER)]).await, 1,
        "stale OAuth v2 proof must not consume the challenge");
}
