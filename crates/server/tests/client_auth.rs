// Client-derived auth: the server never receives a password or a wrapping key.
// These tests exercise registration, challenge login, single-use proofs, the
// version 1 fallback, reset-to-v2 migration, and MFA after a v2 login.

use hmac::Mac;
use openwarp_crypto as oc;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const AUTH_KEY: [u8; 32] = [3u8; 32];

struct Resp { status: u16, text: String, body: Value, headers: reqwest::header::HeaderMap }
impl Resp {
    fn header(&self, key: &str) -> String { self.headers.get(key).and_then(|v| v.to_str().ok()).unwrap_or("").to_string() }
}
struct Server { child: Child, base: String, dir: PathBuf, client: Client }
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn free_port() -> u16 { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }
impl Server {
    async fn start() -> Server {
        let _start = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-client-auth-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL").env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_KMS_URL").env_remove("OPENWARP_EMAIL_WEBHOOK")
            .env_remove("OPENWARP_REQUIRE_EMAIL_VERIFICATION")
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let server = Server { child, base, dir, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await { if r.status().is_success() { return server; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    fn url(&self, p: &str) -> String { format!("{}{}", self.base, p) }
    async fn call(&self, m: Method, p: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(m, self.url(p));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        let r = req.send().await.expect("request");
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let text = r.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }
    async fn form(&self, p: &str, fields: &[(&str, String)]) -> Resp {
        let r = self.client.post(self.url(p)).form(fields).send().await.expect("form request");
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let text = r.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }
    async fn get(&self, p: &str) -> Resp { self.call(Method::GET, p, None, None).await }
}

fn b64key(key: &[u8]) -> String { oc::b64(key) }
fn wrapped_private() -> String { format!("owv2:{}", oc::b64(&[9u8; 40])) }
fn proof(key: &[u8], challenge: &str, id: &str) -> String {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(format!("{}|{}", challenge, id).as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}
fn totp(secret_b32: &str) -> String {
    let mut out = Vec::new(); let (mut val, mut bits) = (0u32, 0u32);
    for c in secret_b32.chars() {
        let d = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;
        val = (val << 5) | d; bits += 5;
        if bits >= 8 { out.push(((val >> (bits - 8)) & 0xff) as u8); bits -= 8; }
    }
    let counter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&out).expect("hmac");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize;
    let code = (((hash[off] as u32 & 0x7f) << 24) | ((hash[off + 1] as u32) << 16) | ((hash[off + 2] as u32) << 8) | hash[off + 3] as u32) % 1_000_000;
    format!("{:06}", code)
}

async fn register_v1(s: &Server, email: &str) -> Resp {
    s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await
}
async fn register_v2(s: &Server, email: &str) -> Resp {
    let kp = oc::Keypair::generate();
    let salt = oc::b64(&[1u8; 16]);
    s.call(Method::POST, "/api/auth/register-v2", None, Some(json!({
        "email": email, "salt": salt, "iterations": 600000, "algo": "pbkdf2-sha256",
        "auth_key": b64key(&AUTH_KEY), "public_key": kp.public, "wrapped_privkey": wrapped_private()
    }))).await
}
async fn login_v2(s: &Server, email: &str) -> Resp {
    let ch = s.call(Method::POST, "/api/auth/challenge", None, Some(json!({"email": email}))).await;
    assert_eq!(ch.status, 200, "challenge failed: {} {}", ch.status, ch.text);
    let id = ch.body["challenge_id"].as_str().unwrap();
    let challenge = ch.body["challenge"].as_str().unwrap();
    s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({
        "email": email, "challenge_id": id, "proof": proof(&AUTH_KEY, challenge, id)
    }))).await
}

#[tokio::test]
async fn client_auth_registers_and_logs_in_without_a_password() {
    let s = Server::start().await;
    let kdf = s.get("/api/auth/kdf?email=new@test.invalid").await;
    assert_eq!(kdf.status, 200, "{}", kdf.text);
    assert_eq!(kdf.body["version"], json!(2), "{}", kdf.text);
    assert_eq!(kdf.body["algo"], json!("pbkdf2-sha256"));

    let reg = register_v2(&s, "new@test.invalid").await;
    assert_eq!(reg.status, 200, "register failed: {} {}", reg.status, reg.text);
    assert!(!reg.body["token"].as_str().unwrap_or("").is_empty());
    assert!(reg.body.get("recovery_kit").is_none(), "the server must not return a recovery kit it never saw");
    let token = reg.body["token"].as_str().unwrap();
    let me = s.call(Method::GET, "/api/me", Some(token), None).await;
    assert_eq!(me.body["email"], json!("new@test.invalid"));

    let kdf = s.get("/api/auth/kdf?email=new@test.invalid").await;
    assert_eq!(kdf.body["version"], json!(2), "{}", kdf.text);
    let login = login_v2(&s, "new@test.invalid").await;
    assert_eq!(login.status, 200, "login failed: {} {}", login.status, login.text);
    assert!(!login.body["wrapped_privkey"].as_str().unwrap_or("").is_empty());

    // A password login is not a path into a v2 account.
    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "new@test.invalid", "password": "anything-at-all"}))).await;
    assert_eq!(r.status, 401, "a v2 account must not accept a password: {} {}", r.status, r.text);
}

#[tokio::test]
async fn a_proof_is_single_use_and_a_wrong_proof_is_rejected() {
    let s = Server::start().await;
    let reg = register_v2(&s, "proof@test.invalid").await;
    assert_eq!(reg.status, 200, "{}", reg.text);
    let ch = s.call(Method::POST, "/api/auth/challenge", None, Some(json!({"email": "proof@test.invalid"}))).await;
    let id = ch.body["challenge_id"].as_str().unwrap().to_string();
    let challenge = ch.body["challenge"].as_str().unwrap().to_string();

    let wrong = s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({"email": "proof@test.invalid", "challenge_id": id, "proof": "00"}))).await;
    assert_eq!(wrong.status, 401, "{}", wrong.text);
    let good = s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({"email": "proof@test.invalid", "challenge_id": id, "proof": proof(&AUTH_KEY, &challenge, &id)}))).await;
    assert_eq!(good.status, 200, "the challenge should survive a wrong proof: {} {}", good.status, good.text);
    let replay = s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({"email": "proof@test.invalid", "challenge_id": id, "proof": proof(&AUTH_KEY, &challenge, &id)}))).await;
    assert_eq!(replay.status, 401, "a consumed proof must fail: {} {}", replay.status, replay.text);
}

#[tokio::test]
async fn version_one_accounts_still_work_and_reset_upgrades_them() {
    let s = Server::start().await;
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "legacy@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let uid = r.body["user_id"].as_str().unwrap().to_string();
    let stored_pub = r.body["public_key"].as_str().unwrap().to_string();
    let old = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "legacy@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(old.status, 200, "v1 login must keep working: {} {}", old.status, old.text);
    let kdf = s.get("/api/auth/kdf?email=legacy@test.invalid").await;
    assert_eq!(kdf.body["version"], json!(1), "{}", kdf.text);

    // A reset link can upgrade the account to client-derived auth, but it cannot
    // silently replace the account key without the explicit discard flag.
    let reset_token = "reset-token-for-test";
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    conn.execute("INSERT INTO auth_tokens(token_hash,user_id,kind,created_at,expires_at,used) VALUES(?,?,?,?,?,0)",
        rusqlite::params![oc::hash_token(reset_token), uid, "reset", 0i64, 4_000_000_000i64]).unwrap();
    let info = s.call(Method::POST, "/api/auth/reset-info", None, Some(json!({"token": reset_token}))).await;
    assert_eq!(info.status, 200, "reset info failed: {} {}", info.status, info.text);
    assert_eq!(info.body["public_key"].as_str().unwrap_or(""), stored_pub.as_str(), "{}", info.text);
    let kp = oc::Keypair::generate();
    let r = s.call(Method::POST, "/api/auth/reset-v2", None, Some(json!({
        "token": reset_token, "salt": oc::b64(&[2u8; 16]), "iterations": 600000, "algo": "pbkdf2-sha256",
        "auth_key": b64key(&AUTH_KEY), "public_key": kp.public, "wrapped_privkey": wrapped_private()
    }))).await;
    assert_eq!(r.status, 400, "a different key needs the discard flag: {} {}", r.status, r.text);
    let r = s.call(Method::POST, "/api/auth/reset-v2", None, Some(json!({
        "token": reset_token, "salt": oc::b64(&[2u8; 16]), "iterations": 600000, "algo": "pbkdf2-sha256",
        "auth_key": b64key(&AUTH_KEY), "public_key": stored_pub, "wrapped_privkey": wrapped_private()
    }))).await;
    assert_eq!(r.status, 200, "v2 reset failed: {} {}", r.status, r.text);
    let kdf = s.get("/api/auth/kdf?email=legacy@test.invalid").await;
    assert_eq!(kdf.body["version"], json!(2), "{}", kdf.text);
    let login = login_v2(&s, "legacy@test.invalid").await;
    assert_eq!(login.status, 200, "v2 login after reset failed: {} {}", login.status, login.text);
    let password = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "legacy@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(password.status, 401, "the old password must stop working after the upgrade");

    let reset2 = "reset-token-2";
    conn.execute("INSERT INTO auth_tokens(token_hash,user_id,kind,created_at,expires_at,used) VALUES(?,?,?,?,?,0)",
        rusqlite::params![oc::hash_token(reset2), uid, "reset", 0i64, 4_000_000_000i64]).unwrap();
    let r = s.call(Method::POST, "/api/auth/reset-v2", None, Some(json!({
        "token": reset2, "salt": oc::b64(&[3u8; 16]), "iterations": 600000, "algo": "pbkdf2-sha256",
        "auth_key": b64key(&AUTH_KEY), "public_key": kp.public, "wrapped_privkey": wrapped_private(), "discard_e2e_key": true
    }))).await;
    assert_eq!(r.status, 200, "an explicit discard must allow a new key: {} {}", r.status, r.text);
}

#[tokio::test]
async fn a_weak_stored_kdf_is_refused() {
    let s = Server::start().await;
    let reg = register_v2(&s, "weak-kdf@test.invalid").await;
    assert_eq!(reg.status, 200, "{}", reg.text);
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    conn.execute("UPDATE users SET kdf_iterations=1 WHERE email=?", ["weak-kdf@test.invalid"]).unwrap();
    let kdf = s.get("/api/auth/kdf?email=weak-kdf@test.invalid").await;
    assert!(kdf.status >= 400, "a weak stored KDF must be refused: {} {}", kdf.status, kdf.text);
    let ch = s.call(Method::POST, "/api/auth/challenge", None, Some(json!({"email": "weak-kdf@test.invalid"}))).await;
    assert_eq!(ch.status, 200, "{}", ch.text);
    let id = ch.body["challenge_id"].as_str().unwrap();
    let challenge = ch.body["challenge"].as_str().unwrap();
    let r = s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({"email": "weak-kdf@test.invalid", "challenge_id": id, "proof": proof(&AUTH_KEY, challenge, id)}))).await;
    assert_eq!(r.status, 401, "a weak KDF row must not authenticate: {} {}", r.status, r.text);
}

#[tokio::test]
async fn a_v2_login_still_requires_the_second_factor() {
    let s = Server::start().await;
    let reg = register_v2(&s, "mfa-v2@test.invalid").await;
    assert_eq!(reg.status, 200, "{}", reg.text);
    let token = reg.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "totp setup failed: {}", r.text);
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "totp verify failed: {}", r.text);

    let ch = s.call(Method::POST, "/api/auth/challenge", None, Some(json!({"email": "mfa-v2@test.invalid"}))).await;
    let id = ch.body["challenge_id"].as_str().unwrap().to_string();
    let challenge = ch.body["challenge"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({"email": "mfa-v2@test.invalid", "challenge_id": id, "proof": proof(&AUTH_KEY, &challenge, &id)}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["mfa_required"], json!(true), "{}", r.text);
    let mfa = r.body["mfa_token"].as_str().unwrap();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": mfa, "code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "MFA after v2 login failed: {} {}", r.status, r.text);
}

#[tokio::test]
async fn oauth_consent_accepts_a_client_proof() {
    let s = Server::start().await;
    let reg = register_v2(&s, "consent-v2@test.invalid").await;
    assert_eq!(reg.status, 200, "{}", reg.text);
    let r = s.call(Method::POST, "/oauth/register", None, Some(json!({
        "redirect_uris": ["http://127.0.0.1:9/cb"], "token_endpoint_auth_method": "none", "scope": "secrets:read"
    }))).await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let ch = s.call(Method::POST, "/api/auth/challenge", None, Some(json!({"email": "consent-v2@test.invalid"}))).await;
    let id = ch.body["challenge_id"].as_str().unwrap().to_string();
    let challenge = ch.body["challenge"].as_str().unwrap().to_string();
    let fields = vec![
        ("response_type", "code".to_string()), ("client_id", client_id), ("redirect_uri", "http://127.0.0.1:9/cb".to_string()),
        ("scope", "secrets:read".to_string()), ("state", "s".to_string()), ("code_challenge", "abc".to_string()),
        ("code_challenge_method", "S256".to_string()), ("email", "consent-v2@test.invalid".to_string()),
        ("challenge_id", id.clone()), ("proof", proof(&AUTH_KEY, &challenge, &id)), ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &fields).await;
    assert_eq!(r.status, 303, "a v2 proof should issue an OAuth code: {} {}", r.status, r.text);
    assert!(r.header("location").contains("code="), "expected a code, got {}", r.header("location"));
}

#[tokio::test]
async fn a_v2_account_can_redeem_an_invite() {
    let s = Server::start().await;
    let owner = register_v1(&s, "invite-owner@test.invalid").await;
    let ot = owner.body["token"].as_str().unwrap();
    let org = owner.body["org_id"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "invitee-v2@test.invalid", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "invite failed: {} {}", r.status, r.text);
    let invite = r.body["invite_token"].as_str().unwrap().to_string();
    let kp = oc::Keypair::generate();
    let r = s.call(Method::POST, "/api/auth/accept-invite-v2", None, Some(json!({
        "token": invite, "salt": oc::b64(&[4u8; 16]), "iterations": 600000, "algo": "pbkdf2-sha256",
        "auth_key": b64key(&AUTH_KEY), "public_key": kp.public, "wrapped_privkey": wrapped_private()
    }))).await;
    assert_eq!(r.status, 200, "invite acceptance failed: {} {}", r.status, r.text);
    let it = r.body["token"].as_str().unwrap();
    let orgs = s.call(Method::GET, "/api/orgs", Some(it), None).await;
    assert_eq!(orgs.status, 200, "{}", orgs.text);
    assert!(orgs.text.contains(org), "the invitee must join the inviting org: {}", orgs.text);
    let login = login_v2(&s, "invitee-v2@test.invalid").await;
    assert_eq!(login.status, 200, "v2 login after invite failed: {} {}", login.status, login.text);
}
