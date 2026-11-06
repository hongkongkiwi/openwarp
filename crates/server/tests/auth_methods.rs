// Sign-in method policy and second factors: provider switching, emailed codes
// and a complete WebAuthn passkey registration plus assertion. Each test owns a
// private database and port.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::Mac;
use p256::ecdsa::signature::Signer;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp {
    status: u16,
    text: String,
    body: Value,
    headers: reqwest::header::HeaderMap,
}
impl Resp {
    fn header(&self, key: &str) -> String {
        self.headers.get(key).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }
}

struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("ephemeral port").local_addr().unwrap().port()
}

impl Server {
    async fn start() -> Server { Server::start_env(&[]).await }
    async fn start_env(extra: &[(&str, String)]) -> Server {
        let _start = START_LOCK.lock().await;
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-authmethods-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_SIGNUPS")
            .env_remove("OPENWARP_AUTH_PROVIDERS")
            .env_remove("OPENWARP_EMAIL_WEBHOOK")
            .env_remove("OPENWARP_EMAIL_TOKEN")
            .env_remove("OPENWARP_RP_ID")
            .env_remove("OPENWARP_RP_ORIGIN")
            .env_remove("OPENWARP_GOOGLE_CLIENT_ID")
            .env_remove("OPENWARP_GOOGLE_CLIENT_SECRET")
            .env_remove("OPENWARP_GITHUB_CLIENT_ID")
            .env_remove("OPENWARP_GITHUB_CLIENT_SECRET")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra { cmd.env(k, v); }
        let child = cmd.spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let server = Server { child, base, dir, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy at {}", server.base);
    }
    fn url(&self, path: &str) -> String { format!("{}{}", self.base, path) }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        let response = req.send().await.expect("http request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }
    async fn get(&self, path: &str) -> Resp { self.call(Method::GET, path, None, None).await }
}

async fn register(s: &Server, email: &str) -> Resp {
    s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await
}
async fn login(s: &Server, email: &str) -> Resp {
    s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await
}

fn start_email_relay() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("email relay");
    let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let sink = inbox.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (mut head_end, mut len) = (0usize, 0usize);
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 { break; }
                buf.extend_from_slice(&chunk[..n]);
                let Some(pos) = find(&buf, b"\r\n\r\n") else { continue };
                let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                let body_len = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                if buf.len() >= pos + 4 + body_len { head_end = pos + 4; len = body_len; break; }
            }
            let body = String::from_utf8_lossy(&buf[head_end..head_end + len.min(buf.len().saturating_sub(head_end))]).to_string();
            sink.lock().unwrap().push(body);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (format!("http://{}/hook", addr), inbox)
}
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> { haystack.windows(needle.len()).position(|w| w == needle) }
async fn email_code(inbox: &Arc<Mutex<Vec<String>>>) -> String {
    for _ in 0..100 {
        if let Some(body) = inbox.lock().unwrap().last().cloned() {
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                if let Some(text) = v.get("text").and_then(|t| t.as_str()) {
                    for word in text.split(|c: char| !c.is_ascii_digit()) {
                        if word.len() == 6 { return word.to_string(); }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no six-digit code reached the email relay");
}
async fn reset_token(inbox: &Arc<Mutex<Vec<String>>>) -> String {
    for _ in 0..100 {
        if let Some(body) = inbox.lock().unwrap().last().cloned() {
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                if let Some(text) = v.get("text").and_then(|t| t.as_str()) {
                    if let Some(pos) = text.find("#reset=") {
                        return text[pos + 7..].split_whitespace().next().unwrap_or("").to_string();
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no reset link reached the email relay");
}
fn totp(secret_b32: &str) -> String {
    let mut out = Vec::new();
    let (mut val, mut bits) = (0u32, 0u32);
    for c in secret_b32.chars() {
        let d = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;
        val = (val << 5) | d;
        bits += 5;
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

#[tokio::test]
async fn sign_in_methods_can_be_switched_and_password_login_stops() {
    let s = Server::start_env(&[
        ("OPENWARP_GOOGLE_CLIENT_ID", "test-google".into()),
        ("OPENWARP_GOOGLE_CLIENT_SECRET", "test-secret".into()),
    ]).await;
    let owner = register(&s, "owner@test.invalid").await;
    assert_eq!(owner.status, 200, "{}", owner.text);
    let ot = owner.body["token"].as_str().unwrap().to_string();
    let member = register(&s, "member@test.invalid").await;
    let mt = member.body["token"].as_str().unwrap().to_string();

    // An unconfigured provider cannot be switched on.
    let r = s.call(Method::PUT, "/api/instance/auth", Some(&ot), Some(json!({"github": true}))).await;
    assert_eq!(r.status, 400, "github has no credentials yet: {} {}", r.status, r.text);

    let r = s.call(Method::PUT, "/api/instance/auth", Some(&mt), Some(json!({"password": false}))).await;
    assert_eq!(r.status, 403, "only the instance owner may change sign-in methods: {} {}", r.status, r.text);

    let r = s.call(Method::PUT, "/api/instance/auth", Some(&ot), Some(json!({"password": false, "google": true}))).await;
    assert_eq!(r.status, 200, "provider switch failed: {} {}", r.status, r.text);
    let p = s.get("/api/auth/providers").await;
    assert_eq!(p.body["password"], json!(false), "{}", p.text);
    assert_eq!(p.body["google"], json!(true), "{}", p.text);

    let r = login(&s, "owner@test.invalid").await;
    assert_eq!(r.status, 403, "password login must stop when the method is off: {} {}", r.status, r.text);
    let r = register(&s, "new@test.invalid").await;
    assert_eq!(r.status, 403, "password registration must stop too: {} {}", r.status, r.text);
    let r = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": "x", "password": "long-enough-password"}))).await;
    assert_eq!(r.status, 403, "password reset must stop too: {} {}", r.status, r.text);

    // The last method cannot be turned off.
    let r = s.call(Method::PUT, "/api/instance/auth", Some(&ot), Some(json!({"google": false}))).await;
    assert_eq!(r.status, 400, "an instance needs at least one sign-in method: {} {}", r.status, r.text);
}

#[tokio::test]
async fn provider_policy_can_be_locked_by_the_environment() {
    let s = Server::start_env(&[
        ("OPENWARP_GOOGLE_CLIENT_ID", "test-google".into()),
        ("OPENWARP_GOOGLE_CLIENT_SECRET", "test-secret".into()),
        ("OPENWARP_AUTH_PROVIDERS", "password,google".into()),
    ]).await;
    let owner = register(&s, "locked@test.invalid").await;
    let ot = owner.body["token"].as_str().unwrap();
    let p = s.get("/api/auth/providers").await;
    assert_eq!(p.body["password"], json!(true), "{}", p.text);
    assert_eq!(p.body["github"], json!(false), "{}", p.text);
    assert_eq!(p.body["env_locked"], json!(true), "{}", p.text);
    let r = s.call(Method::PUT, "/api/instance/auth", Some(ot), Some(json!({"github": false}))).await;
    assert_eq!(r.status, 409, "the environment lock must win over the console: {} {}", r.status, r.text);
}

#[tokio::test]
async fn email_codes_work_as_a_second_factor() {
    let (hook, inbox) = start_email_relay();
    let s = Server::start_env(&[("OPENWARP_EMAIL_WEBHOOK", hook)]).await;
    let u = register(&s, "email-mfa@test.invalid").await;
    let t = u.body["token"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, "/api/me/mfa/email/start", Some(&t), Some(json!({}))).await;
    assert_eq!(r.status, 200, "email enrollment did not send: {} {}", r.status, r.text);
    let code = email_code(&inbox).await;
    let r = s.call(Method::POST, "/api/me/mfa/email/verify", Some(&t), Some(json!({"code": code}))).await;
    assert_eq!(r.status, 200, "email enrollment failed: {} {}", r.status, r.text);
    assert_eq!(r.body["recovery_codes"].as_array().map(|a| a.len()), Some(8), "{}", r.text);

    let r = login(&s, "email-mfa@test.invalid").await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["mfa_required"], json!(true), "{}", r.text);
    assert!(r.body["methods"].as_array().map(|a| a.iter().any(|m| m == "email")).unwrap_or(false), "{}", r.text);
    let challenge = r.body["mfa_token"].as_str().unwrap().to_string();

    // A wrong code costs an attempt but does not consume the challenge.
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": "000000"}))).await;
    assert_eq!(r.status, 401, "{} {}", r.status, r.text);

    let r = s.call(Method::POST, "/api/auth/mfa/email/send", None, Some(json!({"mfa_token": challenge}))).await;
    assert_eq!(r.status, 200, "login code was not sent: {} {}", r.status, r.text);
    let code = email_code(&inbox).await;
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": code}))).await;
    assert_eq!(r.status, 200, "email code did not complete sign-in: {} {}", r.status, r.text);

    // A code is single use: a new challenge with the same code must fail.
    let r = login(&s, "email-mfa@test.invalid").await;
    let challenge = r.body["mfa_token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": code}))).await;
    assert_eq!(r.status, 401, "a used email code must not work again: {} {}", r.status, r.text);
}

#[tokio::test]
async fn email_codes_need_a_mail_relay() {
    let s = Server::start().await;
    let u = register(&s, "no-mail@test.invalid").await;
    let t = u.body["token"].as_str().unwrap();
    let r = s.call(Method::POST, "/api/me/mfa/email/start", Some(t), Some(json!({}))).await;
    assert_eq!(r.status, 503, "without a relay the feature must fail closed: {} {}", r.status, r.text);
    let m = s.call(Method::GET, "/api/me/mfa", Some(t), None).await;
    assert_eq!(m.body["email_available"], json!(false), "{}", m.text);
}

#[tokio::test]
async fn a_password_reset_still_requires_the_second_factor() {
    let (hook, inbox) = start_email_relay();
    let s = Server::start_env(&[("OPENWARP_EMAIL_WEBHOOK", hook)]).await;
    let u = register(&s, "reset-mfa@test.invalid").await;
    let t = u.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&t), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&t), Some(json!({"code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "reset-mfa@test.invalid"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let token = reset_token(&inbox).await;
    let r = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": token, "password": "new-correct-horse", "discard_e2e_key": true}))).await;
    assert_eq!(r.status, 200, "reset failed: {} {}", r.status, r.text);
    assert_eq!(r.body["mfa_required"], json!(true), "a reset must not skip the second factor: {}", r.text);
    assert!(r.body.get("token").is_none(), "a reset must not mint a session before MFA: {}", r.text);
    assert!(r.header("set-cookie").is_empty(), "a reset must not set a session cookie before MFA: {}", r.header("set-cookie"));

    let challenge = r.body["mfa_token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "second factor after reset failed: {} {}", r.status, r.text);
    let session = r.body["token"].as_str().unwrap();
    let me = s.call(Method::GET, "/api/me", Some(session), None).await;
    assert_eq!(me.status, 200, "{} {}", me.status, me.text);
}

#[tokio::test]
async fn re_enrolling_totp_keeps_the_old_factor_until_verified() {
    let s = Server::start().await;
    let u = register(&s, "re-enroll@test.invalid").await;
    let t = u.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&t), Some(json!({}))).await;
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&t), Some(json!({"code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&t), Some(json!({"password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "re-enrolment start failed: {} {}", r.status, r.text);
    assert_eq!(r.body["recovery_codes"].as_array().map(|a| a.len()), Some(0), "existing recovery codes should survive: {}", r.text);

    let st = s.call(Method::GET, "/api/me/mfa", Some(&t), None).await;
    assert_eq!(st.body["totp"], json!(true), "an unverified re-enrolment must not disable TOTP: {}", st.text);
    let r = login(&s, "re-enroll@test.invalid").await;
    assert_eq!(r.body["mfa_required"], json!(true), "the old factor must stay active: {}", r.text);
    let challenge = r.body["mfa_token"].as_str().unwrap();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "the old authenticator must still work: {} {}", r.status, r.text);
}

fn b64u(bytes: &[u8]) -> String { Base64UrlUnpadded::encode_string(bytes) }
fn cbor_map(entries: Vec<(ciborium::value::Value, ciborium::value::Value)>) -> Vec<u8> {
    let v = ciborium::value::Value::Map(entries);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).expect("cbor");
    out
}
fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    use ciborium::value::Value as C;
    cbor_map(vec![
        (C::Integer(1.into()), C::Integer(2.into())),
        (C::Integer(3.into()), C::Integer((-7).into())),
        (C::Integer((-1).into()), C::Integer(1.into())),
        (C::Integer((-2).into()), C::Bytes(x.to_vec())),
        (C::Integer((-3).into()), C::Bytes(y.to_vec())),
    ])
}
fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    use ciborium::value::Value as C;
    cbor_map(vec![
        (C::Text("fmt".into()), C::Text("none".into())),
        (C::Text("attStmt".into()), C::Map(Vec::new())),
        (C::Text("authData".into()), C::Bytes(auth_data.to_vec())),
    ])
}
fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})).unwrap()
}
fn auth_data(rp_id: &str, flags: u8, counter: u32, extra: &[u8]) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(extra);
    out
}

#[tokio::test]
async fn a_passkey_can_be_registered_and_used_as_a_second_factor() {
    let origin = "https://example.com".to_string();
    let s = Server::start_env(&[
        ("OPENWARP_RP_ID", "example.com".into()),
        ("OPENWARP_RP_ORIGIN", origin.clone()),
    ]).await;
    let u = register(&s, "passkey@test.invalid").await;
    let t = u.body["token"].as_str().unwrap().to_string();

    // Register a P-256 credential the way a browser would.
    let r = s.call(Method::POST, "/api/me/passkeys/start", Some(&t), Some(json!({}))).await;
    assert_eq!(r.status, 200, "passkey start failed: {} {}", r.status, r.text);
    let state_id = r.body["state_id"].as_str().unwrap().to_string();
    let challenge = r.body["options"]["publicKey"]["challenge"].as_str().unwrap().to_string();
    let signing = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = signing.verifying_key().to_encoded_point(false);
    let cose = cose_key(point.x().unwrap().as_slice(), point.y().unwrap().as_slice());
    let cred_id = [9u8; 32];
    let mut extra = vec![0u8; 16];
    extra.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    extra.extend_from_slice(&cred_id);
    extra.extend_from_slice(&cose);
    let reg_auth = auth_data("example.com", 0x45, 0, &extra);
    let reg_cd = client_data("webauthn.create", &challenge, &origin);
    let credential = json!({
        "id": b64u(&cred_id), "rawId": b64u(&cred_id), "type": "public-key",
        "clientExtensionResults": {},
        "response": {"clientDataJSON": b64u(&reg_cd), "attestationObject": b64u(&attestation_object(&reg_auth)), "transports": ["internal"]}
    });
    let r = s.call(Method::POST, "/api/me/passkeys/finish", Some(&t), Some(json!({"state_id": state_id, "name": "test key", "credential": credential}))).await;
    assert_eq!(r.status, 200, "passkey registration failed: {} {}", r.status, r.text);
    assert_eq!(r.body["recovery_codes"].as_array().map(|a| a.len()), Some(8), "{}", r.text);

    let status = s.call(Method::GET, "/api/me/mfa", Some(&t), None).await;
    assert_eq!(status.body["passkeys"].as_array().map(|a| a.len()), Some(1), "{}", status.text);

    // Sign in with the passkey.
    let r = login(&s, "passkey@test.invalid").await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["mfa_required"], json!(true), "{}", r.text);
    assert!(r.body["methods"].as_array().map(|a| a.iter().any(|m| m == "passkey")).unwrap_or(false), "{}", r.text);
    let challenge_token = r.body["mfa_token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/mfa/passkey/start", None, Some(json!({"mfa_token": challenge_token}))).await;
    assert_eq!(r.status, 200, "passkey login start failed: {} {}", r.status, r.text);
    let challenge = r.body["options"]["publicKey"]["challenge"].as_str().unwrap().to_string();
    let assertion_auth = auth_data("example.com", 0x05, 1, &[]);
    let assertion_cd = client_data("webauthn.get", &challenge, &origin);
    let mut message = assertion_auth.clone();
    message.extend_from_slice(&Sha256::digest(&assertion_cd));
    let signature: p256::ecdsa::Signature = signing.sign(&message);
    let assertion = json!({
        "id": b64u(&cred_id), "rawId": b64u(&cred_id), "type": "public-key",
        "clientExtensionResults": {},
        "response": {"clientDataJSON": b64u(&assertion_cd), "authenticatorData": b64u(&assertion_auth), "signature": b64u(signature.to_der().as_bytes()), "userHandle": null}
    });
    let r = s.call(Method::POST, "/api/auth/mfa/passkey/finish", None, Some(json!({"mfa_token": challenge_token, "credential": assertion}))).await;
    assert_eq!(r.status, 200, "passkey assertion failed: {} {}", r.status, r.text);
    assert!(!r.header("set-cookie").is_empty(), "a completed passkey sign-in must set the session cookie");
    let session = r.body["token"].as_str().unwrap();
    let me = s.call(Method::GET, "/api/me", Some(session), None).await;
    assert_eq!(me.status, 200, "the passkey session must authenticate: {} {}", me.status, me.text);

    // A counter that does not advance signals a cloned credential.
    let r = login(&s, "passkey@test.invalid").await;
    let challenge_token = r.body["mfa_token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/mfa/passkey/start", None, Some(json!({"mfa_token": challenge_token}))).await;
    let challenge = r.body["options"]["publicKey"]["challenge"].as_str().unwrap().to_string();
    let assertion_cd = client_data("webauthn.get", &challenge, &origin);
    let mut message = auth_data("example.com", 0x05, 1, &[]);
    message.extend_from_slice(&Sha256::digest(&assertion_cd));
    let signature: p256::ecdsa::Signature = signing.sign(&message);
    let assertion = json!({
        "id": b64u(&cred_id), "rawId": b64u(&cred_id), "type": "public-key",
        "clientExtensionResults": {},
        "response": {"clientDataJSON": b64u(&assertion_cd), "authenticatorData": b64u(&auth_data("example.com", 0x05, 1, &[])), "signature": b64u(signature.to_der().as_bytes()), "userHandle": null}
    });
    let r = s.call(Method::POST, "/api/auth/mfa/passkey/finish", None, Some(json!({"mfa_token": challenge_token, "credential": assertion}))).await;
    assert!(matches!(r.status, 400 | 401), "a replayed signature counter must be rejected: {} {}", r.status, r.text);
}
