// Delegated environments: the client owns the environment key, the runner gets
// a second wrapped copy, integrations are queued instead of executed, and the
// customer-run binary decrypts and pushes without the server seeing plaintext.

use openwarp_crypto as oc;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp { status: u16, text: String, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, log: PathBuf, client: Client }
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
        let dir = std::env::temp_dir().join(format!("openwarp-delegated-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let log = dir.join("server.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_KMS_URL")
            .env_remove("OPENWARP_EMAIL_WEBHOOK")
            .stdout(Stdio::null()).stderr(Stdio::from(log_file))
            .spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let server = Server { child, base, dir, log, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await { if r.status().is_success() { return server; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    fn url(&self, p: &str) -> String { format!("{}{}", self.base, p) }
    fn verification_link(&self) -> String {
        let pattern = format!("{}/api/auth/verify?token=", self.base);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&self.log) {
                if let Some(i) = text.rfind(&pattern) {
                    let rest = &text[i..];
                    let end = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '<').unwrap_or(rest.len());
                    return rest[..end].to_string();
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the verification link was not written to the server log");
    }
    async fn verify(&self) {
        let link = self.verification_link();
        let path = link.strip_prefix(&self.base).unwrap_or(&link).to_string();
        let r = self.call(Method::GET, &path, None, None).await;
        assert_eq!(r.status, 200, "verification link failed: {} {}", r.status, r.text);
    }
    async fn call(&self, m: Method, p: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(m, self.url(p));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        let r = req.send().await.expect("request");
        let status = r.status().as_u16();
        let text = r.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body }
    }
}

async fn register_verified(s: &Server, email: &str) -> (String, String, String) {
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let org = r.body["org_id"].as_str().unwrap().to_string();
    s.verify().await;
    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 200, "login after verification failed: {} {}", login.status, login.text);
    (login.body["token"].as_str().unwrap().to_string(), org, login.body["public_key"].as_str().unwrap().to_string())
}

fn start_webhook() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
                let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                let body_len = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                if buf.len() >= pos + 4 + body_len { head_end = pos + 4; len = body_len; break; }
            }
            sink.lock().unwrap().push(String::from_utf8_lossy(&buf[head_end..head_end + len.min(buf.len().saturating_sub(head_end))]).to_string());
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (format!("http://{}/hook", addr), inbox)
}

#[tokio::test]
async fn a_delegated_environment_syncs_through_the_customer_runner() {
    let (hook, inbox) = start_webhook();
    let s = Server::start().await;
    let (token, org, user_pub) = register_verified(&s, "delegated@test.invalid").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({"name": "app"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let app = r.body["id"].as_str().unwrap().to_string();

    // The runner identity holds its own X25519 key; the server only gets the public key.
    let runner_key = oc::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&token), Some(json!({"name": "vpc-runner", "public_key": runner_key.public}))).await;
    assert_eq!(r.status, 200, "runner create failed: {} {}", r.status, r.text);
    let runner_id = r.body["id"].as_str().unwrap().to_string();
    let runner_token = r.body["token"].as_str().unwrap().to_string();

    // The client generates the environment key and wraps it to both itself and the runner.
    let env_key = oc::random_key();
    let owner_wrapped = oc::encrypt_to(&user_pub, &env_key).unwrap();
    let runner_wrapped = oc::encrypt_to(&runner_key.public, &env_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs", app), Some(&token), Some(json!({
        "name": "production", "mode": "delegated", "runner_id": runner_id,
        "wrapped_key": owner_wrapped, "runner_wrapped_key": runner_wrapped
    }))).await;
    assert_eq!(r.status, 200, "delegated env create failed: {} {}", r.status, r.text);
    let env = r.body["id"].as_str().unwrap().to_string();

    let key_enc = oc::encrypt_symmetric(&env_key, b"API_KEY");
    let value_enc = oc::encrypt_symmetric(&env_key, b"secret-value");
    let r = s.call(Method::PUT, &format!("/api/envs/{}/e2e/secrets", env), Some(&token), Some(json!({
        "secrets": [{"key_enc": key_enc, "value_enc": value_enc, "key_hash": oc::hash_token("API_KEY"), "path": "/", "path_enc": oc::encrypt_symmetric(&env_key, b"/")}]
    }))).await;
    assert_eq!(r.status, 200, "client-side deploy failed: {} {}", r.status, r.text);

    // The server cannot read the environment.
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&token), None).await;
    assert!(r.status >= 400, "the server must not decrypt a delegated env: {} {}", r.status, r.text);

    // An integration config is sealed to the runner, not the server.
    let r = s.call(Method::POST, &format!("/api/envs/{}/integrations", env), Some(&token), Some(json!({"kind": "webhook", "config": {"url": hook}}))).await;
    assert_eq!(r.status, 200, "integration create failed: {} {}", r.status, r.text);
    let iid = r.body["id"].as_str().unwrap().to_string();
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let config_enc: String = conn.query_row("SELECT config_enc FROM integrations WHERE id=?", [&iid], |row| row.get(0)).unwrap();
    assert!(config_enc.starts_with("owrunner:"), "config is not sealed to the runner: {}", config_enc);

    let r = s.call(Method::POST, &format!("/api/integrations/{}/sync", iid), Some(&token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "sync did not queue: {} {}", r.status, r.text);
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200, "{}", jobs.text);
    assert_eq!(jobs.body["jobs"].as_array().map(|a| a.len()), Some(1), "expected one queued job: {}", jobs.text);
    let jid = jobs.body["jobs"][0]["id"].as_str().unwrap().to_string();
    let first_claim = jobs.body["jobs"][0]["claim"].as_str().unwrap().to_string();
    // Simulate the ten-minute stale window and claim the job again.
    conn.execute("UPDATE sync_jobs SET claimed_at=0", []).unwrap();
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    let second_claim = jobs.body["jobs"][0]["claim"].as_str().unwrap().to_string();
    assert_ne!(first_claim, second_claim, "the reclaim must fence the old runner");
    let late = s.call(Method::POST, &format!("/api/runner/jobs/{}/result", jid), Some(&runner_token), Some(json!({"ok": true, "detail": "late", "managed": [], "claim": first_claim}))).await;
    assert_eq!(late.status, 409, "a superseded claim must not complete: {} {}", late.status, late.text);
    let current = s.call(Method::POST, &format!("/api/runner/jobs/{}/result", jid), Some(&runner_token), Some(json!({"ok": true, "detail": "current", "managed": [], "claim": second_claim}))).await;
    assert_eq!(current.status, 200, "the current claim must complete: {} {}", current.status, current.text);
    let r = s.call(Method::POST, &format!("/api/integrations/{}/sync", iid), Some(&token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "second sync did not queue: {} {}", r.status, r.text);

    let mut child = Command::new(env!("CARGO_BIN_EXE_openwarp-runner"))
        .env("OPENWARP_URL", &s.base)
        .env("OPENWARP_RUNNER_TOKEN", &runner_token)
        .env("OPENWARP_RUNNER_KEY", runner_key.secret_b64())
        .env("OPENWARP_RUNNER_ONCE", "1")
        .stdout(Stdio::null()).stderr(Stdio::inherit())
        .spawn().expect("spawn runner");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Ok(Some(status)) = child.try_wait() { break Some(status); }
        if Instant::now() >= deadline { break None; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    match status {
        Some(status) => { let _ = child.wait(); assert!(status.success(), "runner exited with {:?}", status); }
        None => { let _ = child.kill(); let _ = child.wait(); panic!("runner did not finish"); }
    }

    let bodies = inbox.lock().unwrap().clone();
    assert!(!bodies.is_empty(), "the webhook never received the sync");
    let body: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(body["secrets"]["API_KEY"], json!("secret-value"));
    let status: String = conn.query_row("SELECT status FROM sync_jobs", [], |row| row.get(0)).unwrap();
    assert_eq!(status, "done", "runner result was not recorded");
}

#[tokio::test]
async fn a_runner_token_cannot_read_other_organisations_jobs() {
    let s = Server::start().await;
    let (at, ao, _) = register_verified(&s, "a@test.invalid").await;
    let (bt, _, _) = register_verified(&s, "b@test.invalid").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", ao), Some(at.as_str()), Some(json!({"name": "r", "public_key": oc::Keypair::generate().public}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let rt = r.body["token"].as_str().unwrap();
    let r = s.call(Method::GET, "/api/runner/jobs", Some(rt), None).await;
    assert_eq!(r.status, 200, "runner should see its own empty queue: {} {}", r.status, r.text);
    assert_eq!(r.body["jobs"].as_array().map(|a| a.len()), Some(0));
    let r = s.call(Method::GET, "/api/orgs", Some(bt.as_str()), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
}
