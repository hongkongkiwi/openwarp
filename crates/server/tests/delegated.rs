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
        let dir = std::env::temp_dir().join(format!("openwarp-delegated-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_KMS_URL")
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
        let text = r.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body }
    }
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
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "delegated@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let token = r.body["token"].as_str().unwrap().to_string();
    let org = r.body["org_id"].as_str().unwrap().to_string();
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    let user_pub = me.body["pubkey"].as_str().unwrap().to_string();
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
    let a = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "a@test.invalid", "password": "correct-horse-battery"}))).await;
    let b = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "b@test.invalid", "password": "correct-horse-battery"}))).await;
    let (at, ao) = (a.body["token"].as_str().unwrap(), a.body["org_id"].as_str().unwrap());
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", ao), Some(at), Some(json!({"name": "r", "public_key": oc::Keypair::generate().public}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let rt = r.body["token"].as_str().unwrap();
    let r = s.call(Method::GET, "/api/runner/jobs", Some(rt), None).await;
    assert_eq!(r.status, 200, "runner should see its own empty queue: {} {}", r.status, r.text);
    assert_eq!(r.body["jobs"].as_array().map(|a| a.len()), Some(0));
    let bt = b.body["token"].as_str().unwrap();
    let r = s.call(Method::GET, "/api/orgs", Some(bt), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
}

async fn register(s: &Server, email: &str) -> (String, String, String) {
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let token = r.body["token"].as_str().unwrap().to_string();
    let org = r.body["org_id"].as_str().unwrap().to_string();
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    let pubkey = me.body["pubkey"].as_str().unwrap().to_string();
    (token, org, pubkey)
}

fn default_envs(runner_pub: &str, user_pub: &str, key: &[u8; 32]) -> Vec<Value> {
    ["Development", "Staging", "Production"].iter().map(|name| json!({
        "name": name,
        "wrapped_key": oc::encrypt_to(user_pub, key).unwrap(),
        "runner_wrapped_key": oc::encrypt_to(runner_pub, key).unwrap(),
    })).collect()
}

#[tokio::test]
async fn the_instance_policy_controls_new_app_environments() {
    let s = Server::start().await;
    let (token, org, user_pub) = register(&s, "policy@test.invalid").await;
    let info = s.call(Method::GET, "/api/instance", Some(&token), None).await;
    assert_eq!(info.body["app_env_policy"], json!("managed"), "managed is the default: {}", info.text);
    assert_eq!(info.body["app_env_policy_locked"], json!(false));

    let r = s.call(Method::PUT, "/api/instance/app-env-policy", Some(&token), Some(json!({"policy": "delegated"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let info = s.call(Method::GET, "/api/instance", Some(&token), None).await;
    assert_eq!(info.body["app_env_policy"], json!("delegated"));

    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({"name": "no-runner"}))).await;
    assert_eq!(r.status, 400, "a delegated app without a runner must fail: {} {}", r.status, r.text);

    let runner = oc::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&token), Some(json!({"name": "corp", "public_key": runner.public}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let runner_id = r.body["id"].as_str().unwrap().to_string();

    let env_key = oc::random_key();
    let envs = default_envs(&runner.public, &user_pub, &env_key);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({
        "name": "delegated-app", "readme": "zero knowledge", "mode": "delegated", "runner_id": runner_id, "envs": envs
    }))).await;
    assert_eq!(r.status, 200, "delegated app create failed: {} {}", r.status, r.text);
    let app = r.body["id"].as_str().unwrap().to_string();
    assert_eq!(r.body["mode"], json!("delegated"));

    let r = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(&token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let list = r.body.as_array().unwrap();
    assert_eq!(list.len(), 3, "{}", r.text);
    for env in list {
        assert_eq!(env["mode"], json!("delegated"));
        assert_eq!(env["runner_id"], json!(runner_id));
        let eid = env["id"].as_str().unwrap();
        let server = s.call(Method::GET, &format!("/api/envs/{}/secrets", eid), Some(&token), None).await;
        assert_eq!(server.status, 409, "the server must not read a delegated default: {} {}", server.status, server.text);
    }
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let wrapped: String = conn.query_row("SELECT wrapped_key FROM runner_env_keys WHERE runner_id=?", [&runner_id], |row| row.get(0)).unwrap();
    assert_eq!(runner.decrypt(&wrapped).unwrap(), env_key.to_vec(), "the runner grant must unwrap to the client key");

    // Switching the policy back creates managed apps again and rejects a client
    // that still asks for delegated.
    let r = s.call(Method::PUT, "/api/instance/app-env-policy", Some(&token), Some(json!({"policy": "managed"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let envs = default_envs(&runner.public, &user_pub, &oc::random_key());
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({"name": "mismatch", "mode": "delegated", "runner_id": runner_id, "envs": envs}))).await;
    assert_eq!(r.status, 409, "the instance policy must win: {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({"name": "managed-again"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let managed_app = r.body["id"].as_str().unwrap();
    let r = s.call(Method::GET, &format!("/api/apps/{}/envs", managed_app), Some(&token), None).await;
    assert_eq!(r.body.as_array().unwrap()[0]["mode"], json!("sse"));
}

#[tokio::test]
async fn delegated_app_validation_leaves_no_partial_app() {
    let s = Server::start().await;
    let (token, org, user_pub) = register(&s, "atomic@test.invalid").await;
    let r = s.call(Method::PUT, "/api/instance/app-env-policy", Some(&token), Some(json!({"policy": "delegated"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let runner = oc::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&token), Some(json!({"name": "r", "public_key": runner.public}))).await;
    let runner_id = r.body["id"].as_str().unwrap().to_string();
    let key = oc::random_key();
    let good = default_envs(&runner.public, &user_pub, &key);
    let cases = vec![
        json!({"name": "no-envs", "mode": "delegated", "runner_id": runner_id}),
        json!({"name": "short", "mode": "delegated", "runner_id": runner_id, "envs": good[..2].to_vec()}),
        json!({"name": "duplicate", "mode": "delegated", "runner_id": runner_id, "envs": [good[0], good[0], good[1]]}),
        json!({"name": "bad-blob", "mode": "delegated", "runner_id": runner_id, "envs": [good[0], good[1], json!({"name": "Production", "wrapped_key": "nope", "runner_wrapped_key": "nope"})]}),
        json!({"name": "", "mode": "delegated", "runner_id": runner_id, "envs": good}),
    ];
    for body in cases {
        let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(body.clone())).await;
        assert_eq!(r.status, 400, "invalid delegated app must fail: {} {}", r.text, body);
    }
    // A runner from another organisation is not usable either.
    let (bt, bo, _) = register(&s, "other-org@test.invalid").await;
    let other = oc::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", bo), Some(&bt), Some(json!({"name": "other", "public_key": other.public}))).await;
    let other_runner = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({"name": "foreign-runner", "mode": "delegated", "runner_id": other_runner, "envs": good}))).await;
    assert_eq!(r.status, 400, "a foreign runner must be refused: {} {}", r.status, r.text);
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let apps: i64 = conn.query_row("SELECT COUNT(*) FROM apps WHERE org_id=?", [&org], |row| row.get(0)).unwrap();
    assert_eq!(apps, 0, "a rejected app must leave no row behind");
}

#[tokio::test]
async fn members_can_read_runner_keys_but_only_admins_create_runners() {
    let s = Server::start().await;
    let (token, org, _) = register(&s, "admin@test.invalid").await;
    let runner = oc::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&token), Some(json!({"name": "provisioned", "public_key": runner.public}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let runner_id = r.body["id"].as_str().unwrap().to_string();

    let (mt, _, _) = register(&s, "member@test.invalid").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(&token), Some(json!({"email": "member@test.invalid", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::GET, &format!("/api/orgs/{}/runners", org), Some(&mt), None).await;
    assert_eq!(r.status, 200, "a member needs the public key to wrap env keys: {} {}", r.status, r.text);
    assert_eq!(r.body.as_array().unwrap()[0]["pubkey"], json!(runner.public));
    assert!(!r.text.contains("token"), "the runner list must never expose a token: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&mt), Some(json!({"name": "mine", "public_key": oc::Keypair::generate().public}))).await;
    assert_eq!(r.status, 403, "members must not mint runner tokens: {} {}", r.status, r.text);

    // A read-only custom role must not enumerate runner identities.
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&token), Some(json!({"name": "viewer", "permissions": ["secrets:read"]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let (vt, _, _) = register(&s, "viewer@test.invalid").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(&token), Some(json!({"email": "viewer@test.invalid", "role": "viewer"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/runners", org), Some(&vt), None).await;
    assert_eq!(r.status, 403, "a read-only role must not list runner identities: {} {}", r.status, r.text);

    // The member can still create a delegated app with the provisioned runner.
    let r = s.call(Method::PUT, "/api/instance/app-env-policy", Some(&token), Some(json!({"policy": "delegated"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let me = s.call(Method::GET, "/api/me", Some(&mt), None).await;
    let member_pub = me.body["pubkey"].as_str().unwrap();
    let key = oc::random_key();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&mt), Some(json!({
        "name": "member-app", "mode": "delegated", "runner_id": runner_id, "envs": default_envs(&runner.public, member_pub, &key)
    }))).await;
    assert_eq!(r.status, 200, "a member with secrets:write may use the runner: {} {}", r.status, r.text);
}

#[tokio::test]
async fn a_delegated_rekey_replaces_the_runner_key_grant() {
    let s = Server::start().await;
    let (token, org, user_pub) = register(&s, "rekey-runner@test.invalid").await;
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    let uid = me.body["id"].as_str().unwrap().to_string();
    let runner_key = oc::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&token), Some(json!({"name": "r", "public_key": runner_key.public}))).await;
    let runner_id = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&token), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();

    let old_key = oc::random_key();
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs", app), Some(&token), Some(json!({
        "name": "garbage", "mode": "delegated", "runner_id": runner_id,
        "wrapped_key": "a", "runner_wrapped_key": "b"
    }))).await;
    assert_eq!(r.status, 400, "a malformed wrapped key must not create an unreadable env: {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs", app), Some(&token), Some(json!({
        "name": "production", "mode": "delegated", "runner_id": runner_id,
        "wrapped_key": oc::encrypt_to(&user_pub, &old_key).unwrap(),
        "runner_wrapped_key": oc::encrypt_to(&runner_key.public, &old_key).unwrap()
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let env = r.body["id"].as_str().unwrap().to_string();
    let key_hash = oc::hash_token("/:API_KEY");
    let r = s.call(Method::PUT, &format!("/api/envs/{}/e2e/secrets", env), Some(&token), Some(json!({
        "secrets": [{"key_enc": oc::encrypt_symmetric(&old_key, b"API_KEY"), "value_enc": oc::encrypt_symmetric(&old_key, b"one"), "key_hash": key_hash, "path_enc": oc::encrypt_symmetric(&old_key, b"/")}]
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let new_key = oc::random_key();
    let secrets = json!([{
        "key_hash": key_hash,
        "key_enc": oc::encrypt_symmetric(&new_key, b"API_KEY"),
        "value_enc": oc::encrypt_symmetric(&new_key, b"two"),
        "path_enc": oc::encrypt_symmetric(&new_key, b"/")
    }]);
    let grants = json!([{"user_id": uid, "wrapped_key": oc::encrypt_to(&user_pub, &new_key).unwrap()}]);
    // A delegated rotation without the runner grant would leave the runner
    // unable to sync, so the server must refuse it.
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/rekey", env), Some(&token), Some(json!({"secrets": secrets, "grants": grants}))).await;
    assert_eq!(r.status, 400, "a delegated rekey needs runner_wrapped_key: {} {}", r.status, r.text);
    let runner_wrapped = oc::encrypt_to(&runner_key.public, &new_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/rekey", env), Some(&token), Some(json!({"secrets": secrets, "grants": grants, "runner_wrapped_key": runner_wrapped}))).await;
    assert_eq!(r.status, 200, "rekey failed: {} {}", r.status, r.text);

    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let stored: String = conn.query_row("SELECT wrapped_key FROM runner_env_keys WHERE runner_id=? AND env_id=?", [&runner_id, &env], |row| row.get(0)).unwrap();
    assert_eq!(runner_key.decrypt(&stored).unwrap(), new_key.to_vec(), "the runner must receive the rotated key");
    let e2e = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&token), None).await;
    assert_eq!(e2e.status, 200, "{}", e2e.text);
    let value_enc = e2e.body["secrets"][0]["value_enc"].as_str().unwrap();
    let value = oc::decrypt_symmetric(&new_key, value_enc).unwrap();
    assert_eq!(value, b"two");
}
