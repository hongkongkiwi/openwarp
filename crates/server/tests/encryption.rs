// KMS-backed envelope encryption: the server stores an owkms-wrapped env key,
// binds secret ciphertext to its record, survives a restart, and fails closed
// when the KMS is unavailable. The mock KMS uses the same crate primitives the
// server uses; only the transport and key custody are simulated.

use openwarp_crypto as oc;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const KMS_KEY: [u8; 32] = [7u8; 32];

struct Resp { status: u16, text: String, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, log: PathBuf, client: Client, keep: bool }
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !self.keep { let _ = std::fs::remove_dir_all(&self.dir); }
    }
}
fn free_port() -> u16 { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

impl Server {
    async fn start_env(extra: &[(&str, String)]) -> Server {
        let dir = std::env::temp_dir().join(format!("openwarp-enc-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        Server::start_at(dir, extra).await
    }
    async fn start_at(dir: PathBuf, extra: &[(&str, String)]) -> Server {
        let _start = START_LOCK.lock().await;
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let log = dir.join("server.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_KMS_URL")
            .env_remove("OPENWARP_KMS_TOKEN")
            .env_remove("OPENWARP_KMS_KEY_ID")
            .env_remove("OPENWARP_EMAIL_WEBHOOK")
            .stdout(Stdio::null()).stderr(Stdio::from(log_file));
        for (k, v) in extra { cmd.env(k, v); }
        let child = cmd.spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let server = Server { child, base, dir, log, client, keep: false };
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
    fn kill(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
    fn reuse(mut self) -> PathBuf { self.keep = true; self.kill(); self.dir.clone() }
}

struct Kms { url: String, fail: Arc<AtomicBool>, calls: Arc<AtomicUsize> }
fn start_kms() -> Kms {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let (f, c) = (fail.clone(), calls.clone());
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
            let first = String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string();
            let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
            let body = String::from_utf8_lossy(&buf[head_end..head_end + len.min(buf.len().saturating_sub(head_end))]).to_string();
            c.fetch_add(1, Ordering::SeqCst);
            let reply = if f.load(Ordering::SeqCst) {
                "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
            } else {
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let ctx = v["context"].as_str().unwrap_or("");
                if path.ends_with("/wrap") {
                    let plain = oc::unb64(v["plaintext"].as_str().unwrap_or("")).unwrap_or_default();
                    let wrapped = oc::encrypt_symmetric_aad(&KMS_KEY, ctx.as_bytes(), &plain);
                    let out = json!({"wrapped": wrapped}).to_string();
                    format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", out.len(), out)
                } else {
                    let plain = oc::decrypt_symmetric_aad(&KMS_KEY, ctx.as_bytes(), v["wrapped"].as_str().unwrap_or("")).unwrap_or_default();
                    let out = json!({"plaintext": oc::b64(&plain)}).to_string();
                    format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", out.len(), out)
                }
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    Kms { url: format!("http://{}/kms", addr), fail, calls }
}
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> { haystack.windows(needle.len()).position(|w| w == needle) }

async fn register(s: &Server, email: &str) -> Value {
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let mut body = r.body;
    s.verify().await;
    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 200, "login after verification failed: {} {}", login.status, login.text);
    body["token"] = login.body["token"].clone();
    body
}

#[tokio::test]
async fn kms_wraps_env_keys_and_secret_ciphertext_is_record_bound() {
    let kms = start_kms();
    let s = Server::start_env(&[
        ("OPENWARP_KMS_URL", kms.url.clone()),
        ("OPENWARP_KMS_TOKEN", "test-token".into()),
        ("OPENWARP_KMS_KEY_ID", "test-key-1".into()),
    ]).await;
    let u = register(&s, "kms@test.invalid").await;
    let t = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&t), Some(json!({"name": "app"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let app = r.body["id"].as_str().unwrap().to_string();
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(&t), None).await;
    let env = envs.body[0]["id"].as_str().unwrap().to_string();
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(&t), Some(json!({"secrets": [{"key": "DATABASE_URL", "value": "postgres://secret"}]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["secrets"][0]["value"], json!("postgres://secret"));

    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let wrapped: String = conn.query_row("SELECT env_key_wrapped FROM envs WHERE id=?", [&env], |row| row.get(0)).unwrap();
    assert!(wrapped.starts_with("owkms:test-key-1:"), "env key is not KMS wrapped: {}", wrapped);
    let value_enc: String = conn.query_row("SELECT value_enc FROM secrets WHERE env_id=? AND deleted=0", [&env], |row| row.get(0)).unwrap();
    assert!(value_enc.starts_with("ow2:"), "secret ciphertext is not record-bound: {}", value_enc);
    assert!(kms.calls.load(Ordering::SeqCst) > 0, "the server did not call the KMS");

    // A restart must unwrap the same KMS root, not generate a new one.
    let dir = s.reuse();
    let s2 = Server::start_at(dir, &[
        ("OPENWARP_KMS_URL", kms.url.clone()),
        ("OPENWARP_KMS_TOKEN", "test-token".into()),
        ("OPENWARP_KMS_KEY_ID", "test-key-1".into()),
    ]).await;
    let r = s2.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert_eq!(r.status, 200, "data must survive a KMS-backed restart: {}", r.text);
    assert_eq!(r.body["secrets"][0]["value"], json!("postgres://secret"));

    // With the KMS down, a fresh read must fail rather than fall back to a
    // local key. env_key unwraps per request, so this is deterministic.
    kms.fail.store(true, Ordering::SeqCst);
    let r = s2.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert!(r.status >= 400, "KMS outage must fail closed, got {} {}", r.status, r.text);
    kms.fail.store(false, Ordering::SeqCst);

    let r = s2.call(Method::POST, "/api/instance/rewrap", Some(&t), Some(json!({}))).await;
    assert_eq!(r.status, 200, "rewrap failed: {} {}", r.status, r.text);
    assert_eq!(r.body["key_id"], json!("test-key-1"), "{}", r.text);
}

#[tokio::test]
async fn e2e_rekey_rotates_the_environment_key_and_secret_ciphertext() {
    let s = Server::start_env(&[]).await;
    let u = register(&s, "rekey@test.invalid").await;
    let t = u["token"].as_str().unwrap().to_string();
    let uid = u["user_id"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let me = s.call(Method::GET, "/api/me", Some(&t), None).await;
    let pubkey = me.body["pubkey"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&t), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();
    let env_key = oc::random_key();
    let wrapped = oc::encrypt_to(&pubkey, &env_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs/e2e", app), Some(&t), Some(json!({"name": "vault", "wrapped_key": wrapped}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let env = r.body["id"].as_str().unwrap().to_string();
    let key_hash = oc::hash_token("/:API_KEY");
    let r = s.call(Method::PUT, &format!("/api/envs/{}/e2e/secrets", env), Some(&t), Some(json!({"secrets": [{
        "key_enc": oc::encrypt_symmetric(&env_key, b"API_KEY"),
        "value_enc": oc::encrypt_symmetric(&env_key, b"old-value"),
        "key_hash": key_hash, "path": "/", "path_enc": oc::encrypt_symmetric(&env_key, b"/")
    }]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let new_key = oc::random_key();
    let new_wrapped = oc::encrypt_to(&pubkey, &new_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/rekey", env), Some(&t), Some(json!({
        "secrets": [{"key_enc": oc::encrypt_symmetric(&new_key, b"API_KEY"), "value_enc": oc::encrypt_symmetric(&new_key, b"new-value"), "key_hash": key_hash, "path": "/", "path_enc": oc::encrypt_symmetric(&new_key, b"/")}],
        "grants": [{"user_id": uid, "wrapped_key": new_wrapped}]
    }))).await;
    assert_eq!(r.status, 200, "rekey failed: {} {}", r.status, r.text);
    assert_eq!(r.body["rekeyed"], json!(1), "{}", r.text);

    let d = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&t), None).await;
    let wrapped = d.body["wrapped_key"].as_str().unwrap();
    let raw = oc::Keypair::from_secret_b64(u["recovery_kit"].as_str().unwrap()).unwrap().decrypt(wrapped).unwrap();
    let rotated: [u8;32] = raw.try_into().unwrap();
    let value = oc::decrypt_symmetric(&rotated, d.body["secrets"][0]["value_enc"].as_str().unwrap()).unwrap();
    assert_eq!(value, b"new-value");
    let meta = s.call(Method::GET, &format!("/api/envs/{}/e2e/meta", env), Some(&t), None).await;
    assert_eq!(meta.body["mode"], json!("e2e"), "{}", meta.text);

    // A failing rekey must roll back completely. Duplicate grants violate the
    // env_keys primary key after the secrets have been rewritten in the batch.
    let bad_key = oc::random_key();
    let bad_wrapped = oc::encrypt_to(&pubkey, &bad_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/rekey", env), Some(&t), Some(json!({
        "secrets": [{"key_enc": oc::encrypt_symmetric(&bad_key, b"API_KEY"), "value_enc": oc::encrypt_symmetric(&bad_key, b"bad-value"), "key_hash": key_hash, "path": "/", "path_enc": oc::encrypt_symmetric(&bad_key, b"/")}],
        "grants": [{"user_id": uid, "wrapped_key": bad_wrapped}, {"user_id": uid, "wrapped_key": bad_wrapped}]
    }))).await;
    assert!(r.status >= 400, "a broken rekey must fail: {} {}", r.status, r.text);
    let d = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&t), None).await;
    assert_eq!(d.status, 200, "the old grant must survive a rolled back rekey: {} {}", d.status, d.text);
    let raw = oc::Keypair::from_secret_b64(u["recovery_kit"].as_str().unwrap()).unwrap().decrypt(d.body["wrapped_key"].as_str().unwrap()).unwrap();
    let still: [u8;32] = raw.try_into().unwrap();
    assert_eq!(still, rotated, "a failed rekey must not replace the wrapped key");
    assert_eq!(oc::decrypt_symmetric(&still, d.body["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(), b"new-value");
}

#[tokio::test]
async fn kms_adoption_removes_the_plaintext_master() {
    let s = Server::start_env(&[]).await;
    let u = register(&s, "adopt@test.invalid").await;
    let t = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&t), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(&t), None).await;
    let env = envs.body[0]["id"].as_str().unwrap().to_string();
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(&t), Some(json!({"secrets": [{"key": "A", "value": "before"}]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    { let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
      let n: i64 = conn.query_row("SELECT COUNT(*) FROM meta WHERE k='master'", [], |r| r.get(0)).unwrap();
      assert_eq!(n, 1, "a local-first deployment stores a master row"); }

    let kms = start_kms();
    let dir = s.reuse();
    let s2 = Server::start_at(dir, &[
        ("OPENWARP_KMS_URL", kms.url.clone()),
        ("OPENWARP_KMS_TOKEN", "test-token".into()),
        ("OPENWARP_KMS_KEY_ID", "adopt-key".into()),
    ]).await;
    let r = s2.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert_eq!(r.status, 200, "adopted data must stay readable: {}", r.text);
    assert_eq!(r.body["secrets"][0]["value"], json!("before"));
    let conn = rusqlite::Connection::open(s2.dir.join("test.db")).unwrap();
    let master: i64 = conn.query_row("SELECT COUNT(*) FROM meta WHERE k='master'", [], |r| r.get(0)).unwrap();
    assert_eq!(master, 0, "the plaintext master must be removed after KMS adoption");
    let kms_root: String = conn.query_row("SELECT v FROM meta WHERE k='kms_root'", [], |r| r.get(0)).unwrap();
    assert!(kms_root.starts_with("owkms:"), "kms_root is not wrapped: {}", kms_root);
}

#[tokio::test]
async fn secret_ciphertext_cannot_be_swapped_between_records() {
    let s = Server::start_env(&[]).await;
    let u = register(&s, "swap@test.invalid").await;
    let t = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&t), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(&t), None).await;
    let env = envs.body[0]["id"].as_str().unwrap().to_string();
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(&t), Some(json!({"secrets": [
        {"key": "ALPHA", "value": "one"}, {"key": "BETA", "value": "two"}
    ]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let mut stmt = conn.prepare("SELECT id,value_enc FROM secrets WHERE env_id=? ORDER BY id").unwrap();
    let rows: Vec<(String, String)> = stmt.query_map([&env], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), 2);
    conn.execute("UPDATE secrets SET value_enc=? WHERE id=?", rusqlite::params![rows[1].1, rows[0].0]).unwrap();
    conn.execute("UPDATE secrets SET value_enc=? WHERE id=?", rusqlite::params![rows[0].1, rows[1].0]).unwrap();

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    for s in r.body["secrets"].as_array().unwrap() {
        assert_eq!(s["decrypt_error"], json!(true), "swapped ciphertext must fail the record binding: {}", r.text);
        assert_eq!(s["value"], json!(""), "swapped ciphertext must not reveal the other value: {}", r.text);
    }
}

#[tokio::test]
async fn e2e_paths_can_be_stored_as_client_ciphertext() {
    let s = Server::start_env(&[]).await;
    let u = register(&s, "e2e-path@test.invalid").await;
    let t = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let me = s.call(Method::GET, "/api/me", Some(&t), None).await;
    let pubkey = me.body["pubkey"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&t), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();
    let env_key = oc::random_key();
    let wrapped = oc::encrypt_to(&pubkey, &env_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs/e2e", app), Some(&t), Some(json!({"name": "vault", "wrapped_key": wrapped}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let env = r.body["id"].as_str().unwrap().to_string();
    let path_enc = oc::encrypt_symmetric(&env_key, b"/prod/billing");
    let r = s.call(Method::PUT, &format!("/api/envs/{}/e2e/secrets", env), Some(&t), Some(json!({"secrets": [{
        "key_enc": oc::encrypt_symmetric(&env_key, b"API_KEY"),
        "value_enc": oc::encrypt_symmetric(&env_key, b"secret"),
        "key_hash": oc::hash_token("/:API_KEY"), "path": "/prod/billing", "path_enc": path_enc
    }]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let (path, stored_path_enc): (String, String) = conn.query_row("SELECT path,path_enc FROM secrets WHERE env_id=?", [&env], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert!(path.is_empty(), "the client path must not be stored in the clear: {}", path);
    assert!(!stored_path_enc.is_empty(), "path_enc was not stored");
    let d = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&t), None).await;
    let decrypted = oc::decrypt_symmetric(&env_key, d.body["secrets"][0]["path_enc"].as_str().unwrap()).unwrap();
    assert_eq!(decrypted, b"/prod/billing");
}

#[tokio::test]
async fn rekey_can_remove_a_grantee_atomically() {
    let s = Server::start_env(&[]).await;
    let owner = register(&s, "owner-remove@test.invalid").await;
    let member = register(&s, "member-remove@test.invalid").await;
    let ot = owner["token"].as_str().unwrap().to_string();
    let org = owner["org_id"].as_str().unwrap().to_string();
    let owner_id = owner["user_id"].as_str().unwrap().to_string();
    let owner_pub = owner["public_key"].as_str().unwrap().to_string();
    let mt = member["token"].as_str().unwrap().to_string();
    let member_id = member["user_id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(&ot), Some(json!({"email": "member-remove@test.invalid", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "add member failed: {} {}", r.status, r.text);
    let accepted = s.call(Method::POST, "/api/auth/accept-invite", Some(&mt), Some(json!({"token": r.body["invite_token"]}))).await;
    assert_eq!(accepted.status, 200, "accept member invitation failed: {}", accepted.text);
    let member_pub = s.call(Method::GET, "/api/users/lookup?email=member-remove@test.invalid", Some(&ot), None).await.body["pubkey"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&ot), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();
    let env_key = oc::random_key();
    let wrapped = oc::encrypt_to(&owner_pub, &env_key).unwrap();
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs/e2e", app), Some(&ot), Some(json!({"name": "vault", "wrapped_key": wrapped}))).await;
    let env = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/grant", env), Some(&ot), Some(json!({"email": "member-remove@test.invalid", "wrapped_key": oc::encrypt_to(&member_pub, &env_key).unwrap()}))).await;
    assert_eq!(r.status, 200, "grant failed: {} {}", r.status, r.text);
    let key_hash = oc::hash_token("/:API_KEY");
    let r = s.call(Method::PUT, &format!("/api/envs/{}/e2e/secrets", env), Some(&ot), Some(json!({"secrets": [{
        "key_enc": oc::encrypt_symmetric(&env_key, b"API_KEY"), "value_enc": oc::encrypt_symmetric(&env_key, b"old"),
        "key_hash": key_hash, "path": "/", "path_enc": oc::encrypt_symmetric(&env_key, b"/")
    }]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let before = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&mt), None).await;
    assert_eq!(before.status, 200, "the member should have a grant before removal: {} {}", before.status, before.text);

    let new_key = oc::random_key();
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/rekey", env), Some(&ot), Some(json!({
        "secrets": [{"key_enc": oc::encrypt_symmetric(&new_key, b"API_KEY"), "value_enc": oc::encrypt_symmetric(&new_key, b"new"), "key_hash": key_hash, "path": "", "path_enc": oc::encrypt_symmetric(&new_key, b"/")}],
        "grants": [{"user_id": owner_id, "wrapped_key": oc::encrypt_to(&owner_pub, &new_key).unwrap()}],
        "remove_user": member_id
    }))).await;
    assert_eq!(r.status, 200, "atomic revoke+rekey failed: {} {}", r.status, r.text);
    let grants = s.call(Method::GET, &format!("/api/envs/{}/e2e/grants", env), Some(&ot), None).await;
    assert_eq!(grants.body.as_array().map(|a| a.len()), Some(1), "the removed grant must be gone: {}", grants.text);
    let after = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&mt), None).await;
    assert_eq!(after.status, 403, "the removed member must lose access: {} {}", after.status, after.text);
    let d = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", env), Some(&ot), None).await;
    let raw = oc::Keypair::from_secret_b64(owner["recovery_kit"].as_str().unwrap()).unwrap().decrypt(d.body["wrapped_key"].as_str().unwrap()).unwrap();
    let rotated: [u8;32] = raw.try_into().unwrap();
    assert_eq!(oc::decrypt_symmetric(&rotated, d.body["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(), b"new");
}

#[tokio::test]
async fn secret_metadata_is_encrypted_and_blind_indexed() {
    let s = Server::start_env(&[]).await;
    let u = register(&s, "metadata@test.invalid").await;
    let t = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(&t), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap().to_string();
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(&t), None).await;
    let env = envs.body[0]["id"].as_str().unwrap().to_string();
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(&t), Some(json!({"secrets": [{"key": "ALPHA", "value": "one", "tags": "prod"}]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let (path, path_enc, tags, tags_enc, khash, kindex): (String, String, String, String, String, String) = conn.query_row(
        "SELECT path,path_enc,tags,tags_enc,key_hash,key_index FROM secrets WHERE env_id=? AND deleted=0", [&env],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).unwrap();
    assert!(path.is_empty(), "plaintext path must not be stored: {}", path);
    assert!(path_enc.starts_with("ow2:"), "path is not encrypted: {}", path_enc);
    assert!(tags.is_empty(), "plaintext tags must not be stored: {}", tags);
    assert!(tags_enc.starts_with("ow2:"), "tags are not encrypted: {}", tags_enc);
    assert_eq!(khash, kindex, "key_hash must carry the blind index");
    assert_ne!(khash, oc::hash_token("/:ALPHA"), "the old dictionary hash must be gone");

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert_eq!(r.body["secrets"][0]["path"], json!("/"), "{}", r.text);
    assert_eq!(r.body["secrets"][0]["tags"], json!("prod"), "{}", r.text);

    // The same key/path updates the existing row instead of creating another.
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(&t), Some(json!({"secrets": [{"key": "ALPHA", "value": "two", "tags": "prod"}]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM secrets WHERE env_id=? AND deleted=0", [&env], |r| r.get(0)).unwrap();
    assert_eq!(count, 1, "a re-deploy must update the indexed row");

    // Simulate a row written before metadata encryption, then migrate it.
    conn.execute("UPDATE secrets SET path='/',path_enc='',tags='prod',tags_enc='',key_hash=?,key_index='' WHERE env_id=?",
        rusqlite::params![oc::hash_token("/:ALPHA"), &env]).unwrap();
    let r = s.call(Method::POST, "/api/instance/encrypt-metadata", Some(&t), Some(json!({}))).await;
    assert_eq!(r.status, 200, "metadata migration failed: {} {}", r.status, r.text);
    let (path_enc, kindex): (String, String) = conn.query_row("SELECT path_enc,key_index FROM secrets WHERE env_id=?", [&env], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert!(path_enc.starts_with("ow2:"), "migration did not encrypt the path: {}", path_enc);
    assert!(!kindex.is_empty(), "migration did not set the blind index");
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&t), None).await;
    assert_eq!(r.body["secrets"][0]["path"], json!("/"), "{}", r.text);
    assert_eq!(r.body["secrets"][0]["tags"], json!("prod"), "{}", r.text);
}

#[tokio::test]
async fn without_kms_the_existing_master_path_still_works() {
    let s = Server::start_env(&[]).await;
    let u = register(&s, "local@test.invalid").await;
    let t = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(t), Some(json!({"name": "app"}))).await;
    let app = r.body["id"].as_str().unwrap();
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(t), None).await;
    let env = envs.body[0]["id"].as_str().unwrap();
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(t), Some(json!({"secrets": [{"key": "A", "value": "b"}]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(t), None).await;
    assert_eq!(r.body["secrets"][0]["value"], json!("b"));
    let conn = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let value_enc: String = conn.query_row("SELECT value_enc FROM secrets WHERE env_id=? AND deleted=0", [env], |row| row.get(0)).unwrap();
    assert!(value_enc.starts_with("ow2:"), "legacy master mode still writes bound ciphertext: {}", value_enc);
}
