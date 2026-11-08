#![allow(dead_code)]
// Device PKI authorization and lifecycle tests. Each test owns a private database.

use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
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
        self.headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
    inbox: Arc<Mutex<Vec<Value>>>,
    keep: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !self.keep { let _ = std::fs::remove_dir_all(&self.dir); }
    }
}

fn free_port() -> u16 {
    // Parallel test binaries must not hand the same port to two servers.
    let base = 20000 + (std::process::id() % 30000) as u16;
    for offset in 0..500u16 {
        let port = base.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            return port;
        }
    }
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

impl Server {
    async fn start() -> Server {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-authz-{}-{}", std::process::id(), seq));
        Server::start_at(dir).await
    }

    async fn start_at(dir: PathBuf) -> Server {
        Server::start_with_env(dir, &[]).await
    }

    async fn start_allowing_private_egress() -> Server {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-authz-{}-{}", std::process::id(), seq));
        Server::start_with_env(dir, &[("OPENWARP_ALLOW_PRIVATE_EGRESS", "1")]).await
    }

    async fn start_with_env(dir: PathBuf, extra: &[(&str, &str)]) -> Server {
        let _start = START_LOCK.lock().await;
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let (inbox_url, inbox) = start_inbox();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", &inbox_url)
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY")
            .env_remove("OPENWARP_ALLOWED_DB_HOSTS")
            .env_remove("OPENWARP_ENV");
        for (key, value) in extra { cmd.env(key, value); }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openwarp-server");
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        let server = Server { child, base, dir, client, inbox, keep: false };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() {
                    return server;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy at {}", server.base);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        self.finish(req.send().await).await
    }

    async fn call_with_headers(&self, path: &str, token: &str, body: Value, headers: &[(&str, &str)]) -> Resp {
        let mut req = self.client.post(self.url(path)).bearer_auth(token).json(&body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.finish(req.send().await).await
    }

    async fn form(&self, path: &str, form: &[(&str, String)], token: Option<&str>) -> Resp {
        let mut req = self.client.post(self.url(path)).form(form);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        self.finish(req.send().await).await
    }

    async fn finish(&self, result: Result<reqwest::Response, reqwest::Error>) -> Resp {
        let response = result.expect("http request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }
}

/// Minimal email relay: records each JSON body and answers 200.
fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("inbox bind");
    let addr = listener.local_addr().expect("inbox addr");
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming { Ok(s) => s, Err(_) => continue };
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = match stream.read(&mut chunk) { Ok(0) => break, Ok(n) => n, Err(_) => break };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
            let body = String::from_utf8_lossy(&buf[end.min(buf.len())..]).to_string();
            if let Ok(v) = serde_json::from_str::<Value>(&body) { sink.lock().unwrap().push(v); }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", addr), inbox)
}

/// Enrollment policy hook: /deny refuses, /fail returns 500, anything else allows.
fn start_hook() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("hook bind");
    let addr = listener.local_addr().expect("hook addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming { Ok(s) => s, Err(_) => continue };
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = match stream.read(&mut chunk) { Ok(0) => break, Ok(n) => n, Err(_) => break };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
            let head = String::from_utf8_lossy(&buf[..end.min(buf.len())]).to_string();
            let body = String::from_utf8_lossy(&buf[end.min(buf.len())..]).to_string();
            if let Ok(v) = serde_json::from_str::<Value>(&body) { sink.lock().unwrap().push(v); }
            let path = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("").to_string();
            let (status, payload) = if path.contains("deny") { ("200 OK", "{\"allow\":false,\"reason\":\"inventory says no\"}") }
                else if path.contains("fail") { ("500 Internal Server Error", "{}") }
                else { ("200 OK", "{\"allow\":true}") };
            let response = format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, payload.len(), payload);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (format!("http://{}/hook", addr), seen)
}

async fn wait_for_mail(inbox: &Arc<Mutex<Vec<Value>>>, needle: &str) -> String {
    for _ in 0..60 {
        { let guard = inbox.lock().unwrap();
          if let Some(m) = guard.iter().rev().find(|m| m["text"].as_str().unwrap_or("").contains(needle)) {
              return m["text"].as_str().unwrap_or("").to_string(); } }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no email containing {:?} arrived", needle);
}

fn extract_link(text: &str, needle: &str) -> String {
    for word in text.split_whitespace() {
        if let Some(i) = word.find(needle) { return word[i..].to_string(); }
    }
    panic!("no link containing {:?} in {:?}", needle, text);
}

async fn register(s: &Server, email: &str) -> Value {
    let r = s
        .call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"})))
        .await;
    assert_eq!(r.status, 200, "register failed: {}", r.text);
    let mut body = r.body.clone();
    // Password signup always needs the verification link; finish the flow the
    // way a real operator with a mail relay would.
    if body["verification_required"] == json!(true) {
        let text = wait_for_mail(&s.inbox, "/api/auth/verify?token=").await;
        let link = extract_link(&text, "/api/auth/verify?token=");
        let path = link.strip_prefix(&s.base).unwrap_or(&link).to_string();
        let verified = s.call(Method::GET, &path, None, None).await;
        assert_eq!(verified.status, 200, "verification failed: {} {}", verified.status, verified.text);
        let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
        assert_eq!(login.status, 200, "verified sign-in failed: {} {}", login.status, login.text);
        body["token"] = login.body["token"].clone();
        body["user_id"] = login.body["user_id"].clone();
        body["public_key"] = login.body["public_key"].clone();
    }
    body
}

async fn invite(s: &Server, owner: &str, org: &str, email: &str, role: &str) {
    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(owner), Some(json!({"email": email, "role": role})))
        .await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);
}

async fn app_with_envs(s: &Server, token: &str, org: &str) -> (String, Vec<String>) {
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": "app"}))).await;
    assert_eq!(r.status, 200, "create app failed: {}", r.text);
    let app = r.body["id"].as_str().expect("app id").to_string();
    let r = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(token), None).await;
    let envs: Vec<String> = r.body.as_array().expect("env list").iter().map(|e| e["id"].as_str().unwrap_or("").to_string()).collect();
    assert!(envs.len() >= 2, "expected default envs");
    (app, envs)
}

async fn set_secret(s: &Server, token: &str, env: &str, key: &str, value: &str) {
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", env),
            Some(token),
            Some(json!({"secrets": [{"key": key, "value": value}]})),
        )
        .await;
    assert_eq!(r.status, 200, "set secret failed: {}", r.text);
}

/// Owner plus a member holding a custom role with no permissions at all.
async fn org_with_viewer(s: &Server, suffix: &str) -> (String, String, String, String, String, Vec<String>) {
    let owner = register(s, &format!("owner{}@test.invalid", suffix)).await;
    let member = register(s, &format!("viewer{}@test.invalid", suffix)).await;
    let ot = owner["token"].as_str().unwrap().to_string();
    let org = owner["org_id"].as_str().unwrap().to_string();
    let mt = member["token"].as_str().unwrap().to_string();
    let mu = member["user_id"].as_str().unwrap().to_string();
    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&ot), Some(json!({"name": "viewer", "permissions": []})))
        .await;
    assert_eq!(r.status, 200, "role create failed: {}", r.text);
    invite(s, &ot, &org, &format!("viewer{}@test.invalid", suffix), "viewer").await;
    let (app, envs) = app_with_envs(s, &ot, &org).await;
    set_secret(s, &ot, &envs[0], "SECRET1", "v1").await;
    (ot, org, mt, mu, app, envs)
}

// Device certificates: the key stays on the device, enrollment is a one-time
// code plus a CSR, and the CRL is public because a broker fetches it.
async fn pki_ca(s: &Server, token: &str, org: &str, name: &str) -> (String, String) {
    let r = s.call(Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(token), Some(json!({"name": name}))).await;
    assert_eq!(r.status, 200, "create CA failed: {}", r.text);
    (r.body["id"].as_str().unwrap().to_string(), r.body["certificate"].as_str().unwrap().to_string())
}

async fn pki_device(s: &Server, token: &str, ca: &str, name: &str) -> String {
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(token), Some(json!({"name": name, "sans": ["sensor.local", "192.0.2.10"], "cert_days": 30}))).await;
    assert_eq!(r.status, 200, "create device failed: {}", r.text);
    r.body["id"].as_str().unwrap().to_string()
}

fn device_csr(key: &rcgen::KeyPair, cn: &str) -> String {
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).expect("csr params");
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.serialize_request(key).expect("csr").pem().expect("csr pem")
}

#[tokio::test]
async fn device_csr_enrollment_issues_cert_once() {
    let s = Server::start().await;
    let u = register(&s, "device-enroll@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, ca_pem) = pki_ca(&s, token, org, "iot-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let code = r.body["code"].as_str().expect("enrollment code").to_string();
    let key = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&key, "claimed-other-device");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 200, "enrollment failed: {}", r.text);
    assert_eq!(r.body["name"], json!("sensor-1"), "the device record owns the CN, not the CSR: {}", r.text);
    assert!(r.body["certificate"].as_str().unwrap_or("").starts_with("-----BEGIN CERTIFICATE-----"), "{}", r.text);
    assert_eq!(r.body["ca_certificate"].as_str().unwrap_or(""), ca_pem);
    assert!(r.body.get("private_key").is_none(), "enrollment must never return the device private key");
    let again = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(again.status, 401, "an enrollment code is single use: {}", again.text);
}

#[tokio::test]
async fn device_enrollment_rejects_unknown_code() {
    let s = Server::start().await;
    let key = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&key, "unknown");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": "owdev_does-not-exist", "csr": csr}))).await;
    assert_eq!(r.status, 401, "{}", r.text);
    assert!(r.text.contains("invalid or expired enrollment code"), "{}", r.text);
}

#[tokio::test]
async fn device_management_requires_pki_write() {
    let s = Server::start().await;
    let (owner, org, viewer, _viewer_id, _app, _envs) = org_with_viewer(&s, "pkiperm").await;
    let (ca, _) = pki_ca(&s, &owner, &org, "perm-ca").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&viewer), Some(json!({"name": "sensor-1"}))).await;
    assert_eq!(r.status, 403, "a viewer must not create devices: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/devices", ca), Some(&viewer), None).await;
    assert_eq!(r.status, 403, "a role without pki:read must not read the inventory: {}", r.text);

    let operator = register(&s, "pki-operator@test.invalid").await;
    let op_token = operator["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&owner), Some(json!({"name": "pki-ops", "permissions": ["pki:read", "pki:write"]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    invite(&s, &owner, &org, "pki-operator@test.invalid", "pki-ops").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&op_token), Some(json!({"name": "sensor-2"}))).await;
    assert_eq!(r.status, 200, "pki:write may create devices: {}", r.text);
    let device = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(&op_token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "pki:write may mint enrollment codes: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/devices", ca), Some(&op_token), None).await;
    assert_eq!(r.status, 200, "pki:read may read the inventory: {}", r.text);
}

#[tokio::test]
async fn device_revocation_invalidates_outstanding_enrollment_codes() {
    let s = Server::start().await;
    let u = register(&s, "device-revoke-codes@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "revoke-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let second = r.body["code"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/revoke", device), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let key = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&key, "sensor-1");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": second, "csr": csr}))).await;
    assert_eq!(r.status, 401, "revoking a device must invalidate its outstanding codes: {}", r.text);
}

#[tokio::test]
async fn device_management_honours_token_scopes() {
    let s = Server::start().await;
    let (owner, org, _viewer, _viewer_id, app, envs) = org_with_viewer(&s, "pkitoken").await;
    let (ca, _) = pki_ca(&s, &owner, &org, "token-ca").await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&owner), Some(json!({"name": "pki-pat", "scopes": "pki:read pki:write"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let pki_token = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&pki_token), Some(json!({"name": "sensor-a"}))).await;
    assert_eq!(r.status, 200, "a pki:write token may create devices: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&owner), Some(json!({"name": "secret-pat", "scopes": "secrets:write"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let secret_token = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&secret_token), Some(json!({"name": "sensor-b"}))).await;
    assert_eq!(r.status, 403, "a secrets-only token must not administer devices: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&owner), Some(json!({"name": "env-pat", "scopes": "pki:read pki:write", "env_id": envs[0]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let env_token = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&env_token), Some(json!({"name": "sensor-env"}))).await;
    assert_eq!(r.status, 200, "an environment-scoped token may create a device in its environment: {}", r.text);
    assert_eq!(r.body["env_id"], json!(envs[0]));
    let env_device = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&env_token), Some(json!({"name": "sensor-elsewhere", "env_id": envs[1]}))).await;
    assert_eq!(r.status, 403, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/devices", ca), Some(&env_token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let names: Vec<&str> = r.body.as_array().expect("devices").iter().filter_map(|d| d["name"].as_str()).collect();
    assert!(names.contains(&"sensor-env"), "{}", r.text);
    assert!(!names.contains(&"sensor-a"), "the env-scoped token must not list another environment: {}", r.text);
    let r = s.call(Method::PATCH, &format!("/api/pki/devices/{}", env_device), Some(&env_token), Some(json!({"env_id": envs[1]}))).await;
    assert_eq!(r.status, 403, "an environment-scoped token must not move a device out of its environment: {}", r.text);
    let r = s.call(Method::PATCH, &format!("/api/pki/devices/{}", env_device), Some(&env_token), Some(json!({"name": "sensor-env-2"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["env_id"], json!(envs[0]));
    let r = s.call(Method::GET, &format!("/api/orgs/{}/pki/cas", org), Some(&pki_token), None).await;
    assert_eq!(r.status, 200, "a pki:read token may list CAs: {}", r.text);
    let mcp = s.call(Method::POST, "/mcp", Some(&pki_token), Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_secrets", "arguments": {"env_id": envs[0]}}}))).await;
    assert_eq!(mcp.status, 200, "{}", mcp.text);
    assert!(mcp.body["error"]["message"].as_str().unwrap_or("").contains("insufficient scope"), "a pki-only token must not read secrets over MCP: {}", mcp.text);
}

#[tokio::test]
async fn device_can_enroll_again_after_revocation() {
    let s = Server::start().await;
    let u = register(&s, "device-renew@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "renew-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let code = r.body["code"].as_str().unwrap().to_string();
    let first = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&first, "sensor-1");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let first_cert = r.body["serial"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/revoke", device), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    // A deliberate new code after revocation is a fresh device generation.
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let code = r.body["code"].as_str().unwrap().to_string();
    let second = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&second, "sensor-1");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 200, "renewal after revocation must work: {}", r.text);
    let renewed = r.body["serial"].as_str().unwrap().to_string();
    assert_ne!(renewed, first_cert);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["active_cert"]["serial"], json!(renewed));
    assert_eq!(r.body["active_cert"]["revoked"], json!(false));
}

#[tokio::test]
async fn crl_is_public_and_lists_device_revocation() {
    let s = Server::start().await;
    let u = register(&s, "device-crl@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "crl-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"device_id": device, "days": 10}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/revoke", device), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/crl", ca), None, None).await;
    assert_eq!(r.status, 200, "a broker fetches the CRL without a token: {}", r.text);
    assert!(r.header("content-type").contains("pkix-crl"), "{}", r.header("content-type"));
    assert!(r.text.contains("BEGIN X509 CRL"), "{}", r.text);
}

#[tokio::test]
async fn device_records_are_workspace_scoped() {
    let s = Server::start().await;
    let a = register(&s, "device-scope-a@test.invalid").await;
    let b = register(&s, "device-scope-b@test.invalid").await;
    let at = a["token"].as_str().unwrap();
    let aorg = a["org_id"].as_str().unwrap();
    let bt = b["token"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, at, aorg, "scope-ca").await;
    let device = pki_device(&s, at, &ca, "sensor-1").await;
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/devices", ca), Some(bt), None).await;
    assert_ne!(r.status, 200, "another workspace must not list the inventory: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(bt), Some(json!({}))).await;
    assert_ne!(r.status, 200, "another workspace must not mint an enrollment code: {}", r.text);
}

#[tokio::test]
async fn server_issued_device_cert_is_bound_to_device() {
    let s = Server::start().await;
    let u = register(&s, "device-bind@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "bind-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"device_id": device, "days": 10}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let cert = r.body["id"].as_str().unwrap().to_string();
    assert!(!r.body["private_key"].as_str().unwrap_or("").is_empty(), "the server-key path returns the key once: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["active_cert_id"], json!(cert));
    assert_eq!(r.body["active_cert"]["id"], json!(cert));
    assert_eq!(r.body["name"], json!("sensor-1"));
    let r = s.call(Method::POST, &format!("/api/pki/certs/{}/revoke", cert), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert!(r.body["active_cert"].is_null(), "revoking the cert must clear the active pointer: {}", r.text);
    assert_eq!(r.body["active_cert_id"], json!(""));
}

fn now_secs() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn sha256_hex(data: &str) -> String { use sha2::Digest; format!("{:x}", sha2::Sha256::digest(data.as_bytes())) }

#[tokio::test]
async fn device_renewal_revokes_the_previous_certificate() {
    let s = Server::start().await;
    let u = register(&s, "device-renewal@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "renewal-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let code = r.body["code"].as_str().unwrap().to_string();
    let first_key = rcgen::KeyPair::generate().expect("device key");
    let first_csr = device_csr(&first_key, "sensor-1");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": first_csr}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let first_serial = r.body["serial"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/renew", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["revoke_previous"], json!(true));
    let code = r.body["code"].as_str().unwrap().to_string();
    let second_key = rcgen::KeyPair::generate().expect("device key");
    let second_csr = device_csr(&second_key, "sensor-1");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": second_csr}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let second_serial = r.body["serial"].as_str().unwrap().to_string();
    assert_ne!(second_serial, first_serial);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["active_cert"]["serial"], json!(second_serial));
    let certs = r.body["certs"].as_array().expect("cert history");
    assert!(certs.iter().any(|c| c["serial"] == json!(first_serial) && c["revoked"] == json!(1)), "the previous cert must be revoked: {}", r.text);
}

#[tokio::test]
async fn device_expiry_report_lists_buckets() {
    let s = Server::start().await;
    let u = register(&s, "device-expiry@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "expiry-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"device_id": device, "days": 6}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let device2 = pki_device(&s, token, &ca, "sensor-2").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"device_id": device2, "days": 20}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/pki/expiring?days=7", org), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["counts"]["7"], json!(1), "{}", r.text);
    assert_eq!(r.body["counts"]["14"], json!(1), "{}", r.text);
    assert_eq!(r.body["counts"]["30"], json!(2), "the 30-day bucket must cover the full window: {}", r.text);
    let certificates = r.body["certificates"].as_array().expect("certs");
    assert_eq!(certificates.len(), 1, "a 7-day request returns only the 7-day window: {}", r.text);
    assert_eq!(certificates[0]["name"], json!("sensor-1"));
    let r = s.call(Method::GET, &format!("/api/orgs/{}/pki/expiring?days=30", org), Some(token), None).await;
    assert_eq!(r.body["counts"]["30"], json!(2), "{}", r.text);
    assert_eq!(r.body["certificates"].as_array().expect("certs").len(), 2, "{}", r.text);
}

#[tokio::test]
async fn device_bulk_import_codes_and_export() {
    let s = Server::start().await;
    let u = register(&s, "device-bulk@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "bulk-ca").await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices/import", ca), Some(token), Some(json!({"devices": [{"name": "bulk-1", "tags": "site=a"}, {"name": "bulk-2"}, {"name": "bulk-1"}], "mint_codes": true, "ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["created"], json!(2), "{}", r.text);
    assert_eq!(r.body["failed"], json!(1), "{}", r.text);
    let results = r.body["results"].as_array().expect("results");
    assert_eq!(results.iter().filter(|x| x["code"].is_string()).count(), 2, "{}", r.text);
    let ids: Vec<String> = results.iter().filter_map(|x| x["id"].as_str().map(|s| s.to_string())).collect();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices/codes", ca), Some(token), Some(json!({"device_ids": ids, "ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["codes"].as_array().expect("codes").iter().filter(|x| x["code"].is_string()).count(), 2, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/devices/export", ca), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.header("content-type").contains("text/csv"), "{}", r.header("content-type"));
    assert!(r.text.contains("name,model") && r.text.contains("bulk-1"), "{}", r.text);
}

#[tokio::test]
async fn device_groups_inherit_defaults_and_revoke() {
    let s = Server::start().await;
    let u = register(&s, "device-groups@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "group-ca").await;
    let (_app, envs) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/groups", ca), Some(token), Some(json!({"name": "factory-a", "env_id": envs[0], "sans": ["gw.local"], "cert_days": 45, "tags": "site=a"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let group = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(token), Some(json!({"name": "grouped-other-env", "group_id": group, "env_id": envs[1]}))).await;
    assert_eq!(r.status, 400, "a device may not join a group in another environment: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(token), Some(json!({"name": "grouped", "group_id": group}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["env_id"], json!(envs[0]));
    assert_eq!(r.body["cert_days"], json!(45));
    assert_eq!(r.body["tags"], json!("site=a"));
    assert_eq!(r.body["sans"], json!(["gw.local"]));
    let device = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"device_id": device, "days": 10}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/groups/{}/revoke", group), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["revoked"], json!(1), "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert!(r.body["active_cert"].is_null(), "group revoke must clear the active cert: {}", r.text);
    let r = s.call(Method::PATCH, &format!("/api/pki/groups/{}", group), Some(token), Some(json!({"name": "factory-b"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::PATCH, &format!("/api/pki/groups/{}", group), Some(token), Some(json!({"env_id": envs[1]}))).await;
    assert_eq!(r.status, 400, "a group with members in its environment may not move: {}", r.text);
    let r = s.call(Method::DELETE, &format!("/api/pki/groups/{}", group), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert_eq!(r.body["group_id"], json!(""));
}

#[tokio::test]
async fn device_enrollment_hook_fails_closed() {
    let (hook_url, seen) = start_hook();
    let s = Server::start_allowing_private_egress().await;
    let u = register(&s, "device-hook@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "hook-ca").await;
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Some(token), Some(json!({"url": format!("{}/deny", hook_url), "secret": "s3cret"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let code = r.body["code"].as_str().unwrap().to_string();
    let key = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&key, "sensor-1");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 403, "a denied hook must block enrollment: {}", r.text);
    assert!(r.text.contains("denied by policy"), "{}", r.text);
    let r = s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Some(token), Some(json!({"url": format!("{}/allow", hook_url)}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 200, "a denied attempt must not consume the code: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Some(token), Some(json!({"url": format!("{}/fail", hook_url)}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    let code = r.body["code"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 502, "a failing hook must deny enrollment: {}", r.text);
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 3, "the hook must be called for each attempt");
    assert_eq!(seen[0]["event"], json!("pki.enroll"));
    assert_eq!(seen[0]["csr_sha256"].as_str().unwrap_or("").len(), 64);
}

#[tokio::test]
async fn intermediate_ca_chain_and_revocation() {
    let s = Server::start().await;
    let u = register(&s, "device-intermediate@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (root, _) = pki_ca(&s, token, org, "root-ca").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(token), Some(json!({"name": "factory", "parent_id": root}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["kind"], json!("intermediate"));
    let intermediate = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/devices", intermediate), Some(token), Some(json!({"name": "sensor-int"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let device = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    let code = r.body["code"].as_str().unwrap().to_string();
    let key = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&key, "sensor-int");
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", intermediate), Some(token), Some(json!({"device_id": device, "days": 10}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["ca_chain"].as_array().expect("chain").len(), 2, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/revoke", intermediate), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["certificates"].as_i64().unwrap_or(0) >= 1, "{}", r.text);
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert!(matches!(r.status, 400 | 401), "a revoked CA must not issue: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 400, "minting under a revoked CA must fail: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/crl", root), None, None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.text.contains("BEGIN X509 CRL"), "{}", r.text);
}

#[tokio::test]
async fn device_attestation_is_required_and_bound_to_the_csr() {
    let s = Server::start().await;
    let u = register(&s, "device-attest@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (ca, _) = pki_ca(&s, token, org, "attest-ca").await;
    let attest_key = rcgen::KeyPair::generate().expect("attest key");
    let r = s.call(Method::PUT, &format!("/api/pki/cas/{}/attestation", ca), Some(token), Some(json!({"issuer": "attest.test", "public_key_pem": attest_key.public_key_pem(), "algorithm": "ES256", "required": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    // Saving again without the key must keep the configured key.
    let r = s.call(Method::PUT, &format!("/api/pki/cas/{}/attestation", ca), Some(token), Some(json!({"issuer": "attest.test", "algorithm": "ES256", "required": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["key_set"], json!(true), "the configured key must be preserved: {}", r.text);
    let device = pki_device(&s, token, &ca, "sensor-1").await;
    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let code = r.body["code"].as_str().unwrap().to_string();
    let nonce = r.body["nonce"].as_str().unwrap().to_string();
    let key = rcgen::KeyPair::generate().expect("device key");
    let csr = device_csr(&key, "sensor-1");
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(attest_key.serialize_pem().as_bytes()).expect("attest encoding key");
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    let sign = |claim_nonce: &str| {
        let claims = json!({"iss": "attest.test", "aud": "openwarp-pki", "sub": device, "exp": now_secs() + 300, "iat": now_secs(), "nonce": claim_nonce, "csr_sha256": sha256_hex(&csr), "hardware_backed": true});
        jsonwebtoken::encode(&header, &claims, &enc).expect("attestation jwt") };
    let jwt = sign(&nonce);
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr, "attestation": jwt}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["attested"], json!(true), "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
    assert_eq!(r.body["attested"], json!(true), "{}", r.text);

    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    let code = r.body["code"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await;
    assert_eq!(r.status, 403, "required attestation must block an unattested enrollment: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(token), Some(json!({"ttl_seconds": 300}))).await;
    let code = r.body["code"].as_str().unwrap().to_string();
    let correct_nonce = r.body["nonce"].as_str().unwrap().to_string();
    let bad = sign("wrong-nonce");
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr, "attestation": bad}))).await;
    assert_eq!(r.status, 403, "a stale nonce must be rejected: {}", r.text);
    let good = sign(&correct_nonce);
    let r = s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr, "attestation": good}))).await;
    assert_eq!(r.status, 200, "a rejected assertion must not consume the code: {}", r.text);
}
