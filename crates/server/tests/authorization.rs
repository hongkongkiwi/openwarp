// Authorization regression suite: custom roles, admin gates, scope escapes,
// OIDC secret handling and the SSRF surfaces. Each test owns a private database.

use hmac::Mac;
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

fn totp(secret_b32: &str) -> String {
    let mut out = Vec::new();
    let (mut val, mut bits) = (0u32, 0u32);
    for c in secret_b32.chars() {
        let d = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;
        val = (val << 5) | d;
        bits += 5;
        if bits >= 8 {
            out.push(((val >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    let counter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&out).expect("hmac");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize;
    let code = (((hash[off] as u32 & 0x7f) << 24)
        | ((hash[off + 1] as u32) << 16)
        | ((hash[off + 2] as u32) << 8)
        | hash[off + 3] as u32)
        % 1_000_000;
    format!("{:06}", code)
}

fn base64url(data: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(data)
}

fn parse_query(location: &str) -> std::collections::HashMap<String, String> {
    location
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn oauth_access_token(s: &Server, session: &str, scope: &str) -> String {
    let r = s
        .call(
            Method::POST,
            "/oauth/register",
            None,
            Some(json!({
                "redirect_uris": ["http://127.0.0.1:8917/callback"],
                "token_endpoint_auth_method": "none",
                "scope": scope
            })),
        )
        .await;
    assert_eq!(r.status, 201, "client registration failed: {}", r.text);
    let client_id = r.body["client_id"].as_str().expect("client id").to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = {
        use sha2::{Digest, Sha256};
        base64url(&Sha256::digest(verifier.as_bytes()))
    };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.clone()),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", scope.to_string()),
        ("state", "state-1".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("resource", format!("{}/mcp", s.base)),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(session)).await;
    let code = parse_query(&r.header("location")).get("code").cloned();
    assert!(code.is_some(), "authorize did not issue a code ({}): {}", r.status, r.text);
    let exchange = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.unwrap()),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("code_verifier", verifier.to_string()),
    ];
    let r = s.form("/oauth/token", &exchange, None).await;
    assert_eq!(r.status, 200, "token exchange failed: {}", r.text);
    r.body["access_token"].as_str().expect("access token").to_string()
}

#[tokio::test]
async fn custom_roles_with_admin_rights_need_an_owner_to_grant() {
    let s = Server::start().await;
    let owner = register(&s, "owner-roles@test.invalid").await;
    let admin = register(&s, "admin-roles@test.invalid").await;
    let ot = owner["token"].as_str().unwrap().to_string();
    let org = owner["org_id"].as_str().unwrap().to_string();
    let at = admin["token"].as_str().unwrap().to_string();
    let au = admin["user_id"].as_str().unwrap().to_string();
    invite(&s, &ot, &org, "admin-roles@test.invalid", "admin").await;

    let wide = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&at),
        Some(json!({"name": "ops", "permissions": ["*"]}))).await;
    assert_eq!(wide.status, 200, "admin could not create a role: {}", wide.text);
    let narrow = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&at),
        Some(json!({"name": "reader", "permissions": ["secrets:read"]}))).await;
    assert_eq!(narrow.status, 200, "admin could not create a read-only role: {}", narrow.text);

    // An all-powerful custom role is admin by another name: a non-owner admin
    // must not be able to grant it, to themselves or to anyone else.
    let self_promote = s.call(Method::PATCH, &format!("/api/orgs/{}/members/{}", org, au), Some(&at),
        Some(json!({"role": "ops"}))).await;
    assert_eq!(self_promote.status, 403, "admin granted itself an all-powerful custom role: {}", self_promote.text);
    let invite_wide = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(&at),
        Some(json!({"email": "newcomer@test.invalid", "role": "ops"}))).await;
    assert_eq!(invite_wide.status, 403, "admin invited a member into an all-powerful custom role: {}", invite_wide.text);

    // A machine identity is a durable principal, so it follows the same rule.
    let machine = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(&at),
        Some(json!({"name": "ci", "role": "ops"}))).await;
    assert_eq!(machine.status, 403, "admin minted an admin-equivalent machine identity: {}", machine.text);

    // Read-only custom roles remain delegable.
    let delegate = s.call(Method::PATCH, &format!("/api/orgs/{}/members/{}", org, au), Some(&at),
        Some(json!({"role": "reader"}))).await;
    assert_eq!(delegate.status, 200, "admin could not grant a read-only custom role: {}", delegate.text);

    // The owner can grant it, and it behaves as admin afterwards.
    let by_owner = s.call(Method::PATCH, &format!("/api/orgs/{}/members/{}", org, au), Some(&ot),
        Some(json!({"role": "ops"}))).await;
    assert_eq!(by_owner.status, 200, "owner could not grant the custom role: {}", by_owner.text);
    let machine_owner = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(&ot),
        Some(json!({"name": "ci-owner", "role": "ops"}))).await;
    assert_eq!(machine_owner.status, 200, "owner could not mint an identity with the custom role: {}", machine_owner.text);
    let settings = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(&at), None).await;
    assert_eq!(settings.status, 200, "the granted role does not carry admin access: {}", settings.text);
}

#[tokio::test]
async fn custom_roles_are_enforced_on_reads() {
    let s = Server::start().await;
    let (ot, org, mt, _, _, envs) = org_with_viewer(&s, "reads").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&mt), None).await;
    assert_eq!(r.status, 403, "a zero-permission role must not list secrets, got {} {}", r.status, r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/export", envs[0]), Some(&mt), None).await;
    assert_eq!(r.status, 403, "a zero-permission role must not export, got {} {}", r.status, r.text);

    let reader = register(&s, "viewer2@test.invalid").await;
    let rt = reader["token"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&ot), Some(json!({"name": "reader", "permissions": ["secrets:read"]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    invite(&s, &ot, &org, "viewer2@test.invalid", "reader").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(rt), None).await;
    assert_eq!(r.status, 200, "a reader role should read secrets: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(rt), Some(json!({"secrets": [{"key": "X", "value": "y"}]}))).await;
    assert_eq!(r.status, 403, "a reader role must not write secrets, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn custom_roles_cannot_change_org_security_settings() {
    let s = Server::start().await;
    let (_, org, mt, _, _, _) = org_with_viewer(&s, "admin").await;
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(&mt), Some(json!({"ip_allowlist": "127.0.0.1/32"}))).await;
    assert_eq!(r.status, 403, "a custom role must not write org settings, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&mt), Some(json!({"name": "escalate", "permissions": ["*"]}))).await;
    assert_eq!(r.status, 403, "a custom role must not create roles, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/log-streams", org), Some(&mt), Some(json!({"name": "x", "url": "http://127.0.0.1:1/x"}))).await;
    assert_eq!(r.status, 403, "a custom role must not create log streams, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(&mt), Some(json!({"name": "ca"}))).await;
    assert_eq!(r.status, 403, "a custom role must not create a CA, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn custom_roles_cannot_use_unchecked_write_endpoints() {
    let s = Server::start().await;
    let (ot, _, mt, _, app, envs) = org_with_viewer(&s, "writes").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&ot), None).await;
    let sid = r.body["secrets"][0]["id"].as_str().unwrap().to_string();

    for (method, path, body) in [
        (Method::POST, format!("/api/envs/{}/restore-point", envs[0]), json!({"timestamp": 1})),
        (Method::POST, format!("/api/envs/{}/rotate", envs[0]), json!({"key": "SECRET1"})),
        (Method::POST, format!("/api/secrets/{}/restore/1", sid), json!({})),
        (Method::POST, format!("/api/envs/{}/integrations", envs[0]), json!({"kind": "webhook", "config": {"url": "http://127.0.0.1:1/h"}})),
        (Method::POST, format!("/api/envs/{}/dynamic", envs[0]), json!({"name": "lease"})),
        (Method::POST, format!("/api/envs/{}/rotations", envs[0]), json!({"key": "SECRET1", "interval_secs": 60})),
        (Method::POST, format!("/api/apps/{}/tokens", app), json!({"name": "t"})),
        (Method::POST, format!("/api/envs/{}/e2e/grant", envs[0]), json!({"email": "x@test.invalid", "wrapped_key": "k"})),
    ] {
        let r = s.call(method.clone(), &path, Some(&mt), Some(body)).await;
        assert_eq!(r.status, 403, "{} {} must be denied for a zero-permission role, got {} {}", method, path, r.status, r.text);
    }
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&ot), None).await;
    assert_eq!(r.body["secrets"][0]["value"].as_str().unwrap_or(""), "v1", "no viewer write may have landed: {}", r.text);
}

#[tokio::test]
async fn changing_the_oidc_issuer_requires_a_new_client_secret() {
    let s = Server::start().await;
    let u = register(&s, "oidc-settings@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s
        .call(
            Method::PUT,
            &format!("/api/orgs/{}/settings", org),
            Some(token),
            Some(json!({"oidc_issuer": "https://idp-one.example", "oidc_client_id": "c1", "oidc_client_secret": "s1", "oidc_redirect_uri": "https://app.example/cb"})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s
        .call(
            Method::PUT,
            &format!("/api/orgs/{}/settings", org),
            Some(token),
            Some(json!({"oidc_issuer": "https://idp-two.example"})),
        )
        .await;
    assert_eq!(r.status, 200, "issuer change should be accepted but invalidate the secret: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/auth/oidc/{}/start", org), None, None).await;
    assert_eq!(r.status, 400, "a flow must not start with a stale issuer secret, got {} {}", r.status, r.text);
    assert!(r.text.contains("client secret") || r.text.contains("client_secret") || r.text.contains("re-enter"), "expected a secret-required error, got {}", r.text);
}

#[tokio::test]
async fn postgres_leases_are_denied_without_an_allowlist() {
    let s = Server::start().await;
    let u = register(&s, "pg-lease@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s
        .call(
            Method::POST,
            &format!("/api/envs/{}/dynamic", envs[0]),
            Some(token),
            Some(json!({"name": "pg", "type": "postgres", "config": {"connection": "postgres://u:p@127.0.0.1:5432/db"}})),
        )
        .await;
    assert_eq!(r.status, 400, "postgres leases must fail closed without OPENWARP_ALLOWED_DB_HOSTS, got {} {}", r.status, r.text);
    assert!(r.text.contains("ALLOWED_DB_HOSTS"), "the error must name the setting: {}", r.text);
}

#[tokio::test]
async fn env_scoped_tokens_cannot_reach_scim() {
    let s = Server::start().await;
    let (ot, org, _mt, mu, app, envs) = org_with_viewer(&s, "scim").await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&ot), Some(json!({"name": "ci", "env_id": envs[0]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let pat = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::DELETE, &format!("/scim/v2/Users/{}?org_id={}", mu, org), Some(&pat), None).await;
    assert_eq!(r.status, 403, "an env-scoped token must not deprovision users, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn machine_tokens_cannot_mint_service_tokens() {
    let s = Server::start().await;
    let u = register(&s, "machine-mint@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, _) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(token), Some(json!({"name": "ci", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let cid = r.body["client_id"].as_str().unwrap().to_string();
    let secret = r.body["client_secret"].as_str().unwrap().to_string();
    let r = s
        .call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": secret})))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let machine = r.body["accessToken"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&machine), Some(json!({"name": "persist"}))).await;
    assert_eq!(r.status, 403, "a 1h machine token must not mint a long-lived token, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn mfa_code_guessing_is_rate_limited() {
    let s = Server::start().await;
    let u = register(&s, "mfa-limit@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "totp verify failed: {}", r.text);

    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "mfa-limit@test.invalid", "password": "correct-horse-battery"}))).await;
    let challenge = r.body["mfa_token"].as_str().expect("mfa challenge").to_string();
    let mut last = 0;
    for i in 0..8 {
        let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": format!("{:06}", i)}))).await;
        last = r.status;
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429, "repeated wrong TOTP codes at the MFA step were not rate limited");
}

#[tokio::test]
async fn mcp_rejects_a_forged_origin() {
    let s = Server::start().await;
    let u = register(&s, "mcp-origin@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, &token, org).await;
    set_secret(&s, &token, &envs[0], "MCPKEY", "mcpval").await;
    let oat = oauth_access_token(&s, &token, "secrets:read").await;
    let host = s.base.trim_start_matches("http://").to_string();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_secrets", "arguments": {"env_id": envs[0]}}});
    let r = s.call_with_headers("/mcp", &oat, body.clone(), &[("Origin", &format!("http://{}.evil.example", host))]).await;
    assert_eq!(r.status, 403, "a forged Origin must be rejected, got {} {}", r.status, r.text);
    let r = s.call_with_headers("/mcp", &oat, body.clone(), &[("Origin", &format!("http://evil.example/?{}", host))]).await;
    assert_eq!(r.status, 403, "an origin with a smuggled host must be rejected, got {} {}", r.status, r.text);
    let r = s.call_with_headers("/mcp", &oat, body, &[("Origin", &format!("http://{}", host))]).await;
    assert_eq!(r.status, 200, "the real origin should still work: {}", r.text);
    assert!(r.text.contains("MCPKEY"), "{}", r.text);
}

#[tokio::test]
async fn deactivated_accounts_stop_working_immediately() {
    let s = Server::start().await;
    let owner = register(&s, "deact-owner@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (app, _) = app_with_envs(&s, ot, org).await;
    // A SCIM-provisioned user has no personal organisation, so removing their
    // last membership is real deactivation.
    let r = s
        .call(Method::POST, &format!("/scim/v2/Users?org_id={}", org), Some(ot), Some(json!({"userName": "scim-user@test.invalid"})))
        .await;
    assert_eq!(r.status, 200, "scim create failed: {}", r.text);
    let uid = r.body["id"].as_str().unwrap().to_string();
    let temp_password = r.body["temp_password"].as_str().unwrap().to_string();
    let r = s
        .call(Method::POST, "/api/auth/login", None, Some(json!({"email": "scim-user@test.invalid", "password": temp_password})))
        .await;
    assert_eq!(r.status, 200, "scim user login failed: {}", r.text);
    let mt = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&mt), Some(json!({"name": "ci"}))).await;
    assert_eq!(r.status, 200, "a developer should be able to mint a token: {}", r.text);
    let pat = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::GET, "/api/me", Some(&pat), None).await;
    assert_eq!(r.status, 200, "the token must work before deactivation: {}", r.text);
    let r = s.call(Method::DELETE, &format!("/scim/v2/Users/{}?org_id={}", uid, org), Some(ot), None).await;
    assert_eq!(r.status, 200, "scim deactivate failed: {}", r.text);
    let r = s.call(Method::GET, "/api/me", Some(&pat), None).await;
    assert_eq!(r.status, 401, "a deactivated account's token must stop working, got {} {}", r.status, r.text);
    let r = s.call(Method::GET, "/api/me", Some(&mt), None).await;
    assert_eq!(r.status, 401, "a deactivated account's session must stop working, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn user_lookup_does_not_reveal_account_existence() {
    let s = Server::start().await;
    let u = register(&s, "lookup@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    register(&s, "existing-other@test.invalid").await;
    let missing = s.call(Method::GET, "/api/users/lookup?email=nobody@test.invalid", Some(token), None).await;
    let other = s.call(Method::GET, "/api/users/lookup?email=existing-other@test.invalid", Some(token), None).await;
    assert_eq!(missing.status, other.status, "lookup must not distinguish missing from cross-org accounts ({} vs {})", missing.status, other.status);
    assert_eq!(missing.status, 403, "cross-org lookup should be forbidden, got {} {}", missing.status, missing.text);
}

#[tokio::test]
async fn secret_keys_reject_markup() {
    let s = Server::start().await;
    let u = register(&s, "keys@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", envs[0]),
            Some(token),
            Some(json!({"secrets": [{"key": "<img src=x onerror=alert(1)>", "value": "v"}]})),
        )
        .await;
    assert_eq!(r.status, 400, "markup in a secret key must be rejected, got {} {}", r.status, r.text);
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", envs[0]),
            Some(token),
            Some(json!({"secrets": [{"key": "VALID_KEY-1", "value": "v"}]})),
        )
        .await;
    assert_eq!(r.status, 200, "a normal key must still deploy: {}", r.text);
}

#[tokio::test]
async fn registration_is_rate_limited() {
    let s = Server::start().await;
    let mut last = 0;
    for i in 0..8 {
        let r = s
            .call(Method::POST, "/api/auth/register", None, Some(json!({"email": format!("burst{}@test.invalid", i), "password": "correct-horse-battery"})))
            .await;
        last = r.status;
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429, "repeated registrations from one address were not rate limited");
}

#[tokio::test]
async fn pkce_rejects_an_empty_verifier() {
    let s = Server::start().await;
    let u = register(&s, "pkce@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let r = s
        .call(
            Method::POST,
            "/oauth/register",
            None,
            Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none", "scope": "secrets:read"})),
        )
        .await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let challenge = { use sha2::{Digest, Sha256}; base64url(&Sha256::digest(b"".as_slice())) };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.clone()),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", "secrets:read".to_string()),
        ("state", "s".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(token)).await;
    let code = parse_query(&r.header("location")).get("code").cloned().expect("code");
    let exchange = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("code_verifier", String::new()),
    ];
    let r = s.form("/oauth/token", &exchange, None).await;
    assert_eq!(r.status, 400, "an empty PKCE verifier must be rejected, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn rate_limits_survive_a_restart() {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("openwarp-authz-persist-{}-{}", std::process::id(), seq));
    let first = Server::start_at(dir.clone()).await;
    register(&first, "persist@test.invalid").await;
    let mut last = 0;
    for _ in 0..6 {
        let r = first
            .call(Method::POST, "/api/auth/login", None, Some(json!({"email": "persist@test.invalid", "password": "wrong-password"})))
            .await;
        last = r.status;
    }
    assert_eq!(last, 429, "the first process must exhaust the budget");
    let mut first = first;
    first.keep = true;
    drop(first);

    let second = Server::start_at(dir.clone()).await;
    let r = second
        .call(Method::POST, "/api/auth/login", None, Some(json!({"email": "persist@test.invalid", "password": "wrong-password"})))
        .await;
    assert_eq!(r.status, 429, "a restart must not clear the failure budget, got {} {}", r.status, r.text);
    let mut second = second;
    second.keep = true;
    drop(second);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn restricted_environments_require_a_grant() {
    let s = Server::start().await;
    let owner = register(&s, "restrict-owner@test.invalid").await;
    let member = register(&s, "restrict-member@test.invalid").await;
    let other = register(&s, "restrict-other@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, ot, org).await;
    set_secret(&s, ot, &envs[0], "RESTRICTED_KEY", "v1").await;
    invite(&s, ot, org, "restrict-member@test.invalid", "developer").await;
    invite(&s, ot, org, "restrict-other@test.invalid", "developer").await;
    let mt = member["token"].as_str().unwrap();
    let xt = other["token"].as_str().unwrap();

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 200, "an unrestricted env is open to org members: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(ot), Some(json!({"restricted": true}))).await;
    assert_eq!(r.status, 200, "policy change failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 403, "a restricted env must deny non-members, got {} {}", r.status, r.text);

    let r = s.call(Method::POST, &format!("/api/envs/{}/access-requests", envs[0]), Some(mt), Some(json!({"reason": "need it"}))).await;
    assert_eq!(r.status, 200, "access request failed: {}", r.text);
    let rid = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/access-requests/{}/approve", rid), Some(ot), Some(json!({}))).await;
    assert_eq!(r.status, 200, "approval failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 200, "an approved member must get access: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(xt), None).await;
    assert_eq!(r.status, 403, "approving one member must not open the env to others, got {} {}", r.status, r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(mt), Some(json!({"restricted": false}))).await;
    assert_eq!(r.status, 403, "only an admin may change env policy, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn clients_cannot_request_scopes_they_did_not_register() {
    let s = Server::start().await;
    let u = register(&s, "scopes@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let r = s
        .call(
            Method::POST,
            "/oauth/register",
            None,
            Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none", "scope": "secrets:read"})),
        )
        .await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = { use sha2::{Digest, Sha256}; base64url(&Sha256::digest(verifier.as_bytes())) };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", "secrets:read secrets:write".to_string()),
        ("state", "s".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(token)).await;
    assert_eq!(r.status, 400, "a client must not escalate to an unregistered scope, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn settings_round_trip_preserves_the_oidc_secret() {
    let s = Server::start().await;
    let u = register(&s, "settings@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "client",
        "oidc_client_secret": "top-secret-value",
        "oidc_redirect_uri": "https://app.example/cb",
        "oidc_auto_provision": true,
        "oidc_allowed_domains": "example.com"
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["oidc_issuer"], "https://idp.example");
    assert_eq!(r.body["oidc_client_secret_set"], true);
    assert!(!r.text.contains("top-secret-value"), "the client secret must never be returned: {}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({"ip_allowlist": "127.0.0.1/32"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(token), None).await;
    assert_eq!(r.body["oidc_issuer"], "https://idp.example", "a partial update must not clear OIDC: {}", r.text);
    assert_eq!(r.body["oidc_client_secret_set"], true, "a blank secret must keep the stored one: {}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({"ip_allowlist": "not-a-cidr"}))).await;
    assert_eq!(r.status, 400, "invalid CIDRs must be rejected, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn identities_can_be_rotated_and_deleted() {
    let s = Server::start().await;
    let u = register(&s, "identity-life@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(token), Some(json!({"name": "ci", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let iid = r.body["id"].as_str().unwrap().to_string();
    let cid = r.body["client_id"].as_str().unwrap().to_string();
    let old_secret = r.body["client_secret"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities/{}/rotate", org, iid), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let new_secret = r.body["client_secret"].as_str().unwrap().to_string();
    assert_ne!(old_secret, new_secret, "rotation must issue a new secret");

    let old_login = s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": old_secret}))).await;
    assert_eq!(old_login.status, 401, "the old secret must stop working, got {} {}", old_login.status, old_login.text);
    let new_login = s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": new_secret}))).await;
    assert_eq!(new_login.status, 200, "{}", new_login.text);

    let r = s.call(Method::DELETE, &format!("/api/orgs/{}/identities/{}", org, iid), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let after = s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": new_secret}))).await;
    assert_eq!(after.status, 401, "a deleted identity must not authenticate, got {} {}", after.status, after.text);
}

#[tokio::test]
async fn integrations_can_be_edited_and_deleted() {
    let s = Server::start().await;
    let u = register(&s, "integration-life@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::POST, &format!("/api/envs/{}/integrations", envs[0]), Some(token), Some(json!({
        "kind": "webhook", "name": "first", "config": {"url": "http://127.0.0.1:1/hook"}
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let iid = r.body["id"].as_str().unwrap().to_string();

    let r = s.call(Method::PATCH, &format!("/api/integrations/{}", iid), Some(token), Some(json!({"name": "renamed", "config": {"url": "http://127.0.0.1:2/hook"}}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/integrations", envs[0]), Some(token), None).await;
    assert!(r.body.as_array().unwrap().iter().any(|i| i["name"] == "renamed"), "{}", r.text);

    let r = s.call(Method::DELETE, &format!("/api/integrations/{}", iid), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/integrations", envs[0]), Some(token), None).await;
    assert_eq!(r.body.as_array().unwrap().len(), 0, "{}", r.text);
}

#[tokio::test]
async fn point_in_time_restore_removes_later_secrets_and_restores_deleted_ones() {
    let s = Server::start().await;
    let u = register(&s, "pitr@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "ALPHA", "one").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    set_secret(&s, token, &envs[0], "BETA", "two").await;

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(token), None).await;
    let sid = r.body["secrets"].as_array().unwrap().iter().find(|x| x["key"] == "ALPHA").unwrap()["id"].as_str().unwrap().to_string();
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", sid), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::POST, &format!("/api/envs/{}/restore-point", envs[0]), Some(token), Some(json!({"timestamp": ts}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["restored"].as_i64().unwrap_or(0) >= 1, "{}", r.text);
    assert!(r.body["removed"].as_i64().unwrap_or(0) >= 1, "{}", r.text);

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(token), None).await;
    let keys: Vec<&str> = r.body["secrets"].as_array().unwrap().iter().map(|x| x["key"].as_str().unwrap_or("")).collect();
    assert!(keys.contains(&"ALPHA"), "a secret deleted after the timestamp must come back: {}", r.text);
    assert!(!keys.contains(&"BETA"), "a secret created after the timestamp must be gone: {}", r.text);
}

#[tokio::test]
async fn e2e_grants_can_be_listed_and_revoked() {
    let s = Server::start().await;
    let owner = register(&s, "e2e-owner@test.invalid").await;
    let member = register(&s, "e2e-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mid = member["user_id"].as_str().unwrap().to_string();
    invite(&s, ot, org, "e2e-member@test.invalid", "developer").await;
    let (app, _) = app_with_envs(&s, ot, org).await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs/e2e", app), Some(ot), Some(json!({"name": "vault"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let eid = r.body["id"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/grant", eid), Some(ot), Some(json!({"email": "e2e-member@test.invalid", "wrapped_key": "AAAA"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/e2e/grants", eid), Some(ot), None).await;
    assert!(r.body.as_array().unwrap().iter().any(|g| g["user_id"] == mid), "{}", r.text);

    let r = s.call(Method::DELETE, &format!("/api/envs/{}/e2e/grants/{}", eid, mid), Some(ot), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/e2e/grants", eid), Some(ot), None).await;
    assert!(!r.body.as_array().unwrap().iter().any(|g| g["user_id"] == mid), "the revoked member must be gone: {}", r.text);
}

#[tokio::test]
async fn a_totp_code_cannot_be_replayed() {
    let s = Server::start().await;
    let u = register(&s, "replay@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let code = totp(&secret);
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": code}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "replay@test.invalid", "password": "correct-horse-battery"}))).await;
    let challenge = r.body["mfa_token"].as_str().expect("mfa challenge").to_string();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": code}))).await;
    assert_eq!(r.status, 200, "the first use of a current code should succeed: {}", r.text);

    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "replay@test.invalid", "password": "correct-horse-battery"}))).await;
    let challenge = r.body["mfa_token"].as_str().expect("second mfa challenge").to_string();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": code}))).await;
    assert_eq!(r.status, 401, "the same TOTP code must not be accepted twice, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn approval_policy_blocks_direct_developer_deploys() {
    let s = Server::start().await;
    let owner = register(&s, "approval-owner@test.invalid").await;
    let member = register(&s, "approval-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    invite(&s, ot, org, "approval-member@test.invalid", "developer").await;
    let (_, envs) = app_with_envs(&s, ot, org).await;

    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(ot), Some(json!({"require_approval": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), Some(json!({"secrets": [{"key": "DIRECT", "value": "no"}]}))).await;
    assert_eq!(r.status, 403, "a developer must not bypass the approval policy, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/envs/{}/proposals", envs[0]), Some(mt), Some(json!({"secrets": [{"key": "APPROVED", "value": "yes"}]}))).await;
    assert_eq!(r.status, 200, "a developer must still be able to propose: {}", r.text);
    let pid = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/proposals/{}/approve", pid), Some(ot), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(ot), None).await;
    assert!(r.body["secrets"].as_array().unwrap().iter().any(|x| x["key"] == "APPROVED"), "{}", r.text);
}

#[tokio::test]
async fn ownership_can_be_transferred_and_a_member_can_leave() {
    let s = Server::start().await;
    let owner = register(&s, "transfer-owner@test.invalid").await;
    let member = register(&s, "transfer-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mid = member["user_id"].as_str().unwrap().to_string();
    invite(&s, ot, org, "transfer-member@test.invalid", "developer").await;

    let r = s.call(Method::PATCH, &format!("/api/orgs/{}/members/{}", org, mid), Some(ot), Some(json!({"role": "admin"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/transfer", org), Some(ot), Some(json!({"user_id": mid}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, "/api/orgs", Some(mt), None).await;
    assert!(r.body.as_array().unwrap().iter().any(|o| o["id"] == org && o["role"] == "owner"), "the grantee must own the org: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/leave", org), Some(ot), Some(json!({}))).await;
    assert_eq!(r.status, 200, "the former owner must be able to leave: {}", r.text);
    let r = s.call(Method::GET, "/api/orgs", Some(ot), None).await;
    assert!(!r.body.as_array().unwrap().iter().any(|o| o["id"] == org), "the former owner must no longer see the org: {}", r.text);
}

#[tokio::test]
async fn environments_can_be_cloned_and_compared() {
    let s = Server::start().await;
    let u = register(&s, "clone@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "ALPHA", "one").await;
    set_secret(&s, token, &envs[0], "BETA", "two").await;

    let r = s.call(Method::POST, &format!("/api/envs/{}/clone", envs[0]), Some(token), Some(json!({"target_env_id": envs[1]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["cloned"].as_i64().unwrap_or(0) >= 2, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[1]), Some(token), None).await;
    let keys: Vec<&str> = r.body["secrets"].as_array().unwrap().iter().map(|x| x["key"].as_str().unwrap_or("")).collect();
    assert!(keys.contains(&"ALPHA") && keys.contains(&"BETA"), "{}", r.text);

    let r = s.call(Method::GET, &format!("/api/envs/{}/compare?other={}", envs[0], envs[1]), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["same"].as_i64().unwrap_or(0), 2, "{}", r.text);
    set_secret(&s, token, &envs[1], "BETA", "changed").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/compare?other={}", envs[0], envs[1]), Some(token), None).await;
    assert!(r.body["changed"].as_array().unwrap().iter().any(|k| k.as_str().unwrap_or("").ends_with("BETA")), "{}", r.text);
}

#[tokio::test]
async fn scim_discovery_and_paging_are_available() {
    let s = Server::start().await;
    let u = register(&s, "scim-page@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::GET, "/scim/v2/ServiceProviderConfig", None, None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}&startIndex=1&count=1", org), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["itemsPerPage"], 1, "{}", r.text);
    assert!(r.body["totalResults"].as_i64().unwrap_or(0) >= 1, "{}", r.text);
    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}&filter=userName%20eq%20%22scim-page%40test.invalid%22", org), Some(token), None).await;
    assert_eq!(r.body["totalResults"], 1, "{}", r.text);
}

#[tokio::test]
async fn service_token_scopes_and_last_used_are_enforced() {
    let s = Server::start().await;
    let u = register(&s, "scoped-token@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "READABLE", "one").await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(token), Some(json!({"name": "ro", "env_id": envs[0], "scopes": "secrets:read"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let tid = r.body["id"].as_str().unwrap().to_string();
    let ro = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&ro), None).await;
    assert_eq!(r.status, 200, "a read-only token must read: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(&ro), Some(json!({"secrets": [{"key": "NOPE", "value": "x"}]}))).await;
    assert_eq!(r.status, 403, "a read-only token must not write, got {} {}", r.status, r.text);
    let r = s.call(Method::GET, &format!("/api/apps/{}/tokens", app), Some(token), None).await;
    let row = r.body.as_array().unwrap().iter().find(|x| x["id"] == tid).expect("token row");
    assert_eq!(row["scopes"], "secrets:read");
    assert!(row["last_used_at"].as_i64().unwrap_or(0) > 0, "last_used_at should be recorded: {}", r.text);
}

#[tokio::test]
async fn team_grants_open_a_restricted_environment() {
    let s = Server::start().await;
    let owner = register(&s, "team-owner@test.invalid").await;
    let member = register(&s, "team-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let mid = member["user_id"].as_str().unwrap().to_string();
    invite(&s, ot, org, "team-member@test.invalid", "developer").await;
    let (_, envs) = app_with_envs(&s, ot, org).await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/teams", org), Some(ot), Some(json!({"name": "platform"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let tid = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/teams/{}/members", org, tid), Some(ot), Some(json!({"user_id": mid}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(ot), Some(json!({"restricted": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 403, "a restricted env must deny a non-granted member: {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/envs/{}/team-grants", envs[0]), Some(ot), Some(json!({"team_id": tid}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 200, "a team grant must open the env: {}", r.text);
    let r = s.call(Method::DELETE, &format!("/api/orgs/{}/teams/{}/members/{}", org, tid, mid), Some(ot), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 403, "removing team membership must revoke access: {} {}", r.status, r.text);
}

#[tokio::test]
async fn secret_listing_is_paginated() {
    let s = Server::start().await;
    let u = register(&s, "page@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    for key in ["ONE", "TWO", "THREE"] { set_secret(&s, token, &envs[0], key, "v").await; }
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets?limit=2&offset=1", envs[0]), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["total"], 3, "{}", r.text);
    assert_eq!(r.body["secrets"].as_array().unwrap().len(), 2, "{}", r.text);
    assert_eq!(r.body["limit"], 2, "{}", r.text);
    assert_eq!(r.body["offset"], 1, "{}", r.text);
}

#[tokio::test]
async fn secret_scanning_flags_high_confidence_keys() {
    let s = Server::start().await;
    let u = register(&s, "scan@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(token), Some(json!({"secrets": [{"key": "AWS_ACCESS_KEY_ID", "value": "AKIAABCDEFGHIJKLMNOP"}]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["scan_findings"].as_array().unwrap().iter().any(|f| f["rules"].as_array().unwrap().iter().any(|x| x == "aws_access_key")), "deploy should report the finding: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/scan", envs[0]), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["findings"].as_array().unwrap().iter().any(|f| f["key"] == "AWS_ACCESS_KEY_ID"), "{}", r.text);
    assert!(!r.text.contains("AKIAABCDEFGHIJKLMNOP"), "the scanned value must not be returned: {}", r.text);
}

#[tokio::test]
async fn crl_lists_revoked_certificates() {
    let s = Server::start().await;
    let u = register(&s, "crl@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(token), Some(json!({"name": "test-ca"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let ca = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"cn": "service"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let cert = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/certs/{}/revoke", cert), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/pki/cas/{}/crl", ca), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.header("content-type").contains("pkix-crl"), "{}", r.header("content-type"));
    assert!(r.text.contains("BEGIN X509 CRL"), "{}", r.text);
}

#[tokio::test]
async fn master_key_rotation_keeps_existing_data_readable() {
    let s = Server::start().await;
    let u = register(&s, "rotate-master@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "KEEP", "value").await;
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({"oidc_issuer": "https://idp.example", "oidc_client_id": "c", "oidc_client_secret": "s"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let new_key = { use base64ct::{Base64, Encoding}; Base64::encode_string(&[7u8; 32]) };
    let r = s.call(Method::POST, "/api/instance/rotate-master", Some(token), Some(json!({"new_key": new_key}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(token), None).await;
    assert!(r.body["secrets"].as_array().unwrap().iter().any(|x| x["key"] == "KEEP" && x["value"] == "value"), "{}", r.text);
    set_secret(&s, token, &envs[0], "AFTER", "works").await;
    let r = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(token), None).await;
    assert_eq!(r.body["oidc_client_secret_set"], true, "{}", r.text);
}

#[tokio::test]
async fn ocsp_reports_good_then_revoked() {
    let s = Server::start().await;
    let u = register(&s, "ocsp@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(token), Some(json!({"name": "ocsp-ca"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let ca = r.body["id"].as_str().unwrap().to_string();
    let ca_pem = r.body["certificate"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/pki/cas/{}/issue", ca), Some(token), Some(json!({"cn": "svc"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let cert = r.body["id"].as_str().unwrap().to_string();
    let leaf_pem = r.body["certificate"].as_str().unwrap().to_string();

    let ca_der = keystore_ocsp::pem::decode("CERTIFICATE", &ca_pem).expect("CA DER");
    let leaf_der = keystore_ocsp::pem::decode("CERTIFICATE", &leaf_pem).expect("leaf DER");
    let cert_id = keystore_ocsp::CertificateId::from_certificate(&leaf_der, &ca_der, keystore_ocsp::HashAlgorithm::Sha256).expect("cert id");
    let request = keystore_ocsp::OcspRequestBuilder::new().add_request(cert_id.clone()).build().to_der();
    let resp = s.client.post(s.url(&format!("/api/pki/cas/{}/ocsp", ca))).header("content-type", "application/ocsp-request").body(request).send().await.expect("OCSP request");
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").contains("ocsp-response"));
    let body = resp.bytes().await.expect("OCSP body");
    let parsed = keystore_ocsp::OcspResponse::from_der(&body).expect("parse OCSP response");
    let basic = parsed.basic_response().expect("basic OCSP response");
    assert!(matches!(basic.tbs_response_data.responses[0].cert_status, keystore_ocsp::CertStatus::Good), "expected Good");

    let r = s.call(Method::POST, &format!("/api/pki/certs/{}/revoke", cert), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let request = keystore_ocsp::OcspRequestBuilder::new().add_request(cert_id).build().to_der();
    let resp = s.client.post(s.url(&format!("/api/pki/cas/{}/ocsp", ca))).header("content-type", "application/ocsp-request").body(request).send().await.expect("OCSP request");
    let body = resp.bytes().await.expect("OCSP body");
    let parsed = keystore_ocsp::OcspResponse::from_der(&body).expect("parse OCSP response");
    let basic = parsed.basic_response().expect("basic OCSP response");
    assert!(matches!(basic.tbs_response_data.responses[0].cert_status, keystore_ocsp::CertStatus::Revoked { .. }), "expected Revoked");
}

#[tokio::test]
async fn saml_sp_round_trip_signs_validates_and_provisions() {
    use risaml::{AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
        IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy, RespondSso,
        Saml, SamlValidationContext, SpDescriptor, SsoEndpoint, Subject};

    let s = Server::start().await;
    let owner = register(&s, "saml-owner@test.invalid").await;
    let token = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();

    let idp_rsa = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("idp rsa key");
    use rsa::pkcs8::EncodePrivateKey;
    let idp_key_pem = idp_rsa.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).expect("idp key pem").to_string();
    let idp_key = rcgen::KeyPair::from_pem(&idp_key_pem).expect("idp key");
    let idp_params = rcgen::CertificateParams::new(vec!["idp.test".into()]).expect("idp params");
    let idp_cert = idp_params.self_signed(&idp_key).expect("idp cert");
    let idp_entity = "https://idp.test/metadata";
    let idp = Saml::idp(IdpConfig::builder(EntityId::try_new(idp_entity).unwrap())
        .sso_endpoint(SsoEndpoint::post("https://idp.test/sso").unwrap())
        .sso_endpoint(SsoEndpoint::redirect("https://idp.test/sso").unwrap())
        .credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(idp_key_pem)),
            signing_certificate: Some(CertificatePem::new(idp_cert.pem())),
            ..Credentials::default()
        })
        .validation(IdpValidationPolicy::strict())
        .build().unwrap()).unwrap();
    let idp_metadata = idp.metadata_xml().to_string();

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/saml", org), Some(token), Some(json!({
        "idp_entity_id": idp_entity,
        "metadata_xml": idp_metadata,
        "allow_unsigned_metadata": true,
        "auto_provision": true,
        "allowed_domains": "test.invalid"
    }))).await;
    assert_eq!(r.status, 200, "SAML config failed: {}", r.text);

    let sp_entity = format!("{}/api/auth/saml/{}/metadata", s.base, org);
    let r = s.call(Method::GET, &format!("/api/auth/saml/{}/metadata", org), None, None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.text.contains("EntityDescriptor"), "{}", r.text);
    let sp = SpDescriptor::from_metadata_xml_for(EntityId::try_new(sp_entity).unwrap(), &r.text, MetadataTrustPolicy::UnsignedForCompatibility).expect("SP descriptor");

    let r = s.call(Method::GET, &format!("/api/auth/saml/{}/start", org), None, None).await;
    assert_eq!(r.status, 307, "{}", r.text);
    let location = r.header("location");
    let query = location.split_once('?').expect("SAML redirect query").1.to_string();
    let validation = || SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility);
    let request = idp.receive_sso(&sp, BrowserInput::<AuthnRequest>::redirect(query), validation()).expect("IdP receives AuthnRequest");
    let response = idp.respond_sso(&sp, &request, Subject::new(NameId::new("saml-user@test.invalid", None), Vec::new()), RespondSso::post()).expect("IdP responds");
    let form = response.post_form().expect("SAML response form");
    let fields: Vec<(&str, String)> = form.fields().iter().map(|f| (f.name(), f.value().to_string())).collect();
    let r = s.form(&format!("/api/auth/saml/{}/acs", org), &fields, None).await;
    assert_eq!(r.status, 303, "ACS failed: {} {}", r.status, r.text);
    let replay = s.form(&format!("/api/auth/saml/{}/acs", org), &fields, None).await;
    assert_ne!(replay.status, 303, "a completed SAML response must not be reusable");
    let cookie = r.header("set-cookie");
    assert!(cookie.contains("ow_session="), "session cookie missing: {}", cookie);
    let session = cookie.split(';').next().unwrap().trim().strip_prefix("ow_session=").unwrap().to_string();
    let me = s.client.get(s.url("/api/me")).header("cookie", format!("ow_session={}", session)).send().await.expect("session request");
    assert_eq!(me.status(), 200);
    let body: Value = me.json().await.expect("session body");
    assert_eq!(body["email"], "saml-user@test.invalid");
}

#[tokio::test]
async fn rotation_hook_receives_a_signed_payload() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("hook bind");
    let addr = listener.local_addr().expect("hook addr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("hook accept");
        let mut buf = Vec::new(); let mut chunk = [0u8; 4096]; let mut end = None;
        loop {
            let n = stream.read(&mut chunk).unwrap_or(0); if n == 0 { break; }
            buf.extend_from_slice(&chunk[..n]);
            if end.is_none() { end = buf.windows(4).position(|w| w == b"\r\n\r\n"); }
            if let Some(pos) = end {
                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                if buf.len() >= pos + 4 + len { break; }
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });

    let s = Server::start().await;
    let u = register(&s, "hook@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "ROTATE_ME", "old").await;
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/rotation-hook", org), Some(token), Some(json!({"url": format!("http://{}/hook", addr), "secret": "hook-secret"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/envs/{}/rotate", envs[0]), Some(token), Some(json!({"key": "ROTATE_ME", "value": "new-value"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["rotation_hook_error"].is_null(), "{}", r.text);
    let captured = rx.recv_timeout(Duration::from_secs(5)).expect("rotation hook request");
    assert!(captured.to_lowercase().contains("x-openwarp-signature"), "{}", captured);
    assert!(captured.contains("\"event\":\"secret.rotated\""), "{}", captured);
    assert!(captured.contains("\"key\":\"ROTATE_ME\""), "{}", captured);
    assert!(captured.contains("\"value\":\"new-value\""), "{}", captured);
}

#[tokio::test]
async fn rotation_schedules_store_provider_adapters_without_leaking_config() {
    let s = Server::start().await;
    let u = register(&s, "adapter@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::POST, &format!("/api/envs/{}/rotations", envs[0]), Some(token), Some(json!({
        "key": "MAIL_KEY", "interval_secs": 60,
        "config": {"kind": "resend", "api_key": "re_parent", "key_id": "old-key"}
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["provider_rotation"], json!(true));
    assert_eq!(r.body["kind"], json!("resend"));
    let listed = s.call(Method::GET, &format!("/api/envs/{}/rotations", envs[0]), Some(token), None).await;
    assert_eq!(listed.status, 200, "{}", listed.text);
    let row = listed.body.as_array().and_then(|rows| rows.first()).expect("rotation row");
    assert_eq!(row["provider_rotation"], json!(1));
    assert!(!row.as_object().unwrap().contains_key("config_enc"), "encrypted config must not be returned: {}", listed.text);
    let bad = s.call(Method::POST, &format!("/api/envs/{}/rotations", envs[0]), Some(token), Some(json!({
        "key": "OTHER", "interval_secs": 60, "config": {"kind": "unknown"}
    }))).await;
    assert_eq!(bad.status, 400, "{}", bad.text);
    let incomplete = s.call(Method::POST, &format!("/api/envs/{}/rotations", envs[0]), Some(token), Some(json!({
        "key": "OPENAI_KEY", "interval_secs": 60, "config": {"kind": "openai", "admin_key": "sk"}
    }))).await;
    assert_eq!(incomplete.status, 400, "{}", incomplete.text);
    let relay = s.call(Method::POST, &format!("/api/envs/{}/rotations", envs[0]), Some(token), Some(json!({
        "key": "RELAY_KEY", "interval_secs": 60, "config": {"rotation_url": "https://rotate.example.com/hook", "rotation_token": "tok"}
    }))).await;
    assert_eq!(relay.status, 200, "{}", relay.text);
    assert_eq!(relay.body["kind"], json!("webhook"));
}

#[tokio::test]
async fn reuse_check_confines_environment_scoped_tokens() {
    let s = Server::start().await;
    let u = register(&s, "reuse-scope@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "SHARED_PASSWORD", "scoped-value").await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(token), Some(json!({"name": "scoped", "env_id": envs[1]}))).await;
    assert_eq!(r.status, 200, "token create failed: {}", r.text);
    let scoped = r.body["token"].as_str().expect("scoped token").to_string();
    let candidates = json!([{"key": "NEW_PASSWORD", "value": "scoped-value", "path": "/", "type": "secret"}]);

    let r = reuse_check(&s, &scoped, &envs[1], candidates.clone(), json!([])).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0),
        "an environment-scoped token must not see another environment: {}", r.text);

    let r = reuse_check(&s, &scoped, &envs[0], candidates, json!([])).await;
    assert_eq!(r.status, 403, "the token is confined to its own environment: {}", r.text);
}

#[tokio::test]
async fn reuse_check_refreshes_fingerprints_after_restore() {
    let s = Server::start().await;
    let u = register(&s, "reuse-restore@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "RESTORED_PASSWORD", "old-value").await;
    set_secret(&s, token, &envs[0], "RESTORED_PASSWORD", "new-value").await;
    let sid = secret_id(&s, token, &envs[0], "RESTORED_PASSWORD").await;
    let r = s.call(Method::POST, &format!("/api/secrets/{}/restore/1", sid), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "restore failed: {}", r.text);

    let r = check_value(&s, token, &envs[1], "old-value").await;
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(1),
        "the restored value must be indexed again: {}", r.text);
    let r = check_value(&s, token, &envs[1], "new-value").await;
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0),
        "the replaced value must not match: {}", r.text);
}

#[tokio::test]
async fn reuse_check_survives_master_key_rotation() {
    let s = Server::start().await;
    let owner = register(&s, "reuse-rotate@test.invalid").await;
    let token = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "SHARED_PASSWORD", "rotation-value").await;

    // 32 bytes of 0x01, base64. The value is irrelevant as long as it is not
    // the generated key already in use.
    let r = s.call(Method::POST, "/api/instance/rotate-master", Some(token),
        Some(json!({"new_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}))).await;
    assert_eq!(r.status, 200, "rotation failed: {}", r.text);

    // The re-index runs off the request, so poll for the rebuilt fingerprint.
    let mut matched = false;
    for _ in 0..60 {
        let r = check_value(&s, token, &envs[1], "rotation-value").await;
        if r.body["matches"].as_array().map(|m| m.len()) == Some(1) { matched = true; break; }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(matched, "the index must be rebuilt under the new master key");
}

// ---------- password reuse detection ----------

async fn reuse_check(s: &Server, token: &str, env: &str, secrets: Value, exclude: Value) -> Resp {
    s.call(
        Method::POST,
        &format!("/api/envs/{}/secrets/reuse-check", env),
        Some(token),
        Some(json!({"secrets": secrets, "exclude": exclude})),
    )
    .await
}

async fn check_value(s: &Server, token: &str, env: &str, value: &str) -> Resp {
    reuse_check(s, token, env, json!([{"key": "NEW_PASSWORD", "value": value, "path": "/", "type": "secret"}]), json!([])).await
}

async fn secret_id(s: &Server, token: &str, env: &str, key: &str) -> String {
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    assert_eq!(r.status, 200, "list secrets failed: {}", r.text);
    r.body["secrets"]
        .as_array()
        .expect("secrets array")
        .iter()
        .find(|row| row["key"] == json!(key))
        .and_then(|row| row["id"].as_str())
        .unwrap_or_else(|| panic!("secret {} not found: {}", key, r.text))
        .to_string()
}

#[tokio::test]
async fn reuse_check_finds_a_value_across_app_environments() {
    let s = Server::start().await;
    let u = register(&s, "reuse-owner@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "SHARED_PASSWORD", "hunter2").await;
    let listing = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(token), None).await;
    assert_eq!(listing.status, 200, "list envs failed: {}", listing.text);
    let env_name = listing.body.as_array().expect("env array").iter()
        .find(|e| e["id"] == json!(&envs[0]))
        .and_then(|e| e["name"].as_str())
        .expect("source env name")
        .to_string();

    let r = reuse_check(
        &s, token, &envs[1],
        json!([{"key": "NEW_PASSWORD", "value": "hunter2", "path": "/", "type": "secret"}]),
        json!([]),
    ).await;
    assert_eq!(r.status, 200, "reuse check failed: {}", r.text);
    assert_eq!(r.body["enabled"], json!(true), "the check defaults on: {}", r.text);
    let matches = r.body["matches"].as_array().expect("matches array");
    assert_eq!(matches.len(), 1, "one candidate must be reported: {}", r.text);
    assert_eq!(matches[0]["key"], json!("NEW_PASSWORD"), "{}", r.text);
    assert_eq!(matches[0]["path"], json!("/"), "{}", r.text);
    let items = matches[0]["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1, "exactly one stored secret holds the value: {}", r.text);
    assert_eq!(items[0]["key"], json!("SHARED_PASSWORD"), "{}", r.text);
    assert_eq!(items[0]["path"], json!("/"), "{}", r.text);
    assert_eq!(items[0]["env_id"], json!(&envs[0]), "{}", r.text);
    assert_eq!(items[0]["env_name"], json!(env_name), "{}", r.text);
    assert_eq!(items[0]["app_id"], json!(&app), "{}", r.text);
    assert_eq!(items[0]["app_name"], json!("app"), "{}", r.text);
    assert!(items[0]["secret_id"].as_str().map(|v| !v.is_empty()).unwrap_or(false), "{}", r.text);
    assert!(items[0]["updated_at"].as_i64().unwrap_or(0) > 0, "{}", r.text);
    assert!(!r.text.contains("hunter2"), "the response must never echo the value: {}", r.text);
}

#[tokio::test]
async fn reuse_check_stays_inside_the_workspace() {
    let s = Server::start().await;
    let u = register(&s, "reuse-tenancy@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org_a = u["org_id"].as_str().unwrap();
    let (_, envs_a) = app_with_envs(&s, token, org_a).await;
    set_secret(&s, token, &envs_a[0], "SHARED_PASSWORD", "cross-tenant-value").await;

    let r = s.call(Method::POST, "/api/orgs", Some(token), Some(json!({"name": "second"}))).await;
    assert_eq!(r.status, 200, "create second org failed: {}", r.text);
    let org_b = r.body["id"].as_str().unwrap();
    let (_, envs_b) = app_with_envs(&s, token, org_b).await;

    let r = reuse_check(
        &s, token, &envs_b[0],
        json!([{"key": "NEW_PASSWORD", "value": "cross-tenant-value", "path": "/", "type": "secret"}]),
        json!([]),
    ).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0), "another workspace must not match: {}", r.text);

    let r = reuse_check(
        &s, token, &envs_a[1],
        json!([{"key": "NEW_PASSWORD", "value": "cross-tenant-value", "path": "/", "type": "secret"}]),
        json!([]),
    ).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(1), "the owning workspace must match: {}", r.text);
}

#[tokio::test]
async fn reuse_check_hides_restricted_environments() {
    let s = Server::start().await;
    let owner = register(&s, "reuse-restrict-owner@test.invalid").await;
    let member = register(&s, "reuse-restrict-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    invite(&s, ot, org, "reuse-restrict-member@test.invalid", "developer").await;
    let (_, envs) = app_with_envs(&s, ot, org).await;
    set_secret(&s, ot, &envs[0], "RESTRICTED_PASSWORD", "only-admins-see-this").await;
    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(ot), Some(json!({"restricted": true}))).await;
    assert_eq!(r.status, 200, "restrict env failed: {}", r.text);

    let candidates = json!([{"key": "NEW_PASSWORD", "value": "only-admins-see-this", "path": "/", "type": "secret"}]);
    let r = reuse_check(&s, mt, &envs[1], candidates.clone(), json!([])).await;
    assert_eq!(r.status, 200, "a member may check an env they can open: {}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0), "a restricted env must be omitted: {}", r.text);

    let r = reuse_check(&s, ot, &envs[1], candidates, json!([])).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(1), "an admin still sees the match: {}", r.text);
}

#[tokio::test]
async fn reuse_check_respects_workspace_and_project_switches() {
    let s = Server::start().await;
    let owner = register(&s, "reuse-switch-owner@test.invalid").await;
    let dev = register(&s, "reuse-switch-dev@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let dt = dev["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    invite(&s, ot, org, "reuse-switch-dev@test.invalid", "developer").await;
    let (app, envs) = app_with_envs(&s, ot, org).await;
    set_secret(&s, ot, &envs[0], "SHARED_PASSWORD", "switch-value").await;
    let candidates = json!([{"key": "NEW_PASSWORD", "value": "switch-value", "path": "/", "type": "secret"}]);
    let enabled = |r: &Resp| r.body["enabled"].clone();
    let match_count = |r: &Resp| r.body["matches"].as_array().map(|m| m.len()).unwrap_or(99);

    let r = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(ot), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["reuse_check"], json!(true), "workspace switch defaults on: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/apps/{}/settings", app), Some(ot), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["reuse_check"], json!(true), "project switch defaults on: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/apps", org), Some(ot), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let app_row = r.body.as_array().expect("app array").iter().find(|a| a["id"] == json!(&app)).expect("app row");
    assert_eq!(app_row["reuse_check"], json!(true), "the app list carries the switch: {}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(ot), Some(json!({"reuse_check": false}))).await;
    assert_eq!(r.status, 200, "disable workspace check failed: {}", r.text);
    let r = reuse_check(&s, ot, &envs[1], candidates.clone(), json!([])).await;
    assert_eq!(enabled(&r), json!(false), "{}", r.text);
    assert_eq!(match_count(&r), 0, "{}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(ot), Some(json!({"reuse_check": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::PUT, &format!("/api/apps/{}/settings", app), Some(ot), Some(json!({"reuse_check": false}))).await;
    assert_eq!(r.status, 200, "disable project check failed: {}", r.text);
    let r = reuse_check(&s, ot, &envs[1], candidates.clone(), json!([])).await;
    assert_eq!(enabled(&r), json!(false), "{}", r.text);
    assert_eq!(match_count(&r), 0, "{}", r.text);

    let r = s.call(Method::PUT, &format!("/api/apps/{}/settings", app), Some(ot), Some(json!({"reuse_check": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = reuse_check(&s, ot, &envs[1], candidates, json!([])).await;
    assert_eq!(enabled(&r), json!(true), "{}", r.text);
    assert_eq!(match_count(&r), 1, "{}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(dt), Some(json!({"reuse_check": false}))).await;
    assert_eq!(r.status, 403, "only an admin may change the workspace switch: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/apps/{}/settings", app), Some(dt), Some(json!({"reuse_check": false}))).await;
    assert_eq!(r.status, 403, "only an admin may change the project switch: {}", r.text);
}

#[tokio::test]
async fn reuse_check_skips_non_secret_types_and_excluded_ids() {
    let s = Server::start().await;
    let u = register(&s, "reuse-types@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(token), Some(json!({"secrets": [
        {"key": "SHARED_PASSWORD", "value": "typed-value", "type": "secret"},
        {"key": "SHARED_CONFIG", "value": "typed-value", "type": "config"},
        {"key": "SHARED_SEALED", "value": "typed-value", "type": "sealed"}
    ]}))).await;
    assert_eq!(r.status, 200, "seed secrets failed: {}", r.text);
    let sid = secret_id(&s, token, &envs[0], "SHARED_PASSWORD").await;
    let candidates = json!([{"key": "NEW_PASSWORD", "value": "typed-value", "path": "/", "type": "secret"}]);

    let r = reuse_check(&s, token, &envs[1], candidates.clone(), json!([])).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let matches = r.body["matches"].as_array().expect("matches");
    assert_eq!(matches.len(), 1, "{}", r.text);
    let items = matches[0]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "config and sealed values must not match: {}", r.text);
    assert_eq!(items[0]["key"], json!("SHARED_PASSWORD"), "{}", r.text);

    let r = reuse_check(&s, token, &envs[1], candidates.clone(), json!([sid])).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0), "an excluded secret must not match itself: {}", r.text);

    let r = reuse_check(&s, token, &envs[1], json!([
        {"key": "AS_CONFIG", "value": "typed-value", "path": "/", "type": "config"},
        {"key": "AS_SEALED", "value": "typed-value", "path": "/", "type": "sealed"}
    ]), json!([])).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0), "only secret candidates are checked: {}", r.text);
}

#[tokio::test]
async fn reuse_check_matches_exactly_and_ignores_deleted() {
    let s = Server::start().await;
    let u = register(&s, "reuse-exact@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "SHARED_PASSWORD", "Passw0rd!").await;
    for value in ["passw0rd!", "Passw0rd", ""] {
        let r = check_value(&s, token, &envs[1], value).await;
        assert_eq!(r.status, 200, "{}", r.text);
        assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0), "value {:?} must not match: {}", value, r.text);
    }
    let r = check_value(&s, token, &envs[1], "Passw0rd!").await;
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(1), "the exact value must match: {}", r.text);

    let sid = secret_id(&s, token, &envs[0], "SHARED_PASSWORD").await;
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", sid), Some(token), None).await;
    assert_eq!(r.status, 200, "delete failed: {}", r.text);
    let r = check_value(&s, token, &envs[1], "Passw0rd!").await;
    assert_eq!(r.body["matches"].as_array().map(|m| m.len()), Some(0), "a deleted secret must not match: {}", r.text);
}

#[tokio::test]
async fn reuse_check_requires_target_environment_access() {
    let s = Server::start().await;
    let owner = register(&s, "reuse-outsider-owner@test.invalid").await;
    let outsider = register(&s, "reuse-outsider@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let xt = outsider["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, ot, org).await;
    let r = reuse_check(&s, xt, &envs[0], json!([{"key": "NEW_PASSWORD", "value": "x", "type": "secret"}]), json!([])).await;
    assert_eq!(r.status, 403, "a non-member must not probe another workspace: {}", r.text);
}

async fn put_secret(s: &Server, token: &str, env: &str, key: &str, value: &str, tags: &str) {
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", env),
            Some(token),
            Some(json!({"secrets": [{"key": key, "value": value, "tags": tags}]})),
        )
        .await;
    assert_eq!(r.status, 200, "put {} failed: {}", key, r.text);
}

#[tokio::test]
async fn pitr_restores_creates_deletes_and_tags() {
    let s = Server::start().await;
    let u = register(&s, "pitr@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let env = envs[0].clone();

    put_secret(&s, token, &env, "ALPHA", "v1", "team=a").await;
    put_secret(&s, token, &env, "BRAVO", "b1", "team=b").await;
    let reference = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    put_secret(&s, token, &env, "ALPHA", "v2", "team=changed").await;
    let bravo = secret_id(&s, token, &env, "BRAVO").await;
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", bravo), Some(token), None).await;
    assert_eq!(r.status, 200, "delete failed: {}", r.text);
    put_secret(&s, token, &env, "CHARLIE", "c1", "").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let r = s
        .call(Method::POST, &format!("/api/envs/{}/restore-point", env), Some(token), Some(json!({"timestamp": reference})))
        .await;
    assert_eq!(r.status, 200, "restore-point failed: {}", r.text);
    assert!(r.body["restored"].as_i64().unwrap_or(0) >= 1, "at least one secret restored: {}", r.text);

    let list = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    let secrets = list.body["secrets"].as_array().expect("secrets");
    let alpha = secrets.iter().find(|x| x["key"] == "ALPHA").expect("ALPHA");
    assert_eq!(alpha["value"], json!("v1"), "the value at the reference time must return");
    assert_eq!(alpha["tags"], json!("team=a"), "tags recorded with the version must return");
    assert!(secrets.iter().any(|x| x["key"] == "BRAVO"), "a secret deleted after the reference time must return");
    assert!(!secrets.iter().any(|x| x["key"] == "CHARLIE"), "a secret created after the reference time must disappear");

    // A later restore must not resurrect CHARLIE (deleted by the first restore)
    // and must keep BRAVO (its deleted_at was cleared when it was restored).
    let later = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let r = s
        .call(Method::POST, &format!("/api/envs/{}/restore-point", env), Some(token), Some(json!({"timestamp": later})))
        .await;
    assert_eq!(r.status, 200, "second restore-point failed: {}", r.text);
    let list = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    let secrets = list.body["secrets"].as_array().expect("secrets");
    assert!(secrets.iter().any(|x| x["key"] == "BRAVO"), "a restored secret must survive a later restore: {}", list.text);
    assert!(!secrets.iter().any(|x| x["key"] == "CHARLIE"), "a removed secret must stay removed: {}", list.text);

    // The explicit version restore must also clear the tombstone.
    let bravo = secret_id(&s, token, &env, "BRAVO").await;
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", bravo), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/secrets/{}/restore/1", bravo), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "version restore failed: {}", r.text);
    let r = s
        .call(Method::POST, &format!("/api/envs/{}/restore-point", env), Some(token), Some(json!({"timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64})))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let list = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    assert!(list.body["secrets"].as_array().expect("secrets").iter().any(|x| x["key"] == "BRAVO"), "a manually restored secret must survive a point-in-time restore: {}", list.text);
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
