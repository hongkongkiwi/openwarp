use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const PASSWORD: &str = "cookie-scope-test-password";
const REDIRECT: &str = "http://127.0.0.1:8917/callback";
const VERIFIER: &str = "cookie-scope-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
struct Resp { status: u16, body: Value, location: String }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
struct User { id: String, org: String, session: String }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("inbox bind");
    let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection");
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = stream.read(&mut chunk).expect("mail read"); if n == 0 { break; }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
            if let Ok(v) = serde_json::from_slice::<Value>(&buf[end..]) { sink.lock().unwrap().push(v); }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", addr), inbox)
}
impl Server {
    async fn start() -> Self {
        let _lock = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-cookie-scope-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (relay, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", relay).env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL").env_remove("OPENWARP_SIGNUPS")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client, inbox }; let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    async fn response(r: reqwest::Response) -> Resp {
        let status = r.status().as_u16();
        let location = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Resp { status, location, body: serde_json::from_str(&r.text().await.unwrap()).unwrap_or(Value::Null) }
    }
    async fn call(&self, method: Method, path: &str, token: &str, cookie: bool, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = if cookie { req.header("Cookie", format!("ow_session={}", token)) } else { req.bearer_auth(token) }; }
        if let Some(body) = body { req = req.json(&body); }
        Self::response(req.send().await.expect("HTTP request")).await
    }
    async fn form(&self, path: &str, token: &str, form: &[(&str, String)]) -> Resp {
        let mut req = self.client.post(format!("{}{}", self.base, path)).form(form);
        if !token.is_empty() { req = req.bearer_auth(token); }
        Self::response(req.send().await.expect("form request")).await
    }
    async fn register(&self) -> User {
        let email = "cookie-scope@test.invalid";
        let r = self.call(Method::POST, "/api/auth/register", "", false, Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "register account"); assert_eq!(r.body["verification_required"], true);
        let mut verified = false;
        for _ in 0..60 {
            let link = { self.inbox.lock().unwrap().iter().rev().filter(|m| m["to"] == email).filter_map(|m| m["text"].as_str())
                .find_map(|text| text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string()))) };
            if let Some(link) = link { assert_eq!(self.call(Method::GET, &link, "", false, None).await.status, 200); verified = true; break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(verified, "verification mail did not arrive");
        let login = self.call(Method::POST, "/api/auth/login", "", false, Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(login.status, 200, "verified password login");
        User { id: field(&r.body, "user_id"), org: field(&r.body, "org_id"), session: field(&login.body, "token") }
    }
    async fn oauth(&self, user: &User, scope: &str, resource: &str) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use sha2::{Digest, Sha256};
        let r = self.call(Method::POST, "/oauth/register", "", false, Some(json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "scope": scope}))).await;
        assert_eq!(r.status, 201, "register OAuth client"); let client = field(&r.body, "client_id");
        let form = [("response_type", "code".into()), ("client_id", client.clone()), ("redirect_uri", REDIRECT.into()),
            ("scope", scope.into()), ("state", "cookie-scope".into()), ("resource", resource.into()), ("approve", "1".into()),
            ("code_challenge", Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))), ("code_challenge_method", "S256".into())];
        let decision = self.form("/oauth/authorize/decision", &user.session, &form).await;
        assert_eq!(decision.status, 303, "OAuth consent");
        let code = decision.location.split_once('?').unwrap().1.split('&').filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "code").expect("authorization code").1.to_string();
        let r = self.form("/oauth/token", "", &[("grant_type", "authorization_code".into()), ("client_id", client),
            ("redirect_uri", REDIRECT.into()), ("code_verifier", VERIFIER.into()), ("code", code)]).await;
        assert_eq!(r.status, 200, "exchange authorization code"); field(&r.body, "access_token")
    }
}
fn field(body: &Value, key: &str) -> String { body[key].as_str().expect("response field").to_string() }
fn initialize() -> Value { json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) }

#[tokio::test]
async fn account_session_cookie_still_authenticates_me() {
    let s = Server::start().await; let u = s.register().await;
    for cookie in [false, true] {
        let r = s.call(Method::GET, "/api/me", &u.session, cookie, None).await;
        assert_eq!(r.status, 200, "account session works as bearer and cookie");
        assert_eq!(r.body["id"], u.id, "session resolves the registered account");
    }
}

#[tokio::test]
async fn oauth_tokens_cannot_be_session_cookies_or_bypass_scope_and_audience() {
    let s = Server::start().await; let u = s.register().await;
    let api = s.oauth(&u, "secrets:read", &s.base).await;
    let write_only = s.oauth(&u, "secrets:write", &s.base).await;
    let mcp = s.oauth(&u, "secrets:read mcp", &format!("{}/mcp", s.base)).await;
    let mut cookies = Vec::new();
    for (token, api_status, mcp_status) in [(&api, 200, 401), (&write_only, 403, 401), (&mcp, 403, 200)] {
        assert_eq!(s.call(Method::GET, "/api/orgs", token, false, None).await.status, api_status, "bearer API scopes and audience still apply");
        assert_eq!(s.call(Method::POST, "/mcp", token, false, Some(initialize())).await.status, mcp_status, "bearer MCP audience still applies");
        cookies.push(s.call(Method::GET, "/api/orgs", token, true, None).await.status);
        cookies.push(s.call(Method::POST, "/mcp", token, true, Some(initialize())).await.status);
    }
    assert_eq!(cookies, vec![401; 6], "ow_session accepts account sessions only, never OAuth credentials of either audience or scope");
}

#[tokio::test]
async fn env_scoped_service_token_cookie_cannot_inherit_creator_access() {
    let s = Server::start().await; let u = s.register().await;
    let app = s.call(Method::POST, &format!("/api/orgs/{}/apps", u.org), &u.session, false, Some(json!({"name": "cookie-test"}))).await;
    assert_eq!(app.status, 200); let app = field(&app.body, "id");
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), &u.session, false, None).await;
    assert_eq!(envs.status, 200);
    let own = format!("/api/envs/{}/secrets", field(&envs.body[0], "id"));
    let other = format!("/api/envs/{}/secrets", field(&envs.body[1], "id"));
    let minted = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), &u.session, false,
        Some(json!({"name": "scoped-ci", "env_id": field(&envs.body[0], "id"), "scopes": "secrets:read"}))).await;
    assert_eq!(minted.status, 200); let token = field(&minted.body, "token");
    assert_eq!(s.call(Method::GET, &other, &u.session, false, None).await.status, 200, "creator can access the other environment");
    assert_eq!(s.call(Method::GET, &own, &token, false, None).await.status, 200, "scoped bearer works in its environment");
    assert_eq!(s.call(Method::GET, &other, &token, false, None).await.status, 403, "scoped bearer cannot escape its environment");
    assert_eq!(s.call(Method::GET, "/api/orgs", &token, false, None).await.status, 403, "scoped bearer cannot list workspaces");
    let orgs = s.call(Method::GET, "/api/orgs", &token, true, None).await.status;
    let secrets = s.call(Method::GET, &other, &token, true, None).await.status;
    let mcp = s.call(Method::POST, "/mcp", &token, true, Some(initialize())).await.status;
    assert_eq!([orgs, secrets, mcp], [401; 3], "service tokens in ow_session cannot inherit the creator's access");
}
