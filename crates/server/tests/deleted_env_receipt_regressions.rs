#![cfg(not(target_arch = "wasm32"))]

use axum::{extract::State, routing::post, Json, Router};
use reqwest::{Client, Method};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Inbox = Arc<Mutex<Vec<Value>>>;
struct Response { status: u16, body: Value }
struct Token { id: String, value: String }
struct Fixture {
    child: Option<Child>, mail: tokio::task::JoinHandle<()>, inbox: Inbox,
    dir: PathBuf, base: String, client: Client,
    owner: String, org: String, app: String, env: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() { let _ = child.kill(); let _ = child.wait(); }
        self.mail.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
async fn capture_mail(State(inbox): State<Inbox>, Json(body): Json<Value>) -> Json<Value> {
    inbox.lock().expect("private inbox lock").push(body); Json(json!({}))
}
fn field(value: &Value, key: &str) -> String { value[key].as_str().filter(|s| !s.is_empty()).expect(key).to_string() }
fn good(response: Response, action: &str) -> Value { assert_eq!(response.status, 200, "{action}"); response.body }
async fn response(request: reqwest::RequestBuilder) -> Response {
    let response = request.send().await.unwrap_or_else(|_| panic!("private HTTP request failed"));
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap_or_else(|_| panic!("read private HTTP response"));
    Response { status, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
}
impl Fixture {
    async fn start(redis_url: Option<&str>) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").expect("private server port");
        let addr = socket.local_addr().expect("server address");
        let mail_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("private mail port");
        let mail_addr = mail_socket.local_addr().expect("mail address");
        let dir = std::env::temp_dir().join(openwarp_crypto::random_token("openwarp-receipt-regression"));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
        builder.create(&dir).expect("create fresh private fixture directory");
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let mail_app = Router::new().route("/mail", post(capture_mail)).with_state(inbox.clone());
        let mail = tokio::spawn(async move { let _ = axum::serve(mail_socket, mail_app).await; });
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().expect("local HTTP client");
        let mut s = Self { child: None, mail, inbox, dir, base: format!("http://{addr}"), client,
            owner: String::new(), org: String::new(), app: String::new(), env: String::new() };
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        // Ambient deployment credentials and cache settings must not reach the private server.
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("OPENWARP_") || matches!(name.as_ref(), "DATABASE_URL" | "REDIS_URL" | "ADDR" | "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY" | "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy") { command.env_remove(key); }
        }
        if let Some(url) = redis_url { command.env("REDIS_URL", url); }
        drop(socket);
        s.child = Some(command.env("DATABASE_URL", format!("sqlite://{}/test.db", s.dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &s.base).env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", format!("http://{mail_addr}/mail"))
            .env("TOKIO_WORKER_THREADS", "1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn private server"));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(s.child.as_mut().expect("server child").try_wait().expect("poll server").is_none(), "server exited before readiness");
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).timeout(Duration::from_secs(1)).send().await { if r.status().as_u16() == 200 { break; } }
            assert!(Instant::now() < deadline, "private server health timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let owner = s.register("receipt-regression-owner@example.invalid").await;
        s.owner = field(&owner, "token");
        let orgs = good(s.raw(Method::GET, "/api/orgs", Some(&s.owner), None).await, "list owner workspaces");
        s.org = field(orgs.as_array().and_then(|v| v.first()).expect("owner workspace"), "id");
        let app = good(s.session(Method::POST, &format!("/api/orgs/{}/apps", s.org), &s.owner, Some(json!({"name":"receipt-regression-app"}))).await, "create private application");
        s.app = field(&app, "id");
        let envs = good(s.raw(Method::GET, &format!("/api/apps/{}/envs", s.app), Some(&s.owner), None).await, "list live environments");
        s.env = field(envs.as_array().expect("environment list").iter().find(|v| v["name"] == "Development").expect("source environment"), "id");
        s
    }
    fn db(&self) -> Connection {
        let db = Connection::open(self.dir.join("test.db")).expect("open private fixture database");
        db.busy_timeout(Duration::from_secs(5)).expect("private database timeout"); db
    }
    async fn raw(&self, method: Method, path: &str, token: Option<&str>, body: Option<&Value>) -> Response {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = token { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(body); }
        response(request).await
    }
    async fn session(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Response {
        let result = self.raw(method.clone(), path, Some(token), body.as_ref()).await;
        if result.status != 428 { return result; }
        assert!(result.body["step_up_required"] == true && result.body["totp_required"] == false, "fixture needs email proof without TOTP");
        let risk = field(&result.body, "risk");
        let before = self.inbox.lock().expect("inbox lock").len();
        let started = good(self.raw(Method::POST, "/api/auth/step-up/start", Some(token), Some(&json!({"risk":risk}))).await, "start real email proof");
        assert_eq!(started["email_sent"], true, "proof must deliver a real local email");
        let text = self.mail_after(before, "Your verification code is ").await;
        let code = text.split_once("Your verification code is ").expect("emailed code").1.split(|c: char| !c.is_ascii_digit()).next().filter(|s| s.len() == 6).expect("six-digit email code");
        let verified = good(self.raw(Method::POST, "/api/auth/step-up/verify", Some(token), Some(&json!({"challenge":field(&started,"challenge"),"email_code":code}))).await, "verify real email proof");
        let mut request = self.client.request(method, format!("{}{}", self.base, path)).bearer_auth(token).header("x-openwarp-step-up", field(&verified, "token"));
        if let Some(body) = body { request = request.json(&body); }
        response(request).await
    }
    async fn mail_after(&self, before: usize, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let text = self.inbox.lock().expect("inbox lock").iter().skip(before).filter_map(|mail| mail["text"].as_str()).find(|text| text.contains(needle)).map(str::to_string);
            if let Some(text) = text { return text; }
            assert!(Instant::now() < deadline, "expected fresh local email");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    async fn register(&self, email: &str) -> Value {
        let before = self.inbox.lock().expect("inbox lock").len();
        let credentials = json!({"email":email,"password":"correct-horse-battery"});
        let registered = good(self.raw(Method::POST, "/api/auth/register", None, Some(&credentials)).await, "register private account");
        assert_eq!(registered["verification_required"], true);
        let text = self.mail_after(before, "/api/auth/verify?token=").await;
        let path = text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| &word[i..])).expect("verification link");
        good(self.raw(Method::GET, path, None, None).await, "verify private account");
        good(self.raw(Method::POST, "/api/auth/login", None, Some(&credentials)).await, "sign in verified account")
    }
    async fn member(&self) -> Value {
        let member = self.register("receipt-regression-member@example.invalid").await;
        let invite = good(self.session(Method::POST, &format!("/api/orgs/{}/members", self.org), &self.owner,
            Some(json!({"email":"receipt-regression-member@example.invalid","role":"developer"}))).await, "invite token creator");
        good(self.session(Method::POST, "/api/auth/accept-invite", &field(&member,"token"), Some(json!({"token":field(&invite,"invite_token")}))).await, "accept creator membership");
        member
    }
    async fn mint(&self, creator: &str) -> Token {
        let minted = good(self.session(Method::POST, &format!("/api/apps/{}/tokens", self.app), creator,
            Some(json!({"name":"receipt-regression-reader","env_id":self.env,"expires_in":600,"scopes":"secrets:read"}))).await, "mint static human-owned token");
        Token { id: field(&minted,"id"), value: field(&minted,"token") }
    }
    async fn set_role(&self, member_id: &str, role: &str) {
        good(self.session(Method::PATCH, &format!("/api/orgs/{}/members/{member_id}", self.org), &self.owner, Some(json!({"role":role}))).await, "change creator role");
    }
    async fn delete(&self) {
        good(self.session(Method::DELETE, &format!("/api/envs/{}", self.env), &self.owner, None).await, "delete source through authenticated API");
        assert_eq!(self.raw(Method::GET, &format!("/api/envs/{}/meta", self.env), Some(&self.owner), None).await.status, 404, "source must actually be gone");
    }
    async fn receipt_me(&self, token: &Token) {
        let me = good(self.raw(Method::GET, "/api/me", Some(&token.value), None).await, "eligible token retains a terminal receipt");
        assert_eq!(me, json!({"env_scope":self.env}), "receipt must not expose an ordinary account principal");
    }
    async fn terminal_status(&self, token: &Token, expected: u16) {
        for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", self.env), format!("/api/envs/{}/export?base=1", self.env)] {
            let result = self.raw(Method::GET, &path, Some(&token.value), None).await;
            assert_eq!(result.status, expected, "ineligible or revoked credential must remain denied on terminal route");
            assert_ne!(result.body["code"], "environment_deleted", "denial must not signal deletion");
        }
    }
    fn ordinary_token_count(&self, token: &Token) -> i64 {
        self.db().query_row("SELECT COUNT(*) FROM tokens WHERE id=? OR token_hash=?", params![token.id, openwarp_crypto::hash_token(&token.value)], |r| r.get(0)).expect("inspect ordinary token removal")
    }
    fn receipt_count(&self, token: &Token) -> i64 {
        self.db().query_row("SELECT COUNT(*) FROM deleted_env_receipts WHERE token_id=? OR token_hash=?", params![token.id, openwarp_crypto::hash_token(&token.value)], |r| r.get(0)).expect("inspect receipt admission")
    }
}

#[tokio::test]
async fn malformed_custom_role_at_deletion_cannot_gain_a_receipt_after_read_permission_returns() {
    let s = Fixture::start(None).await; let member = s.member().await;
    let token = s.mint(&field(&member,"token")).await; let control = s.mint(&s.owner).await;
    good(s.raw(Method::GET, &format!("/api/envs/{}/meta",s.env), Some(&token.value), None).await, "developer can read live source");
    good(s.session(Method::POST, &format!("/api/orgs/{}/roles",s.org), &s.owner,
        Some(json!({"name":"object-not-read-permission","permissions":{"secrets:read":false}}))).await, "create object-shaped custom role");
    s.set_role(&field(&member,"user_id"), "object-not-read-permission").await;
    assert_eq!(s.raw(Method::GET, &format!("/api/envs/{}/meta",s.env), Some(&token.value), None).await.status, 403, "an object key is not an effective read permission");
    s.delete().await;
    assert_eq!(s.ordinary_token_count(&token), 0);
    s.receipt_me(&control).await;
    s.set_role(&field(&member,"user_id"), "developer").await;
    s.terminal_status(&token, 401).await;
    assert_eq!(s.receipt_count(&token), 0, "a token without read authority at deletion must never enter the receipt store");
}

#[tokio::test]
async fn valid_custom_read_role_at_deletion_retains_only_the_terminal_receipt() {
    let s = Fixture::start(None).await; let member = s.member().await;
    let token = s.mint(&field(&member,"token")).await;
    good(s.session(Method::POST, &format!("/api/orgs/{}/roles",s.org), &s.owner,
        Some(json!({"name":"actual-read-permission","permissions":["secrets:read"]}))).await, "create valid custom read role");
    s.set_role(&field(&member,"user_id"), "actual-read-permission").await;
    good(s.raw(Method::GET, &format!("/api/envs/{}/meta",s.env), Some(&token.value), None).await, "custom read role can read live source");
    s.delete().await;
    assert_eq!(s.ordinary_token_count(&token), 0);
    s.receipt_me(&token).await;
    let exported = s.raw(Method::GET, &format!("/api/envs/{}/export?base=1",s.env), Some(&token.value), None).await;
    assert_eq!(exported.status, 404);
    assert_eq!(exported.body, json!({"error":"environment deleted","code":"environment_deleted"}));
    assert_eq!(s.raw(Method::GET, &format!("/api/envs/{}/secrets",s.env), Some(&token.value), None).await.status, 403, "eligible receipt is not an ordinary credential");
}

#[cfg(feature = "redis-cache")]
#[tokio::test]
#[ignore = "requires explicitly owned OPENWARP_TEST_RECEIPT_REDIS_URL fixture"]
async fn redis_logged_out_static_token_cannot_regain_access_as_a_deletion_receipt() {
    assert_eq!(std::env::var("OPENWARP_TEST_RECEIPT_REDIS_OWNED").ok().as_deref(), Some("1"), "explicitly acknowledge an owned disposable Redis fixture");
    let url = std::env::var("OPENWARP_TEST_RECEIPT_REDIS_URL").expect("explicit owned Redis URL is required; ambient REDIS_URL is not used");
    let parsed = reqwest::Url::parse(&url).unwrap_or_else(|_| panic!("invalid owned Redis fixture URL"));
    assert_eq!(parsed.scheme(), "redis");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"), "Redis fixture must be local and explicitly owned");
    assert!(parsed.port().is_some_and(|port| port != 6379 && port != 0), "Redis fixture must use an explicit non-default private port");
    let client = redis::Client::open(url.as_str()).unwrap_or_else(|_| panic!("invalid owned Redis configuration"));
    let mut connection = client.get_connection().unwrap_or_else(|_| panic!("owned Redis fixture unavailable"));
    let pong: String = redis::cmd("PING").query(&mut connection).expect("owned Redis fixture must answer PING");
    assert_eq!(pong, "PONG");
    let s = Fixture::start(Some(&url)).await;
    let revoked = s.mint(&s.owner).await; let control = s.mint(&s.owner).await;
    good(s.raw(Method::GET, "/api/me", Some(&revoked.value), None).await, "live static token authenticates before logout");
    good(s.raw(Method::POST, "/api/auth/logout", Some(&revoked.value), None).await, "log out static bearer through the real API");
    assert_eq!(s.raw(Method::GET, "/api/me", Some(&revoked.value), None).await.status, 401, "logout must already deny ordinary authentication before deletion");
    good(s.raw(Method::GET, "/api/me", Some(&control.value), None).await, "logout must not revoke adjacent credential");
    s.delete().await;
    assert_eq!(s.ordinary_token_count(&revoked), 0);
    s.receipt_me(&control).await;
    s.terminal_status(&revoked, 401).await;
}
