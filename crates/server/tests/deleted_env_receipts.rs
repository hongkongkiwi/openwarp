#![cfg(not(target_arch = "wasm32"))]

use axum::{extract::State, routing::post, Json, Router};
use reqwest::{Client, Method};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Inbox = Arc<Mutex<Vec<Value>>>;
struct Response { status: u16, body: Value }
struct Token { id: String, value: String, expires_at: i64 }
struct Fixture {
    child: Option<Child>, mail: tokio::task::JoinHandle<()>, inbox: Inbox,
    dir: PathBuf, base: String, client: Client,
    owner: String, owner_id: String, org: String, workspace: String, app: String, env: String, other_env: String,
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
fn denied(response: Response, action: &str) {
    assert!(matches!(response.status, 401 | 403), "{action} must deny authentication or authority, got {}", response.status);
    assert_ne!(response.body["code"], "environment_deleted", "policy denial must not masquerade as source deletion");
}
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() as i64 }
async fn response(request: reqwest::RequestBuilder) -> Response {
    let response = request.send().await.unwrap_or_else(|_| panic!("private HTTP request failed"));
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap_or_else(|_| panic!("read private HTTP response"));
    Response { status, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
}
impl Fixture {
    async fn start() -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").expect("private server port");
        let addr = socket.local_addr().expect("server address");
        let mail_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("private mail port");
        let mail_addr = mail_socket.local_addr().expect("mail address");
        let dir = std::env::temp_dir().join(openwarp_crypto::random_token("openwarp-deleted-env"));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
        builder.create(&dir).expect("create fresh private fixture directory");
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let mail_app = Router::new().route("/mail", post(capture_mail)).with_state(inbox.clone());
        let mail = tokio::spawn(async move { let _ = axum::serve(mail_socket, mail_app).await; });
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().expect("local HTTP client");
        let mut s = Self { child: None, mail, inbox, dir, base: format!("http://{addr}"), client,
            owner: String::new(), owner_id: String::new(), org: String::new(), workspace: String::new(), app: String::new(), env: String::new(), other_env: String::new() };
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        // Child processes must not inherit deployment credentials, proxies or policy overrides.
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("OPENWARP_") || matches!(name.as_ref(), "DATABASE_URL" | "REDIS_URL" | "ADDR" | "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY" | "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy") { command.env_remove(key); }
        }
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
        let owner = s.register("receipt-owner@example.invalid").await;
        s.owner = field(&owner, "token"); s.owner_id = field(&owner, "user_id");
        let orgs = good(s.raw(Method::GET, "/api/orgs", Some(&s.owner), None).await, "list owner workspaces");
        let org = orgs.as_array().and_then(|v| v.first()).expect("owner workspace");
        s.org = field(org, "id"); s.workspace = field(org, "name");
        let app = good(s.session(Method::POST, &format!("/api/orgs/{}/apps", s.org), &s.owner, Some(json!({"name":"receipt-app"}))).await, "create receipt application");
        s.app = field(&app, "id");
        let envs = good(s.raw(Method::GET, &format!("/api/apps/{}/envs", s.app), Some(&s.owner), None).await, "list live environments");
        let envs = envs.as_array().expect("environment list");
        s.env = field(envs.iter().find(|v| v["name"] == "Development").expect("source environment"), "id");
        s.other_env = field(envs.iter().find(|v| v["name"] == "Staging").expect("adjacent environment"), "id");
        good(s.session(Method::PUT, &format!("/api/envs/{}/secrets", s.env), &s.owner,
            Some(json!({"secrets":[{"key":"RECEIPT_SECRET","value":"private-fixture-value"}]}))).await, "deploy live secret control");
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
        assert_eq!(registered["verification_required"], true, "signup must require email verification");
        let text = self.mail_after(before, "/api/auth/verify?token=").await;
        let path = text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| &word[i..])).expect("verification link");
        good(self.raw(Method::GET, path, None, None).await, "verify private account");
        good(self.raw(Method::POST, "/api/auth/login", None, Some(&credentials)).await, "sign in verified account")
    }
    async fn member(&self) -> Value {
        let member = self.register("receipt-member@example.invalid").await;
        let invite = good(self.session(Method::POST, &format!("/api/orgs/{}/members", self.org), &self.owner,
            Some(json!({"email":"receipt-member@example.invalid","role":"developer"}))).await, "invite token creator");
        good(self.session(Method::POST, "/api/auth/accept-invite", &field(&member,"token"), Some(json!({"token":field(&invite,"invite_token")}))).await, "accept creator membership");
        member
    }
    async fn mint(&self, creator: &str, expires_in: i64, scoped: bool) -> Token {
        let minted = good(self.session(Method::POST, &format!("/api/apps/{}/tokens", self.app), creator,
            Some(json!({"name":"receipt-reader","env_id":if scoped { self.env.as_str() } else { "" },"expires_in":expires_in,"scopes":"secrets:read"}))).await, "mint static human-owned token");
        Token { id: field(&minted,"id"), value: field(&minted,"token"), expires_at: minted["expires_at"].as_i64().expect("token expiry") }
    }
    async fn delete(&self) {
        good(self.session(Method::DELETE, &format!("/api/envs/{}", self.env), &self.owner, None).await, "delete source through authenticated API");
        assert_eq!(self.raw(Method::GET, &format!("/api/envs/{}/meta", self.env), Some(&self.owner), None).await.status, 404, "source must actually be gone");
    }
    async fn receipt_me(&self, token: &Token) {
        let me = good(self.raw(Method::GET, "/api/me", Some(&token.value), None).await, "deleted environment token retains only a terminal receipt");
        assert_eq!(me, json!({"env_scope":self.env}), "receipt must not disclose an account profile or become an ordinary principal");
    }
    async fn terminal_status(&self, token: &Token, expected: u16) {
        for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", self.env), format!("/api/envs/{}/export?base=1", self.env)] {
            let r = self.raw(Method::GET, &path, Some(&token.value), None).await;
            assert_eq!(r.status, expected, "current receipt admission policy must apply to {path}");
            assert_ne!(r.body["code"], "environment_deleted", "denial must never be a deletion signal");
        }
    }
    fn ordinary_token_count(&self, token: &Token) -> i64 {
        self.db().query_row("SELECT COUNT(*) FROM tokens WHERE id=? OR token_hash=?", params![token.id, openwarp_crypto::hash_token(&token.value)], |r| r.get(0)).expect("inspect ordinary token removal")
    }
}

#[tokio::test]
async fn deleted_environment_receipt_has_minimal_snapshot_and_coded_export_without_ordinary_token() {
    let s = Fixture::start().await;
    let token = s.mint(&s.owner, 600, true).await;
    let live = good(s.raw(Method::GET, &format!("/api/envs/{}/meta", s.env), Some(&token.value), None).await, "live static token control");
    assert_eq!(live["name"], "Development");
    s.delete().await;
    assert_eq!(s.ordinary_token_count(&token), 0, "deletion must still remove the ordinary token row, including its hash");
    s.receipt_me(&token).await;
    let meta = good(s.raw(Method::GET, &format!("/api/envs/{}/meta", s.env), Some(&token.value), None).await, "receipt metadata snapshot");
    assert_eq!(meta, json!({"id":s.env,"name":"Development","app":"receipt-app","workspace":s.workspace}), "only four naming fields survive deletion");
    for query in ["", "?base=1"] {
        let exported = s.raw(Method::GET, &format!("/api/envs/{}/export{query}", s.env), Some(&token.value), None).await;
        assert_eq!(exported.status, 404, "terminal export must preserve the ESO deletion signal");
        assert_eq!(exported.body, json!({"error":"environment deleted","code":"environment_deleted"}));
    }
    let (original, effective): (i64, i64) = s.db().query_row("SELECT original_expires_at,expires_at FROM deleted_env_receipts WHERE token_id=?", [&token.id], |r| Ok((r.get(0)?,r.get(1)?))).expect("inspect admitted receipt expiry");
    assert_eq!(original, token.expires_at);
    assert_eq!(effective, token.expires_at, "a 600-second credential must not gain lifetime on deletion");
}

#[tokio::test]
async fn deleted_receipt_cannot_read_secrets_enumerate_orgs_mint_revoke_or_dispatch_mcp() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    for (method, path, body) in [
        (Method::GET, format!("/api/envs/{}/secrets", s.env), None),
        (Method::GET, format!("/api/envs/{}/secrets", s.other_env), None),
        (Method::GET, "/api/orgs".into(), None),
        (Method::POST, format!("/api/apps/{}/tokens", s.app), Some(json!({"name":"must-not-mint"}))),
        (Method::DELETE, format!("/api/tokens/{}", token.id), None),
        (Method::POST, "/api/auth/step-up/start".into(), Some(json!({"risk":"very_risky"}))),
        (Method::POST, "/mcp".into(), Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))),
    ] { denied(s.raw(method, &path, Some(&token.value), body.as_ref()).await, &path); }
    assert_eq!(s.ordinary_token_count(&token), 0);
}

#[tokio::test]
async fn admitted_receipt_rejects_other_methods_queries_paths_and_environment_ids() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    s.receipt_me(&token).await;
    for (method, path) in [
        (Method::HEAD, "/api/me".to_string()), (Method::POST, "/api/me".into()),
        (Method::HEAD, format!("/api/envs/{}/export", s.env)), (Method::POST, format!("/api/envs/{}/export", s.env)),
        (Method::GET, "/api/me?base=1".into()), (Method::GET, format!("/api/envs/{}/meta?base=1", s.env)),
        (Method::GET, format!("/api/envs/{}/export?base=true", s.env)), (Method::GET, format!("/api/envs/{}/export?base=0", s.env)),
        (Method::GET, format!("/api/envs/{}/export?base=1&base=1", s.env)), (Method::GET, format!("/api/envs/{}/export?base=1&extra=1", s.env)),
        (Method::GET, format!("/api/envs/{}/meta", s.other_env)), (Method::GET, format!("/api/envs/{}/export?base=1", s.other_env)),
        (Method::GET, "/api/not-a-receipt-route".into()),
    ] { assert_eq!(s.raw(method, &path, Some(&token.value), None).await.status, 403, "an admitted terminal receipt must reject {path}"); }
}

#[tokio::test]
async fn receipt_requires_the_original_exact_bearer_not_cookie_hash_or_forgery() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", s.env), format!("/api/envs/{}/export?base=1", s.env)] {
        let cookie = response(s.client.get(format!("{}{path}", s.base)).header("cookie", format!("ow_session={}", token.value))).await;
        assert_eq!(cookie.status, 401, "a receipt cannot be transported as a browser session");
        for invalid in [openwarp_crypto::hash_token(&token.value), format!("{}x", token.value)] {
            assert_eq!(s.raw(Method::GET, &path, Some(&invalid), None).await.status, 401, "only original bearer possession may find a receipt");
        }
        assert_eq!(s.raw(Method::GET, &path, None, None).await.status, 401);
    }
}

#[tokio::test]
async fn receipt_lifetime_is_capped_at_thirty_days_and_expiry_denies_every_terminal_route() {
    let s = Fixture::start().await;
    let permanent = s.mint(&s.owner, 0, true).await; let long = s.mint(&s.owner, 365 * 86400, true).await;
    s.delete().await; s.receipt_me(&permanent).await; s.receipt_me(&long).await;
    for token in [&permanent, &long] {
        let (deleted, effective, original): (i64, i64, i64) = s.db().query_row("SELECT deleted_at,expires_at,original_expires_at FROM deleted_env_receipts WHERE token_id=?", [&token.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).expect("inspect admitted receipt lifetime");
        assert_eq!(original, token.expires_at);
        assert_eq!(effective, deleted + 30 * 86400, "permanent and long-lived tokens both receive only thirty days after deletion");
        assert_eq!(s.db().execute("UPDATE deleted_env_receipts SET expires_at=? WHERE token_id=?", params![now()-1,token.id]).expect("advance private receipt expiry"), 1);
        s.terminal_status(token, 401).await;
    }
}

#[tokio::test]
async fn receipt_is_listed_without_credential_material_and_revocable_by_original_id() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await; s.receipt_me(&token).await;
    let listed = good(s.raw(Method::GET, &format!("/api/apps/{}/tokens", s.app), Some(&s.owner), None).await, "ordinary administration lists retained receipt");
    let entry = listed.as_array().expect("token list").iter().find(|v| v["id"] == token.id).expect("original token id remains administrable");
    assert_eq!(entry["kind"], "deleted_env_receipt", "terminal status must not be advertised as a live service credential");
    for key in ["token", "token_hash", "email", "pubkey", "wrapped_privkey"] { assert!(entry.get(key).is_none(), "receipt administration must omit {key}"); }
    good(s.session(Method::DELETE, &format!("/api/tokens/{}", token.id), &s.owner, None).await, "revoke receipt by original token id");
    s.terminal_status(&token, 401).await;
    assert_eq!(s.ordinary_token_count(&token), 0);
}

#[tokio::test]
async fn deactivated_or_unverified_creator_cannot_obtain_any_receipt_response() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    for column in ["active", "email_verified"] {
        assert_eq!(s.db().execute(&format!("UPDATE users SET {column}=0 WHERE id=?"), [&s.owner_id]).expect("disable private creator state"), 1);
        s.terminal_status(&token, 401).await;
        assert_eq!(s.db().execute(&format!("UPDATE users SET {column}=1 WHERE id=?"), [&s.owner_id]).expect("restore private creator state"), 1);
    }
}

#[tokio::test]
async fn locked_creator_membership_denies_receipt_and_unlock_restores_only_the_receipt() {
    let s = Fixture::start().await; let member = s.member().await; let member_id = field(&member,"user_id");
    let token = s.mint(&field(&member,"token"), 600, true).await; s.delete().await;
    good(s.session(Method::POST, &format!("/api/orgs/{}/members/{member_id}/lock", s.org), &s.owner, None).await, "lock receipt creator membership");
    for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", s.env), format!("/api/envs/{}/export?base=1", s.env)] { denied(s.raw(Method::GET, &path, Some(&token.value), None).await, "locked creator receipt"); }
    good(s.session(Method::POST, &format!("/api/orgs/{}/members/{member_id}/unlock", s.org), &s.owner, None).await, "unlock receipt creator membership");
    s.receipt_me(&token).await; assert_eq!(s.ordinary_token_count(&token), 0);
}

#[tokio::test]
async fn removed_creator_membership_cannot_use_a_receipt_even_while_the_account_is_active() {
    let s = Fixture::start().await; let member = s.member().await; let member_id = field(&member,"user_id");
    let token = s.mint(&field(&member,"token"), 600, true).await; s.delete().await;
    good(s.session(Method::DELETE, &format!("/api/orgs/{}/members/{member_id}", s.org), &s.owner, None).await, "remove creator membership");
    for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", s.env), format!("/api/envs/{}/export?base=1", s.env)] { denied(s.raw(Method::GET, &path, Some(&token.value), None).await, "removed creator receipt"); }
    assert_eq!(s.db().query_row("SELECT active FROM users WHERE id=?", [member_id], |r| r.get::<_,i64>(0)).expect("creator remains active"), 1);
}

#[tokio::test]
async fn current_read_permission_is_required_even_after_environment_deletion() {
    let s = Fixture::start().await; let member = s.member().await; let member_id = field(&member,"user_id");
    let token = s.mint(&field(&member,"token"), 600, true).await; s.delete().await;
    good(s.session(Method::POST, &format!("/api/orgs/{}/roles", s.org), &s.owner, Some(json!({"name":"no-read","permissions":[]}))).await, "create no-read role");
    good(s.session(Method::PATCH, &format!("/api/orgs/{}/members/{member_id}", s.org), &s.owner, Some(json!({"role":"no-read"}))).await, "remove creator read permission");
    for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", s.env), format!("/api/envs/{}/export?base=1", s.env)] { denied(s.raw(Method::GET, &path, Some(&token.value), None).await, "creator without read permission"); }
}

#[tokio::test]
async fn receipt_checks_surviving_workspace_ip_policy_and_ignores_untrusted_forwarded_ip() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    good(s.session(Method::PUT, &format!("/api/orgs/{}/settings", s.org), &s.owner, Some(json!({"ip_allowlist":"192.0.2.0/24"}))).await, "restrict surviving workspace source IP");
    for path in ["/api/me".to_string(), format!("/api/envs/{}/meta", s.env), format!("/api/envs/{}/export?base=1", s.env)] {
        denied(s.raw(Method::GET, &path, Some(&token.value), None).await, "blocked peer receipt");
        denied(response(s.client.get(format!("{}{path}", s.base)).bearer_auth(&token.value).header("x-forwarded-for","192.0.2.9")).await, "untrusted forwarded peer receipt");
    }
}

#[tokio::test]
async fn project_and_workspace_emergency_policy_deny_receipts_before_any_terminal_response() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    for path in [format!("/api/apps/{}/emergency", s.app), format!("/api/orgs/{}/emergency", s.org)] {
        good(response(s.client.put(format!("{}{path}", s.base)).header("cookie",format!("ow_session={}",s.owner)).header("origin",&s.base).json(&json!({"locked":true}))).await, "owner activates emergency policy");
        for target in ["/api/me".to_string(), format!("/api/envs/{}/meta", s.env), format!("/api/envs/{}/export?base=1", s.env)] { denied(s.raw(Method::GET, &target, Some(&token.value), None).await, "emergency policy receipt denial"); }
        good(response(s.client.put(format!("{}{path}", s.base)).header("cookie",format!("ow_session={}",s.owner)).header("origin",&s.base).json(&json!({"locked":false}))).await, "owner restores emergency policy");
    }
}

#[tokio::test]
async fn only_live_static_human_owned_environment_tokens_are_eligible_for_receipts() {
    let s = Fixture::start().await;
    let identity = good(s.session(Method::POST, &format!("/api/orgs/{}/identities", s.org), &s.owner, Some(json!({"name":"receipt-machine","role":"developer"}))).await, "create machine identity exclusion control");
    let mut excluded = Vec::new();
    for class in ["machine", "workload", "trust-linked", "revision-linked", "identity-owned", "expired", "revoked"] {
        let token = s.mint(&s.owner, 600, true).await;
        let db = s.db();
        let changed = match class {
            "machine" | "workload" => db.execute("UPDATE tokens SET kind=? WHERE id=?", params![class,token.id]),
            "trust-linked" => db.execute("UPDATE tokens SET trust_id='private-trust' WHERE id=?", [&token.id]),
            "revision-linked" => db.execute("UPDATE tokens SET workload_revision='private-revision' WHERE id=?", [&token.id]),
            "identity-owned" => db.execute("UPDATE tokens SET created_by=? WHERE id=?", params![field(&identity,"id"),token.id]),
            "expired" => db.execute("UPDATE tokens SET expires_at=? WHERE id=?", params![now()-1,token.id]),
            "revoked" => { good(s.session(Method::DELETE, &format!("/api/tokens/{}",token.id), &s.owner, None).await, "revoke before deletion"); excluded.push((class,token)); continue; },
            _ => unreachable!(),
        }.expect("set private excluded token class");
        assert_eq!(changed, 1); excluded.push((class,token));
    }
    let unscoped = s.mint(&s.owner, 600, false).await;
    s.delete().await;
    for (class, token) in excluded { assert_eq!(s.ordinary_token_count(&token), 0, "deletion removes excluded {class} ordinary token"); s.terminal_status(&token, 401).await; }
    assert_eq!(s.ordinary_token_count(&unscoped), 1, "unscoped application token is not converted into a terminal receipt");
    let me = good(s.raw(Method::GET, "/api/me", Some(&unscoped.value), None).await, "unscoped live credential survives unrelated source deletion");
    assert_eq!(me["id"], s.owner_id, "unscoped token remains governed by ordinary authentication");
}

#[tokio::test]
async fn failed_guarded_deletion_keeps_live_token_and_never_resurrects_a_previously_revoked_token() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await;
    s.db().execute("INSERT INTO leases(id,env_id,name,value_enc,expires_at,revoked,created_at) VALUES('receipt-delete-blocker',?,'fixture-unresolved','',?,0,?)", params![s.env,now()+3600,now()]).expect("insert unresolved private lease");
    assert_eq!(s.session(Method::DELETE, &format!("/api/envs/{}",s.env), &s.owner, None).await.status, 409, "unresolved lease must abort the whole deletion");
    assert_eq!(s.ordinary_token_count(&token), 1);
    let me = good(s.raw(Method::GET, "/api/me", Some(&token.value), None).await, "failed deletion preserves ordinary authentication");
    assert_eq!(me["id"],s.owner_id);
    let exported = good(s.raw(Method::GET, &format!("/api/envs/{}/export?base=1",s.env), Some(&token.value), None).await, "failed deletion preserves live export");
    assert!(exported["secrets"].as_array().expect("live export secrets").iter().any(|v| v["key"] == "RECEIPT_SECRET"));
    good(s.session(Method::DELETE, &format!("/api/tokens/{}",token.id), &s.owner, None).await, "revoke token after refused deletion");
    s.db().execute("DELETE FROM leases WHERE id='receipt-delete-blocker'", []).expect("resolve private deletion blocker");
    s.delete().await; s.terminal_status(&token, 401).await;
}

#[tokio::test]
async fn recreated_environment_and_renamed_parents_cannot_rebind_the_deleted_snapshot() {
    let s = Fixture::start().await; let token = s.mint(&s.owner, 600, true).await; s.delete().await;
    let new_env = good(s.session(Method::POST, &format!("/api/apps/{}/envs",s.app), &s.owner, Some(json!({"name":"Development"}))).await, "recreate same environment name");
    let new_env = field(&new_env,"id"); assert_ne!(new_env,s.env);
    good(s.session(Method::PUT, &format!("/api/envs/{new_env}/secrets"), &s.owner, Some(json!({"secrets":[{"key":"NEW_ENV_SECRET","value":"replacement-private-value"}]}))).await, "write replacement environment control");
    good(s.session(Method::PATCH, &format!("/api/apps/{}",s.app), &s.owner, Some(json!({"name":"renamed-app"}))).await, "rename surviving application");
    good(s.session(Method::PATCH, &format!("/api/orgs/{}",s.org), &s.owner, Some(json!({"name":"renamed-workspace"}))).await, "rename surviving workspace");
    s.receipt_me(&token).await;
    let meta = good(s.raw(Method::GET, &format!("/api/envs/{}/meta",s.env), Some(&token.value), None).await, "old receipt retains deletion-time names");
    assert_eq!(meta,json!({"id":s.env,"name":"Development","app":"receipt-app","workspace":s.workspace}));
    assert_eq!(s.raw(Method::GET, &format!("/api/envs/{}/export?base=1",s.env), Some(&token.value), None).await.status,404);
    for suffix in ["meta","export?base=1","secrets"] { assert_eq!(s.raw(Method::GET,&format!("/api/envs/{new_env}/{suffix}"),Some(&token.value),None).await.status,403,"receipt must not gain authority over a new environment with the old name"); }
}
