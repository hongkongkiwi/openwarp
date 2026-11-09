// Console administration HTTP contracts: browser session management, app
// metadata patches and per-integration sync history. Each test owns a private
// database and email inbox; no outbound network calls are made.

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
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp {
    status: u16,
    text: String,
    body: Value,
    headers: reqwest::header::HeaderMap,
}

struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
    inbox: Arc<Mutex<Vec<Value>>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    // True ephemeral: the OS never hands out a port that is still bound, so
    // parallel test binaries cannot converge the way a PID-derived scan
    // does. The only residual hazard is the gap between dropping this
    // listener and the child binding it, which the startup retry covers.
    TcpListener::bind("127.0.0.1:0").expect("ephemeral port").local_addr().expect("local addr").port()
}

impl Server {
    async fn start() -> Server {
        let _start = START_LOCK.lock().await;
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-ui-admin-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let (inbox_url, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", &inbox_url)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_SIGNUPS")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().expect("http client");
        let server = Server { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { drop(_start); return Box::pin(Server::start()).await; }
        panic!("server did not become healthy at {}", server.base);
    }

    fn url(&self, path: &str) -> String { format!("{}{}", self.base, path) }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        self.finish(req).await
    }

    async fn call_cookie(&self, method: Method, path: &str, cookie: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path)).header("cookie", cookie);
        if let Some(b) = body { req = req.json(&b); }
        self.finish(req).await
    }

    async fn finish(&self, req: reqwest::RequestBuilder) -> Resp {
        let response = req.send().await.expect("http request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }

    async fn get(&self, path: &str) -> Resp { self.call(Method::GET, path, None, None).await }
}

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

fn session_cookie(resp: &Resp) -> String {
    for header in resp.headers.get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()) {
        if let Some(pair) = header.split(';').next() {
            if pair.starts_with("ow_session=") && pair.len() > "ow_session=".len() { return pair.to_string(); }
        }
    }
    panic!("no ow_session cookie in response headers: {}", resp.text);
}

async fn register(s: &Server, email: &str) -> Resp {
    let reg = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(reg.status, 200, "registration failed: {}", reg.text);
    assert_eq!(reg.body["verification_required"], json!(true), "verification is required: {}", reg.text);
    let text = wait_for_mail(&s.inbox, "/api/auth/verify?token=").await;
    let link = extract_link(&text, "/api/auth/verify?token=");
    let path = link.strip_prefix(&s.base).unwrap_or(&link).to_string();
    let verified = s.get(&path).await;
    assert_eq!(verified.status, 200, "verification link failed: {}", verified.text);
    let signin = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(signin.status, 200, "sign-in after verification failed: {}", signin.text);
    let mut body = reg.body.clone();
    for key in ["token", "user_id", "public_key"] { body[key] = signin.body[key].clone(); }
    Resp { status: signin.status, text: signin.text, body, headers: signin.headers }
}

async fn login(s: &Server, email: &str) -> Resp {
    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "login failed: {}", r.text);
    r
}

async fn create_app(s: &Server, token: &str, org: &str, name: &str) -> String {
    let app = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": name}))).await;
    assert_eq!(app.status, 200, "app creation failed: {}", app.text);
    app.body["id"].as_str().expect("app id").to_string()
}

async fn first_env(s: &Server, token: &str, app: &str) -> String {
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(token), None).await;
    assert_eq!(envs.status, 200, "listing environments failed: {}", envs.text);
    envs.body[0]["id"].as_str().expect("environment id").to_string()
}

#[tokio::test]
async fn browser_sessions_list_revoke_and_stay_inside_the_account() {
    let s = Server::start().await;
    let owner = register(&s, "sessions-owner@test.invalid").await;
    let cookie_one = session_cookie(&owner);
    let second = login(&s, "sessions-owner@test.invalid").await;
    let cookie_two = session_cookie(&second);

    let listed = s.call_cookie(Method::GET, "/api/me/sessions", &cookie_one, None).await;
    assert_eq!(listed.status, 200, "listing sessions failed: {}", listed.text);
    let rows = listed.body.as_array().expect("session array");
    assert_eq!(rows.len(), 2, "both browser sessions are listed: {}", listed.text);
    let current: Vec<&Value> = rows.iter().filter(|r| r["current"] == json!(true)).collect();
    assert_eq!(current.len(), 1, "exactly one session is current");
    let other_id = rows.iter().find(|r| r["current"] == json!(false)).and_then(|r| r["id"].as_str()).expect("a second session id").to_string();

    let revoked = s.call_cookie(Method::DELETE, &format!("/api/me/sessions/{}", other_id), &cookie_one, None).await;
    assert_eq!(revoked.status, 200, "revoking a sibling session failed: {}", revoked.text);
    assert_eq!(revoked.body["current"], json!(false));
    let ended = s.call_cookie(Method::GET, "/api/me", &cookie_two, None).await;
    assert_eq!(ended.status, 401, "the revoked browser session must be dead: {} {}", ended.status, ended.text);

    let stranger = register(&s, "sessions-stranger@test.invalid").await;
    let stranger_cookie = session_cookie(&stranger);
    let remaining = s.call_cookie(Method::GET, "/api/me/sessions", &cookie_one, None).await;
    let survivor = remaining.body[0]["id"].as_str().expect("surviving session id").to_string();
    let denied = s.call_cookie(Method::DELETE, &format!("/api/me/sessions/{}", survivor), &stranger_cookie, None).await;
    assert_eq!(denied.status, 404, "another account must not learn the session exists: {} {}", denied.status, denied.text);
    let stranger_rows = s.call_cookie(Method::GET, "/api/me/sessions", &stranger_cookie, None).await;
    assert_eq!(stranger_rows.body.as_array().map(Vec::len), Some(1), "the stranger sees only its own session: {}", stranger_rows.text);
}

#[tokio::test]
async fn ending_every_session_needs_a_session_credential() {
    let s = Server::start().await;
    let first = register(&s, "all-sessions@test.invalid").await;
    let cookie_one = session_cookie(&first);
    let cookie_two = session_cookie(&login(&s, "all-sessions@test.invalid").await);

    let ended = s.call_cookie(Method::DELETE, "/api/me/sessions", &cookie_one, None).await;
    assert_eq!(ended.status, 200, "ending all sessions failed: {}", ended.text);
    assert!(ended.body["revoked"].as_u64().unwrap_or(0) >= 2, "both sessions are revoked: {}", ended.text);
    for cookie in [&cookie_one, &cookie_two] {
        let me = s.call_cookie(Method::GET, "/api/me", cookie, None).await;
        assert_eq!(me.status, 401, "every browser cookie is invalidated: {} {}", me.status, me.text);
    }

    let again = login(&s, "all-sessions@test.invalid").await;
    let cookie = session_cookie(&again);
    let token = again.body["token"].as_str().expect("session token").to_string();
    let org = again.body["org_id"].as_str().unwrap_or(first.body["org_id"].as_str().expect("org id")).to_string();
    let app = create_app(&s, &token, &org, "Payments").await;
    let pat = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(token.as_str()), Some(json!({"name": "ci", "scopes": "secrets:read"}))).await;
    assert_eq!(pat.status, 200, "PAT creation failed: {}", pat.text);
    let pat_token = pat.body["token"].as_str().expect("token value").to_string();
    let refused = s.call(Method::DELETE, "/api/me/sessions", Some(pat_token.as_str()), None).await;
    assert_eq!(refused.status, 403, "a PAT must not end browser sessions: {} {}", refused.status, refused.text);
    let still_listed = s.call_cookie(Method::GET, "/api/me/sessions", &cookie, None).await;
    assert_eq!(still_listed.status, 200, "the refused call revokes nothing: {}", still_listed.text);
}

#[tokio::test]
async fn app_metadata_patch_edits_name_and_readme_and_audits_lengths() {
    let s = Server::start().await;
    let owner = register(&s, "app-meta@test.invalid").await;
    let token = owner.body["token"].as_str().expect("token").to_string();
    let org = owner.body["org_id"].as_str().expect("org").to_string();
    let app = create_app(&s, &token, &org, "Payments").await;
    let readme = "Owner: platform team. Runbook: docs/payments.md";

    let patched = s.call(Method::PATCH, &format!("/api/apps/{}", app), Some(token.as_str()), Some(json!({"readme": readme}))).await;
    assert_eq!(patched.status, 200, "readme patch failed: {}", patched.text);
    let apps = s.call(Method::GET, &format!("/api/orgs/{}/apps", org), Some(token.as_str()), None).await;
    assert_eq!(apps.body[0]["readme"], json!(readme), "the readme is stored verbatim: {}", apps.text);

    let renamed = s.call(Method::PATCH, &format!("/api/apps/{}", app), Some(token.as_str()), Some(json!({"name": "Payments API"}))).await;
    assert_eq!(renamed.status, 200, "rename failed: {}", renamed.text);
    let apps = s.call(Method::GET, &format!("/api/orgs/{}/apps", org), Some(token.as_str()), None).await;
    assert_eq!(apps.body[0]["name"], json!("Payments API"));
    assert_eq!(apps.body[0]["readme"], json!(readme), "renaming must not clear the readme");

    let empty = s.call(Method::PATCH, &format!("/api/apps/{}", app), Some(token.as_str()), Some(json!({}))).await;
    assert_eq!(empty.status, 400, "an empty patch is rejected: {} {}", empty.status, empty.text);

    let audit = s.call(Method::GET, &format!("/api/orgs/{}/audit?limit=200", org), Some(token.as_str()), None).await;
    let rows = audit.body.as_array().expect("audit array");
    let readme_row = rows.iter().find(|r| r["action"] == json!("app.readme")).expect("app.readme audit row");
    assert_eq!(readme_row["detail"], json!(format!("{} bytes", readme.len())), "the audit records only the length");
    assert!(!audit.text.contains(readme), "the readme content must not enter the audit log");
    let rename_row = rows.iter().find(|r| r["action"] == json!("app.rename")).expect("app.rename audit row");
    assert_eq!(rename_row["detail"], json!("Payments API"));
}

#[tokio::test]
async fn integration_history_returns_only_that_integrations_attempts() {
    let s = Server::start().await;
    let owner = register(&s, "sync-history@test.invalid").await;
    let token = owner.body["token"].as_str().expect("token").to_string();
    let org = owner.body["org_id"].as_str().expect("org").to_string();
    let app = create_app(&s, &token, &org, "Payments").await;
    let env = first_env(&s, &token, &app).await;

    // An invalid initial_sync makes the sync fail before any provider call.
    let bad = json!({"initial_sync": "not-a-mode"});
    let mut ids = Vec::new();
    for name in ["first", "second"] {
        let created = s.call(Method::POST, &format!("/api/envs/{}/integrations", env), Some(token.as_str()), Some(json!({"kind": "webhook", "name": name, "config": bad}))).await;
        assert_eq!(created.status, 200, "integration creation failed: {}", created.text);
        let iid = created.body["id"].as_str().expect("integration id").to_string();
        let failed = s.call(Method::POST, &format!("/api/integrations/{}/sync", iid), Some(token.as_str()), Some(json!({}))).await;
        assert_eq!(failed.status, 400, "the invalid config must fail the sync: {} {}", failed.status, failed.text);
        ids.push(iid);
    }

    let history = s.call(Method::GET, &format!("/api/integrations/{}/history", ids[0]), Some(token.as_str()), None).await;
    assert_eq!(history.status, 200, "history failed: {}", history.text);
    let rows = history.body.as_array().expect("history array");
    assert_eq!(rows.len(), 1, "exactly the first integration's attempt is returned: {}", history.text);
    assert_eq!(rows[0]["action"], json!("integration.sync_failed"));
    let detail = rows[0]["detail"].as_str().expect("detail");
    assert!(detail.starts_with(&format!("{}: ", ids[0])), "the detail is bound to its integration: {}", detail);
    assert!(!detail.contains(&ids[1]), "the other integration's attempt must not leak in: {}", detail);

    let unknown = s.call(Method::GET, "/api/integrations/does-not-exist/history", Some(token.as_str()), None).await;
    assert_eq!(unknown.status, 404, "an unknown integration is not found: {} {}", unknown.status, unknown.text);

    let stranger = register(&s, "sync-stranger@test.invalid").await;
    let stranger_token = stranger.body["token"].as_str().expect("stranger token").to_string();
    let denied = s.call(Method::GET, &format!("/api/integrations/{}/history", ids[0]), Some(stranger_token.as_str()), None).await;
    assert_eq!(denied.status, 403, "another workspace cannot read the history: {} {}", denied.status, denied.text);
}
