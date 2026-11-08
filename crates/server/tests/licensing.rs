// Edition gating: core stays available without a key, enterprise routes return
// the stable 403 body, a signed or development license unlocks them, and an
// invalid or production-rejected key falls back to self-hosted.
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

struct Resp {
    status: u16,
    text: String,
    body: Value,
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
    let base = 24000 + (std::process::id() % 18000) as u16;
    for offset in 0..500u16 {
        let port = base.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            return port;
        }
    }
    TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port").local_addr().expect("local addr").port()
}

impl Server {
    async fn start(extra: &[(&str, &str)]) -> Server {
        let _start = START_LOCK.lock().await;
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-licensing-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let (inbox_url, inbox) = start_inbox();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", &inbox_url)
            .env("TOKIO_WORKER_THREADS", "2")
            .env("OPENWARP_LICENSE", "none")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_SIGNUPS")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in extra { cmd.env(key, value); }
        let child = cmd.spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().expect("http client");
        let server = Server { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(60);
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
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body }
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

async fn register(s: &Server, email: &str) -> Resp {
    let reg = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(reg.status, 200, "registration failed: {}", reg.text);
    let text = wait_for_mail(&s.inbox, "/api/auth/verify?token=").await;
    let link = extract_link(&text, "/api/auth/verify?token=");
    let path = link.strip_prefix(&s.base).unwrap_or(&link).to_string();
    let verified = s.get(&path).await;
    assert_eq!(verified.status, 200, "verification failed: {}", verified.text);
    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 200, "login failed: {}", login.text);
    let mut body = reg.body;
    for key in ["token", "user_id", "public_key"] { body[key] = login.body[key].clone(); }
    Resp { status: login.status, text: login.text, body }
}

async fn app(s: &Server, token: &str, org: &str) -> String {
    let created = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": "Payments"}))).await;
    assert_eq!(created.status, 200, "app creation failed: {}", created.text);
    created.body["id"].as_str().expect("app id").to_string()
}

#[tokio::test]
async fn self_hosted_keeps_core_and_locks_every_enterprise_route() {
    let s = Server::start(&[]).await;
    let owner = register(&s, "self-hosted@test.invalid").await;
    let token = owner.body["token"].as_str().expect("token").to_string();
    let org = owner.body["org_id"].as_str().expect("org").to_string();
    let app = app(&s, &token, &org).await;

    let edition = s.call(Method::GET, "/api/instance/edition", Some(&token), None).await;
    assert_eq!(edition.status, 200, "edition status failed: {}", edition.text);
    assert_eq!(edition.body["tier"], json!("self-hosted"));
    assert_eq!(edition.body["enterprise"], json!(false));

    let core = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(&token), None).await;
    assert_eq!(core.status, 200, "core features do not consult the license: {}", core.text);

    for (compiled, feature, path, license_feature) in [
        (cfg!(feature = "saml"), "saml", format!("/api/orgs/{}/saml", org), "org_sso"),
        (cfg!(feature = "ldap"), "ldap", format!("/api/orgs/{}/ldap", org), "directory_sync"),
        (cfg!(feature = "scim"), "scim", format!("/scim/v2/Users?org_id={}", org), "directory_sync"),
    ] {
        if compiled {
            let grant = s.call(Method::PUT, "/api/instance/features", Some(&token), Some(json!({"org": org, "features": [feature]}))).await;
            assert_eq!(grant.status, 200, "grant failed: {}", grant.text);
        }
        let response = s.call(Method::GET, &path, Some(&token), None).await;
        assert_eq!(response.status, if compiled { 403 } else { 404 }, "{}: {}", feature, response.text);
        if compiled {
            assert_eq!(response.body["code"], json!("enterprise_feature"));
            assert_eq!(response.body["feature"], json!(license_feature));
        }
    }

    let oidc = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(&token), Some(json!({"oidc_issuer": "https://idp.example"}))).await;
    assert_eq!(oidc.status, 403, "workspace OIDC is enterprise: {} {}", oidc.status, oidc.text);
    assert_eq!(oidc.body["feature"], json!("org_oidc"));

    let stream = s.call(Method::POST, &format!("/api/orgs/{}/log-streams", org), Some(&token), Some(json!({"name": "SIEM", "url": "https://example.com/hook"}))).await;
    assert_eq!(stream.status, 403, "log streams are enterprise: {} {}", stream.status, stream.text);
    assert_eq!(stream.body["feature"], json!("audit_streaming"));

    let core_settings = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(&token), Some(json!({"ip_allowlist": "203.0.113.0/24"}))).await;
    assert_eq!(core_settings.status, 200, "core settings still save: {}", core_settings.text);
}

#[tokio::test]
async fn enterprise_license_unlocks_the_same_routes() {
    let s = Server::start(&[("OPENWARP_LICENSE", "development")]).await;
    let owner = register(&s, "enterprise@test.invalid").await;
    let token = owner.body["token"].as_str().expect("token").to_string();
    let org = owner.body["org_id"].as_str().expect("org").to_string();

    let edition = s.call(Method::GET, "/api/instance/edition", Some(&token), None).await;
    assert_eq!(edition.status, 200, "edition status failed: {}", edition.text);
    assert_eq!(edition.body["tier"], json!("enterprise"));
    assert_eq!(edition.body["development"], json!(true));

    for (compiled, feature, path) in [
        (cfg!(feature = "saml"), "saml", format!("/api/orgs/{}/saml", org)),
        (cfg!(feature = "ldap"), "ldap", format!("/api/orgs/{}/ldap", org)),
        (cfg!(feature = "scim"), "scim", format!("/scim/v2/Users?org_id={}", org)),
    ] {
        if compiled {
            let denied = s.call(Method::GET, &path, Some(&token), None).await;
            assert_eq!(denied.status, 403, "a license alone cannot grant {}: {}", feature, denied.text);
            let grant = s.call(Method::PUT, "/api/instance/features", Some(&token), Some(json!({"org": org, "features": [feature]}))).await;
            assert_eq!(grant.status, 200, "grant failed: {}", grant.text);
        }
        let response = s.call(Method::GET, &path, Some(&token), None).await;
        assert_eq!(response.status, if compiled { 200 } else { 404 }, "a license cannot conjure an uncompiled {} route: {}", feature, response.text);
        if compiled && feature != "scim" { assert_eq!(response.body["configured"], json!(false)); }
    }

    let oidc = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(&token), Some(json!({"oidc_issuer": "https://idp.example"}))).await;
    assert_eq!(oidc.status, 200, "workspace OIDC saves with a license: {}", oidc.text);

    let stream = s.call(Method::POST, &format!("/api/orgs/{}/log-streams", org), Some(&token), Some(json!({"name": "SIEM", "url": "https://example.com/hook"}))).await;
    assert_eq!(stream.status, 200, "log streams unlock with a license: {}", stream.text);

    let member = register(&s, "enterprise-member@test.invalid").await;
    let member_token = member.body["token"].as_str().expect("member token").to_string();
    let member_edition = s.call(Method::GET, "/api/instance/edition", Some(&member_token), None).await;
    assert_eq!(member_edition.body["tier"], json!("enterprise"));
    assert!(member_edition.body.get("customer").is_none(), "only the instance owner sees the licensed customer: {}", member_edition.text);
    assert!(member_edition.body.get("expires_at").is_none(), "only the instance owner sees the expiry: {}", member_edition.text);
}

#[tokio::test]
async fn an_invalid_license_falls_back_to_self_hosted() {
    let s = Server::start(&[("OPENWARP_LICENSE", "not-a-license")]).await;
    let owner = register(&s, "invalid-license@test.invalid").await;
    let token = owner.body["token"].as_str().expect("token").to_string();
    let org = owner.body["org_id"].as_str().expect("org").to_string();
    let edition = s.call(Method::GET, "/api/instance/edition", Some(&token), None).await;
    assert_eq!(edition.status, 200);
    assert_eq!(edition.body["tier"], json!("self-hosted"));
    assert!(edition.body["warning"].as_str().unwrap_or("").contains("license"), "the rejection reason is reported: {}", edition.text);
    let saml = s.call(Method::GET, &format!("/api/orgs/{}/saml", org), Some(&token), None).await;
    assert_eq!(saml.status, if cfg!(feature = "saml") { 403 } else { 404 });
    if cfg!(feature = "saml") {
        assert_eq!(saml.body["code"], json!("enterprise_feature"));
        assert_eq!(saml.body["feature"], json!("org_sso"));
    }
}

#[tokio::test]
async fn a_development_license_is_rejected_by_production_configuration() {
    let s = Server::start(&[("OPENWARP_ENV", "production"), ("OPENWARP_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), ("OPENWARP_LICENSE", "development")]).await;
    let owner = register(&s, "production@test.invalid").await;
    let token = owner.body["token"].as_str().expect("token").to_string();
    let edition = s.call(Method::GET, "/api/instance/edition", Some(&token), None).await;
    assert_eq!(edition.status, 200);
    assert_eq!(edition.body["tier"], json!("self-hosted"), "production must ignore the development key: {}", edition.text);
}
