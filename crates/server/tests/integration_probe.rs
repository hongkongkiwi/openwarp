use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
struct Resp { status: u16, body: Value, text: String }
struct Server { child: Child, dir: PathBuf, base: String, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-probe-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mail_url = format!("http://{}/mail", listener.local_addr().unwrap());
        let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { break }; let mut buf = Vec::new(); let mut chunk = [0; 8192];
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 { break; } buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]);
                        let len = head.lines().find_map(|l| { let (k,v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                        if buf.len() >= end + 4 + len { if let Ok(v) = serde_json::from_slice(&buf[end+4..end+4+len]) { sink.lock().unwrap().push(v); } break; }
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            }
        });
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars().filter(|(k,_)| k.starts_with("OPENWARP_") || k.ends_with("_PROXY") || k == "REDIS_URL") { cmd.env_remove(key); }
        let child = cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", format!("127.0.0.1:{port}"))
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", mail_url).env("TOKIO_WORKER_THREADS", "1")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let s = Self { child, dir, base, client, inbox }; let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline { if s.client.get(format!("{}/health", s.base)).send().await.is_ok_and(|r| r.status().is_success()) { return s; } tokio::time::sleep(Duration::from_millis(100)).await; }
        panic!("private probe test server did not start");
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = req.bearer_auth(token); }
        if let Some(v) = body { req = req.json(&v); }
        finish(req.send().await.unwrap()).await
    }
    async fn register(&self, email: &str) -> Value {
        let r = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(r.status, 200, "account registration: {}", r.text); let mut user = r.body;
        let deadline = Instant::now() + Duration::from_secs(10);
        let link = loop {
            let found = self.inbox.lock().unwrap().iter().rev().filter(|v| v.to_string().contains(email)).find_map(|v| v["text"].as_str().and_then(|t| t.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string()))));
            if let Some(link) = found { break link; } assert!(Instant::now() < deadline, "verification mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(self.call(Method::GET, &link, "", None).await.status, 200);
        let login = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(login.status, 200); user["token"] = login.body["token"].clone(); user
    }
}
async fn finish(r: reqwest::Response) -> Resp { let status = r.status().as_u16(); let text = r.text().await.unwrap(); let body = serde_json::from_str(&text).unwrap_or(Value::Null); Resp { status, body, text } }
fn id(v: &Value, key: &str) -> String { v[key].as_str().unwrap_or_else(|| panic!("missing {key}")).to_string() }

async fn suite() -> (Server, String, String) {
    let s = Server::start().await;
    let u = s.register("owner@probe.test.invalid").await;
    let token = id(&u, "token");
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", id(&u, "org_id")), &token, Some(json!({"name": "probe"}))).await;
    assert_eq!(r.status, 200, "create app: {}", r.text); let app = id(&r.body, "id");
    let r = s.call(Method::GET, &format!("/api/apps/{app}/envs"), &token, None).await;
    assert_eq!(r.status, 200, "list envs: {}", r.text);
    (s, token, id(&r.body[0], "id"))
}
async fn make_integration(s: &Server, token: &str, env: &str, kind: &str, config: Value) -> String {
    let r = s.call(Method::POST, &format!("/api/envs/{env}/integrations"), token, Some(json!({"kind": kind, "name": "probe-target", "config": config}))).await;
    assert_eq!(r.status, 200, "create integration: {}", r.text);
    id(&r.body, "id")
}

#[tokio::test]
async fn probe_reaches_a_local_target_and_reports_http_status() {
    let (s, token, env) = suite().await;
    let iid = make_integration(&s, &token, &env, "webhook", json!({"url": format!("{}/health", s.base)})).await;
    let r = s.call(Method::POST, &format!("/api/integrations/{iid}/test"), &token, None).await;
    assert_ne!(r.status, 501, "no kind may answer 501: {}", r.text);
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["ok"], json!(true));
    let detail = r.body["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("HTTP 200"), "detail: {detail}");
    assert!(detail.contains("credentials are not verified"), "detail: {detail}");
}

#[tokio::test]
async fn probe_reports_an_unreachable_endpoint() {
    let (s, token, env) = suite().await;
    let iid = make_integration(&s, &token, &env, "webhook", json!({"url": "http://127.0.0.1:1/hook"})).await;
    let r = s.call(Method::POST, &format!("/api/integrations/{iid}/test"), &token, None).await;
    assert_ne!(r.status, 501);
    assert_eq!(r.status, 400, "{}", r.text);
    assert!(r.body["error"].as_str().unwrap_or_default().contains("unreachable"), "{}", r.text);
}

#[tokio::test]
async fn probe_unreachable_error_redacts_url_secrets_from_the_entire_body() {
    let (s, token, env) = suite().await;
    // A bound socket without a listener reserves a local port that refuses connections.
    let target = tokio::net::TcpSocket::new_v4().unwrap(); target.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let sentinels = ["probe-user-sentinel", "probe-password-sentinel", "probe-path-sentinel", "probe-query-sentinel"];
    let url = format!("http://{}:{}@{}/{}?token={}", sentinels[0], sentinels[1], target.local_addr().unwrap(), sentinels[2], sentinels[3]);
    let iid = make_integration(&s, &token, &env, "webhook", json!({"url": url})).await;
    let r = s.call(Method::POST, &format!("/api/integrations/{iid}/test"), &token, None).await;
    assert_eq!(r.status, 400, "{}", r.text);
    assert!(r.body["error"].as_str().unwrap_or_default().contains("unreachable"), "{}", r.text);
    let leaked: Vec<_> = sentinels.iter().filter(|secret| r.text.contains(**secret)).collect();
    assert!(leaked.is_empty(), "URL secrets {leaked:?} leaked in response: {}", r.text);
}

#[tokio::test]
async fn probe_malformed_url_error_redacts_secrets_from_the_entire_body() {
    let (s, token, env) = suite().await;
    let sentinels = ["invalid-user-sentinel", "invalid-password-sentinel", "invalid-path-sentinel", "invalid-query-sentinel"];
    let url = format!("http://{}:{}@127.0.0.1:invalid-port/{}?token={}", sentinels[0], sentinels[1], sentinels[2], sentinels[3]);
    let iid = make_integration(&s, &token, &env, "webhook", json!({"url": url})).await;
    let r = s.call(Method::POST, &format!("/api/integrations/{iid}/test"), &token, None).await;
    assert_eq!(r.status, 400, "{}", r.text);
    let error = r.body["error"].as_str().unwrap_or_default();
    assert!(error.contains("invalid") || error.contains("unreachable"), "{}", r.text);
    let leaked: Vec<_> = sentinels.iter().filter(|secret| r.text.contains(**secret)).collect();
    assert!(leaked.is_empty(), "URL secrets {leaked:?} leaked in response: {}", r.text);
}

#[tokio::test]
async fn probe_treats_401_and_403_as_reachable_without_sending_credentials() {
    let (s, token, env) = suite().await;
    for status in [401, 403] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/probe", listener.local_addr().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let tx = tx.clone(); async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, 8192).await.unwrap();
                tx.send((parts, body)).unwrap();
                axum::http::StatusCode::from_u16(status).unwrap()
            }
        });
        let fixture = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let iid = make_integration(&s, &token, &env, "webhook", json!({"url": url, "token": "probe-bearer-sentinel", "signing_secret": "probe-signing-sentinel"})).await;
        let r = s.call(Method::POST, &format!("/api/integrations/{iid}/test"), &token, None).await;
        fixture.abort();
        assert_eq!(r.status, 200, "HTTP {status}: {}", r.text);
        assert_eq!(r.body["ok"], json!(true), "{}", r.text);
        let detail = r.body["detail"].as_str().unwrap_or_default();
        assert!(detail.contains(&format!("HTTP {status}")), "detail: {detail}");
        assert!(detail.contains("credentials are not verified"), "detail: {detail}");
        let (parts, body) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await.unwrap().expect("probe request missing");
        assert_eq!(parts.method, Method::GET);
        assert_eq!(parts.uri, "/probe");
        for name in ["authorization", "cookie", "x-openwarp-timestamp", "x-openwarp-signature"] {
            assert!(!parts.headers.contains_key(name), "probe sent {name}");
        }
        assert!(body.is_empty(), "probe sent a request body");
        let request = format!("{:?}{:?}{:?}", parts.uri, parts.headers, body);
        for secret in ["probe-bearer-sentinel", "probe-signing-sentinel", token.as_str()] {
            assert!(!request.contains(secret), "probe sent a credential");
        }
    }
}

#[tokio::test]
async fn probe_requires_config_keys_and_never_501s() {
    let (s, token, env) = suite().await;
    for (kind, config, fragment) in [
        ("webhook", json!({}), "needs url"),
        ("kubernetes", json!({}), "needs api_server"),
        ("hashicorp_vault", json!({}), "needs addr"),
    ] {
        let iid = make_integration(&s, &token, &env, kind, config).await;
        let r = s.call(Method::POST, &format!("/api/integrations/{iid}/test"), &token, None).await;
        assert_ne!(r.status, 501, "{kind}: {}", r.text);
        assert_eq!(r.status, 400, "{kind}: {}", r.text);
        assert!(r.body["error"].as_str().unwrap_or_default().contains(fragment), "{kind}: {}", r.text);
    }
}
