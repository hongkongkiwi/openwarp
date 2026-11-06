// Live Postgres proof for the async storage path. Requires a reachable admin
// database; set OPENWARP_TEST_POSTGRES_URL, for example
// postgres://andy@127.0.0.1:5432/postgres. The test creates and drops its own
// database, so it never touches application data.

use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Resp {
    status: u16,
    text: String,
    body: Value,
}

struct PgServer {
    child: Child,
    admin_url: String,
    db_name: String,
    inbox: Arc<Mutex<Vec<Value>>>,
}

impl Drop for PgServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let admin = self.admin_url.clone();
        let name = self.db_name.clone();
        // Drop runs at the end of an async test; use a short-lived thread so no
        // nested runtime is created in the test's runtime.
        let _ = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() { Ok(r) => r, Err(_) => return };
            runtime.block_on(async move {
                if let Ok((client, connection)) = tokio_postgres::connect(&admin, tokio_postgres::NoTls).await {
                    let driver = tokio::spawn(async move { let _ = connection.await; });
                    let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", name)).await;
                    driver.abort();
                }
            });
        }).join();
    }
}

fn free_port() -> u16 {
    let base = 20000 + (std::process::id() % 30000) as u16;
    for offset in 0..500u16 {
        let port = base.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            return port;
        }
    }
    TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port").local_addr().expect("addr").port()
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
    for _ in 0..80 {
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

async fn call(client: &Client, base: &str, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
    let mut request = client.request(method, format!("{}{}", base, path));
    if let Some(token) = token { request = request.bearer_auth(token); }
    if let Some(body) = body { request = request.json(&body); }
    let response = request.send().await.expect("request");
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Resp { status, text, body }
}

#[tokio::test]
async fn postgres_backend_round_trip() {
    let admin_url = match std::env::var("OPENWARP_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return,
    };
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let db_name = format!("openwarp_http_{}_{}", std::process::id(), seq);
    let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.expect("connect admin");
    let admin_driver = tokio::spawn(async move { let _ = connection.await; });
    admin.batch_execute(&format!("CREATE DATABASE {}", db_name)).await.expect("create test database");
    let base_url = admin_url.split('?').next().unwrap_or(&admin_url);
    let db_url = match base_url.rfind('/') {
        Some(index) => format!("{}/{}", &base_url[..index], db_name),
        None => format!("{}/{}", base_url, db_name),
    };

    let port = free_port();
    let base = format!("http://127.0.0.1:{}", port);
    let (inbox_url, inbox) = start_inbox();
    let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
        .env("DATABASE_URL", &db_url)
        .env("ADDR", format!("127.0.0.1:{}", port))
        .env("OPENWARP_PUBLIC_URL", &base)
        .env("OPENWARP_EMAIL_WEBHOOK", &inbox_url)
        .env("TOKIO_WORKER_THREADS", "2")
        .env_remove("OPENWARP_MASTER_KEY")
        .env_remove("REDIS_URL")
        .env_remove("OPENWARP_TRUST_PROXY")
        .env_remove("OPENWARP_ENV")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openwarp-server");
    let server = PgServer { child, admin_url, db_name, inbox };
    let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(10)).build().expect("client");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline { panic!("Postgres-backed server did not become healthy"); }
        if let Ok(r) = client.get(format!("{}/health", base)).send().await { if r.status().is_success() { break; } }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let email = "postgres@test.invalid";
    let password = "postgres-password-1";
    let registered = call(&client, &base, Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(registered.status, 200, "register: {}", registered.text);
    let text = wait_for_mail(&server.inbox, "/api/auth/verify?token=").await;
    let verified = client.get(format!("{}{}", base, extract_link(&text, "/api/auth/verify?token="))).send().await.expect("verify request");
    assert_eq!(verified.status(), 200);
    let login = call(&client, &base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(login.status, 200, "login: {}", login.text);
    let token = login.body["token"].as_str().expect("session token");
    let org = registered.body["org_id"].as_str().expect("org id");
    let app = call(&client, &base, Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": "postgres-it"}))).await;
    assert_eq!(app.status, 200, "create app: {}", app.text);
    let app_id = app.body["id"].as_str().expect("app id");
    let envs = call(&client, &base, Method::GET, &format!("/api/apps/{}/envs", app_id), Some(token), None).await;
    assert_eq!(envs.status, 200, "list envs: {}", envs.text);
    let envs = envs.body.as_array().expect("env array");
    assert_eq!(envs.len(), 3);
    let env = envs[0]["id"].as_str().expect("env id");
    let deployed = call(&client, &base, Method::PUT, &format!("/api/envs/{}/secrets", env), Some(token), Some(json!({"secrets": [{"key": "PG_TOKEN", "value": "v1", "path": "/", "type": "secret", "comment": "", "tags": ""}]}))).await;
    assert_eq!(deployed.status, 200, "deploy: {}", deployed.text);
    assert_eq!(deployed.body["deployed"], 1);
    let listed = call(&client, &base, Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    assert_eq!(listed.status, 200, "list secrets: {}", listed.text);
    assert_eq!(listed.body["secrets"][0]["value"], "v1");
    let deleted = call(&client, &base, Method::DELETE, &format!("/api/secrets/{}", listed.body["secrets"][0]["id"].as_str().expect("secret id")), Some(token), None).await;
    assert_eq!(deleted.status, 200, "delete: {}", deleted.text);
    admin_driver.abort();
    drop(server);
}
