// Live MySQL/MariaDB proof for the storage adapter and dynamic database leases.
// Requires a reachable admin database; set OPENWARP_TEST_MYSQL_URL, for example
// mysql://root:openwarp@127.0.0.1:3306/mysql. The test creates and drops its own
// database, so it never touches application data.

use mysql_async::prelude::Queryable;
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

/// Run administrative statements against the admin URL. The test owns the
/// database it creates here.
async fn mysql_admin(admin_url: &str, statements: &[String]) -> Result<(), String> {
    let opts = mysql_async::Opts::from_url(admin_url).map_err(|e| e.to_string())?;
    let pool = mysql_async::Pool::new(opts);
    let result = async {
        let mut c = pool.get_conn().await.map_err(|e| e.to_string())?;
        for s in statements { c.query_drop(s.as_str()).await.map_err(|e| e.to_string())?; }
        Ok(()) }.await;
    pool.disconnect().await.ok();
    result
}

/// True when the URL can open a connection, used to prove a lease account is
/// usable and then that revocation removed it.
async fn can_login(url: &str) -> bool {
    let opts = match mysql_async::Opts::from_url(url) { Ok(o) => o, Err(_) => return false };
    let pool = mysql_async::Pool::new(opts);
    let ok = async {
        let mut c = match pool.get_conn().await { Ok(c) => c, Err(_) => return false };
        c.query_drop("SELECT 1").await.is_ok() }.await;
    pool.disconnect().await.ok();
    ok
}

struct MyServer {
    child: Child,
    admin_url: String,
    db_name: String,
    inbox: Arc<Mutex<Vec<Value>>>,
}

impl Drop for MyServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let admin = self.admin_url.clone();
        let name = self.db_name.clone();
        let _ = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() { Ok(r) => r, Err(_) => return };
            runtime.block_on(async move { let _ = mysql_admin(&admin, &[format!("DROP DATABASE IF EXISTS `{}`", name)]).await; });
        }).join();
    }
}

fn free_port() -> u16 {
    // True ephemeral: the OS never hands out a port that is still bound, so
    // parallel test binaries cannot converge the way a PID-derived scan
    // does. The only residual hazard is the gap between dropping this
    // listener and the child binding it, which the startup retry covers.
    TcpListener::bind("127.0.0.1:0").expect("ephemeral port").local_addr().expect("local addr").port()
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

fn spawn_server(db_url: &str, port: u16, inbox_url: &str, allowed_db_hosts: Option<&str>) -> Child {
    let base = format!("http://127.0.0.1:{}", port);
    let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
    command.env("DATABASE_URL", db_url)
        .env("ADDR", format!("127.0.0.1:{}", port))
        .env("OPENWARP_PUBLIC_URL", &base)
        .env("OPENWARP_EMAIL_WEBHOOK", inbox_url)
        .env("TOKIO_WORKER_THREADS", "2")
        .env_remove("OPENWARP_MASTER_KEY")
        .env_remove("REDIS_URL")
        .env_remove("OPENWARP_TRUST_PROXY")
        .env_remove("OPENWARP_ENV");
    match allowed_db_hosts { Some(hosts) => { command.env("OPENWARP_ALLOWED_DB_HOSTS", hosts); } None => { command.env_remove("OPENWARP_ALLOWED_DB_HOSTS"); } }
    command.stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn openwarp-server")
}

async fn wait_healthy(client: &Client, port: u16, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline { panic!("{} did not become healthy", label); }
        if let Ok(r) = client.get(format!("http://127.0.0.1:{}/health", port)).send().await { if r.status().is_success() { return; } }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Opt-in: set OPENWARP_TEST_MYSQL_TLS_URL to an admin URL with
/// `?require_ssl=true&verify_ca=false`. A TLS-requesting URL used to reach a
/// client that panics when the crate is built without a TLS backend.
#[tokio::test]
async fn mysql_tls_connection_is_available() {
    let url = match std::env::var("OPENWARP_TEST_MYSQL_TLS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return,
    };
    assert!(can_login(&url).await, "a require_ssl connection must complete, not panic");
}

#[tokio::test]
async fn mysql_backend_round_trip_and_dynamic_lease() {
    let admin_url = match std::env::var("OPENWARP_TEST_MYSQL_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return,
    };
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let db_name = format!("openwarp_http_{}_{}", std::process::id(), seq);
    mysql_admin(&admin_url, &[format!("CREATE DATABASE `{}` DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_bin", db_name)]).await.expect("create test database");
    let base_url = admin_url.split('?').next().unwrap_or(&admin_url);
    let db_url = match base_url.rfind('/') {
        Some(index) => format!("{}/{}", &base_url[..index], db_name),
        None => format!("{}/{}", base_url, db_name),
    };
    // The lease allowlist names the host and port the server will dial.
    let authority = db_url.split("://").nth(1).and_then(|rest| rest.rsplit('@').next()).and_then(|hp| hp.split('/').next()).unwrap_or("").to_string();

    let (inbox_url, inbox) = start_inbox();
    let first_port = free_port();
    let child = spawn_server(&db_url, first_port, &inbox_url, Some(&authority));
    let mut server = MyServer { child, admin_url: admin_url.clone(), db_name: db_name.clone(), inbox };
    let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(10)).build().expect("client");
    wait_healthy(&client, first_port, "MySQL-backed server").await;
    let base = format!("http://127.0.0.1:{}", first_port);

    let email = "mysql@test.invalid";
    let password = "mysql-password-1";
    let registered = call(&client, &base, Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(registered.status, 200, "register: {}", registered.text);
    let text = wait_for_mail(&server.inbox, "/api/auth/verify?token=").await;
    let verified = client.get(format!("{}{}", base, extract_link(&text, "/api/auth/verify?token="))).send().await.expect("verify request");
    assert_eq!(verified.status(), 200);
    let login = call(&client, &base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(login.status, 200, "login: {}", login.text);
    let token = login.body["token"].as_str().expect("session token");
    let org = registered.body["org_id"].as_str().expect("org id");
    let app = call(&client, &base, Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": "mysql-it"}))).await;
    assert_eq!(app.status, 200, "create app: {}", app.text);
    let app_id = app.body["id"].as_str().expect("app id");
    let envs = call(&client, &base, Method::GET, &format!("/api/apps/{}/envs", app_id), Some(token), None).await;
    assert_eq!(envs.status, 200, "list envs: {}", envs.text);
    let envs = envs.body.as_array().expect("env array");
    assert_eq!(envs.len(), 3);
    let env = envs[0]["id"].as_str().expect("env id");
    let deployed = call(&client, &base, Method::PUT, &format!("/api/envs/{}/secrets", env), Some(token), Some(json!({"secrets": [{"key": "MY_TOKEN", "value": "v1", "path": "/", "type": "secret", "comment": "", "tags": ""}]}))).await;
    assert_eq!(deployed.status, 200, "deploy: {}", deployed.text);
    assert_eq!(deployed.body["deployed"], 1);
    let listed = call(&client, &base, Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    assert_eq!(listed.status, 200, "list secrets: {}", listed.text);
    assert_eq!(listed.body["secrets"][0]["value"], "v1");

    // A dynamic lease creates a real MariaDB account, grants only the named
    // privilege, and drops the account on revoke.
    let lease = call(&client, &base, Method::POST, &format!("/api/envs/{}/dynamic", env), Some(token), Some(json!({
        "name": "reporter", "type": "mysql",
        "config": {"connection": db_url, "grants": [format!("SELECT ON {}.*", db_name)]}
    }))).await;
    assert_eq!(lease.status, 200, "mysql lease: {}", lease.text);
    let username = lease.body["username"].as_str().expect("lease username");
    let lease_password = lease.body["password"].as_str().expect("lease password");
    assert!(username.starts_with("dyn_"), "generated account name: {}", username);
    let lease_url = format!("mysql://{}:{}@{}/{}", username, lease_password, authority, db_name);
    assert!(can_login(&lease_url).await, "the lease account must be able to sign in");
    let revoked = call(&client, &base, Method::DELETE, &format!("/api/leases/{}", lease.body["id"].as_str().expect("lease id")), Some(token), None).await;
    assert_eq!(revoked.status, 200, "revoke: {}", revoked.text);
    assert!(!can_login(&lease_url).await, "revocation must drop the account");

    // A second boot replays the schema and every migration against a populated
    // database; a non-idempotent statement would abort startup here.
    let _ = server.child.kill();
    let _ = server.child.wait();
    let second_port = free_port();
    let mut second = MyServer { child: spawn_server(&db_url, second_port, &inbox_url, Some(&authority)), admin_url: admin_url.clone(), db_name: db_name.clone(), inbox: server.inbox.clone() };
    wait_healthy(&client, second_port, "restarted MySQL-backed server").await;
    let base = format!("http://127.0.0.1:{}", second_port);
    let login = call(&client, &base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(login.status, 200, "login after restart: {}", login.text);
    let token = login.body["token"].as_str().expect("session token");
    let listed = call(&client, &base, Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    assert_eq!(listed.status, 200, "list after restart: {}", listed.text);
    assert_eq!(listed.body["secrets"][0]["value"], "v1", "secrets must survive a restart");
    // Failed logins exercise the rate_limits upsert, the one statement the MySQL
    // dialect must rewrite. Running them after the restart also shows the
    // counter persists.
    for attempt in 0..6 {
        let r = call(&client, &base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "wrong-password"}))).await;
        if attempt < 5 { assert_eq!(r.status, 401, "attempt {}: {}", attempt, r.text); }
        else { assert_eq!(r.status, 429, "the sixth failed sign-in must be rate limited, got {} {}", r.status, r.text); }
    }
    let _ = second.child.kill();
    let _ = second.child.wait();
}
