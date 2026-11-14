// Native process lifecycle coverage. The live PostgreSQL case is deliberately
// ignored: selecting it explicitly requires a numeric-loopback test admin URL.
use openwarp_crypto as oc;
use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const PASSWORD: &str = "restart-replica-test-password";
const SECRET_KEY: &str = "RESTART_REPLICA_SECRET";

struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-restart-{}-{}", std::process::id(), oc::random_token("fixture")));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).expect("create private test directory");
        Self(path)
    }
    fn url(&self) -> String { format!("sqlite://{}", self.0.join("restart.db").display()) }
}
impl Drop for PrivateDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

struct Inbox {
    url: String,
    messages: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Inbox {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind private mail relay");
        let url = format!("http://{}/mail", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = messages.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(10)); continue; }
                    Err(_) => break,
                };
                stream.set_nonblocking(false).expect("set private mail relay stream blocking");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                while bytes.len() < 65536 {
                    let n = match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(n) => n };
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let len = header.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None }
                        }).unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            if let Ok(message) = serde_json::from_slice::<Value>(&bytes[end + 4..end + 4 + len]) { sink.lock().unwrap().push(message); }
                            break;
                        }
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            }
        });
        Self { url, messages, stop, thread: Some(thread) }
    }
    async fn verification_path(&self, email: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            {
                let messages = self.messages.lock().unwrap();
                for message in messages.iter().rev() {
                    if message["to"].as_str() != Some(email) { continue; }
                    for word in message["text"].as_str().unwrap_or("").split_whitespace() {
                        if let Some(index) = word.find("/api/auth/verify?token=") { return word[index..].to_string(); }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("verification email did not arrive at the private relay");
    }
}
impl Drop for Inbox {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, client: Client }
impl Server {
    fn spawn(db_url: &str, master: &[u8; 32], inbox: &Inbox) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve native server port");
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        drop(listener);
        // Inherited operator configuration must not select external providers,
        // a KMS, Redis, or a different authentication policy in this fixture.
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env_clear()
            .env("DATABASE_URL", db_url)
            .env("ADDR", addr.to_string())
            .env("OPENWARP_MASTER_KEY", oc::b64(master))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_PROVIDER", "webhook")
            .env("OPENWARP_EMAIL_WEBHOOK", &inbox.url)
            .env("OPENWARP_AUTH_PROVIDERS", "password")
            .env("OPENWARP_SIGNUPS", "open")
            .env("TOKIO_WORKER_THREADS", "2")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped())
            .spawn().expect("spawn native openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(10)).build().unwrap();
        Self { child, base, client }
    }
    async fn start(db_url: &str, master: &[u8; 32], inbox: &Inbox) -> Self {
        let mut server = Self::spawn(db_url, master, inbox);
        let deadline = Instant::now() + Duration::from_secs(40);
        while Instant::now() < deadline {
            assert!(server.child.try_wait().expect("inspect native child").is_none(), "native server exited before readiness");
            if let Ok(response) = server.client.get(format!("{}/health", server.base)).timeout(Duration::from_millis(500)).send().await {
                if response.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("native server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = token { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.unwrap_or_else(|_| panic!("native API transport failed"));
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap_or_else(|_| panic!("native API response read failed"));
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Resp { status, body }
    }
    fn stop(&mut self) {
        self.child.kill().expect("stop owned native child");
        self.child.wait().expect("reap owned native child");
    }
    async fn assert_wrong_key_refused(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("inspect wrong-key child") {
                assert!(!status.success(), "wrong-key startup must exit unsuccessfully");
                let mut diagnostic = String::new();
                self.child.stderr.take().expect("wrong-key startup diagnostic").read_to_string(&mut diagnostic).expect("read startup diagnostic");
                assert!(diagnostic.contains("master key") && diagnostic.contains("does not match"),
                    "startup must fail specifically because the supplied root does not match the persisted database");
                return;
            }
            if let Ok(response) = self.client.get(format!("{}/health", self.base)).timeout(Duration::from_millis(300)).send().await {
                assert!(!response.status().is_success(), "wrong-key process must never become ready");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("wrong-key startup must terminate, not merely leave an unhealthy process");
    }
}
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

async fn login(server: &Server, email: &str) -> String {
    let response = server.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": PASSWORD}))).await;
    assert_eq!(response.status, 200, "verified password login");
    response.body["token"].as_str().expect("login session token").to_string()
}
async fn register(server: &Server, inbox: &Inbox, email: &str) -> (String, String) {
    let response = server.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": PASSWORD}))).await;
    assert_eq!(response.status, 200, "register private account");
    assert!(response.body["token"].is_null(), "unverified registration must not issue a session");
    let org = response.body["org_id"].as_str().expect("registration workspace").to_string();
    let verification = inbox.verification_path(email).await;
    assert_eq!(server.call(Method::GET, &verification, None, None).await.status, 200, "verify using delivered email proof");
    (login(server, email).await, org)
}
async fn create_environment(server: &Server, token: &str, org: &str) -> String {
    let app = server.call(Method::POST, &format!("/api/orgs/{org}/apps"), Some(token), Some(json!({"name": "restart-replica"}))).await;
    assert_eq!(app.status, 200, "create application");
    let app_id = app.body["id"].as_str().expect("application id");
    let envs = server.call(Method::GET, &format!("/api/apps/{app_id}/envs"), Some(token), None).await;
    assert_eq!(envs.status, 200, "list default environments");
    envs.body.as_array().expect("environment array").iter().find(|env| env["name"] == "Development")
        .or_else(|| envs.body.as_array().unwrap().first()).expect("default environment")["id"].as_str().expect("environment id").to_string()
}
async fn deploy(server: &Server, token: &str, env: &str, value: &str) {
    let response = server.call(Method::PUT, &format!("/api/envs/{env}/secrets"), Some(token), Some(json!({"secrets": [{"key": SECRET_KEY, "value": value, "path": "/", "type": "secret"}]}))).await;
    assert_eq!(response.status, 200, "deploy SSE secret without configured TOTP");
    assert_eq!(response.body["deployed"], 1, "one secret must commit");
}
async fn assert_secret(server: &Server, token: &str, env: &str, value: &str) -> String {
    let response = server.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(token), None).await;
    assert_eq!(response.status, 200, "read persisted SSE secret with original session");
    let secrets = response.body["secrets"].as_array().expect("secret array");
    assert_eq!(secrets.len(), 1, "restart/update must not lose or duplicate the secret");
    assert_eq!(secrets[0]["key"], SECRET_KEY);
    assert_eq!(secrets[0]["value"], value);
    secrets[0]["id"].as_str().expect("secret id").to_string()
}

#[tokio::test]
async fn sqlite_process_restart_preserves_session_and_secret_and_rejects_wrong_key() {
    let _serial = TEST_LOCK.lock().await;
    let db = PrivateDir::new();
    let inbox = Inbox::start();
    let master = oc::random_key();
    let mut server = Server::start(&db.url(), &master, &inbox).await;
    let (session, org) = register(&server, &inbox, "restart@test.invalid").await;
    let env = create_environment(&server, &session, &org).await;
    deploy(&server, &session, &env, "before-restart").await;
    let secret_id = assert_secret(&server, &session, &env, "before-restart").await;
    server.stop();
    drop(server);

    let mut restarted = Server::start(&db.url(), &master, &inbox).await;
    assert_eq!(assert_secret(&restarted, &session, &env, "before-restart").await, secret_id);
    deploy(&restarted, &session, &env, "after-restart").await;
    restarted.stop();
    drop(restarted);

    let mut wrong_key = Server::spawn(&db.url(), &oc::random_key(), &inbox);
    wrong_key.assert_wrong_key_refused().await;
    drop(wrong_key);

    let recovered = Server::start(&db.url(), &master, &inbox).await;
    assert_eq!(assert_secret(&recovered, &session, &env, "after-restart").await, secret_id,
        "failed wrong-key boot must not replace persisted key material or secrets");
}

struct PgDatabase { admin_url: String, name: Option<String>, url: String }
impl PgDatabase {
    async fn create() -> Self {
        let admin_url = std::env::var("OPENWARP_TEST_REPLICA_PG")
            .or_else(|_| std::env::var("OPENWARP_TEST_POSTGRES_URL"))
            .expect("ignored PostgreSQL case requires OPENWARP_TEST_REPLICA_PG or OPENWARP_TEST_POSTGRES_URL pointing to a disposable numeric-loopback admin database");
        let mut parsed = reqwest::Url::parse(&admin_url).unwrap_or_else(|_| panic!("replica test admin URL is invalid"));
        assert!(matches!(parsed.scheme(), "postgres" | "postgresql"), "replica test requires a PostgreSQL URL");
        let host = parsed.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
        assert!(host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()), "replica test admin host must be numeric loopback");
        assert!(parsed.port().is_some_and(|port| port != 0), "replica test admin URL requires an explicit nonzero port");
        assert!(parsed.query().is_none() && parsed.fragment().is_none(), "replica test admin URL must not override its authority through query parameters or a fragment");
        assert!(parsed.path().len() > 1, "replica test admin URL must name an administrator database");
        let name = format!("openwarp_replica_{}_{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.unwrap_or_else(|_| panic!("connect replica test administrator"));
        let driver = tokio::spawn(async move { let _ = connection.await; });
        let result = admin.batch_execute(&format!("CREATE DATABASE {name}")).await;
        driver.abort();
        assert!(result.is_ok(), "create isolated replica test database");
        parsed.set_path(&format!("/{name}"));
        Self { admin_url, name: Some(name), url: parsed.to_string() }
    }
    async fn drop_owned(admin_url: &str, name: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(10), async {
            let Ok((admin, connection)) = tokio_postgres::connect(admin_url, tokio_postgres::NoTls).await else { return false; };
            let driver = tokio::spawn(async move { let _ = connection.await; });
            let result = admin.batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)")).await;
            driver.abort();
            result.is_ok()
        }).await.unwrap_or(false)
    }
    async fn cleanup(&mut self) {
        let name = self.name.as_deref().expect("owned replica database");
        assert!(Self::drop_owned(&self.admin_url, name).await, "remove isolated replica test database");
        self.name = None;
    }
}
impl Drop for PgDatabase {
    fn drop(&mut self) {
        let Some(name) = self.name.take() else { return; };
        let admin_url = self.admin_url.clone();
        let cleaned = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return false; };
            runtime.block_on(Self::drop_owned(&admin_url, &name))
        }).join().unwrap_or(false);
        if !cleaned { eprintln!("could not remove the owned restart/replica test database"); }
    }
}

#[tokio::test]
#[ignore = "requires a disposable numeric-loopback PostgreSQL administrator URL; select explicitly with --ignored --exact"]
async fn postgres_two_processes_share_reads_revocation_and_replica_restart() {
    let _serial = TEST_LOCK.lock().await;
    let mut db = PgDatabase::create().await;
    let inbox = Inbox::start();
    let master = oc::random_key();
    let mut a = Server::start(&db.url, &master, &inbox).await;
    let b = Server::start(&db.url, &master, &inbox).await;
    let email = "replicas@test.invalid";
    let (owner_session, org) = register(&a, &inbox, email).await;
    let env = create_environment(&a, &owner_session, &org).await;
    deploy(&a, &owner_session, &env, "created-on-a").await;
    let secret_id = assert_secret(&b, &owner_session, &env, "created-on-a").await;
    deploy(&a, &owner_session, &env, "updated-on-a").await;
    assert_eq!(assert_secret(&b, &owner_session, &env, "updated-on-a").await, secret_id);

    let revoked_session = login(&b, email).await;
    assert_secret(&b, &revoked_session, &env, "updated-on-a").await;
    let sessions = b.call(Method::GET, "/api/me/sessions", Some(&revoked_session), None).await;
    assert_eq!(sessions.status, 200, "list real sessions through replica B");
    let revoked_id = sessions.body.as_array().expect("session array").iter().find(|session| session["current"] == true)
        .expect("current replica B session")["id"].as_str().expect("stable session id");
    let revoked = a.call(Method::DELETE, &format!("/api/me/sessions/{revoked_id}"), Some(&owner_session), None).await;
    assert_eq!(revoked.status, 200, "revoke replica B session through replica A");
    assert_eq!(revoked.body["current"], false, "revocation must not target the surviving caller session");
    assert_eq!(b.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&revoked_session), None).await.status, 401,
        "a session already used on B must be denied immediately after A commits revocation");
    assert_secret(&b, &owner_session, &env, "updated-on-a").await;

    a.stop();
    drop(a);
    deploy(&b, &owner_session, &env, "written-while-a-stopped").await;
    assert_eq!(assert_secret(&b, &owner_session, &env, "written-while-a-stopped").await, secret_id);
    let restarted_a = Server::start(&db.url, &master, &inbox).await;
    assert_eq!(assert_secret(&restarted_a, &owner_session, &env, "written-while-a-stopped").await, secret_id);
    assert_eq!(restarted_a.call(Method::GET, "/api/me", Some(&revoked_session), None).await.status, 401,
        "restarting a replica must not restore a revoked session");
    assert_secret(&b, &owner_session, &env, "written-while-a-stopped").await;
    drop(restarted_a);
    drop(b);
    db.cleanup().await;
}
