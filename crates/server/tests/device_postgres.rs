#![cfg(feature = "pki")]
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
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

use openwarp_server::db as storage;

async fn pg_server() -> Option<(PgServer, Client, String, String)> {
    let _start = START_LOCK.lock().await;
    let admin_url = match std::env::var("OPENWARP_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return None,
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
        .env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1")
        // PKI is an enterprise feature; the debug test build accepts the
        // development license, which unlocks it without a signed token.
        .env("OPENWARP_LICENSE", "development")
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

    admin_driver.abort();
    Some((server, client, base, db_url))
}

async fn grant_pki(client: &Client, base: &str, token: &str, org: &str) {
        let granted = call(client, base, Method::PUT, "/api/instance/features", Some(token), Some(json!({"org": org, "features": ["pki"]}))).await;
        assert_eq!(granted.status, 200, "grant pki to the fixture workspace: {}", granted.text);
    }

async fn pg_owner(server: &PgServer, client: &Client, base: &str) -> (String, String) {
    let email = "postgres@test.invalid";
    let password = "postgres-password-1";
    let registered = call(client, base, Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(registered.status, 200, "register: {}", registered.text);
    let text = wait_for_mail(&server.inbox, "/api/auth/verify?token=").await;
    let verified = client.get(format!("{}{}", base, extract_link(&text, "/api/auth/verify?token="))).send().await.expect("verify request");
    assert_eq!(verified.status(), 200);
    let login = call(client, base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(login.status, 200, "login: {}", login.text);
    (login.body["token"].as_str().expect("session token").to_string(), registered.body["org_id"].as_str().expect("org id").to_string())
}

#[tokio::test]
async fn postgres_backend_round_trip() {
    let Some((server, client, base, _)) = pg_server().await else { return; };
    let (token, org) = pg_owner(&server, &client, &base).await;
    let token = token.as_str();
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
    drop(server);
}

async fn pg_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await.expect("connect disposable database");
    tokio::spawn(async move { let _ = connection.await; }); client
}

#[tokio::test]
async fn postgres_transactions_roll_back_errors_failed_checks_and_cancellation() {
    let Some((_server, _, _, url)) = pg_server().await else { return; };
    let observer = pg_client(&url).await;
    observer.batch_execute("CREATE TABLE tx_probe(id BIGINT PRIMARY KEY, value BIGINT NOT NULL); INSERT INTO tx_probe VALUES(1,0),(2,0)").await.unwrap();
    let db = std::sync::Arc::new(storage::Db::open(&url).await.unwrap());
    let failed = db.tx(&[("UPDATE tx_probe SET value=10 WHERE id=1", vec![]), ("INSERT INTO tx_probe VALUES(1,99)", vec![])]).await;
    assert!(failed.is_err(), "duplicate key must abort transaction");
    assert_eq!(observer.query_one("SELECT value FROM tx_probe WHERE id=1", &[]).await.unwrap().get::<_, i64>(0), 0, "error must roll back preceding write");
    let failed = db.tx_checked(&[("UPDATE tx_probe SET value=20 WHERE id=1", vec![]), ("UPDATE tx_probe SET value=99 WHERE id=99", vec![])], &[(1,1)]).await;
    assert!(failed.is_err(), "failed affected-row check must abort transaction");
    assert_eq!(observer.query_one("SELECT value FROM tx_probe WHERE id=1", &[]).await.unwrap().get::<_, i64>(0), 0, "failed check must roll back preceding write");
    for locked in [false, true] {
        // Hold the second write so cancellation happens after the first write ran.
        observer.batch_execute("BEGIN; UPDATE tx_probe SET value=value WHERE id=2").await.unwrap();
        let worker_db = db.clone();
        let task = tokio::spawn(async move {
            let statements = [("UPDATE tx_probe SET value=30 WHERE id=1", vec![]), ("UPDATE tx_probe SET value=40 WHERE id=2", vec![])];
            if locked { worker_db.tx_locked("SELECT id FROM tx_probe WHERE id=1", &[], |_| true, &statements, &[(0,1),(1,1)]).await }
            else { worker_db.tx_checked(&statements, &[(0,1),(1,1)]).await }
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            observer.query_one("SELECT pg_stat_clear_snapshot()", &[]).await.unwrap();
            let blocked: bool = observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE 'UPDATE tx_probe SET value=40%')", &[]).await.unwrap().get(0);
            if blocked { break; }
            assert!(!task.is_finished(), "transaction ended before cancellation barrier");
            assert!(Instant::now() < deadline, "transaction never reached second-write lock");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort(); assert!(task.await.unwrap_err().is_cancelled());
        observer.batch_execute("ROLLBACK").await.unwrap();
        // Checking out every pool slot also exposes an abandoned transaction
        // which would otherwise hide uncommitted rows on an idle connection.
        let storage::Db::Postgres(pool) = db.as_ref() else { panic!("expected Postgres adapter"); };
        let mut slots = Vec::new();
        for _ in 0..pool.status().max_size {
            slots.push(tokio::time::timeout(Duration::from_secs(5), pool.get()).await.expect("pool slot must remain usable").unwrap());
        }
        for slot in &slots {
            let value: i64 = tokio::time::timeout(Duration::from_secs(5), slot.query_one("SELECT value FROM tx_probe WHERE id=1", &[])).await.expect("connection must not remain blocked").unwrap().get(0);
            assert_eq!(value, 0, "cancelled transaction must roll back on every reusable connection (locked={})", locked);
        }
        drop(slots);
        observer.batch_execute("SET lock_timeout='2s'; UPDATE tx_probe SET value=value WHERE id=1").await.expect("cancelled transaction must release row locks");
    }
}

fn blocked_hook() -> (String, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
    let (arrived_tx, arrived_rx) = std::sync::mpsc::channel(); let (release_tx, release_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap(); stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
        loop {
            let n = stream.read(&mut chunk).unwrap(); assert_ne!(n,0); buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]);
                let len = head.lines().find_map(|l| { let (k,v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                if buf.len() >= end+4+len { break; }
            }
        }
        arrived_tx.send(()).unwrap(); if release_rx.recv_timeout(Duration::from_secs(5)).is_err() { return; }
        let payload = "{\"allow\":true}";
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload);
    });
    (format!("http://{}/hook", addr), arrived_rx, release_tx)
}

#[tokio::test]
async fn postgres_renewal_rechecks_expiry_after_device_lock() {
    let Some((server,client,base,url))=pg_server().await else{return};
    let (token,org)=pg_owner(&server,&client,&base).await;
    grant_pki(&client,&base,&token,&org).await;
    let r=call(&client,&base,Method::POST,&format!("/api/orgs/{}/pki/cas",org),Some(&token),Some(json!({"name":"expiry-lock"}))).await;
    assert_eq!(r.status,200,"CA creation: {}",r.text);let ca=r.body["id"].as_str().unwrap();
    let r=call(&client,&base,Method::POST,&format!("/api/pki/cas/{}/devices",ca),Some(&token),Some(json!({"name":"expiry-sensor"}))).await;
    assert_eq!(r.status,200);let device=r.body["id"].as_str().unwrap().to_string();
    let old=rcgen::KeyPair::generate().unwrap();let csr=rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&old).unwrap().pem().unwrap();
    let r=call(&client,&base,Method::POST,&format!("/api/pki/devices/{}/enrollment",device),Some(&token),Some(json!({}))).await;assert_eq!(r.status,200);
    let r=call(&client,&base,Method::POST,"/api/pki/enroll",None,Some(json!({"code":r.body["code"],"csr":csr}))).await;assert_eq!(r.status,200);
    let replacement=rcgen::KeyPair::generate().unwrap();let csr=rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&replacement).unwrap().pem().unwrap();
    let challenge=call(&client,&base,Method::POST,"/api/pki/renew/challenge",None,Some(json!({"device_id":device,"csr":csr}))).await;assert_eq!(challenge.status,200);
    let observer=pg_client(&url).await;
    observer.execute("UPDATE pki_certs SET expires_at=FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT+2 WHERE device_id=$1",&[&device]).await.unwrap();
    let mut blocker=pg_client(&url).await;let tx=blocker.transaction().await.unwrap();
    tx.query_one("SELECT id FROM pki_devices WHERE id=$1 FOR UPDATE",&[&device]).await.unwrap();
    let signed=keystore_pki::sign(keystore_pki::SignatureAlgorithm::Sha256WithEcdsa,&old.serialize_der(),challenge.body["challenge"].as_str().unwrap().as_bytes()).unwrap();
    use base64ct::{Base64,Encoding};let proof=json!({"challenge_id":challenge.body["challenge_id"],"signature":Base64::encode_string(&signed)});
    let worker=client.clone();let worker_base=base.clone();let request=tokio::spawn(async move{call(&worker,&worker_base,Method::POST,"/api/pki/renew",None,Some(proof)).await});
    let deadline=Instant::now()+Duration::from_secs(4);
    loop{let blocked:bool=observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')",&[]).await.unwrap().get(0);if blocked{break}assert!(Instant::now()<deadline,"renewal must reach the row lock");tokio::time::sleep(Duration::from_millis(20)).await;}
    tokio::time::sleep(Duration::from_secs(3)).await;tx.commit().await.unwrap();
    let r=request.await.unwrap();assert!([400,401,403,409].contains(&r.status),"expired authorization must roll back: {}",r.text);
    let n:i64=observer.query_one("SELECT COUNT(*) FROM pki_certs WHERE device_id=$1",&[&device]).await.unwrap().get(0);assert_eq!(n,1);
    let used:i64=observer.query_one("SELECT used_at FROM pki_renew_challenges WHERE id=$1",&[&challenge.body["challenge_id"].as_str().unwrap()]).await.unwrap().get(0);assert_eq!(used,0);
}

#[tokio::test]
async fn postgres_enrollment_cannot_cross_revocation_or_group_deletion() {
    let Some((server, client, base, url)) = pg_server().await else { return; };
    let (token, org) = pg_owner(&server, &client, &base).await;
    grant_pki(&client, &base, &token, &org).await;
    let observer = pg_client(&url).await;
    for mutation in ["device-revoke", "group-revoke", "group-delete", "ca-revoke", "root-revoke", "device-policy"] {
        let r = call(&client, &base, Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(&token), Some(json!({"name": mutation}))).await;
        assert_eq!(r.status,200,"CA creation for {}: {}",mutation,r.text); let root = r.body["id"].as_str().unwrap().to_string();
        let ca = if mutation == "root-revoke" {
            let r = call(&client, &base, Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(&token), Some(json!({"name": "child", "parent_id": root}))).await;
            assert_eq!(r.status,200); r.body["id"].as_str().unwrap().to_string()
        } else { root.clone() };
        let r = call(&client, &base, Method::POST, &format!("/api/pki/cas/{}/groups", ca), Some(&token), Some(json!({"name": "factory"}))).await;
        assert_eq!(r.status,200); let group = r.body["id"].as_str().unwrap().to_string();
        let r = call(&client, &base, Method::POST, &format!("/api/pki/cas/{}/devices", ca), Some(&token), Some(json!({"name": "sensor", "group_id": group}))).await;
        assert_eq!(r.status,200); let device = r.body["id"].as_str().unwrap().to_string();
        let r = call(&client, &base, Method::POST, &format!("/api/pki/devices/{}/enrollment", device), Some(&token), Some(json!({}))).await;
        assert_eq!(r.status,200); let code = r.body["code"].clone();
        let (hook, arrived, release) = blocked_hook();
        assert_eq!(call(&client, &base, Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Some(&token), Some(json!({"url": hook}))).await.status,200);
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(vec!["sensor.local".to_string()]).unwrap().serialize_request(&key).unwrap().pem().unwrap();
        let worker_client = client.clone(); let worker_base = base.clone();
        let issuance = tokio::spawn(async move { call(&worker_client, &worker_base, Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await });
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(5))).await.unwrap().expect("issuance reached hook barrier");
        let (method, path) = match mutation {
            "device-revoke" => (Method::POST, format!("/api/pki/devices/{}/revoke", device)),
            "group-revoke" => (Method::POST, format!("/api/pki/groups/{}/revoke", group)),
            "group-delete" => (Method::DELETE, format!("/api/pki/groups/{}", group)),
            "device-policy" => (Method::PATCH, format!("/api/pki/devices/{}",device)),
            "ca-revoke" => (Method::POST, format!("/api/pki/cas/{}/revoke", ca)),
            _ => (Method::POST, format!("/api/pki/cas/{}/revoke", root)),
        };
        let change=if mutation=="device-policy" {json!({"sans":["new.example"],"cert_days":1})}else{json!({})};
        let changed = call(&client, &base, method, &path, Some(&token), Some(change)).await;
        assert_eq!(changed.status,200,"{} must complete while enrollment policy is pending", mutation);
        release.send(()).unwrap(); let issued = issuance.await.unwrap();
        if mutation == "group-delete" {
            assert!([200,400,401,403,409].contains(&issued.status), "group deletion may serialize before or invalidate enrollment");
        } else {
            assert!([400,401,403,409].contains(&issued.status), "{} must invalidate in-flight enrollment, got {}", mutation, issued.status);
        }
        let r = call(&client, &base, Method::GET, &format!("/api/pki/devices/{}", device), Some(&token), None).await; assert_eq!(r.status,200);
        if mutation == "group-delete" { assert_eq!(r.body["group_id"], "", "issuance cannot restore deleted group snapshot"); }
        else {
            assert!(r.body["active_cert"].is_null(), "revocation cannot leave an active certificate");
            let live: i64 = observer.query_one("SELECT COUNT(*) FROM pki_certs WHERE device_id=$1 AND revoked=0", &[&device]).await.unwrap().get(0);
            assert_eq!(live,0,"{} must not leave an orphan unrevoked certificate",mutation);
        }
    }
}
