use openwarp_server::{db::{self, Db}, new_state, process_maintenance};
use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASSWORD: &str = "correct-horse-battery";

struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill(); let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mail relay bind");
    let address = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection");
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0; 8192];
            loop {
                let n = match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(n) => n };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let len = head.lines().find_map(|line| { let (key, value) = line.split_once(':')?; if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                if let Ok(body) = serde_json::from_slice(&buf[end + 4..]) { sink.lock().unwrap().push(body); }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", address), inbox)
}

impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-emergency-merge-{}-{}", std::process::id(), openwarp_crypto::random_token("test")));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (mail_url, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", mail_url).env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ALLOWED_DB_HOSTS")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let server = Self { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(format!("{}/health", server.base)).send().await {
                if r.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("test server did not become healthy");
    }

    async fn call(&self, method: Method, path: &str, session: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(session) = session { req = req.header("cookie", format!("ow_session={}", session)).header("origin", &self.base); }
        if let Some(body) = body { req = req.json(&body); }
        let response = req.send().await.expect("HTTP request"); let status = response.status().as_u16();
        let text = response.text().await.expect("HTTP response body");
        let body = serde_json::from_str(&text).unwrap_or(Value::Null); Resp { status, body }
    }

    async fn login(&self, email: &str) -> String {
        let r = self.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "verified user sign-in"); field(&r.body, "token")
    }

    async fn register(&self, email: &str) -> Value {
        let r = self.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "registration setup"); let mut user = r.body;
        if user["verification_required"] == json!(true) {
            let mut link = None;
            for _ in 0..60 {
                {
                    let inbox = self.inbox.lock().unwrap();
                    link = inbox.iter().rev().filter_map(|mail| mail["text"].as_str()).flat_map(str::split_whitespace)
                        .find(|word| word.contains("/api/auth/verify?token=")).map(str::to_string);
                }
                if link.is_some() { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let link = link.expect("verification email"); let index = link.find("/api/auth/verify?token=").unwrap();
            assert_eq!(self.call(Method::GET, &link[index..], None, None).await.status, 200, "email verification setup");
            user["token"] = json!(self.login(email).await);
        }
        user
    }
}

fn field(body: &Value, key: &str) -> String { body[key].as_str().filter(|v| !v.is_empty()).expect("nonempty response field").to_string() }

async fn seed_lease(db: &Db, id: &str, env: &str, expires: i64) {
    db.exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,?,?,?,?,?)", &[json!(id), json!(env), json!(id), json!(openwarp_crypto::encrypt_symmetric(&[9; 32], b"dummy-lease-value")), json!(expires), json!(1)]).await.unwrap();
}

async fn revoked(db: &Db, id: &str) -> i64 {
    db::n(&db.one("SELECT revoked FROM leases WHERE id=?", &[json!(id)]).await.unwrap().expect("seeded lease"), "revoked")
}

#[tokio::test]
async fn merge_locked_project_leases_do_not_starve_running_projects_or_workspaces() {
    let db = Db::open_memory().await.unwrap();
    for org in ["workspace-a", "workspace-b"] {
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(org), json!(org), json!(1)]).await.unwrap();
    }
    for (app, org) in [("locked", "workspace-a"), ("sibling", "workspace-a"), ("unrelated", "workspace-b")] {
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(app), json!(org), json!(app), json!(1)]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)", &[json!(app), json!(app), json!(app), json!(openwarp_crypto::encrypt_symmetric(&[7; 32], &[9; 32])), json!(1)]).await.unwrap();
    }
    let (live, _) = tokio::sync::broadcast::channel(16);
    let st = new_state(db, String::new(), "emergency-merge".into(), String::new(), [7; 32], live, #[cfg(feature = "redis-cache")] None);
    let db = st.db();
    seed_lease(db, "control", "sibling", 1).await;
    let future = openwarp_server::clock::now() + 86400;
    seed_lease(db, "not-expired", "unrelated", future).await;
    process_maintenance(&st).await;
    assert_eq!(revoked(db, "control").await, 1, "generic expired leases must be reaped without an external provider");
    assert_eq!(revoked(db, "not-expired").await, 0, "unexpired leases must stay active");

    db.exec("UPDATE apps SET emergency_locked=1 WHERE id=?", &[json!("locked")]).await.unwrap();
    for index in 0..50 { seed_lease(db, &format!("blocked-{index}"), "locked", 10 + index).await; }
    seed_lease(db, "sibling-expired", "sibling", 100).await;
    seed_lease(db, "unrelated-expired", "unrelated", 101).await;
    process_maintenance(&st).await;
    let blocked = db.one("SELECT COUNT(*) AS n FROM leases WHERE env_id=? AND revoked=0", &[json!("locked")]).await.unwrap().unwrap();
    assert_eq!(db::n(&blocked, "n"), 50, "lockdown must continue to pause every lease in the locked project");
    assert_eq!(revoked(db, "not-expired").await, 0, "maintenance must not revoke an unrelated future lease");
    assert_eq!((revoked(db, "sibling-expired").await, revoked(db, "unrelated-expired").await), (1, 1), "50 older locked leases must not starve expired leases in a running sibling project or another workspace");

    db.exec("UPDATE apps SET emergency_locked=0 WHERE id=?", &[json!("locked")]).await.unwrap();
    process_maintenance(&st).await;
    let remaining = db.one("SELECT COUNT(*) AS n FROM leases WHERE env_id=? AND revoked=0", &[json!("locked")]).await.unwrap().unwrap();
    assert_eq!(db::n(&remaining, "n"), 0, "restoration must let paused expired leases resume revocation");
}

fn assert_visible_chain(body: &Value) {
    let mut rows: Vec<_> = body.as_array().expect("audit rows").iter().filter(|row| row["seq"].as_i64().unwrap_or(0) > 0).collect();
    rows.sort_by_key(|row| row["seq"].as_i64().unwrap());
    assert!(rows.len() >= 2, "fixture must contain linked audit rows");
    let mut previous = String::new();
    for row in rows {
        assert_eq!(row["prev_hash"].as_str(), Some(previous.as_str()), "unlocked audit rows must expose their chain links");
        let payload = json!([previous, row["seq"], row["org_id"], row["app_id"], row["env_id"], row["actor"], row["action"], row["detail"], row["created_at"]]);
        let computed = format!("{:x}", Sha256::digest(payload.to_string().as_bytes()));
        assert_eq!(row["hash"].as_str(), Some(computed.as_str()), "unlocked audit hashes must remain independently verifiable");
        previous = computed;
    }
}

async fn audit_hashes_hidden_during_lockdown(project: bool) {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let member = s.register("member@test.invalid").await; let mt = field(&member, "token");
    assert_eq!(s.call(Method::POST, &format!("/api/orgs/{org}/members"), Some(&ot), Some(json!({"email": "member@test.invalid", "role": "developer"}))).await.status, 200, "membership setup");
    let r = s.call(Method::POST, &format!("/api/orgs/{org}/apps"), Some(&ot), Some(json!({"name": "project"}))).await;
    assert_eq!(r.status, 200, "project setup"); let app = field(&r.body, "id");
    let url = "https://fixture-user:fixture-password@example.invalid/rotate?token=fixture-hook-secret";
    assert_eq!(s.call(Method::PUT, &format!("/api/orgs/{org}/rotation-hook"), Some(&ot), Some(json!({"url": url}))).await.status, 200, "credential-bearing audit event setup");
    let audit = format!("/api/orgs/{org}/audit"); let verify = format!("{audit}/verify");
    let before = s.call(Method::GET, &audit, Some(&mt), None).await;
    assert_eq!(before.status, 200, "unlocked member audit access");
    assert!(before.body.as_array().unwrap().iter().any(|row| row["action"] == "rotation_hook.set" && row["detail"] == url), "fixture must contain sensitive detail covered by the chain");
    assert_visible_chain(&before.body);
    let r = s.call(Method::GET, &verify, Some(&ot), None).await;
    assert_eq!(r.status, 200); assert_eq!(r.body["ok"], json!(true), "unlocked server-side chain verification");

    let lock = if project { format!("/api/apps/{app}/emergency") } else { format!("/api/orgs/{org}/emergency") };
    assert_eq!(s.call(Method::PUT, &lock, Some(&ot), Some(json!({"locked": true}))).await.status, 200, "owner cookie activates lockdown");
    let fresh_member = s.login("member@test.invalid").await;
    let mut exposed = Vec::new();
    for (role, token) in [("owner", ot.as_str()), ("member", fresh_member.as_str())] {
        let r = s.call(Method::GET, &audit, Some(token), None).await;
        assert_eq!(r.status, 200, "locked audit metadata remains inspectable by {role}");
        let rows = r.body.as_array().expect("locked audit rows");
        assert!(rows.iter().any(|row| row["action"] == "rotation_hook.set"), "redaction must retain the credential-bearing event's metadata");
        assert!(rows.len() > before.body.as_array().unwrap().len(), "lock activation must add a successor to the sensitive audit chain");
        for row in rows {
            assert_eq!(row["detail"], json!(""), "locked audit detail stays redacted");
            for key in ["hash", "prev_hash"] {
                if !row[key].is_null() && row[key] != json!("") { exposed.push((role, key)); }
            }
        }
    }
    assert!(exposed.is_empty(), "locked audit must hide both hashes on every row, including successor links; exposed fields: {exposed:?}");

    assert_eq!(s.call(Method::PUT, &lock, Some(&ot), Some(json!({"locked": false}))).await.status, 200, "owner cookie restores access");
    let restored = s.call(Method::GET, &audit, Some(&fresh_member), None).await;
    assert_eq!(restored.status, 200); assert_visible_chain(&restored.body);
    let r = s.call(Method::GET, &verify, Some(&ot), None).await;
    assert_eq!(r.status, 200); assert_eq!(r.body["ok"], json!(true), "redaction must not alter the stored audit chain");
}

#[tokio::test]
async fn merge_workspace_lockdown_hides_audit_hash_guess_oracles() { audit_hashes_hidden_during_lockdown(false).await; }

#[tokio::test]
async fn merge_project_lockdown_hides_audit_hash_guess_oracles() { audit_hashes_hidden_during_lockdown(true).await; }
