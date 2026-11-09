use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
const OWNER: &str = "delayed-health-owner-session-fixture";
const OTHER: &str = "delayed-health-other-session-fixture";
const RELAYS: [&str; 2] = ["/api/me/secret-health/enzoic/accounts", "/api/me/secret-health/enzoic/credentials"];

struct Server { child: Child, base: String, dir: PathBuf, client: Client }

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill(); let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-delayed-health-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).expect("private database directory");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port");
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("OPENWARP_") || key == "REDIS_URL" { cmd.env_remove(key); }
        }
        let child = cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "1")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() { s.seed(); return s; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { return Box::pin(Server::start()).await; }
        panic!("server did not become healthy");
    }

    fn seed(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let db = rusqlite::Connection::open(self.dir.join("test.db")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        for (uid, org, session) in [("delayed-owner", "delayed-workspace", OWNER), ("delayed-other", "other-workspace", OTHER)] {
            db.execute("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,'','','',?,1,1)", rusqlite::params![uid, format!("{}@example.test", uid), now]).unwrap();
            db.execute("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", rusqlite::params![openwarp_crypto::hash_token(session), uid, now]).unwrap();
            db.execute("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", rusqlite::params![org, org, now]).unwrap();
            db.execute("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", rusqlite::params![org, uid]).unwrap();
        }
        db.execute("INSERT INTO apps(id,org_id,name,created_at) VALUES('delayed-project','delayed-workspace','Delayed project',?)", [now]).unwrap();
    }

    async fn call(&self, method: Method, path: &str, session: &str, body: Value) -> (u16, Value) {
        let r = self.client.request(method, format!("{}{}", self.base, path))
            .header("cookie", format!("ow_session={}", session)).header("origin", &self.base)
            .json(&body).send().await.expect("HTTP request");
        let status = r.status().as_u16();
        (status, r.json().await.expect("JSON response"))
    }

    async fn hold_body(&self, path: &str) -> TcpStream {
        tokio::time::timeout(Duration::from_secs(5), async {
            let addr = self.base.strip_prefix("http://").unwrap();
            let mut stream = TcpStream::connect(addr).await.expect("connect delayed request");
            let headers = format!("POST {} HTTP/1.1\r\nHost: {}\r\nCookie: ow_session={}\r\nOrigin: {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", path, addr, OWNER, self.base);
            stream.write_all(headers.as_bytes()).await.expect("send headers without body");
            // Hyper sends Continue only after the application polls the body, past ingress middleware.
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(stream.read_u8().await.expect("read Continue response"));
                assert!(response.len() <= 8192, "bounded Continue headers");
            }
            assert_eq!(String::from_utf8(response).unwrap(), "HTTP/1.1 100 Continue\r\n\r\n", "request must reach body extraction before lockdown");
            stream
        }).await.expect("server must acknowledge body extraction before lockdown")
    }
}

async fn finish_body(mut stream: TcpStream) -> (u16, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        // Missing consent stops before credential lookup, quota consumption, or provider egress.
        stream.write_all(b"{}").await.expect("complete delayed JSON body");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.expect("read final response");
        let response = String::from_utf8(bytes).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").expect("HTTP response headers");
        let status = headers.split_whitespace().nth(1).unwrap().parse().expect("HTTP status");
        (status, serde_json::from_str(body).expect("JSON error body"))
    }).await.expect("delayed request must complete")
}

#[tokio::test]
async fn delayed_pair_bodies_without_lockdown_still_require_consent() {
    let s = Server::start().await;
    for path in RELAYS {
        let stream = s.hold_body(path).await;
        assert_eq!(finish_body(stream).await, (400, json!({"error":"explicit consent required"})), "unlocked delayed request at {}", path);
    }
}

async fn lockdown_during_body(project: bool) {
    let s = Server::start().await;
    let mut held = Vec::new();
    for path in RELAYS { held.push((path, s.hold_body(path).await)); }
    let emergency = if project { "/api/apps/delayed-project/emergency" } else { "/api/orgs/delayed-workspace/emergency" };
    let locked = s.call(Method::PUT, emergency, OWNER, json!({"locked":true})).await;
    assert_eq!(locked.0, 200, "retained owner cookie must activate lockdown");
    assert_eq!(locked.1["locked"], json!(true));
    for path in RELAYS {
        assert_eq!(s.call(Method::POST, path, OTHER, json!({})).await, (400, json!({"error":"explicit consent required"})), "unrelated workspace must remain unaffected");
    }
    let mut actual = Vec::new();
    for (path, stream) in held { actual.push((path, finish_body(stream).await)); }
    let restored = s.call(Method::PUT, emergency, OWNER, json!({"locked":false})).await;
    assert_eq!(restored.0, 200, "owner session must survive lockdown");
    assert_eq!(restored.1["locked"], json!(false));
    for path in RELAYS {
        assert_eq!(s.call(Method::POST, path, OWNER, json!({})).await, (400, json!({"error":"explicit consent required"})), "restoration must retain ordinary consent validation");
    }
    assert!(actual.iter().all(|(_, (status, _))| *status == 423), "lockdown activated after body extraction began must reject both pair relays before consent validation: {:?}", actual);
}

#[tokio::test]
async fn workspace_lockdown_after_ingress_blocks_delayed_pair_bodies() { lockdown_during_body(false).await; }

#[tokio::test]
async fn project_lockdown_after_ingress_blocks_delayed_pair_bodies() { lockdown_during_body(true).await; }
