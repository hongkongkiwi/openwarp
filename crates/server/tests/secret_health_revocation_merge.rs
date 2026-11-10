// A session revoked after authentication must not finish secret health work it
// queued: no provider dispatch, no credential settings write.
use axum::body::{to_bytes, Body};
use axum::http::Request;
use openwarp_crypto as oc;
use openwarp_server::db::Db;
use openwarp_server::{new_state, router, PeerAddr, S};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;

static SEQ: AtomicU32 = AtomicU32::new(0);
const MASTER: [u8; 32] = [7; 32];

// The relay clients build plain reqwest clients, which honor HTTPS_PROXY, so a
// loopback listener receives any provider dispatch instead of the real host.
struct ProxyEnv { https: Option<String>, no_proxy: Option<String>, no_proxy_lower: Option<String> }
impl ProxyEnv {
    fn install(proxy: &str) -> Self {
        let env = Self { https: std::env::var("HTTPS_PROXY").ok(), no_proxy: std::env::var("NO_PROXY").ok(), no_proxy_lower: std::env::var("no_proxy").ok() };
        std::env::set_var("HTTPS_PROXY", proxy);
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
        env
    }
}
impl Drop for ProxyEnv {
    fn drop(&mut self) {
        match &self.https { Some(v) => std::env::set_var("HTTPS_PROXY", v), None => std::env::remove_var("HTTPS_PROXY") }
        match &self.no_proxy { Some(v) => std::env::set_var("NO_PROXY", v), None => std::env::remove_var("NO_PROXY") }
        match &self.no_proxy_lower { Some(v) => std::env::set_var("no_proxy", v), None => std::env::remove_var("no_proxy") }
    }
}

struct Fixture { state: S, app: axum::Router, dir: PathBuf }

impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

impl Fixture {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-sh-revocation-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).expect("private database directory");
        let db = Db::open(&format!("sqlite://{}/test.db", dir.display())).await.expect("open sqlite fixture");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        for uid in ["relay-victim", "save-victim", "active-control"] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,'','','',?,1,1)", &[json!(uid), json!(format!("{}@example.test", uid)), json!(now)]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&format!("{}-session-fixture", uid))), json!(uid), json!(now)]).await.unwrap();
        }
        let credentials = oc::encrypt_symmetric(&MASTER, json!({"api_key":"local-fixture-key","api_secret":"local-fixture-secret"}).to_string().as_bytes());
        for uid in ["relay-victim", "active-control"] {
            db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(format!("enzoic_credentials:{}", uid)), json!(credentials)]).await.unwrap();
        }
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite-fixture".into(), "tests".into(), "https://openwarp.test".into(), MASTER, live, #[cfg(feature = "redis-cache")] None);
        let app = router(state.clone());
        Self { state, app, dir }
    }

    fn request(&self, method: &str, path: &str, uid: &str, body: Value) -> Request<Body> {
        Request::builder().method(method).uri(path).header("host", "openwarp.test").extension(PeerAddr(std::net::IpAddr::from([127, 0, 0, 1])))
            .header("cookie", format!("ow_session={}-session-fixture", uid))
            .header("host", "openwarp.test")
            .header("origin", "https://openwarp.test")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())).expect("request body")
    }

    async fn call(&self, method: &str, path: &str, uid: &str, body: Value) -> (u16, Value) {
        let response = self.app.clone().oneshot(self.request(method, path, uid, body)).await.expect("control response");
        reply(response).await
    }

    // A victim runs on a dedicated runtime thread because it parks inside a
    // blocking SQLite call while holding the credential mutex; that must never
    // stall the runtime driving the test.
    fn spawn_victim(&self, method: &str, path: &str, uid: &str, body: Value) -> std::sync::mpsc::Receiver<(u16, Value)> {
        let (tx, rx) = std::sync::mpsc::channel();
        let app = self.app.clone();
        let request = self.request(method, path, uid, body);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("victim runtime");
            runtime.block_on(async move {
                let response = app.oneshot(request).await.expect("victim response");
                let _ = tx.send(reply(response).await);
            });
        });
        rx
    }

    // The revoker holds the WAL write lock, so the victim's first write blocks
    // inside the handler while holding the single SQLite connection. A stable
    // hold proves the victim authenticated and parked; reads only hold the
    // connection for microseconds. A fix that revalidates before that write
    // denies the victim early instead, which also satisfies this test.
    async fn wait_parked(&self, victim: &std::sync::mpsc::Receiver<(u16, Value)>) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut held_since: Option<Instant> = None;
        while Instant::now() < deadline {
            let held = match self.state.db() { Db::Sqlite(c) => c.try_lock().is_err(), _ => panic!("fixture must use sqlite") };
            held_since = if held { held_since.or_else(|| Some(Instant::now())) } else { None };
            if held_since.is_some_and(|t| t.elapsed() > Duration::from_millis(250)) { return true; }
            if let Ok((status, body)) = victim.try_recv() {
                assert_eq!(status, 401, "victim failed before parking: {} {}", status, body);
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("victim neither parked in a database operation nor completed");
    }

    fn revoker(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.dir.join("test.db")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
}

async fn reply(response: axum::response::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))))
}

// Count and immediately cut any provider connection: the relay maps the failed
// dispatch to a 502 instead of waiting out its client timeout.
async fn fake_provider(listener: tokio::net::TcpListener, dispatches: Arc<AtomicU8>) {
    loop {
        let (mut stream, _) = match listener.accept().await { Ok(pair) => pair, Err(_) => return };
        dispatches.fetch_add(1, Ordering::SeqCst);
        let _ = stream.shutdown().await;
    }
}

#[tokio::test]
async fn revoked_sessions_cannot_finish_queued_secret_health_work() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("fake provider listener");
    let port = listener.local_addr().unwrap().port();
    let dispatches = Arc::new(AtomicU8::new(0));
    // The listener needs its own thread: the test blocks on synchronous
    // receives while victims run, and a parked provider connection must still
    // be accepted and cut immediately.
    {
        let dispatches = dispatches.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("listener runtime");
            runtime.block_on(fake_provider(listener, dispatches));
        });
    }
    let _proxy = ProxyEnv::install(&format!("http://127.0.0.1:{}", port));
    let f = Fixture::new().await;

    // Positive control: a live session still authenticates late and dispatches.
    let (status, body) = f.call("POST", "/api/me/secret-health/enzoic/password", "active-control", json!({"prefix":"aaaaaaaaaa","consent":true})).await;
    assert_ne!(status, 401, "live session must pass the late revalidation: {} {}", status, body);
    assert_eq!(dispatches.load(Ordering::SeqCst), 1, "live session must dispatch through the fake provider");

    // Relay victim: authenticates, drops the credential guard after decrypting,
    // then parks at the quota write that immediately precedes egress. Revoking
    // while it parks must stop the provider dispatch after it resumes.
    let revoker = f.revoker();
    revoker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let relay = f.spawn_victim("POST", "/api/me/secret-health/enzoic/password", "relay-victim", json!({"prefix":"bbbbbbbbbb","consent":true}));
    if f.wait_parked(&relay).await {
        revoker.execute("DELETE FROM sessions WHERE user_id='relay-victim'", []).unwrap();
        revoker.execute_batch("COMMIT").unwrap();
        let (status, body) = relay.recv_timeout(Duration::from_secs(20)).expect("relay victim completes");
        assert_eq!(status, 401, "relay queued before revocation must reauthenticate before egress: {} {}", status, body);
    } else { revoker.execute_batch("ROLLBACK").unwrap(); }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dispatches.load(Ordering::SeqCst), 1, "revoked session must not dispatch to the provider");

    // Save victim: authenticates, takes the credential guard, then parks inside
    // the guarded credential write. Revoking while it parks must stop the write.
    let revoker = f.revoker();
    revoker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let save = f.spawn_victim("PUT", "/api/me/secret-health/enzoic", "save-victim", json!({"api_key":"revoked-fixture-key","api_secret":"revoked-fixture-secret"}));
    if f.wait_parked(&save).await {
        revoker.execute("DELETE FROM sessions WHERE user_id='save-victim'", []).unwrap();
        revoker.execute_batch("COMMIT").unwrap();
        let (status, body) = save.recv_timeout(Duration::from_secs(20)).expect("save victim completes");
        assert_eq!(status, 401, "queued credential save must reauthenticate after the guard: {} {}", status, body);
    } else { revoker.execute_batch("ROLLBACK").unwrap(); }
    let stored: i64 = f.revoker().query_row("SELECT COUNT(*) FROM meta WHERE k='enzoic_credentials:save-victim'", [], |r| r.get(0)).unwrap();
    assert_eq!(stored, 0, "revoked session must not write credential settings");
}
