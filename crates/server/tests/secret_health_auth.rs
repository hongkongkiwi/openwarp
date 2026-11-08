// Session authentication boundaries without signup mail or external provider calls.
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
const SESSION: &str = "secret-health-auth-session-fixture";
const SETTINGS: [&str; 2] = ["/api/me/secret-health", "/api/me/secret-health/enzoic"];
const RELAYS: [&str; 3] = ["/api/me/secret-health/email", "/api/me/secret-health/enzoic/password", "/api/me/secret-health/leakcheck"];

struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    async fn start() -> Self {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-secret-health-auth-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("private database directory");
        let port = TcpListener::bind("127.0.0.1:0").expect("bind port").local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{}", port);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("OPENWARP_") || key == "REDIS_URL" { cmd.env_remove(key); }
        }
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() { s.seed_session(); return s; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }

    fn db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.dir.join("test.db")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }

    fn seed_session(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let db = self.db();
        db.execute("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active) VALUES('health-user','health@example.test','','','',?,1)", [now]).unwrap();
        db.execute("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'health-user',?)", rusqlite::params![openwarp_crypto::hash_token(SESSION), now]).unwrap();
    }

    async fn call(&self, method: Method, path: &str, bearer: Option<&str>, cookie: bool, body: Option<Value>) -> (u16, Value) {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = bearer { req = req.bearer_auth(token); }
        if cookie { req = req.header("cookie", format!("ow_session={}", SESSION)); }
        if let Some(body) = body { req = req.json(&body); }
        let response = req.send().await.expect("HTTP request");
        let status = response.status().as_u16();
        let body = response.json().await.expect("JSON response");
        (status, body)
    }
}

#[tokio::test]
async fn active_sessions_can_read_secret_health_settings() {
    let s = Server::start().await;
    for (path, body) in SETTINGS.into_iter().zip([json!({"api_key_set":false}), json!({"configured":false})]) {
        assert_eq!(s.call(Method::GET, path, None, false, None).await.0, 401, "anonymous GET {}", path);
        assert_eq!(s.call(Method::GET, path, Some(SESSION), false, None).await, (200, body.clone()), "Bearer GET {}", path);
        assert_eq!(s.call(Method::GET, path, None, true, None).await, (200, body), "cookie GET {}", path);
    }
}

#[tokio::test]
async fn invalid_bearer_does_not_fall_back_to_cookie_for_secret_health() {
    let s = Server::start().await;
    assert_eq!(s.call(Method::GET, "/api/me", Some("invalid-bearer-fixture"), true, None).await.0, 401);
    let mut actual = Vec::new();
    for path in SETTINGS {
        actual.push((path, s.call(Method::GET, path, Some("invalid-bearer-fixture"), true, None).await.0));
    }
    assert_eq!(actual, SETTINGS.map(|path| (path, 401)), "a nonempty Bearer credential must take precedence over the session cookie");
}

#[tokio::test]
async fn inactive_sessions_cannot_manage_settings_or_use_secret_health_relays() {
    let s = Server::start().await;
    assert_eq!(s.call(Method::GET, "/api/me", Some(SESSION), false, None).await.0, 200);
    assert_eq!(s.db().execute("UPDATE users SET active=0 WHERE id='health-user'", []).unwrap(), 1);
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (credential, bearer, cookie) in [("Bearer", Some(SESSION), false), ("cookie", None, true)] {
        assert_eq!(s.call(Method::GET, "/api/me", bearer, cookie, None).await.0, 401, "inactive {} session control", credential);
        for path in SETTINGS {
            for method in [Method::GET, Method::PUT] {
                let body = if method == Method::PUT {
                    Some(if path == SETTINGS[0] { json!({"api_key":null}) } else { json!({"api_key":null,"api_secret":null}) })
                } else { None };
                let label = format!("{} {} {}", credential, method, path);
                actual.push((label.clone(), s.call(method, path, bearer, cookie, body).await.0));
                expected.push((label, 401));
            }
        }
        for path in RELAYS {
            // No consent or provider keys: even a broken auth gate cannot send a provider request.
            let label = format!("{} POST {}", credential, path);
            actual.push((label.clone(), s.call(Method::POST, path, bearer, cookie, Some(json!({}))).await.0));
            expected.push((label, 401));
        }
    }
    assert_eq!(actual, expected, "inactive sessions must be rejected before settings access or relay validation");
}
