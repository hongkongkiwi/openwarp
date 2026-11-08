// Unscoped disclosure relays must honor every lockdown affecting the session's workspaces.
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
const OWNER: &str = "health-lockdown-owner-session-fixture";
const OTHER: &str = "health-lockdown-other-session-fixture";
const RELAYS: [&str; 3] = ["/api/me/secret-health/email", "/api/me/secret-health/enzoic/password", "/api/me/secret-health/leakcheck"];

struct Server { child: Child, base: String, dir: PathBuf, client: Client }

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill(); let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-secret-health-lockdown-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
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
        panic!("server did not become healthy");
    }

    fn seed(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let db = rusqlite::Connection::open(self.dir.join("test.db")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        for (uid, org, session) in [("health-owner", "health-workspace", OWNER), ("health-other", "other-workspace", OTHER)] {
            db.execute("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,'','','',?,1,1)", rusqlite::params![uid, format!("{}@example.test", uid), now]).unwrap();
            db.execute("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", rusqlite::params![openwarp_crypto::hash_token(session), uid, now]).unwrap();
            db.execute("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", rusqlite::params![org, org, now]).unwrap();
            db.execute("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')", rusqlite::params![org, uid]).unwrap();
        }
        for (app, org) in [("health-running-project", "health-workspace"), ("health-halted-project", "health-workspace"), ("other-project", "other-workspace")] {
            db.execute("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", rusqlite::params![app, org, app, now]).unwrap();
        }
    }

    async fn call(&self, method: Method, path: &str, session: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self.client.request(method, format!("{}{}", self.base, path))
            .header("cookie", format!("ow_session={}", session)).header("origin", &self.base);
        if let Some(body) = body { req = req.json(&body); }
        let r = req.send().await.expect("HTTP request"); let status = r.status().as_u16();
        (status, r.json().await.expect("JSON response"))
    }

    async fn missing_consent(&self, session: &str) {
        for path in RELAYS {
            let r = self.call(Method::POST, path, session, Some(json!({}))).await;
            assert_eq!(r.0, 400, "unhalted session must reach consent validation at {}", path);
            assert_eq!(r.1["error"], json!("explicit consent required"), "no provider call is authorized at {}", path);
        }
    }

    async fn account_settings(&self) {
        for path in ["/api/me", "/api/me/mfa"] {
            assert_eq!(self.call(Method::GET, path, OWNER, None).await.0, 200, "lockdown must retain normal account access at {}", path);
        }
        for (path, clear, expected) in [
            ("/api/me/secret-health", json!({"api_key":null}), json!({"api_key_set":false})),
            ("/api/me/secret-health/enzoic", json!({"api_key":null,"api_secret":null}), json!({"configured":false})),
        ] {
            assert_eq!(self.call(Method::GET, path, OWNER, None).await, (200, expected.clone()), "personal credential status is not a disclosure relay");
            assert_eq!(self.call(Method::PUT, path, OWNER, Some(clear)).await, (200, expected), "lockdown must not prevent clearing personal credentials");
        }
    }
}

#[tokio::test]
async fn unlocked_secret_health_relays_require_consent_without_provider_calls() {
    let s = Server::start().await;
    s.missing_consent(OWNER).await;
    s.missing_consent(OTHER).await;
    s.account_settings().await;
}

async fn locked_relays(project: bool) {
    let s = Server::start().await;
    s.missing_consent(OWNER).await;
    let path = if project { "/api/apps/health-halted-project/emergency" } else { "/api/orgs/health-workspace/emergency" };
    let r = s.call(Method::PUT, path, OWNER, Some(json!({"locked":true}))).await;
    assert_eq!(r.0, 200, "owner cookie must activate lockdown");
    assert_eq!(r.1["locked"], json!(true));
    if project {
        let r = s.call(Method::GET, "/api/apps/health-running-project/emergency", OWNER, None).await;
        assert_eq!(r.0, 200);
        assert_eq!(r.1["locked"], json!(false), "a different project remains running, but cannot scope these account-level relays");
    }
    s.account_settings().await;
    s.missing_consent(OTHER).await;

    let mut actual = Vec::new(); let mut expected = Vec::new();
    for relay in RELAYS {
        // Both bodies stop before provider work even when the lockdown guard is absent.
        for (label, body) in [("missing consent", json!({})), ("invalid payload", json!({"consent":true}))] {
            actual.push((relay, label, s.call(Method::POST, relay, OWNER, Some(body)).await.0));
            expected.push((relay, label, 423));
        }
    }
    let r = s.call(Method::PUT, path, OWNER, Some(json!({"locked":false}))).await;
    assert_eq!(r.0, 200, "retained owner session must restore lockdown");
    assert_eq!(r.1["locked"], json!(false));
    s.missing_consent(OWNER).await;
    assert_eq!(actual, expected, "unscoped secret health disclosure must be rejected before consent or payload validation while any member workspace or project is halted");
}

#[tokio::test]
async fn workspace_lockdown_blocks_all_secret_health_relays_before_validation() { locked_relays(false).await; }

#[tokio::test]
async fn any_project_lockdown_blocks_all_secret_health_relays_before_validation() { locked_relays(true).await; }
