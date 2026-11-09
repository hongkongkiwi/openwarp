// Vault-style secret and lease semantics: check-and-set writes, version
// retention, undelete/destroy, single-use wrapping tokens, lease lookup and
// audit-chain verification. Each test owns a private database.

use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::fs::File;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp {
    status: u16,
    text: String,
    body: Value,
}

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

fn free_port() -> u16 {
    // True ephemeral: the OS never hands out a port that is still bound, so
    // parallel test binaries cannot converge the way a PID-derived scan
    // does. The only residual hazard is the gap between dropping this
    // listener and the child binding it, which the startup retry covers.
    TcpListener::bind("127.0.0.1:0").expect("ephemeral port").local_addr().expect("local addr").port()
}

impl Server {
    async fn start() -> Server {
        // Parallel tests in this binary must not race for the same port.
        let _start = START_LOCK.lock().await;
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-semantics-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let log = File::create(dir.join("server.log")).expect("server log");
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("OPENWARP_EMAIL_PROVIDER")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY")
            .env_remove("OPENWARP_ALLOWED_DB_HOSTS")
            .env_remove("OPENWARP_ENV")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn openwarp-server");
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        let server = Server { child, base, dir, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() {
                    return server;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { drop(_start); return Box::pin(Server::start()).await; }
        panic!("server did not become healthy at {}", server.base);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
    }

    async fn wait_link(&self, needle: &str) -> String {
        for _ in 0..200 {
            let log = self.log();
            if let Some(at) = log.find(needle) {
                return log[at..].split_whitespace().next().unwrap_or("").to_string();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no log link containing {needle:?}");
    }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let response = req.send().await.expect("http request");
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body }
    }
}

async fn register(s: &Server, email: &str) -> Value {
    let r = s
        .call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"})))
        .await;
    assert_eq!(r.status, 200, "register failed: {}", r.text);
    let mut body = r.body.clone();
    if body["verification_required"] == json!(true) {
        let link = s.wait_link("/api/auth/verify?token=").await;
        let path = link.strip_prefix(&s.base).unwrap_or(&link).to_string();
        let verified = s.call(Method::GET, &path, None, None).await;
        assert_eq!(verified.status, 200, "verification failed: {}", verified.text);
        let login = s
            .call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"})))
            .await;
        assert_eq!(login.status, 200, "login failed: {}", login.text);
        body["token"] = login.body["token"].clone();
        body["user_id"] = login.body["user_id"].clone();
        if body.get("org_id").is_none() { body["org_id"] = login.body["org_id"].clone(); }
    }
    body
}

/// Owner token, organisation id and the first default environment.
async fn bootstrap(s: &Server, email: &str) -> (String, String, String) {
    let user = register(s, email).await;
    let token = user["token"].as_str().expect("token").to_string();
    let org = user["org_id"].as_str().expect("org id").to_string();
    let r = s.call(Method::POST, &format!("/api/orgs/{org}/apps"), Some(&token), Some(json!({"name": "app"}))).await;
    assert_eq!(r.status, 200, "create app failed: {}", r.text);
    let app = r.body["id"].as_str().expect("app id").to_string();
    let r = s.call(Method::GET, &format!("/api/apps/{app}/envs"), Some(&token), None).await;
    let env = r.body.as_array().expect("env list")[0]["id"].as_str().expect("env id").to_string();
    (token, org, env)
}

async fn put_secret(s: &Server, token: &str, env: &str, value: &str, expected: Option<i64>) -> Resp {
    let mut secret = json!({"key": "CASKEY", "value": value});
    if let Some(v) = expected {
        secret["expected_version"] = json!(v);
    }
    s.call(Method::PUT, &format!("/api/envs/{env}/secrets"), Some(token), Some(json!({"secrets": [secret]})))
        .await
}

#[tokio::test]
async fn cas_rejects_a_stale_write() {
    let s = Server::start().await;
    let (token, _, env) = bootstrap(&s, "cas@test.invalid").await;

    assert_eq!(put_secret(&s, &token, &env, "v1", Some(0)).await.status, 200);
    let stale = put_secret(&s, &token, &env, "v2", Some(0)).await;
    assert_eq!(stale.status, 409, "create-only write must not replace: {}", stale.text);
    assert_eq!(put_secret(&s, &token, &env, "v2", Some(1)).await.status, 200);
    let stale = put_secret(&s, &token, &env, "v3", Some(1)).await;
    assert_eq!(stale.status, 409, "a stale version must lose: {}", stale.text);

    let r = s.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&token), None).await;
    let item = r.body["secrets"].as_array().expect("secrets")[0].clone();
    assert_eq!(item["value"], json!("v2"));
    assert_eq!(item["version"], json!(2));
}

#[tokio::test]
async fn retention_undelete_and_destroy() {
    let s = Server::start().await;
    let (token, _, env) = bootstrap(&s, "versions@test.invalid").await;

    let r = s.call(Method::PUT, &format!("/api/envs/{env}/policy"), Some(&token), Some(json!({"max_versions": 2}))).await;
    assert_eq!(r.status, 200, "policy failed: {}", r.text);
    for version in 0..4 {
        let r = put_secret(&s, &token, &env, &format!("v{}", version + 1), Some(version)).await;
        assert_eq!(r.status, 200, "write {version} failed: {}", r.text);
    }

    let r = s.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&token), None).await;
    let item = r.body["secrets"].as_array().expect("secrets")[0].clone();
    let sid = item["id"].as_str().expect("secret id").to_string();
    assert_eq!(item["version"], json!(4));

    let r = s.call(Method::GET, &format!("/api/secrets/{sid}/history"), Some(&token), None).await;
    let history = r.body.as_array().expect("history");
    assert_eq!(history.len(), 2, "max_versions=2 must retain two rows");
    assert_eq!(history[0]["version"], json!(4));
    assert_eq!(history[1]["version"], json!(3));

    let r = s.call(Method::DELETE, &format!("/api/secrets/{sid}"), Some(&token), None).await;
    assert_eq!(r.status, 200, "delete failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&token), None).await;
    assert!(r.body["secrets"].as_array().expect("secrets").is_empty(), "deleted secrets stay hidden");

    let r = s.call(Method::POST, &format!("/api/secrets/{sid}/undelete"), Some(&token), None).await;
    assert_eq!(r.status, 200, "undelete failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&token), None).await;
    assert_eq!(r.body["secrets"].as_array().expect("secrets").len(), 1);

    let r = s.call(Method::POST, &format!("/api/secrets/{sid}/destroy"), Some(&token), None).await;
    assert_eq!(r.status, 200, "destroy failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/secrets/{sid}/history"), Some(&token), None).await;
    assert!(r.status == 400 || r.status == 404, "destroyed secret has no history: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&token), None).await;
    assert!(r.body["secrets"].as_array().expect("secrets").is_empty());
}

#[tokio::test]
async fn wrap_token_is_single_use() {
    let s = Server::start().await;
    let (token, _, env) = bootstrap(&s, "wrap@test.invalid").await;
    let r = s
        .call(Method::PUT, &format!("/api/envs/{env}/secrets"), Some(&token), Some(json!({"secrets": [{"key": "WRAPME", "value": "handoff"}]})))
        .await;
    assert_eq!(r.status, 200, "secret failed: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/envs/{env}/wrap"), Some(&token), Some(json!({"ttl_secs": 300}))).await;
    assert_eq!(r.status, 200, "wrap failed: {}", r.text);
    let wrapped = r.body["token"].as_str().expect("wrapping token").to_string();

    let lookup = s.call(Method::GET, "/api/unwrap", Some(&wrapped), None).await;
    assert_eq!(lookup.status, 200, "lookup failed: {}", lookup.text);
    assert_eq!(lookup.body["used"], json!(false));

    let redeemed = s.call(Method::POST, "/api/unwrap", Some(&wrapped), None).await;
    assert_eq!(redeemed.status, 200, "unwrap failed: {}", redeemed.text);
    assert_eq!(redeemed.body["secrets"]["WRAPME"], json!("handoff"));

    let again = s.call(Method::POST, "/api/unwrap", Some(&wrapped), None).await;
    assert_eq!(again.status, 404, "a wrapping token must redeem once: {}", again.text);

    let me = s.call(Method::GET, "/api/me", Some(&wrapped), None).await;
    assert_ne!(me.status, 200, "a wrapping token is not an API credential");
}

#[tokio::test]
async fn lease_lookup_reports_state() {
    let s = Server::start().await;
    let (token, _, env) = bootstrap(&s, "lease@test.invalid").await;

    let r = s
        .call(Method::POST, &format!("/api/envs/{env}/dynamic"), Some(&token), Some(json!({"name": "ephemeral", "ttl_secs": 600})))
        .await;
    assert_eq!(r.status, 200, "lease failed: {}", r.text);
    let lid = r.body["id"].as_str().expect("lease id").to_string();

    let r = s.call(Method::GET, &format!("/api/leases/{lid}"), Some(&token), None).await;
    assert_eq!(r.status, 200, "lookup failed: {}", r.text);
    assert_eq!(r.body["type"], json!("generic"));
    assert_eq!(r.body["renewable"], json!(true));
    assert!(r.body.get("value").is_none(), "lookup must not return the value");

    let r = s.call(Method::DELETE, &format!("/api/leases/{lid}"), Some(&token), None).await;
    assert_eq!(r.status, 200, "revoke failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/leases/{lid}"), Some(&token), None).await;
    assert_eq!(r.body["revoked"], json!(true));
    assert_eq!(r.body["renewable"], json!(false));
}

#[tokio::test]
async fn audit_chain_verifies() {
    let s = Server::start().await;
    let (token, org, env) = bootstrap(&s, "chain@test.invalid").await;
    let r = put_secret(&s, &token, &env, "v1", Some(0)).await;
    assert_eq!(r.status, 200, "write failed: {}", r.text);

    let r = s.call(Method::GET, &format!("/api/orgs/{org}/audit/verify"), Some(&token), None).await;
    assert_eq!(r.status, 200, "verify failed: {}", r.text);
    assert_eq!(r.body["ok"], json!(true), "chain must verify: {}", r.text);
    assert!(r.body["checked"].as_i64().unwrap_or(0) >= 1, "expected chained events: {}", r.text);
    assert_eq!(r.body["first_bad"], Value::Null);
    assert_eq!(r.body["head_matches"], json!(true));
}
