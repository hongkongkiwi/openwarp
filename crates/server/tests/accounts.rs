// Account lifecycle: signup policy, invites, and Google/GitHub sign-in against
// local mock providers. Each test owns a private database and port.

use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp {
    status: u16,
    text: String,
    body: Value,
    headers: reqwest::header::HeaderMap,
}

impl Resp {
    fn header(&self, key: &str) -> String {
        self.headers.get(key).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }
}

struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
    inbox: Arc<Mutex<Vec<Value>>>,
    social_cookies: Mutex<Vec<String>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    // Parallel test binaries must not hand the same port to two servers.
    let base = 20000 + (std::process::id() % 30000) as u16;
    for offset in 0..500u16 {
        let port = base.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            return port;
        }
    }
    TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port").local_addr().expect("local addr").port()
}

impl Server {
    async fn start() -> Server {
        Server::start_env(&[]).await
    }

    async fn start_env(extra: &[(&str, String)]) -> Server {
        let _start = START_LOCK.lock().await;
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-accounts-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let (inbox_url, inbox) = start_inbox();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", &inbox_url)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_SIGNUPS")
            .env_remove("OPENWARP_GOOGLE_CLIENT_ID")
            .env_remove("OPENWARP_GITHUB_CLIENT_ID")
            .env_remove("OPENWARP_APPLE_CLIENT_ID")
            .env_remove("OPENWARP_OPENAI_CLIENT_ID")
            .env_remove("OPENWARP_MICROSOFT_CLIENT_ID")
            .env_remove("OPENWARP_OKTA_CLIENT_ID")
            .env_remove("OPENWARP_AUTH0_CLIENT_ID")
            .env_remove("OPENWARP_GITLAB_CLIENT_ID")
            .env_remove("OPENWARP_SLACK_CLIENT_ID")
            .env_remove("OPENWARP_SALESFORCE_CLIENT_ID")
            .env_remove("OPENWARP_ATLASSIAN_CLIENT_ID")
            .env_remove("OPENWARP_X_CLIENT_ID")
            .env_remove("OPENWARP_OIDC_ISSUER")
            .env_remove("OPENWARP_OIDC_CLIENT_ID")
            .env_remove("OPENWARP_OIDC_CLIENT_SECRET")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().expect("http client");
        let server = Server { child, base, dir, client, inbox, social_cookies: Mutex::new(Vec::new()) };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy at {}", server.base);
    }

    fn url(&self, path: &str) -> String { format!("{}{}", self.base, path) }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path));
        if path.starts_with("/api/auth/social/") && path.contains("/callback") {
            req = req.header("cookie", self.social_cookies.lock().unwrap().join("; ")); }
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        let response = req.send().await.expect("http request");
        if path.starts_with("/api/auth/social/") && path.ends_with("/start") {
            for cookie in response.headers().get_all("set-cookie").iter().filter_map(|h| h.to_str().ok()).filter_map(|h| h.split(';').next()).filter(|c| c.starts_with("ow_social_")) {
                self.social_cookies.lock().unwrap().push(cookie.to_string()); } }
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }

    async fn get(&self, path: &str) -> Resp { self.call(Method::GET, path, None, None).await }

    async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> Resp {
        let mut req = self.client.post(self.url(path)).form(form);
        if path.starts_with("/api/auth/social/") && path.contains("/callback") {
            req = req.header("cookie", self.social_cookies.lock().unwrap().join("; ")); }
        let response = req.send().await.expect("http form request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }
}

async fn register_raw(s: &Server, email: &str) -> Resp {
    s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await
}

/// Password signup and the verification link, as an operator with a working
/// mail relay would experience it. Returns the sign-in response.
async fn register(s: &Server, email: &str) -> Resp {
    let reg = register_raw(s, email).await;
    if reg.status != 200 || reg.body["verification_required"] != json!(true) { return reg; }
    let text = wait_for_mail(&s.inbox, "/api/auth/verify?token=").await;
    let link = extract_link(&text, "/api/auth/verify?token=");
    let path = link.strip_prefix(&s.base).unwrap_or(&link).to_string();
    let verified = s.get(&path).await;
    assert_eq!(verified.status, 200, "the verification link must work: {} {}", verified.status, verified.text);
    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 200, "a verified account must sign in: {} {}", login.status, login.text);
    let mut body = reg.body.clone();
    body["token"] = login.body["token"].clone();
    body["user_id"] = login.body["user_id"].clone();
    body["public_key"] = login.body["public_key"].clone();
    Resp { status: login.status, text: login.text, body, headers: login.headers }
}

#[tokio::test]
async fn personal_secret_health_requires_session_consent_and_isolates_encrypted_keys() {
    let s = Server::start().await;
    let path = "/api/me/secret-health";
    assert_eq!(s.get(path).await.status, 401);
    assert_eq!(s.call(Method::PUT, path, None, Some(json!({"api_key":null}))).await.status, 401);
    let a = register(&s, "health-a@example.test").await;
    let b = register(&s, "health-b@example.test").await;
    let at = a.body["token"].as_str().unwrap(); let bt = b.body["token"].as_str().unwrap();
    let key = "0123456789abcdef0123456789abcdef";
    let saved = s.call(Method::PUT, path, Some(at), Some(json!({"api_key":key}))).await;
    assert_eq!(saved.status, 200, "{}", saved.text);
    assert_eq!(saved.body, json!({"api_key_set":true}));
    assert!(!saved.text.contains(key));
    assert_eq!(s.call(Method::GET, path, Some(bt), None).await.body, json!({"api_key_set":false}));
    assert_eq!(s.call(Method::GET, path, Some(at), None).await.body, json!({"api_key_set":true}));
    let db = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    db.execute("INSERT INTO tokens(id,name,token_hash,created_at) VALUES('health-service','health',?,0)", [openwarp_crypto::hash_token("health-service-fixture")]).unwrap();
    db.execute("INSERT INTO oauth_tokens(token_hash,client_id,user_id,expires_at,created_at,scope,resource) VALUES(?,'health-client',?,9999999999,0,'secrets:read secrets:write',?)", [openwarp_crypto::hash_token("health-oauth-fixture"), a.body["user_id"].as_str().unwrap().to_string(), s.base.clone()]).unwrap();
    for token in ["health-service-fixture", "health-oauth-fixture"] {
        assert_eq!(s.call(Method::GET, path, Some(token), None).await.status, 401);
        assert_eq!(s.call(Method::PUT, path, Some(token), Some(json!({"api_key":null}))).await.status, 401);
        assert_eq!(s.call(Method::POST, "/api/me/secret-health/email", Some(token), Some(json!({"email":"fixture@example.test","consent":true}))).await.status, 401);
    }
    let stored: String = db.query_row("SELECT v FROM meta WHERE k=?", [format!("hibp_api_key:{}", a.body["user_id"].as_str().unwrap())], |r| r.get(0)).unwrap();
    assert_ne!(stored, key); assert!(!stored.contains(key));
    let master: String = db.query_row("SELECT v FROM meta WHERE k='master'", [], |r| r.get(0)).unwrap();
    let master: [u8;32] = openwarp_crypto::unb64(&master).unwrap().try_into().unwrap();
    assert_eq!(openwarp_crypto::decrypt_symmetric(&master, &stored).unwrap(), key.as_bytes());
    let cross = s.client.put(s.url(path)).bearer_auth(at).header("origin", "https://untrusted.example").json(&json!({"api_key":null})).send().await.unwrap();
    assert_eq!(cross.status().as_u16(), 403);
    for body in [json!({"email":"fixture@example.test"}), json!({"email":"fixture@example.test","consent":"true"}), json!({"email":"invalid","consent":true})] {
        assert_eq!(s.call(Method::POST, "/api/me/secret-health/email", Some(at), Some(body)).await.status, 400);
    }
    assert_eq!(s.call(Method::POST, "/api/me/secret-health/email", Some(bt), Some(json!({"email":"fixture@example.test","consent":true}))).await.status, 400);
    assert_eq!(s.call(Method::PUT, path, Some(at), Some(json!({"api_key":null}))).await.body, json!({"api_key_set":false}));
    assert_eq!(s.call(Method::GET, path, Some(at), None).await.body, json!({"api_key_set":false}));
}

#[tokio::test]
async fn personal_enzoic_and_leakcheck_boundaries_without_provider_calls() {
    let s = Server::start().await;
    let settings = "/api/me/secret-health/enzoic";
    let password = "/api/me/secret-health/enzoic/password";
    let leakcheck = "/api/me/secret-health/leakcheck";
    for path in [settings, password, leakcheck] { assert_eq!(s.call(Method::POST, path, None, Some(json!({}))).await.status, if path == settings { 405 } else { 401 }); }
    assert_eq!(s.get(settings).await.status, 401);
    let a = register(&s, "enzoic-a@example.test").await;
    let b = register(&s, "enzoic-b@example.test").await;
    let at = a.body["token"].as_str().unwrap(); let bt = b.body["token"].as_str().unwrap();
    let credentials = json!({"api_key":"fixture-enzoic-key","api_secret":"fixture-enzoic-secret"});
    assert_eq!(s.call(Method::PUT, settings, Some(at), Some(credentials.clone())).await.body, json!({"configured":true}));
    assert_eq!(s.call(Method::GET, settings, Some(bt), None).await.body, json!({"configured":false}));
    assert_eq!(s.call(Method::GET, "/api/me/secret-health", Some(at), None).await.body, json!({"api_key_set":false}));
    let db = rusqlite::Connection::open(s.dir.join("test.db")).unwrap();
    let stored: String = db.query_row("SELECT v FROM meta WHERE k=?", [format!("enzoic_credentials:{}", a.body["user_id"].as_str().unwrap())], |r| r.get(0)).unwrap();
    assert!(!stored.contains("fixture-enzoic"));
    let master: String = db.query_row("SELECT v FROM meta WHERE k='master'", [], |r| r.get(0)).unwrap();
    let master: [u8;32] = openwarp_crypto::unb64(&master).unwrap().try_into().unwrap();
    let plaintext = openwarp_crypto::decrypt_symmetric(&master, &stored).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&plaintext).unwrap(), credentials);
    db.execute("INSERT INTO tokens(id,name,token_hash,created_at) VALUES('enzoic-service','health',?,0)", [openwarp_crypto::hash_token("enzoic-service-fixture")]).unwrap();
    db.execute("INSERT INTO oauth_tokens(token_hash,client_id,user_id,expires_at,created_at,scope,resource) VALUES(?,'enzoic-client',?,9999999999,0,'secrets:read secrets:write',?)", [openwarp_crypto::hash_token("enzoic-oauth-fixture"), a.body["user_id"].as_str().unwrap().to_string(), s.base.clone()]).unwrap();
    for token in ["enzoic-service-fixture", "enzoic-oauth-fixture"] {
        assert_eq!(s.call(Method::GET, settings, Some(token), None).await.status, 401);
        assert_eq!(s.call(Method::PUT, settings, Some(token), Some(credentials.clone())).await.status, 401);
        for path in [password, leakcheck] { assert_eq!(s.call(Method::POST, path, Some(token), Some(json!({"consent":true}))).await.status, 401); }
    }
    for path in [settings, password, leakcheck] {
        let method = if path == settings { Method::PUT } else { Method::POST };
        let response = s.client.request(method, s.url(path)).bearer_auth(at).header("origin", "https://untrusted.example").json(&json!({})).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 403);
    }
    for body in [json!({"prefix":"0123456789"}), json!({"prefix":"0123456789","consent":"true"}), json!({"prefix":"A123456789","consent":true}), json!({"prefix":"a".repeat(64),"consent":true}), json!({"prefix":"0123456789","consent":true,"password":"forbidden"})] {
        assert_eq!(s.call(Method::POST, password, Some(at), Some(body)).await.status, 400);
    }
    assert_eq!(s.call(Method::POST, password, Some(bt), Some(json!({"prefix":"0123456789","consent":true}))).await.status, 400);
    for body in [json!({"email_hash":"a".repeat(24)}), json!({"email_hash":"A".repeat(24),"consent":true}), json!({"email_hash":"a".repeat(64),"consent":true}), json!({"email_hash":"a".repeat(24),"consent":true,"email":"forbidden@example.test"})] {
        assert_eq!(s.call(Method::POST, leakcheck, Some(at), Some(body)).await.status, 400);
    }
    for body in [json!({"api_key":null,"api_secret":"partial"}), json!({"api_key":"key"}), json!({"api_key":"key:invalid","api_secret":"secret"})] {
        assert_eq!(s.call(Method::PUT, settings, Some(at), Some(body)).await.status, 400);
    }
    // Pre-exhaust both quota paths so no real provider is contacted.
    for key in [format!("enzoic:{}", a.body["user_id"].as_str().unwrap()), format!("leakcheck:{}", a.body["user_id"].as_str().unwrap()), "leakcheck:instance".to_string()] {
        db.execute("INSERT INTO rate_limits(key,window_start,count) VALUES(?,9999999999,1)", [key]).unwrap();
    }
    assert_eq!(s.call(Method::POST, password, Some(at), Some(json!({"prefix":"0123456789","consent":true}))).await.status, 429);
    assert_eq!(s.call(Method::POST, leakcheck, Some(at), Some(json!({"email_hash":"a".repeat(24),"consent":true}))).await.status, 429);
    assert_eq!(s.call(Method::POST, leakcheck, Some(bt), Some(json!({"email_hash":"b".repeat(24),"consent":true}))).await.status, 429);
    assert_eq!(s.call(Method::PUT, settings, Some(at), Some(json!({"api_key":null,"api_secret":null}))).await.body, json!({"configured":false}));
    assert_eq!(s.call(Method::GET, settings, Some(at), None).await.body, json!({"configured":false}));
}

fn query_param(location: &str, key: &str) -> String {
    location.split_once('?').map(|(_, q)| q).unwrap_or("")
        .split('&').filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key).map(|(_, v)| v.to_string()).unwrap_or_default()
}

const TEST_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC5O340cebdkWsx
FiSVOA0xClu5jkVdfk/T1h6fsEHqHJDRLtxRiJevaMBr7mKlbp4d6PQWQ6ydFzsh
6gb4IqE7/UONKNhq+ZK/SpKaY0DiorFpX7ULfoc9RvZb/0zwBuFi4j4km2BDaf09
WvEId/QbiizE9o0Ev1YQkyqck7dz1t52JnE4tI0aOz6jAvwceV5QflPsGmKa+PiJ
nXEfZin7VRTi/IQRXvntQtIDk4CMl2qT5V/cGNKNtpHi+19za96qt0hIphsD/PwM
YN9Az1BZ8/lygTTnjZIfcrMnZEbVNSfZTtAa2tzgueAlUx+CJmEE6J1MfVW6AGHG
v7SR6XVjAgMBAAECggEAEsF/afgOlGjhHbtMQP/H9itCVmudgnYDx0NrHmhOhFIY
J9ZC4M6f7VcCBOvCeVXWFNk9vfNkSxPLHQgBZKa9BMIEUQrNvyc+QLhgV9ms/EXV
CQJz5pINR5sj3vTe6X8I22ZlPHevK6RTzB6lQWJECXXYSqlcZhqpsEv2iJw8ezIe
eY7nRe27tquhj2ZC8FrA86yWEe1eq5H7t4bFqHm8OUosklw5uIy3PLmIiUk89oML
NdsPJ5sHNEFUGbIQYMjTQIUShEKKp6k3Hx9GvFo7g0DdM7OIN5d1otVXIlJKqQJA
9LPrvfGVU/fZqDqPauVfen/ws8Q8p5dKrlZKs0OFIQKBgQDi2T1OwOuTm2vLlY4y
H3CG4fjPmAwgrIHIU0/NT+w9hi8BRdHxH7jnzz7uYqLV8T6hg8onrwMTkXMybGWE
ZWue4BTW/stqBH8s00/In8HKS1OjzJSEq1rNiH0Qq8tt/1STTO3ARK4jr6gk2fo6
ue+TnwB2Mjl4o3gmLOl3ktuUpQKBgQDRCS7ZwYGevt/MIHF1U2H7clHo/uX1qotG
ruCmxXgzA8r2RkJVpy1ooSYY6T4ykDx68ousHULZtWoXSKv/DaVb+nVEVTt8Sxu3
IzdwmybV7qttY9oFI6zvFzr/i2+bwXkd7KJ42YS1RioMxFFYnNKQS9nVLOZ9bC0a
NQj3V7JbZwKBgH7rImT8hRE5xM7LpxoeAvxEU8v5+tcRDS/ChQSO8dLeT1A7+yEY
KYDwr/n6D7b5WZxOOv2G6oa5OyV8BjRT9imWn7JGLhLr3yd6Nso9r9P53xrm7DVq
Fcymz6pTI+cwEuazBNYs1u06ay3rExhmTUdfj4eRxBveAewB9sGi1d3NAoGAZoq/
rdiMEmiF9mev4KMfvK5u2gI4opOfsPPWhlj2RuhEZx0+KzBQSTRMMQoyFbHFyXYz
6CGOiqfAvF1M6lgyVvV9EyFQhf9+QA+JgbbKjUWAWLAT4lOG4N6fdX5cKKb3GCPd
67SgsiASPqMLWJHNhTWATV+yTbKESYfctyERAF8CgYBo/wn6tKon7NsVzPxv8KrL
OF8MHpy7ObWoOf5KfrHRRwqkYrAapKkT9R5+4rm10oNt9nMitwUOng9IsDyIm1l2
1EuIUbif869vmzHMvy5SEpXTl+BfKUc3rOKIHw1SKvExnT9VPdOguVcYggAPovC/
zx/UpPmCIb8/3cJ8IR+QpA==
-----END PRIVATE KEY-----"#;
const TEST_N: &str = "uTt-NHHm3ZFrMRYklTgNMQpbuY5FXX5P09Yen7BB6hyQ0S7cUYiXr2jAa-5ipW6eHej0FkOsnRc7IeoG-CKhO_1DjSjYavmSv0qSmmNA4qKxaV-1C36HPUb2W_9M8AbhYuI-JJtgQ2n9PVrxCHf0G4osxPaNBL9WEJMqnJO3c9bediZxOLSNGjs-owL8HHleUH5T7Bpimvj4iZ1xH2Yp-1UU4vyEEV757ULSA5OAjJdqk-Vf3BjSjbaR4vtfc2veqrdISKYbA_z8DGDfQM9QWfP5coE0542SH3KzJ2RG1TUn2U7QGtrc4LngJVMfgiZhBOidTH1VugBhxr-0kel1Yw";

struct MockIdp { base: String, issuer: String, token_forms: Arc<Mutex<Vec<String>>>, nonce: Arc<Mutex<String>> }

/// Mock identity provider: discovery, JWKS, and a token endpoint that signs an
/// id_token for the requested email. Also serves the GitHub endpoints.
fn start_mock(email: &'static str, client_id: &'static str) -> MockIdp { start_mock_full(email, client_id, "", None, false) }
/// A non-empty suffix makes the issuer include a path that serves no discovery
/// document, which exercises the explicit endpoint overrides.
fn start_mock_at(email: &'static str, client_id: &'static str, suffix: &'static str) -> MockIdp { start_mock_full(email, client_id, suffix, None, false) }
/// Microsoft mode publishes a templated issuer and returns the UPN instead of email.
fn start_mock_tenant(email: &'static str, client_id: &'static str, tenant: &'static str) -> MockIdp {
    start_mock_full(email, client_id, "", Some(tenant), true) }
fn start_mock_full(email: &'static str, client_id: &'static str, suffix: &'static str, tenant: Option<&'static str>, upn_only: bool) -> MockIdp {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock bind");
    let addr = listener.local_addr().expect("mock addr");
    let base = format!("http://{}", addr);
    let issuer = format!("{}{}", base, suffix);
    let thread_issuer = issuer.clone();
    let discovery_issuer = match tenant { Some(_) => format!("{}/{{tenantid}}/v2.0", issuer), None => issuer.clone() };
    let claim_issuer = match tenant { Some(t) => format!("{}/{}/v2.0", issuer, t), None => issuer.clone() };
    let token_forms = Arc::new(Mutex::new(Vec::new()));
    let captured = token_forms.clone();
    let nonce_slot = Arc::new(Mutex::new(String::new()));
    let issued_nonce = nonce_slot.clone();
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
            let head = String::from_utf8_lossy(&buf).to_string();
            let first = head.lines().next().unwrap_or("").to_string();
            let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
            if path.starts_with("/token") || path.starts_with("/2/oauth2/token") {
                captured.lock().unwrap().push(head.split("\r\n\r\n").nth(1).unwrap_or("").to_string());
            }
            let payload = if path.starts_with("/.well-known/openid-configuration") {
                json!({"issuer": discovery_issuer, "authorization_endpoint": format!("{}/authorize", thread_issuer),
                       "token_endpoint": format!("{}/token", thread_issuer), "jwks_uri": format!("{}/jwks", thread_issuer)}).to_string()
            } else if path.starts_with("/jwks") {
                json!({"keys": [{"kty": "RSA", "kid": "t1", "use": "sig", "alg": "RS256", "n": TEST_N, "e": "AQAB"}]}).to_string()
            } else if path.starts_with("/2/oauth2/token") {
                json!({"access_token": "x-token", "token_type": "bearer"}).to_string()
            } else if path.starts_with("/2/users/me") {
                json!({"data": {"id": "x-user-1", "confirmed_email": email}}).to_string()
            } else if path.starts_with("/token") {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let header = jsonwebtoken::Header { alg: jsonwebtoken::Algorithm::RS256, kid: Some("t1".into()), ..Default::default() };
                let mut claims = json!({"iss": claim_issuer, "aud": client_id, "sub": "mock-subject-1", "iat": now, "exp": now + 300});
                let nonce = issued_nonce.lock().unwrap().clone();
                if !nonce.is_empty() { claims["nonce"] = json!(nonce); }
                if let Some(t) = tenant { claims["tid"] = json!(t); }
                if upn_only { claims["preferred_username"] = json!(email); }
                else { claims["email"] = json!(email); claims["email_verified"] = json!(true); }
                let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PEM.as_bytes()).expect("rsa pem");
                let id_token = jsonwebtoken::encode(&header, &claims, &key).expect("sign id token");
                json!({"access_token": "x", "id_token": id_token, "token_type": "Bearer"}).to_string()
            } else if path.starts_with("/login/oauth/access_token") {
                json!({"access_token": "gho_test", "token_type": "bearer", "scope": "user:email"}).to_string()
            } else if path.starts_with("/user/emails") {
                json!([{"email": email, "primary": true, "verified": true}]).to_string()
            } else if path.starts_with("/user") {
                json!({"id": 4242, "login": "octo", "email": null}).to_string()
            } else {
                json!({}).to_string()
            };
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload).as_bytes());
        }
    });
    MockIdp { base, issuer, token_forms, nonce: nonce_slot }
}
/// The strict nonce check requires the mock to echo the value from the start
/// redirect; every OIDC callback test sets it before answering.
fn set_expected_nonce(idp: &MockIdp, location: &str) {
    *idp.nonce.lock().unwrap() = query_param(location, "nonce");
}

#[tokio::test]
async fn signups_can_be_closed_and_invites_provision_accounts() {
    let s = Server::start().await;
    let owner = register(&s, "first@test.invalid").await;
    assert_eq!(owner.status, 200, "the first account must be creatable: {}", owner.text);
    let ot = owner.body["token"].as_str().unwrap();
    let org = owner.body["org_id"].as_str().unwrap();

    let info = s.call(Method::GET, "/api/instance", Some(ot), None).await;
    assert_eq!(info.status, 200, "{}", info.text);
    assert_eq!(info.body["instance_owner"], json!(true), "the first user owns the instance: {}", info.text);

    let r = s.call(Method::PUT, "/api/instance/signups", Some(ot), Some(json!({"open": false}))).await;
    assert_eq!(r.status, 200, "closing signups failed: {}", r.text);
    let r = register(&s, "second@test.invalid").await;
    assert_eq!(r.status, 403, "a closed instance must refuse self-signup, got {} {}", r.status, r.text);

    let providers = s.get("/api/auth/providers").await;
    assert_eq!(providers.status, 200, "{}", providers.text);
    assert_eq!(providers.body["signups"], json!("invite"), "{}", providers.text);

    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "invitee@test.invalid", "role": "developer"})))
        .await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);
    let invite = r.body["invite_token"].as_str().expect("invite token for a new address").to_string();

    let r = s
        .call(Method::POST, "/api/auth/accept-invite", None, Some(json!({"token": invite, "password": "invitee-password"})))
        .await;
    assert_eq!(r.status, 200, "invite acceptance failed: {}", r.text);
    let it = r.body["token"].as_str().unwrap();
    let r = s.call(Method::GET, "/api/orgs", Some(it), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.text.contains(org), "the invited user must be in the inviting org: {}", r.text);
    let r = s.call(Method::PUT, "/api/instance/signups", Some(it), Some(json!({"open": true}))).await;
    assert_eq!(r.status, 403, "only the instance owner may reopen signups, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, "/api/auth/accept-invite", None, Some(json!({"token": invite, "password": "another-password"}))).await;
    assert_eq!(r.status, 400, "an invite must be single use, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn providers_are_hidden_when_not_configured() {
    let s = Server::start().await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["google"], json!(false), "{}", r.text);
    assert_eq!(r.body["github"], json!(false), "{}", r.text);
    assert_eq!(r.body["apple"], json!(false), "{}", r.text);
    assert_eq!(r.body["openai"], json!(false), "{}", r.text);
    assert_eq!(r.body["microsoft"], json!(false), "{}", r.text);
    assert_eq!(r.body["okta"], json!(false), "{}", r.text);
    assert_eq!(r.body["auth0"], json!(false), "{}", r.text);
    assert_eq!(r.body["gitlab"], json!(false), "{}", r.text);
    assert_eq!(r.body["slack"], json!(false), "{}", r.text);
    assert_eq!(r.body["salesforce"], json!(false), "{}", r.text);
    assert_eq!(r.body["atlassian"], json!(false), "{}", r.text);
    assert_eq!(r.body["x"], json!(false), "{}", r.text);
    assert_eq!(r.body["oidc"], json!(false), "{}", r.text);
    assert_eq!(r.body["signups"], json!("open"), "{}", r.text);
    let r = s.get("/api/auth/social/google/start").await;
    assert_eq!(r.status, 404, "an unconfigured provider must not start a flow, got {} {}", r.status, r.text);
    let r = s.get("/api/auth/social/apple/start").await;
    assert_eq!(r.status, 404, "an unconfigured Apple flow must be refused, got {} {}", r.status, r.text);
    let r = s.get("/api/auth/social/openai/start").await;
    assert_eq!(r.status, 404, "an unconfigured OpenAI flow must be refused, got {} {}", r.status, r.text);
    let r = s.get("/api/auth/social/x/start").await;
    assert_eq!(r.status, 404, "an unconfigured X flow must be refused, got {} {}", r.status, r.text);
    let r = s.get("/api/auth/social/oidc/start").await;
    assert_eq!(r.status, 404, "an unconfigured custom OIDC flow must be refused, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn google_login_provisions_a_user() {
    let idp = start_mock("google-user@test.invalid", "test-google");
    let s = Server::start_env(&[
        ("OPENWARP_GOOGLE_CLIENT_ID", "test-google".to_string()),
        ("OPENWARP_GOOGLE_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_GOOGLE_ISSUER", idp.issuer.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["google"], json!(true), "{}", r.text);

    let r = s.get("/api/auth/social/google/start").await;
    assert_eq!(r.status, 307, "google start failed: {} {}", r.status, r.text);
    set_expected_nonce(&idp, &r.header("location"));
    let state = query_param(&r.header("location"), "state");
    assert!(!state.is_empty(), "no state in {}", r.header("location"));

    let r = s.get(&format!("/api/auth/social/google/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "google callback failed: {} {}", r.status, r.text);
    let location = r.header("location");
    let token = location.split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", location);
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.body["email"], json!("google-user@test.invalid"), "{}", me.text);
    let orgs = s.call(Method::GET, "/api/orgs", Some(&token), None).await;
    assert_eq!(orgs.status, 200, "{}", orgs.text);
    assert_eq!(orgs.body.as_array().map(|a| a.len()).unwrap_or(0), 1, "a self-signed-up social user gets a personal org: {}", orgs.text);
    assert_eq!(orgs.body[0]["role"], json!("owner"), "{}", orgs.text);
}

#[tokio::test]
async fn github_login_provisions_a_user() {
    let api = start_mock("octo@test.invalid", "test-github");
    let s = Server::start_env(&[
        ("OPENWARP_GITHUB_CLIENT_ID", "test-github".to_string()),
        ("OPENWARP_GITHUB_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_GITHUB_WEB", api.issuer.clone()),
        ("OPENWARP_GITHUB_API", api.issuer.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["github"], json!(true), "{}", r.text);

    let r = s.get("/api/auth/social/github/start").await;
    assert_eq!(r.status, 307, "github start failed: {} {}", r.status, r.text);
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/social/github/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "github callback failed: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.body["email"], json!("octo@test.invalid"), "{}", me.text);
}

#[tokio::test]
async fn apple_login_uses_form_post_and_trusts_the_provider_email() {
    let idp = start_mock("apple-user@test.invalid", "test-apple");
    let s = Server::start_env(&[
        ("OPENWARP_APPLE_CLIENT_ID", "test-apple".to_string()),
        ("OPENWARP_APPLE_CLIENT_SECRET", "test-apple-secret".to_string()),
        ("OPENWARP_APPLE_ISSUER", idp.issuer.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["apple"], json!(true), "{}", r.text);

    let start = s.get("/api/auth/social/apple/start").await;
    assert_eq!(start.status, 307, "apple start failed: {} {}", start.status, start.text);
    let location = start.header("location");
    set_expected_nonce(&idp, &location);
    assert!(location.contains("response_mode=form_post"), "Apple requires a form POST response: {}", location);
    assert!(location.contains("scope=openid%20email"), "Apple only supports its advertised scopes: {}", location);
    let state = query_param(&location, "state");
    assert!(!state.is_empty(), "no state in {}", location);

    let r = s.post_form("/api/auth/social/apple/callback", &[("code", "abc"), ("state", &state)]).await;
    assert_eq!(r.status, 307, "apple form POST callback failed: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.status, 200, "a provider-verified email must not need a local verification round: {} {}", me.status, me.text);
    assert_eq!(me.body["email"], json!("apple-user@test.invalid"), "{}", me.text);
}

#[tokio::test]
async fn openai_login_sends_pkce_and_trusts_the_provider_email() {
    let idp = start_mock("openai-user@test.invalid", "test-openai");
    let s = Server::start_env(&[
        ("OPENWARP_OPENAI_CLIENT_ID", "test-openai".to_string()),
        ("OPENWARP_OPENAI_CLIENT_SECRET", "test-openai-secret".to_string()),
        ("OPENWARP_OPENAI_ISSUER", idp.issuer.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["openai"], json!(true), "{}", r.text);

    let start = s.get("/api/auth/social/openai/start").await;
    assert_eq!(start.status, 307, "openai start failed: {} {}", start.status, start.text);
    let location = start.header("location");
    set_expected_nonce(&idp, &location);
    assert!(location.contains("code_challenge="), "OpenAI sign-in must use PKCE: {}", location);
    assert!(location.contains("code_challenge_method=S256"), "{}", location);
    let state = query_param(&location, "state");

    let r = s.get(&format!("/api/auth/social/openai/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "openai callback failed: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.status, 200, "a provider-verified email must not need a local verification round: {} {}", me.status, me.text);
    assert_eq!(me.body["email"], json!("openai-user@test.invalid"), "{}", me.text);
    let forms = idp.token_forms.lock().unwrap();
    assert!(forms.iter().any(|f| f.contains("code_verifier=")), "the PKCE verifier must reach the token endpoint: {:?}", *forms);
    assert!(forms.iter().any(|f| f.contains("client_secret=test-openai-secret")), "the client secret must reach the token endpoint: {:?}", *forms);
}

/// Shared OIDC flow for the branded providers that only differ by env names.
async fn oidc_provider_login(provider: &'static str, email: &'static str, client_id: &'static str,
    id_key: &'static str, secret_key: &'static str, issuer_key: &'static str) {
    let idp = start_mock(email, client_id);
    let s = Server::start_env(&[
        (id_key, client_id.to_string()),
        (secret_key, "test-secret".to_string()),
        (issuer_key, idp.issuer.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body[provider], json!(true), "{} must be advertised: {}", provider, r.text);
    let start = s.get(&format!("/api/auth/social/{}/start", provider)).await;
    assert_eq!(start.status, 307, "{} start failed: {} {}", provider, start.status, start.text);
    set_expected_nonce(&idp, &start.header("location"));
    let state = query_param(&start.header("location"), "state");
    assert!(!state.is_empty(), "{} start has no state", provider);
    let r = s.get(&format!("/api/auth/social/{}/callback?code=abc&state={}", provider, state)).await;
    assert_eq!(r.status, 307, "{} callback failed: {} {}", provider, r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "{} issued no session: {}", provider, r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.status, 200, "{} provider email must be trusted: {} {}", provider, me.status, me.text);
    assert_eq!(me.body["email"], json!(email), "{}", me.text);
}

#[tokio::test]
async fn okta_login_provisions_a_user() {
    oidc_provider_login("okta", "okta-user@test.invalid", "test-okta", "OPENWARP_OKTA_CLIENT_ID", "OPENWARP_OKTA_CLIENT_SECRET", "OPENWARP_OKTA_ISSUER").await;
}

#[tokio::test]
async fn auth0_login_provisions_a_user() {
    oidc_provider_login("auth0", "auth0-user@test.invalid", "test-auth0", "OPENWARP_AUTH0_CLIENT_ID", "OPENWARP_AUTH0_CLIENT_SECRET", "OPENWARP_AUTH0_ISSUER").await;
}

#[tokio::test]
async fn gitlab_login_provisions_a_user() {
    oidc_provider_login("gitlab", "gitlab-user@test.invalid", "test-gitlab", "OPENWARP_GITLAB_CLIENT_ID", "OPENWARP_GITLAB_CLIENT_SECRET", "OPENWARP_GITLAB_ISSUER").await;
}

#[tokio::test]
async fn slack_login_provisions_a_user() {
    oidc_provider_login("slack", "slack-user@test.invalid", "test-slack", "OPENWARP_SLACK_CLIENT_ID", "OPENWARP_SLACK_CLIENT_SECRET", "OPENWARP_SLACK_ISSUER").await;
}

#[tokio::test]
async fn salesforce_login_provisions_a_user() {
    oidc_provider_login("salesforce", "salesforce-user@test.invalid", "test-salesforce", "OPENWARP_SALESFORCE_CLIENT_ID", "OPENWARP_SALESFORCE_CLIENT_SECRET", "OPENWARP_SALESFORCE_ISSUER").await;
}

#[tokio::test]
async fn atlassian_login_provisions_a_user() {
    oidc_provider_login("atlassian", "atlassian-user@test.invalid", "test-atlassian", "OPENWARP_ATLASSIAN_CLIENT_ID", "OPENWARP_ATLASSIAN_CLIENT_SECRET", "OPENWARP_ATLASSIAN_ISSUER").await;
}

#[tokio::test]
async fn microsoft_login_provisions_a_user() {
    oidc_provider_login("microsoft", "microsoft-user@test.invalid", "test-microsoft", "OPENWARP_MICROSOFT_CLIENT_ID", "OPENWARP_MICROSOFT_CLIENT_SECRET", "OPENWARP_MICROSOFT_ISSUER").await;
}

#[tokio::test]
async fn microsoft_login_handles_a_templated_tenant_issuer_and_upn_email() {
    let idp = start_mock_tenant("microsoft-upn@test.invalid", "test-microsoft", "11111111-1111-1111-1111-111111111111");
    let s = Server::start_env(&[
        ("OPENWARP_MICROSOFT_CLIENT_ID", "test-microsoft".to_string()),
        ("OPENWARP_MICROSOFT_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_MICROSOFT_ISSUER", idp.issuer.clone()),
    ]).await;
    let start = s.get("/api/auth/social/microsoft/start").await;
    assert_eq!(start.status, 307, "{}", start.text);
    set_expected_nonce(&idp, &start.header("location"));
    let state = query_param(&start.header("location"), "state");
    let r = s.get(&format!("/api/auth/social/microsoft/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "the templated tenant issuer must validate: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.status, 200, "{}", me.text);
    assert_eq!(me.body["email"], json!("microsoft-upn@test.invalid"), "the UPN fallback must supply the email: {}", me.text);
}

#[tokio::test]
async fn x_login_uses_pkce_and_the_confirmed_email() {
    let idp = start_mock("x-user@test.invalid", "test-x");
    let s = Server::start_env(&[
        ("OPENWARP_X_CLIENT_ID", "test-x".to_string()),
        ("OPENWARP_X_WEB", idp.issuer.clone()),
        ("OPENWARP_X_API", idp.issuer.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["x"], json!(true), "{}", r.text);
    let start = s.get("/api/auth/social/x/start").await;
    assert_eq!(start.status, 307, "x start failed: {} {}", start.status, start.text);
    let location = start.header("location");
    assert!(location.contains("code_challenge="), "X sign-in must use PKCE: {}", location);
    assert!(location.contains("users.email"), "X needs the users.email scope: {}", location);
    let state = query_param(&location, "state");
    let r = s.get(&format!("/api/auth/social/x/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "x callback failed: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.status, 200, "{}", me.text);
    assert_eq!(me.body["email"], json!("x-user@test.invalid"), "{}", me.text);
    let forms = idp.token_forms.lock().unwrap();
    assert!(forms.iter().any(|f| f.contains("code_verifier=")), "the PKCE verifier must reach the X token endpoint: {:?}", *forms);
    assert!(forms.iter().any(|f| f.contains("client_id=test-x")), "a public X client sends its id in the form: {:?}", *forms);
}

#[tokio::test]
async fn custom_oidc_login_uses_pkce_and_provisions_a_user() {
    let idp = start_mock("oidc-user@test.invalid", "test-oidc");
    let s = Server::start_env(&[
        ("OPENWARP_OIDC_ISSUER", idp.issuer.clone()),
        ("OPENWARP_OIDC_CLIENT_ID", "test-oidc".to_string()),
        ("OPENWARP_OIDC_CLIENT_SECRET", "test-oidc-secret".to_string()),
        ("OPENWARP_OIDC_NAME", "Acme ID".to_string()),
        ("OPENWARP_OIDC_SCOPES", "email profile".to_string()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["oidc"], json!(true), "{}", r.text);
    assert_eq!(r.body["oidc_name"], json!("Acme ID"), "{}", r.text);

    let start = s.get("/api/auth/social/oidc/start").await;
    assert_eq!(start.status, 307, "custom OIDC start failed: {} {}", start.status, start.text);
    let location = start.header("location");
    set_expected_nonce(&idp, &location);
    assert!(location.contains("code_challenge=") && location.contains("code_challenge_method=S256"), "custom OIDC must use PKCE: {}", location);
    assert!(location.contains("scope=openid%20email%20profile"), "openid must be added when an operator scope list omits it: {}", location);
    let state = query_param(&location, "state");

    let r = s.get(&format!("/api/auth/social/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "custom OIDC callback failed: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.body["email"], json!("oidc-user@test.invalid"), "{}", me.text);
    let forms = idp.token_forms.lock().unwrap();
    assert!(forms.iter().any(|f| f.contains("code_verifier=")), "the PKCE verifier must reach the token endpoint: {:?}", *forms);
    assert!(forms.iter().any(|f| f.contains("client_secret=test-oidc-secret")), "the client secret must reach the token endpoint: {:?}", *forms);
}

#[tokio::test]
async fn custom_oidc_accepts_explicit_endpoints_without_discovery() {
    let idp = start_mock_at("explicit@test.invalid", "test-oidc", "/tenant");
    let auth_ep = format!("{}/authorize", idp.base);
    let s = Server::start_env(&[
        ("OPENWARP_OIDC_ISSUER", idp.issuer.clone()),
        ("OPENWARP_OIDC_CLIENT_ID", "test-oidc".to_string()),
        ("OPENWARP_OIDC_CLIENT_SECRET", "test-oidc-secret".to_string()),
        ("OPENWARP_OIDC_AUTHORIZATION_ENDPOINT", auth_ep.clone()),
        ("OPENWARP_OIDC_TOKEN_ENDPOINT", format!("{}/token", idp.base)),
        ("OPENWARP_OIDC_JWKS_URI", format!("{}/jwks", idp.base)),
    ]).await;
    let start = s.get("/api/auth/social/oidc/start").await;
    assert_eq!(start.status, 307, "custom OIDC start failed without discovery: {} {}", start.status, start.text);
    let location = start.header("location");
    set_expected_nonce(&idp, &location);
    assert!(location.starts_with(&auth_ep), "the explicit authorization endpoint must be used: {}", location);
    let state = query_param(&location, "state");

    let r = s.get(&format!("/api/auth/social/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "custom OIDC callback failed without discovery: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.body["email"], json!("explicit@test.invalid"), "{}", me.text);
}

#[tokio::test]
async fn custom_oidc_public_client_needs_no_secret() {
    let idp = start_mock("public-client@test.invalid", "test-public");
    let s = Server::start_env(&[
        ("OPENWARP_OIDC_ISSUER", idp.issuer.clone()),
        ("OPENWARP_OIDC_CLIENT_ID", "test-public".to_string()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["oidc"], json!(true), "a client id and issuer are enough to advertise the provider: {}", r.text);
    let start = s.get("/api/auth/social/oidc/start").await;
    set_expected_nonce(&idp, &start.header("location"));
    let state = query_param(&start.header("location"), "state");

    let r = s.get(&format!("/api/auth/social/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "public-client callback failed: {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no session issued: {}", r.header("location"));
    let me = s.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.body["email"], json!("public-client@test.invalid"), "{}", me.text);
    let forms = idp.token_forms.lock().unwrap();
    assert!(forms.iter().any(|f| f.contains("code_verifier=")), "PKCE is required without a client secret: {:?}", *forms);
    assert!(!forms.iter().any(|f| f.contains("client_secret=")), "a public client must not send a client secret: {:?}", *forms);
}

#[tokio::test]
async fn custom_oidc_rejects_an_id_token_without_the_flow_nonce() {
    let idp = start_mock("no-nonce@test.invalid", "test-oidc");
    let s = Server::start_env(&[
        ("OPENWARP_OIDC_ISSUER", idp.issuer.clone()),
        ("OPENWARP_OIDC_CLIENT_ID", "test-oidc".to_string()),
        ("OPENWARP_OIDC_CLIENT_SECRET", "test-oidc-secret".to_string()),
    ]).await;
    let start = s.get("/api/auth/social/oidc/start").await;
    let state = query_param(&start.header("location"), "state");

    let r = s.get(&format!("/api/auth/social/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 400, "a token that omits the flow nonce must be refused, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn org_sso_requires_an_invite_when_signups_are_closed() {
    let idp = start_mock("sso-invite@test.invalid", "test-google");
    let s = Server::start().await;
    let owner = register(&s, "sso-owner@test.invalid").await;
    let ot = owner.body["token"].as_str().unwrap();
    let org = owner.body["org_id"].as_str().unwrap();
    let r = s
        .call(
            Method::PUT,
            &format!("/api/orgs/{}/settings", org),
            Some(ot),
            Some(json!({"oidc_issuer": idp.issuer, "oidc_client_id": "test-google", "oidc_client_secret": "secret", "oidc_redirect_uri": format!("{}/api/auth/oidc/callback", s.base), "oidc_auto_provision": true, "oidc_allowed_domains": "test.invalid"})),
        )
        .await;
    assert_eq!(r.status, 200, "oidc settings failed: {}", r.text);
    let r = s.call(Method::PUT, "/api/instance/signups", Some(ot), Some(json!({"open": false}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.get(&format!("/api/auth/oidc/{}/start", org)).await;
    set_expected_nonce(&idp, &r.header("location"));
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 403, "org SSO must not join an uninvited account while signups are closed, got {} {}", r.status, r.text);

    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "sso-invite@test.invalid", "role": "developer"})))
        .await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);
    let r = s.get(&format!("/api/auth/oidc/{}/start", org)).await;
    set_expected_nonce(&idp, &r.header("location"));
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "an invited SSO user must be admitted, got {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").split('&').next().unwrap_or("").to_string();
    let orgs = s.call(Method::GET, "/api/orgs", Some(&token), None).await;
    assert!(orgs.text.contains(org), "the invited SSO user must join the org: {}", orgs.text);
    assert!(orgs.text.contains("developer"), "the invite role must apply: {}", orgs.text);
}

#[tokio::test]
async fn social_login_requires_an_invite_when_signups_are_closed() {
    let idp = start_mock("closed-google@test.invalid", "test-google");
    let s = Server::start_env(&[
        ("OPENWARP_GOOGLE_CLIENT_ID", "test-google".to_string()),
        ("OPENWARP_GOOGLE_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_GOOGLE_ISSUER", idp.issuer.clone()),
    ]).await;
    let owner = register(&s, "closed-owner@test.invalid").await;
    let ot = owner.body["token"].as_str().unwrap();
    let org = owner.body["org_id"].as_str().unwrap();
    let r = s.call(Method::PUT, "/api/instance/signups", Some(ot), Some(json!({"open": false}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.get("/api/auth/social/google/start").await;
    set_expected_nonce(&idp, &r.header("location"));
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/social/google/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 403, "social signup must be refused while signups are closed, got {} {}", r.status, r.text);

    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "closed-google@test.invalid", "role": "developer"})))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.get("/api/auth/social/google/start").await;
    set_expected_nonce(&idp, &r.header("location"));
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/social/google/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 307, "a pending invite must admit the social user, got {} {}", r.status, r.text);
    let token = r.header("location").split("#token=").nth(1).unwrap_or("").to_string();
    let orgs = s.call(Method::GET, "/api/orgs", Some(&token), None).await;
    assert!(orgs.text.contains(org), "the invited social user must join the inviting org: {}", orgs.text);
    assert!(orgs.text.contains("developer"), "the invite role must apply: {}", orgs.text);
}

/// Minimal email relay: records each JSON body and answers 200.
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
    for _ in 0..60 {
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

#[tokio::test]
async fn email_verification_gates_login() {
    let s = Server::start().await;
    let r = register_raw(&s, "verify-me@test.invalid").await;
    assert_eq!(r.status, 200, "registration failed: {}", r.text);
    assert_eq!(r.body["verification_required"], json!(true), "verification must be required: {}", r.text);
    assert!(r.body["token"].is_null(), "no session may be issued before verification: {}", r.text);
    assert!(r.body["recovery_kit"].as_str().map(|k| !k.is_empty()).unwrap_or(false), "the kit is still shown: {}", r.text);

    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "verify-me@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 403, "an unverified account must not sign in, got {} {}", login.status, login.text);

    let text = wait_for_mail(&s.inbox, "/api/auth/verify?token=").await;
    let link = extract_link(&text, "/api/auth/verify?token=");
    let path = link.strip_prefix(&s.base).unwrap_or(&link).to_string();
    let r = s.get(&path).await;
    assert_eq!(r.status, 200, "the verification link must work: {} {}", r.status, r.text);

    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "verify-me@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 200, "a verified account must sign in: {}", login.text);
    let replay = s.get(&path).await;
    assert_eq!(replay.status, 400, "a verification link must be single use, got {} {}", replay.status, replay.text);
}

#[tokio::test]
async fn password_reset_requires_the_recovery_kit_or_an_explicit_discard() {
    let s = Server::start().await;
    let reg = register(&s, "reset-me@test.invalid").await;
    let kit = reg.body["recovery_kit"].as_str().unwrap().to_string();
    let old_session = reg.body["token"].as_str().unwrap().to_string();
    let pubkey = reg.body["public_key"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "reset-me@test.invalid"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let text = wait_for_mail(&s.inbox, "#reset=").await;
    let token = extract_link(&text, "#reset=").split("#reset=").nth(1).unwrap_or("").to_string();
    assert!(!token.is_empty(), "no reset token in {:?}", text);

    let r = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": token, "password": "brand-new-password", "recovery_kit": "not-a-real-key"}))).await;
    assert_eq!(r.status, 400, "a mismatched kit must be refused, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": token, "password": "brand-new-password"}))).await;
    assert_eq!(r.status, 400, "a missing kit needs an explicit discard, got {} {}", r.status, r.text);
    assert!(r.text.contains("discard_e2e_key"), "the error must name the escape hatch: {}", r.text);

    let r = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": token, "password": "brand-new-password", "recovery_kit": kit}))).await;
    assert_eq!(r.status, 200, "reset with the kit failed: {}", r.text);
    assert_eq!(r.body["e2e_key_replaced"], json!(false), "the kit must keep the key: {}", r.text);
    let new_session = r.body["token"].as_str().unwrap().to_string();
    let me = s.call(Method::GET, "/api/me", Some(&new_session), None).await;
    assert_eq!(me.body["pubkey"].as_str().unwrap_or(""), pubkey, "the public key must not change when the kit is used");
    let old = s.call(Method::GET, "/api/me", Some(&old_session), None).await;
    assert_eq!(old.status, 401, "old sessions must be revoked, got {} {}", old.status, old.text);
    let old_pw = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "reset-me@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(old_pw.status, 401, "the old password must stop working");
    let new_pw = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "reset-me@test.invalid", "password": "brand-new-password"}))).await;
    assert_eq!(new_pw.status, 200, "the new password must work: {}", new_pw.text);
    let replay = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": token, "password": "another-password", "recovery_kit": kit}))).await;
    assert_eq!(replay.status, 400, "a reset token must be single use, got {} {}", replay.status, replay.text);
}

#[tokio::test]
async fn password_reset_without_the_kit_replaces_the_key_only_when_asked() {
    let s = Server::start().await;
    let reg = register(&s, "discard-me@test.invalid").await;
    let pubkey = reg.body["public_key"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "discard-me@test.invalid"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let text = wait_for_mail(&s.inbox, "#reset=").await;
    let token = extract_link(&text, "#reset=").split("#reset=").nth(1).unwrap_or("").to_string();

    let r = s.call(Method::POST, "/api/auth/reset", None, Some(json!({"token": token, "password": "brand-new-password", "discard_e2e_key": true}))).await;
    assert_eq!(r.status, 200, "discarding the key failed: {}", r.text);
    assert_eq!(r.body["e2e_key_replaced"], json!(true), "{}", r.text);
    let session = r.body["token"].as_str().unwrap().to_string();
    let me = s.call(Method::GET, "/api/me", Some(&session), None).await;
    assert_ne!(me.body["pubkey"].as_str().unwrap_or(""), pubkey, "the key must be replaced: {}", me.text);
}

#[tokio::test]
async fn forgot_password_does_not_reveal_accounts() {
    let s = Server::start().await;
    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "nobody@test.invalid"}))).await;
    assert_eq!(r.status, 200, "an unknown address must look the same, got {} {}", r.status, r.text);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(s.inbox.lock().unwrap().is_empty(), "no mail may be sent for an unknown address");
}
