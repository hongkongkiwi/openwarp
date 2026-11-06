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
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
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
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_SIGNUPS")
            .env_remove("OPENWARP_GOOGLE_CLIENT_ID")
            .env_remove("OPENWARP_GITHUB_CLIENT_ID")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().expect("http client");
        let server = Server { child, base, dir, client };
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
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        let response = req.send().await.expect("http request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }

    async fn get(&self, path: &str) -> Resp { self.call(Method::GET, path, None, None).await }
}

async fn register(s: &Server, email: &str) -> Resp {
    s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await
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

/// Mock identity provider: discovery, JWKS, and a token endpoint that signs an
/// id_token for the requested email. Also serves the GitHub endpoints.
fn start_mock(email: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock bind");
    let addr = listener.local_addr().expect("mock addr");
    let issuer = format!("http://{}", addr);
    let thread_issuer = issuer.clone();
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
            let payload = if path.starts_with("/.well-known/openid-configuration") {
                json!({"issuer": thread_issuer, "authorization_endpoint": format!("{}/authorize", thread_issuer),
                       "token_endpoint": format!("{}/token", thread_issuer), "jwks_uri": format!("{}/jwks", thread_issuer)}).to_string()
            } else if path.starts_with("/jwks") {
                json!({"keys": [{"kty": "RSA", "kid": "t1", "use": "sig", "alg": "RS256", "n": TEST_N, "e": "AQAB"}]}).to_string()
            } else if path.starts_with("/token") {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let header = jsonwebtoken::Header { alg: jsonwebtoken::Algorithm::RS256, kid: Some("t1".into()), ..Default::default() };
                let claims = json!({"iss": thread_issuer, "aud": "test-google", "sub": "google-subject-1", "email": email, "email_verified": true, "iat": now, "exp": now + 300});
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
    issuer
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
    assert_eq!(r.body["signups"], json!("open"), "{}", r.text);
    let r = s.get("/api/auth/social/google/start").await;
    assert_eq!(r.status, 404, "an unconfigured provider must not start a flow, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn google_login_provisions_a_user() {
    let idp = start_mock("google-user@test.invalid");
    let s = Server::start_env(&[
        ("OPENWARP_GOOGLE_CLIENT_ID", "test-google".to_string()),
        ("OPENWARP_GOOGLE_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_GOOGLE_ISSUER", idp.clone()),
    ]).await;
    let r = s.get("/api/auth/providers").await;
    assert_eq!(r.body["google"], json!(true), "{}", r.text);

    let r = s.get("/api/auth/social/google/start").await;
    assert_eq!(r.status, 307, "google start failed: {} {}", r.status, r.text);
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
    let api = start_mock("octo@test.invalid");
    let s = Server::start_env(&[
        ("OPENWARP_GITHUB_CLIENT_ID", "test-github".to_string()),
        ("OPENWARP_GITHUB_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_GITHUB_WEB", api.clone()),
        ("OPENWARP_GITHUB_API", api.clone()),
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
async fn org_sso_requires_an_invite_when_signups_are_closed() {
    let idp = start_mock("sso-invite@test.invalid");
    let s = Server::start().await;
    let owner = register(&s, "sso-owner@test.invalid").await;
    let ot = owner.body["token"].as_str().unwrap();
    let org = owner.body["org_id"].as_str().unwrap();
    let r = s
        .call(
            Method::PUT,
            &format!("/api/orgs/{}/settings", org),
            Some(ot),
            Some(json!({"oidc_issuer": idp, "oidc_client_id": "test-google", "oidc_client_secret": "secret", "oidc_redirect_uri": format!("{}/api/auth/oidc/callback", s.base), "oidc_auto_provision": true, "oidc_allowed_domains": "test.invalid"})),
        )
        .await;
    assert_eq!(r.status, 200, "oidc settings failed: {}", r.text);
    let r = s.call(Method::PUT, "/api/instance/signups", Some(ot), Some(json!({"open": false}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.get(&format!("/api/auth/oidc/{}/start", org)).await;
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/oidc/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 403, "org SSO must not join an uninvited account while signups are closed, got {} {}", r.status, r.text);

    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "sso-invite@test.invalid", "role": "developer"})))
        .await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);
    let r = s.get(&format!("/api/auth/oidc/{}/start", org)).await;
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
    let idp = start_mock("closed-google@test.invalid");
    let s = Server::start_env(&[
        ("OPENWARP_GOOGLE_CLIENT_ID", "test-google".to_string()),
        ("OPENWARP_GOOGLE_CLIENT_SECRET", "test-secret".to_string()),
        ("OPENWARP_GOOGLE_ISSUER", idp.clone()),
    ]).await;
    let owner = register(&s, "closed-owner@test.invalid").await;
    let ot = owner.body["token"].as_str().unwrap();
    let org = owner.body["org_id"].as_str().unwrap();
    let r = s.call(Method::PUT, "/api/instance/signups", Some(ot), Some(json!({"open": false}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.get("/api/auth/social/google/start").await;
    let state = query_param(&r.header("location"), "state");
    let r = s.get(&format!("/api/auth/social/google/callback?code=abc&state={}", state)).await;
    assert_eq!(r.status, 403, "social signup must be refused while signups are closed, got {} {}", r.status, r.text);

    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "closed-google@test.invalid", "role": "developer"})))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.get("/api/auth/social/google/start").await;
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
    let (inbox_url, inbox) = start_inbox();
    let s = Server::start_env(&[
        ("OPENWARP_REQUIRE_EMAIL_VERIFICATION", "1".to_string()),
        ("OPENWARP_EMAIL_WEBHOOK", inbox_url),
    ]).await;
    let r = register(&s, "verify-me@test.invalid").await;
    assert_eq!(r.status, 200, "registration failed: {}", r.text);
    assert_eq!(r.body["verification_required"], json!(true), "verification must be required: {}", r.text);
    assert!(r.body["token"].is_null(), "no session may be issued before verification: {}", r.text);
    assert!(r.body["recovery_kit"].as_str().map(|k| !k.is_empty()).unwrap_or(false), "the kit is still shown: {}", r.text);

    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "verify-me@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(login.status, 403, "an unverified account must not sign in, got {} {}", login.status, login.text);

    let text = wait_for_mail(&inbox, "/api/auth/verify?token=").await;
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
    let (inbox_url, inbox) = start_inbox();
    let s = Server::start_env(&[("OPENWARP_EMAIL_WEBHOOK", inbox_url)]).await;
    let reg = register(&s, "reset-me@test.invalid").await;
    let kit = reg.body["recovery_kit"].as_str().unwrap().to_string();
    let old_session = reg.body["token"].as_str().unwrap().to_string();
    let pubkey = reg.body["public_key"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "reset-me@test.invalid"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let text = wait_for_mail(&inbox, "#reset=").await;
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
    let (inbox_url, inbox) = start_inbox();
    let s = Server::start_env(&[("OPENWARP_EMAIL_WEBHOOK", inbox_url)]).await;
    let reg = register(&s, "discard-me@test.invalid").await;
    let pubkey = reg.body["public_key"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "discard-me@test.invalid"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let text = wait_for_mail(&inbox, "#reset=").await;
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
    let (inbox_url, inbox) = start_inbox();
    let s = Server::start_env(&[("OPENWARP_EMAIL_WEBHOOK", inbox_url)]).await;
    let r = s.call(Method::POST, "/api/auth/forgot", None, Some(json!({"email": "nobody@test.invalid"}))).await;
    assert_eq!(r.status, 200, "an unknown address must look the same, got {} {}", r.status, r.text);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(inbox.lock().unwrap().is_empty(), "no mail may be sent for an unknown address");
}
