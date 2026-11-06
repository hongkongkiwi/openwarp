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
            Some(json!({"oidc_issuer": idp, "oidc_client_id": "test-google", "oidc_client_secret": "secret", "oidc_redirect_uri": format!("{}/api/auth/oidc/callback", s.base)})),
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
