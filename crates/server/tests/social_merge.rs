use base64ct::{Base64UrlUnpadded, Encoding};
use reqwest::{redirect::Policy, Client, Response, Url};
use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Server { child: Child, base: String, dir: PathBuf, client: Client }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start(provider: &str, api: &str, extra: &[(&str, &str)]) -> Self {
        let _lock = START_LOCK.lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        let dir = std::env::temp_dir().join(format!("openwarp-social-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir(&dir).unwrap();
        let prefix = format!("OPENWARP_{}", provider.to_uppercase());
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "2")
            .env(format!("{}_CLIENT_ID", prefix), "test-client").env(format!("{}_CLIENT_SECRET", prefix), "test-secret")
            .env(format!("{}_{}", prefix, if provider == "linkedin" { "ISSUER" } else { "API" }), api)
            .stdout(Stdio::null()).stderr(Stdio::null());
        for (key, value) in extra { cmd.env(key, value); }
        drop(listener);
        let child = cmd.spawn().expect("spawn openwarp-server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let server = Self { child, base, dir, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(format!("{}/health", server.base)).send().await {
                if r.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    async fn get(&self, path: &str) -> Response { self.client.get(format!("{}{}", self.base, path)).send().await.unwrap() }
    async fn start_flow(&self, provider: &str) -> Url {
        let r = self.get(&format!("/api/auth/social/{}/start", provider)).await;
        assert_eq!(r.status(), 307, "configured {} must start a login flow", provider);
        let url = Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
        assert!(!param(&url, "state").is_empty(), "login needs state");
        assert_eq!(param(&url, "client_id"), "test-client");
        assert_eq!(param(&url, "redirect_uri"), format!("{}/api/auth/social/{}/callback", self.base, provider));
        let providers: Value = self.get("/api/auth/providers").await.json().await.unwrap();
        assert_eq!(providers[provider], true, "configured provider must be advertised");
        url
    }
    async fn callback(&self, provider: &str, state: &str) -> Response {
        self.get(&format!("/api/auth/social/{}/callback?code=test-code&state={}", provider, state)).await
    }
    async fn rejected(&self, r: Response, reason: &str) {
        assert_eq!(r.status(), 400, "invalid identity/state must fail closed");
        assert!(!r.headers().get("location").and_then(|h| h.to_str().ok()).unwrap_or("").contains("#token="));
        assert!(!r.headers().get_all("set-cookie").iter().any(|h| h.to_str().unwrap_or("").contains("ow_session=")));
        let text = r.text().await.unwrap();
        assert!(text.to_lowercase().contains(reason), "unexpected rejection: {}", text);
        assert_eq!(self.get("/api/me").await.status(), 401);
    }
    async fn signed_in(&self, r: Response, email: &str) {
        assert_eq!(r.status(), 307, "verified identity must sign in");
        let location = r.headers()["location"].to_str().unwrap();
        let token = location.split_once("#token=").map(|(_, t)| t).unwrap_or("");
        assert!(!token.is_empty(), "callback must issue a session");
        let me = self.client.get(format!("{}/api/me", self.base)).bearer_auth(token).send().await.unwrap();
        assert_eq!(me.status(), 200, "issued session must authenticate");
        assert_eq!(me.json::<Value>().await.unwrap()["email"], email);
    }
}
fn param(url: &Url, key: &str) -> String { url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned()).unwrap_or_default() }

#[derive(Default)]
struct Profile { verified: bool, nonce: String, fault: &'static str }
struct Mock { base: String, profile: Arc<Mutex<Profile>>, requests: Arc<Mutex<Vec<String>>> }
impl Mock {
    fn start(oidc: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let profile = Arc::new(Mutex::new(Profile::default()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (issuer, state, captured) = (base.clone(), profile.clone(), requests.clone());
        let key = if oidc { Some(RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap()) } else { None };
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { break };
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
                loop {
                    let n = match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(n) => n };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]);
                        let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                        if buf.len() >= end + 4 + len { break; }
                    }
                }
                let request = String::from_utf8_lossy(&buf).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                captured.lock().unwrap().push(request);
                let p = state.lock().unwrap();
                let payload = match path.as_str() {
                    "/.well-known/openid-configuration" => json!({"issuer": issuer, "authorization_endpoint": format!("{}/authorize", issuer),
                        "token_endpoint": format!("{}/token", issuer), "jwks_uri": format!("{}/jwks", issuer)}),
                    "/jwks" => json!({"keys": [{"kty": "RSA", "kid": "social-test", "alg": "RS256", "use": "sig",
                        "n": Base64UrlUnpadded::encode_string(&key.as_ref().unwrap().n().to_bytes_be()), "e": "AQAB"}]}),
                    "/token" => {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let claims = json!({"iss": if p.fault == "issuer" { "https://wrong.test.invalid" } else { &issuer },
                            "aud": if p.fault == "audience" { "other-client" } else { "test-client" }, "sub": "linkedin-user",
                            "email": "linkedin@test.invalid", "email_verified": true, "iat": now, "exp": now + 300,
                            "nonce": if p.fault == "nonce" { "wrong-nonce" } else { &p.nonce }});
                        let pem = key.as_ref().unwrap().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
                        let header = jsonwebtoken::Header { alg: jsonwebtoken::Algorithm::RS256, kid: Some("social-test".into()), ..Default::default() };
                        let token = jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap();
                        json!({"access_token": "mock-access", "id_token": token, "token_type": "Bearer"})
                    }
                    "/api/oauth2/token" => json!({"access_token": "mock-access", "token_type": "Bearer"}),
                    "/api/users/@me" => json!({"id": "discord-user", "email": "discord@test.invalid", "verified": p.verified}),
                    "/user_management/authenticate" => json!({"user": {"id": "workos-user", "email": "workos@test.invalid", "email_verified": p.verified}}),
                    _ => Value::Null,
                };
                let status = if payload.is_null() { "404 Not Found" } else { "200 OK" };
                let body = payload.to_string();
                let _ = stream.write_all(format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, body.len(), body).as_bytes());
            }
        });
        Self { base, profile, requests }
    }
}

#[tokio::test]
async fn discord_verified_profile_issues_session_but_unverified_profile_does_not() {
    let mock = Mock::start(false);
    let s = Server::start("discord", &mock.base, &[]).await;
    let start = s.start_flow("discord").await;
    assert_eq!(start.path(), "/api/oauth2/authorize");
    assert_eq!(param(&start, "scope"), "identify email");
    s.rejected(s.callback("discord", "invalid-state").await, "state").await;
    assert!(mock.requests.lock().unwrap().is_empty(), "invalid state must not reach the provider");
    s.rejected(s.callback("discord", &param(&start, "state")).await, "verified").await;
    mock.profile.lock().unwrap().verified = true;
    let start = s.start_flow("discord").await;
    let state = param(&start, "state");
    s.signed_in(s.callback("discord", &state).await, "discord@test.invalid").await;
    s.rejected(s.callback("discord", &state).await, "state").await;
}

#[tokio::test]
async fn workos_selectors_and_verified_user_management_identity() {
    let mock = Mock::start(false);
    type Selector<'a> = (&'a [(&'a str, &'a str)], &'a str, &'a str);
    let selectors: &[Selector<'_>] = &[
        (&[], "provider", "authkit"),
        (&[("OPENWARP_WORKOS_PROVIDER", "GoogleOAuth")], "provider", "GoogleOAuth"),
        (&[("OPENWARP_WORKOS_PROVIDER", "GoogleOAuth"), ("OPENWARP_WORKOS_CONNECTION_ID", "conn_test")], "connection_id", "conn_test"),
    ];
    for (extra, selector, value) in selectors {
        mock.profile.lock().unwrap().verified = false;
        let s = Server::start("workos", &mock.base, extra).await;
        let start = s.start_flow("workos").await;
        assert_eq!(start.path(), "/user_management/authorize");
        assert_eq!(param(&start, selector), *value);
        assert!(param(&start, if *selector == "provider" { "connection_id" } else { "provider" }).is_empty());
        s.rejected(s.callback("workos", "invalid-state").await, "state").await;
        s.rejected(s.callback("workos", &param(&start, "state")).await, "verified").await;
        mock.profile.lock().unwrap().verified = true;
        let start = s.start_flow("workos").await;
        s.signed_in(s.callback("workos", &param(&start, "state")).await, "workos@test.invalid").await;
    }
    let requests = mock.requests.lock().unwrap();
    let exchange = requests.iter().find(|r| r.starts_with("POST /user_management/authenticate ")).expect("WorkOS user management exchange");
    let body: Value = serde_json::from_str(exchange.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({"client_id": "test-client", "client_secret": "test-secret", "grant_type": "authorization_code", "code": "test-code"}));
}

#[tokio::test]
async fn linkedin_discovery_login_checks_nonce_audience_and_issuer() {
    let mock = Mock::start(true);
    let s = Server::start("linkedin", &mock.base, &[]).await;
    for fault in ["nonce", "audience", "issuer", ""] {
        let start = s.start_flow("linkedin").await;
        assert_eq!(start.as_str().split('?').next().unwrap(), format!("{}/authorize", mock.base));
        assert!(!param(&start, "nonce").is_empty());
        { let mut p = mock.profile.lock().unwrap(); p.nonce = param(&start, "nonce"); p.fault = fault; }
        let response = s.callback("linkedin", &param(&start, "state")).await;
        if fault.is_empty() { s.signed_in(response, "linkedin@test.invalid").await; }
        else { s.rejected(response, fault).await; }
    }
    assert!(mock.requests.lock().unwrap().iter().any(|r| r.starts_with("GET /.well-known/openid-configuration ")));
}
