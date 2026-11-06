// Authorization regression suite: custom roles, admin gates, scope escapes,
// OIDC secret handling and the SSRF surfaces. Each test owns a private database.

use hmac::Mac;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
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
        self.headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
    keep: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !self.keep { let _ = std::fs::remove_dir_all(&self.dir); }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

impl Server {
    async fn start() -> Server {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-authz-{}-{}", std::process::id(), seq));
        Server::start_at(dir).await
    }

    async fn start_at(dir: PathBuf) -> Server {
        let _start = START_LOCK.lock().await;
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY")
            .env_remove("OPENWARP_ALLOWED_DB_HOSTS")
            .env_remove("OPENWARP_ENV")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openwarp-server");
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        let server = Server { child, base, dir, client, keep: false };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() {
                    return server;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy at {}", server.base);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, self.url(path));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        self.finish(req.send().await).await
    }

    async fn call_with_headers(&self, path: &str, token: &str, body: Value, headers: &[(&str, &str)]) -> Resp {
        let mut req = self.client.post(self.url(path)).bearer_auth(token).json(&body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.finish(req.send().await).await
    }

    async fn form(&self, path: &str, form: &[(&str, String)], token: Option<&str>) -> Resp {
        let mut req = self.client.post(self.url(path)).form(form);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        self.finish(req.send().await).await
    }

    async fn finish(&self, result: Result<reqwest::Response, reqwest::Error>) -> Resp {
        let response = result.expect("http request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body, headers }
    }
}

async fn register(s: &Server, email: &str) -> Value {
    let r = s
        .call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"})))
        .await;
    assert_eq!(r.status, 200, "register failed: {}", r.text);
    r.body.clone()
}

async fn invite(s: &Server, owner: &str, org: &str, email: &str, role: &str) {
    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/members", org), Some(owner), Some(json!({"email": email, "role": role})))
        .await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);
}

async fn app_with_envs(s: &Server, token: &str, org: &str) -> (String, Vec<String>) {
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": "app"}))).await;
    assert_eq!(r.status, 200, "create app failed: {}", r.text);
    let app = r.body["id"].as_str().expect("app id").to_string();
    let r = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(token), None).await;
    let envs: Vec<String> = r.body.as_array().expect("env list").iter().map(|e| e["id"].as_str().unwrap_or("").to_string()).collect();
    assert!(envs.len() >= 2, "expected default envs");
    (app, envs)
}

async fn set_secret(s: &Server, token: &str, env: &str, key: &str, value: &str) {
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", env),
            Some(token),
            Some(json!({"secrets": [{"key": key, "value": value}]})),
        )
        .await;
    assert_eq!(r.status, 200, "set secret failed: {}", r.text);
}

/// Owner plus a member holding a custom role with no permissions at all.
async fn org_with_viewer(s: &Server, suffix: &str) -> (String, String, String, String, String, Vec<String>) {
    let owner = register(s, &format!("owner{}@test.invalid", suffix)).await;
    let member = register(s, &format!("viewer{}@test.invalid", suffix)).await;
    let ot = owner["token"].as_str().unwrap().to_string();
    let org = owner["org_id"].as_str().unwrap().to_string();
    let mt = member["token"].as_str().unwrap().to_string();
    let mu = member["user_id"].as_str().unwrap().to_string();
    let r = s
        .call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&ot), Some(json!({"name": "viewer", "permissions": []})))
        .await;
    assert_eq!(r.status, 200, "role create failed: {}", r.text);
    invite(s, &ot, &org, &format!("viewer{}@test.invalid", suffix), "viewer").await;
    let (app, envs) = app_with_envs(s, &ot, &org).await;
    set_secret(s, &ot, &envs[0], "SECRET1", "v1").await;
    (ot, org, mt, mu, app, envs)
}

fn totp(secret_b32: &str) -> String {
    let mut out = Vec::new();
    let (mut val, mut bits) = (0u32, 0u32);
    for c in secret_b32.chars() {
        let d = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;
        val = (val << 5) | d;
        bits += 5;
        if bits >= 8 {
            out.push(((val >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    let counter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&out).expect("hmac");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize;
    let code = (((hash[off] as u32 & 0x7f) << 24)
        | ((hash[off + 1] as u32) << 16)
        | ((hash[off + 2] as u32) << 8)
        | hash[off + 3] as u32)
        % 1_000_000;
    format!("{:06}", code)
}

fn base64url(data: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(data)
}

fn parse_query(location: &str) -> std::collections::HashMap<String, String> {
    location
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn oauth_access_token(s: &Server, session: &str, scope: &str) -> String {
    let r = s
        .call(
            Method::POST,
            "/oauth/register",
            None,
            Some(json!({
                "redirect_uris": ["http://127.0.0.1:8917/callback"],
                "token_endpoint_auth_method": "none",
                "scope": scope
            })),
        )
        .await;
    assert_eq!(r.status, 201, "client registration failed: {}", r.text);
    let client_id = r.body["client_id"].as_str().expect("client id").to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = {
        use sha2::{Digest, Sha256};
        base64url(&Sha256::digest(verifier.as_bytes()))
    };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.clone()),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", scope.to_string()),
        ("state", "state-1".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("resource", format!("{}/mcp", s.base)),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(session)).await;
    let code = parse_query(&r.header("location")).get("code").cloned();
    assert!(code.is_some(), "authorize did not issue a code ({}): {}", r.status, r.text);
    let exchange = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.unwrap()),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("code_verifier", verifier.to_string()),
    ];
    let r = s.form("/oauth/token", &exchange, None).await;
    assert_eq!(r.status, 200, "token exchange failed: {}", r.text);
    r.body["access_token"].as_str().expect("access token").to_string()
}

#[tokio::test]
async fn custom_roles_are_enforced_on_reads() {
    let s = Server::start().await;
    let (ot, org, mt, _, _, envs) = org_with_viewer(&s, "reads").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&mt), None).await;
    assert_eq!(r.status, 403, "a zero-permission role must not list secrets, got {} {}", r.status, r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/export", envs[0]), Some(&mt), None).await;
    assert_eq!(r.status, 403, "a zero-permission role must not export, got {} {}", r.status, r.text);

    let reader = register(&s, "viewer2@test.invalid").await;
    let rt = reader["token"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&ot), Some(json!({"name": "reader", "permissions": ["secrets:read"]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    invite(&s, &ot, &org, "viewer2@test.invalid", "reader").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(rt), None).await;
    assert_eq!(r.status, 200, "a reader role should read secrets: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(rt), Some(json!({"secrets": [{"key": "X", "value": "y"}]}))).await;
    assert_eq!(r.status, 403, "a reader role must not write secrets, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn custom_roles_cannot_change_org_security_settings() {
    let s = Server::start().await;
    let (_, org, mt, _, _, _) = org_with_viewer(&s, "admin").await;
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(&mt), Some(json!({"ip_allowlist": "127.0.0.1/32"}))).await;
    assert_eq!(r.status, 403, "a custom role must not write org settings, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&mt), Some(json!({"name": "escalate", "permissions": ["*"]}))).await;
    assert_eq!(r.status, 403, "a custom role must not create roles, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/log-streams", org), Some(&mt), Some(json!({"name": "x", "url": "http://127.0.0.1:1/x"}))).await;
    assert_eq!(r.status, 403, "a custom role must not create log streams, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/pki/cas", org), Some(&mt), Some(json!({"name": "ca"}))).await;
    assert_eq!(r.status, 403, "a custom role must not create a CA, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn custom_roles_cannot_use_unchecked_write_endpoints() {
    let s = Server::start().await;
    let (ot, _, mt, _, app, envs) = org_with_viewer(&s, "writes").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&ot), None).await;
    let sid = r.body["secrets"][0]["id"].as_str().unwrap().to_string();

    for (method, path, body) in [
        (Method::POST, format!("/api/envs/{}/restore-point", envs[0]), json!({"timestamp": 1})),
        (Method::POST, format!("/api/envs/{}/rotate", envs[0]), json!({"key": "SECRET1"})),
        (Method::POST, format!("/api/secrets/{}/restore/1", sid), json!({})),
        (Method::POST, format!("/api/envs/{}/integrations", envs[0]), json!({"kind": "webhook", "config": {"url": "http://127.0.0.1:1/h"}})),
        (Method::POST, format!("/api/envs/{}/dynamic", envs[0]), json!({"name": "lease"})),
        (Method::POST, format!("/api/envs/{}/rotations", envs[0]), json!({"key": "SECRET1", "interval_secs": 60})),
        (Method::POST, format!("/api/apps/{}/tokens", app), json!({"name": "t"})),
        (Method::POST, format!("/api/envs/{}/e2e/grant", envs[0]), json!({"email": "x@test.invalid", "wrapped_key": "k"})),
    ] {
        let r = s.call(method.clone(), &path, Some(&mt), Some(body)).await;
        assert_eq!(r.status, 403, "{} {} must be denied for a zero-permission role, got {} {}", method, path, r.status, r.text);
    }
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&ot), None).await;
    assert_eq!(r.body["secrets"][0]["value"].as_str().unwrap_or(""), "v1", "no viewer write may have landed: {}", r.text);
}

#[tokio::test]
async fn changing_the_oidc_issuer_requires_a_new_client_secret() {
    let s = Server::start().await;
    let u = register(&s, "oidc-settings@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s
        .call(
            Method::PUT,
            &format!("/api/orgs/{}/settings", org),
            Some(token),
            Some(json!({"oidc_issuer": "https://idp-one.example", "oidc_client_id": "c1", "oidc_client_secret": "s1", "oidc_redirect_uri": "https://app.example/cb"})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s
        .call(
            Method::PUT,
            &format!("/api/orgs/{}/settings", org),
            Some(token),
            Some(json!({"oidc_issuer": "https://idp-two.example"})),
        )
        .await;
    assert_eq!(r.status, 200, "issuer change should be accepted but invalidate the secret: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/auth/oidc/{}/start", org), None, None).await;
    assert_eq!(r.status, 400, "a flow must not start with a stale issuer secret, got {} {}", r.status, r.text);
    assert!(r.text.contains("client secret") || r.text.contains("client_secret") || r.text.contains("re-enter"), "expected a secret-required error, got {}", r.text);
}

#[tokio::test]
async fn postgres_leases_are_denied_without_an_allowlist() {
    let s = Server::start().await;
    let u = register(&s, "pg-lease@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s
        .call(
            Method::POST,
            &format!("/api/envs/{}/dynamic", envs[0]),
            Some(token),
            Some(json!({"name": "pg", "type": "postgres", "config": {"connection": "postgres://u:p@127.0.0.1:5432/db"}})),
        )
        .await;
    assert_eq!(r.status, 400, "postgres leases must fail closed without OPENWARP_ALLOWED_DB_HOSTS, got {} {}", r.status, r.text);
    assert!(r.text.contains("ALLOWED_DB_HOSTS"), "the error must name the setting: {}", r.text);
}

#[tokio::test]
async fn env_scoped_tokens_cannot_reach_scim() {
    let s = Server::start().await;
    let (ot, org, _mt, mu, app, envs) = org_with_viewer(&s, "scim").await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&ot), Some(json!({"name": "ci", "env_id": envs[0]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let pat = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::DELETE, &format!("/scim/v2/Users/{}?org_id={}", mu, org), Some(&pat), None).await;
    assert_eq!(r.status, 403, "an env-scoped token must not deprovision users, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn machine_tokens_cannot_mint_service_tokens() {
    let s = Server::start().await;
    let u = register(&s, "machine-mint@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, _) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(token), Some(json!({"name": "ci", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let cid = r.body["client_id"].as_str().unwrap().to_string();
    let secret = r.body["client_secret"].as_str().unwrap().to_string();
    let r = s
        .call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": secret})))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let machine = r.body["accessToken"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&machine), Some(json!({"name": "persist"}))).await;
    assert_eq!(r.status, 403, "a 1h machine token must not mint a long-lived token, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn mfa_code_guessing_is_rate_limited() {
    let s = Server::start().await;
    let u = register(&s, "mfa-limit@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": totp(&secret)}))).await;
    assert_eq!(r.status, 200, "totp verify failed: {}", r.text);

    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "mfa-limit@test.invalid", "password": "correct-horse-battery"}))).await;
    let challenge = r.body["mfa_token"].as_str().expect("mfa challenge").to_string();
    let mut last = 0;
    for i in 0..8 {
        let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": format!("{:06}", i)}))).await;
        last = r.status;
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429, "repeated wrong TOTP codes at the MFA step were not rate limited");
}

#[tokio::test]
async fn mcp_rejects_a_forged_origin() {
    let s = Server::start().await;
    let u = register(&s, "mcp-origin@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, &token, org).await;
    set_secret(&s, &token, &envs[0], "MCPKEY", "mcpval").await;
    let oat = oauth_access_token(&s, &token, "secrets:read").await;
    let host = s.base.trim_start_matches("http://").to_string();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_secrets", "arguments": {"env_id": envs[0]}}});
    let r = s.call_with_headers("/mcp", &oat, body.clone(), &[("Origin", &format!("http://{}.evil.example", host))]).await;
    assert_eq!(r.status, 403, "a forged Origin must be rejected, got {} {}", r.status, r.text);
    let r = s.call_with_headers("/mcp", &oat, body.clone(), &[("Origin", &format!("http://evil.example/?{}", host))]).await;
    assert_eq!(r.status, 403, "an origin with a smuggled host must be rejected, got {} {}", r.status, r.text);
    let r = s.call_with_headers("/mcp", &oat, body, &[("Origin", &format!("http://{}", host))]).await;
    assert_eq!(r.status, 200, "the real origin should still work: {}", r.text);
    assert!(r.text.contains("MCPKEY"), "{}", r.text);
}

#[tokio::test]
async fn deactivated_accounts_stop_working_immediately() {
    let s = Server::start().await;
    let owner = register(&s, "deact-owner@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (app, _) = app_with_envs(&s, ot, org).await;
    // A SCIM-provisioned user has no personal organisation, so removing their
    // last membership is real deactivation.
    let r = s
        .call(Method::POST, &format!("/scim/v2/Users?org_id={}", org), Some(ot), Some(json!({"userName": "scim-user@test.invalid"})))
        .await;
    assert_eq!(r.status, 200, "scim create failed: {}", r.text);
    let uid = r.body["id"].as_str().unwrap().to_string();
    let temp_password = r.body["temp_password"].as_str().unwrap().to_string();
    let r = s
        .call(Method::POST, "/api/auth/login", None, Some(json!({"email": "scim-user@test.invalid", "password": temp_password})))
        .await;
    assert_eq!(r.status, 200, "scim user login failed: {}", r.text);
    let mt = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&mt), Some(json!({"name": "ci"}))).await;
    assert_eq!(r.status, 200, "a developer should be able to mint a token: {}", r.text);
    let pat = r.body["token"].as_str().unwrap().to_string();
    let r = s.call(Method::GET, "/api/me", Some(&pat), None).await;
    assert_eq!(r.status, 200, "the token must work before deactivation: {}", r.text);
    let r = s.call(Method::DELETE, &format!("/scim/v2/Users/{}?org_id={}", uid, org), Some(ot), None).await;
    assert_eq!(r.status, 200, "scim deactivate failed: {}", r.text);
    let r = s.call(Method::GET, "/api/me", Some(&pat), None).await;
    assert_eq!(r.status, 401, "a deactivated account's token must stop working, got {} {}", r.status, r.text);
    let r = s.call(Method::GET, "/api/me", Some(&mt), None).await;
    assert_eq!(r.status, 401, "a deactivated account's session must stop working, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn user_lookup_does_not_reveal_account_existence() {
    let s = Server::start().await;
    let u = register(&s, "lookup@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    register(&s, "existing-other@test.invalid").await;
    let missing = s.call(Method::GET, "/api/users/lookup?email=nobody@test.invalid", Some(token), None).await;
    let other = s.call(Method::GET, "/api/users/lookup?email=existing-other@test.invalid", Some(token), None).await;
    assert_eq!(missing.status, other.status, "lookup must not distinguish missing from cross-org accounts ({} vs {})", missing.status, other.status);
    assert_eq!(missing.status, 403, "cross-org lookup should be forbidden, got {} {}", missing.status, missing.text);
}

#[tokio::test]
async fn secret_keys_reject_markup() {
    let s = Server::start().await;
    let u = register(&s, "keys@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", envs[0]),
            Some(token),
            Some(json!({"secrets": [{"key": "<img src=x onerror=alert(1)>", "value": "v"}]})),
        )
        .await;
    assert_eq!(r.status, 400, "markup in a secret key must be rejected, got {} {}", r.status, r.text);
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", envs[0]),
            Some(token),
            Some(json!({"secrets": [{"key": "VALID_KEY-1", "value": "v"}]})),
        )
        .await;
    assert_eq!(r.status, 200, "a normal key must still deploy: {}", r.text);
}

#[tokio::test]
async fn registration_is_rate_limited() {
    let s = Server::start().await;
    let mut last = 0;
    for i in 0..8 {
        let r = s
            .call(Method::POST, "/api/auth/register", None, Some(json!({"email": format!("burst{}@test.invalid", i), "password": "correct-horse-battery"})))
            .await;
        last = r.status;
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429, "repeated registrations from one address were not rate limited");
}

#[tokio::test]
async fn pkce_rejects_an_empty_verifier() {
    let s = Server::start().await;
    let u = register(&s, "pkce@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let r = s
        .call(
            Method::POST,
            "/oauth/register",
            None,
            Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none", "scope": "secrets:read"})),
        )
        .await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let challenge = { use sha2::{Digest, Sha256}; base64url(&Sha256::digest(b"".as_slice())) };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.clone()),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", "secrets:read".to_string()),
        ("state", "s".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(token)).await;
    let code = parse_query(&r.header("location")).get("code").cloned().expect("code");
    let exchange = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("code_verifier", String::new()),
    ];
    let r = s.form("/oauth/token", &exchange, None).await;
    assert_eq!(r.status, 400, "an empty PKCE verifier must be rejected, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn rate_limits_survive_a_restart() {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("openwarp-authz-persist-{}-{}", std::process::id(), seq));
    let first = Server::start_at(dir.clone()).await;
    register(&first, "persist@test.invalid").await;
    let mut last = 0;
    for _ in 0..6 {
        let r = first
            .call(Method::POST, "/api/auth/login", None, Some(json!({"email": "persist@test.invalid", "password": "wrong-password"})))
            .await;
        last = r.status;
    }
    assert_eq!(last, 429, "the first process must exhaust the budget");
    let mut first = first;
    first.keep = true;
    drop(first);

    let second = Server::start_at(dir.clone()).await;
    let r = second
        .call(Method::POST, "/api/auth/login", None, Some(json!({"email": "persist@test.invalid", "password": "wrong-password"})))
        .await;
    assert_eq!(r.status, 429, "a restart must not clear the failure budget, got {} {}", r.status, r.text);
    let mut second = second;
    second.keep = true;
    drop(second);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn restricted_environments_require_a_grant() {
    let s = Server::start().await;
    let owner = register(&s, "restrict-owner@test.invalid").await;
    let member = register(&s, "restrict-member@test.invalid").await;
    let other = register(&s, "restrict-other@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, ot, org).await;
    set_secret(&s, ot, &envs[0], "RESTRICTED_KEY", "v1").await;
    invite(&s, ot, org, "restrict-member@test.invalid", "developer").await;
    invite(&s, ot, org, "restrict-other@test.invalid", "developer").await;
    let mt = member["token"].as_str().unwrap();
    let xt = other["token"].as_str().unwrap();

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 200, "an unrestricted env is open to org members: {}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(ot), Some(json!({"restricted": true}))).await;
    assert_eq!(r.status, 200, "policy change failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 403, "a restricted env must deny non-members, got {} {}", r.status, r.text);

    let r = s.call(Method::POST, &format!("/api/envs/{}/access-requests", envs[0]), Some(mt), Some(json!({"reason": "need it"}))).await;
    assert_eq!(r.status, 200, "access request failed: {}", r.text);
    let rid = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/access-requests/{}/approve", rid), Some(ot), Some(json!({}))).await;
    assert_eq!(r.status, 200, "approval failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), None).await;
    assert_eq!(r.status, 200, "an approved member must get access: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(xt), None).await;
    assert_eq!(r.status, 403, "approving one member must not open the env to others, got {} {}", r.status, r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(mt), Some(json!({"restricted": false}))).await;
    assert_eq!(r.status, 403, "only an admin may change env policy, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn clients_cannot_request_scopes_they_did_not_register() {
    let s = Server::start().await;
    let u = register(&s, "scopes@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let r = s
        .call(
            Method::POST,
            "/oauth/register",
            None,
            Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none", "scope": "secrets:read"})),
        )
        .await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = { use sha2::{Digest, Sha256}; base64url(&Sha256::digest(verifier.as_bytes())) };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", "secrets:read secrets:write".to_string()),
        ("state", "s".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(token)).await;
    assert_eq!(r.status, 400, "a client must not escalate to an unregistered scope, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn settings_round_trip_preserves_the_oidc_secret() {
    let s = Server::start().await;
    let u = register(&s, "settings@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "client",
        "oidc_client_secret": "top-secret-value",
        "oidc_redirect_uri": "https://app.example/cb",
        "oidc_auto_provision": true,
        "oidc_allowed_domains": "example.com"
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["oidc_issuer"], "https://idp.example");
    assert_eq!(r.body["oidc_client_secret_set"], true);
    assert!(!r.text.contains("top-secret-value"), "the client secret must never be returned: {}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({"ip_allowlist": "127.0.0.1/32"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/settings", org), Some(token), None).await;
    assert_eq!(r.body["oidc_issuer"], "https://idp.example", "a partial update must not clear OIDC: {}", r.text);
    assert_eq!(r.body["oidc_client_secret_set"], true, "a blank secret must keep the stored one: {}", r.text);

    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(token), Some(json!({"ip_allowlist": "not-a-cidr"}))).await;
    assert_eq!(r.status, 400, "invalid CIDRs must be rejected, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn identities_can_be_rotated_and_deleted() {
    let s = Server::start().await;
    let u = register(&s, "identity-life@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(token), Some(json!({"name": "ci", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let iid = r.body["id"].as_str().unwrap().to_string();
    let cid = r.body["client_id"].as_str().unwrap().to_string();
    let old_secret = r.body["client_secret"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities/{}/rotate", org, iid), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let new_secret = r.body["client_secret"].as_str().unwrap().to_string();
    assert_ne!(old_secret, new_secret, "rotation must issue a new secret");

    let old_login = s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": old_secret}))).await;
    assert_eq!(old_login.status, 401, "the old secret must stop working, got {} {}", old_login.status, old_login.text);
    let new_login = s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": new_secret}))).await;
    assert_eq!(new_login.status, 200, "{}", new_login.text);

    let r = s.call(Method::DELETE, &format!("/api/orgs/{}/identities/{}", org, iid), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let after = s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": cid, "client_secret": new_secret}))).await;
    assert_eq!(after.status, 401, "a deleted identity must not authenticate, got {} {}", after.status, after.text);
}

#[tokio::test]
async fn integrations_can_be_edited_and_deleted() {
    let s = Server::start().await;
    let u = register(&s, "integration-life@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let r = s.call(Method::POST, &format!("/api/envs/{}/integrations", envs[0]), Some(token), Some(json!({
        "kind": "webhook", "name": "first", "config": {"url": "http://127.0.0.1:1/hook"}
    }))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let iid = r.body["id"].as_str().unwrap().to_string();

    let r = s.call(Method::PATCH, &format!("/api/integrations/{}", iid), Some(token), Some(json!({"name": "renamed", "config": {"url": "http://127.0.0.1:2/hook"}}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/integrations", envs[0]), Some(token), None).await;
    assert!(r.body.as_array().unwrap().iter().any(|i| i["name"] == "renamed"), "{}", r.text);

    let r = s.call(Method::DELETE, &format!("/api/integrations/{}", iid), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/integrations", envs[0]), Some(token), None).await;
    assert_eq!(r.body.as_array().unwrap().len(), 0, "{}", r.text);
}

#[tokio::test]
async fn point_in_time_restore_removes_later_secrets_and_restores_deleted_ones() {
    let s = Server::start().await;
    let u = register(&s, "pitr@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "ALPHA", "one").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    set_secret(&s, token, &envs[0], "BETA", "two").await;

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(token), None).await;
    let sid = r.body["secrets"].as_array().unwrap().iter().find(|x| x["key"] == "ALPHA").unwrap()["id"].as_str().unwrap().to_string();
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", sid), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::POST, &format!("/api/envs/{}/restore-point", envs[0]), Some(token), Some(json!({"timestamp": ts}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["restored"].as_i64().unwrap_or(0) >= 1, "{}", r.text);
    assert!(r.body["removed"].as_i64().unwrap_or(0) >= 1, "{}", r.text);

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(token), None).await;
    let keys: Vec<&str> = r.body["secrets"].as_array().unwrap().iter().map(|x| x["key"].as_str().unwrap_or("")).collect();
    assert!(keys.contains(&"ALPHA"), "a secret deleted after the timestamp must come back: {}", r.text);
    assert!(!keys.contains(&"BETA"), "a secret created after the timestamp must be gone: {}", r.text);
}

#[tokio::test]
async fn e2e_grants_can_be_listed_and_revoked() {
    let s = Server::start().await;
    let owner = register(&s, "e2e-owner@test.invalid").await;
    let member = register(&s, "e2e-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mid = member["user_id"].as_str().unwrap().to_string();
    invite(&s, ot, org, "e2e-member@test.invalid", "developer").await;
    let (app, _) = app_with_envs(&s, ot, org).await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs/e2e", app), Some(ot), Some(json!({"name": "vault"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let eid = r.body["id"].as_str().unwrap().to_string();

    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/grant", eid), Some(ot), Some(json!({"email": "e2e-member@test.invalid", "wrapped_key": "AAAA"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/e2e/grants", eid), Some(ot), None).await;
    assert!(r.body.as_array().unwrap().iter().any(|g| g["user_id"] == mid), "{}", r.text);

    let r = s.call(Method::DELETE, &format!("/api/envs/{}/e2e/grants/{}", eid, mid), Some(ot), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/e2e/grants", eid), Some(ot), None).await;
    assert!(!r.body.as_array().unwrap().iter().any(|g| g["user_id"] == mid), "the revoked member must be gone: {}", r.text);
}

#[tokio::test]
async fn a_totp_code_cannot_be_replayed() {
    let s = Server::start().await;
    let u = register(&s, "replay@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let code = totp(&secret);
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": code}))).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "replay@test.invalid", "password": "correct-horse-battery"}))).await;
    let challenge = r.body["mfa_token"].as_str().expect("mfa challenge").to_string();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": code}))).await;
    assert_eq!(r.status, 200, "the first use of a current code should succeed: {}", r.text);

    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "replay@test.invalid", "password": "correct-horse-battery"}))).await;
    let challenge = r.body["mfa_token"].as_str().expect("second mfa challenge").to_string();
    let r = s.call(Method::POST, "/api/auth/mfa", None, Some(json!({"mfa_token": challenge, "code": code}))).await;
    assert_eq!(r.status, 401, "the same TOTP code must not be accepted twice, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn approval_policy_blocks_direct_developer_deploys() {
    let s = Server::start().await;
    let owner = register(&s, "approval-owner@test.invalid").await;
    let member = register(&s, "approval-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    invite(&s, ot, org, "approval-member@test.invalid", "developer").await;
    let (_, envs) = app_with_envs(&s, ot, org).await;

    let r = s.call(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), Some(ot), Some(json!({"require_approval": true}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), Some(mt), Some(json!({"secrets": [{"key": "DIRECT", "value": "no"}]}))).await;
    assert_eq!(r.status, 403, "a developer must not bypass the approval policy, got {} {}", r.status, r.text);
    let r = s.call(Method::POST, &format!("/api/envs/{}/proposals", envs[0]), Some(mt), Some(json!({"secrets": [{"key": "APPROVED", "value": "yes"}]}))).await;
    assert_eq!(r.status, 200, "a developer must still be able to propose: {}", r.text);
    let pid = r.body["id"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, &format!("/api/proposals/{}/approve", pid), Some(ot), Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(ot), None).await;
    assert!(r.body["secrets"].as_array().unwrap().iter().any(|x| x["key"] == "APPROVED"), "{}", r.text);
}

#[tokio::test]
async fn ownership_can_be_transferred_and_a_member_can_leave() {
    let s = Server::start().await;
    let owner = register(&s, "transfer-owner@test.invalid").await;
    let member = register(&s, "transfer-member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mid = member["user_id"].as_str().unwrap().to_string();
    invite(&s, ot, org, "transfer-member@test.invalid", "developer").await;

    let r = s.call(Method::PATCH, &format!("/api/orgs/{}/members/{}", org, mid), Some(ot), Some(json!({"role": "admin"}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/transfer", org), Some(ot), Some(json!({"user_id": mid}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, "/api/orgs", Some(mt), None).await;
    assert!(r.body.as_array().unwrap().iter().any(|o| o["id"] == org && o["role"] == "owner"), "the grantee must own the org: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/leave", org), Some(ot), Some(json!({}))).await;
    assert_eq!(r.status, 200, "the former owner must be able to leave: {}", r.text);
    let r = s.call(Method::GET, "/api/orgs", Some(ot), None).await;
    assert!(!r.body.as_array().unwrap().iter().any(|o| o["id"] == org), "the former owner must no longer see the org: {}", r.text);
}

#[tokio::test]
async fn environments_can_be_cloned_and_compared() {
    let s = Server::start().await;
    let u = register(&s, "clone@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[0], "ALPHA", "one").await;
    set_secret(&s, token, &envs[0], "BETA", "two").await;

    let r = s.call(Method::POST, &format!("/api/envs/{}/clone", envs[0]), Some(token), Some(json!({"target_env_id": envs[1]}))).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.body["cloned"].as_i64().unwrap_or(0) >= 2, "{}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[1]), Some(token), None).await;
    let keys: Vec<&str> = r.body["secrets"].as_array().unwrap().iter().map(|x| x["key"].as_str().unwrap_or("")).collect();
    assert!(keys.contains(&"ALPHA") && keys.contains(&"BETA"), "{}", r.text);

    let r = s.call(Method::GET, &format!("/api/envs/{}/compare?other={}", envs[0], envs[1]), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["same"].as_i64().unwrap_or(0), 2, "{}", r.text);
    set_secret(&s, token, &envs[1], "BETA", "changed").await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/compare?other={}", envs[0], envs[1]), Some(token), None).await;
    assert!(r.body["changed"].as_array().unwrap().iter().any(|k| k.as_str().unwrap_or("").ends_with("BETA")), "{}", r.text);
}

#[tokio::test]
async fn scim_discovery_and_paging_are_available() {
    let s = Server::start().await;
    let u = register(&s, "scim-page@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let r = s.call(Method::GET, "/scim/v2/ServiceProviderConfig", None, None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}&startIndex=1&count=1", org), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["itemsPerPage"], 1, "{}", r.text);
    assert!(r.body["totalResults"].as_i64().unwrap_or(0) >= 1, "{}", r.text);
    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}&filter=userName%20eq%20%22scim-page%40test.invalid%22", org), Some(token), None).await;
    assert_eq!(r.body["totalResults"], 1, "{}", r.text);
}

async fn put_secret(s: &Server, token: &str, env: &str, key: &str, value: &str, tags: &str) {
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", env),
            Some(token),
            Some(json!({"secrets": [{"key": key, "value": value, "tags": tags}]})),
        )
        .await;
    assert_eq!(r.status, 200, "put {} failed: {}", key, r.text);
}

async fn secret_id(s: &Server, token: &str, env: &str, key: &str) -> String {
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    r.body["secrets"]
        .as_array()
        .expect("secrets")
        .iter()
        .find(|s| s["key"].as_str() == Some(key))
        .and_then(|s| s["id"].as_str())
        .unwrap_or_else(|| panic!("secret {} not found", key))
        .to_string()
}

#[tokio::test]
async fn pitr_restores_creates_deletes_and_tags() {
    let s = Server::start().await;
    let u = register(&s, "pitr@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let env = envs[0].clone();

    put_secret(&s, token, &env, "ALPHA", "v1", "team=a").await;
    put_secret(&s, token, &env, "BRAVO", "b1", "team=b").await;
    let reference = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    put_secret(&s, token, &env, "ALPHA", "v2", "team=changed").await;
    let bravo = secret_id(&s, token, &env, "BRAVO").await;
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", bravo), Some(token), None).await;
    assert_eq!(r.status, 200, "delete failed: {}", r.text);
    put_secret(&s, token, &env, "CHARLIE", "c1", "").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let r = s
        .call(Method::POST, &format!("/api/envs/{}/restore-point", env), Some(token), Some(json!({"timestamp": reference})))
        .await;
    assert_eq!(r.status, 200, "restore-point failed: {}", r.text);
    assert!(r.body["restored"].as_i64().unwrap_or(0) >= 1, "at least one secret restored: {}", r.text);

    let list = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    let secrets = list.body["secrets"].as_array().expect("secrets");
    let alpha = secrets.iter().find(|x| x["key"] == "ALPHA").expect("ALPHA");
    assert_eq!(alpha["value"], json!("v1"), "the value at the reference time must return");
    assert_eq!(alpha["tags"], json!("team=a"), "tags recorded with the version must return");
    assert!(secrets.iter().any(|x| x["key"] == "BRAVO"), "a secret deleted after the reference time must return");
    assert!(!secrets.iter().any(|x| x["key"] == "CHARLIE"), "a secret created after the reference time must disappear");

    // A later restore must not resurrect CHARLIE (deleted by the first restore)
    // and must keep BRAVO (its deleted_at was cleared when it was restored).
    let later = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let r = s
        .call(Method::POST, &format!("/api/envs/{}/restore-point", env), Some(token), Some(json!({"timestamp": later})))
        .await;
    assert_eq!(r.status, 200, "second restore-point failed: {}", r.text);
    let list = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    let secrets = list.body["secrets"].as_array().expect("secrets");
    assert!(secrets.iter().any(|x| x["key"] == "BRAVO"), "a restored secret must survive a later restore: {}", list.text);
    assert!(!secrets.iter().any(|x| x["key"] == "CHARLIE"), "a removed secret must stay removed: {}", list.text);

    // The explicit version restore must also clear the tombstone.
    let bravo = secret_id(&s, token, &env, "BRAVO").await;
    let r = s.call(Method::DELETE, &format!("/api/secrets/{}", bravo), Some(token), None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = s.call(Method::POST, &format!("/api/secrets/{}/restore/1", bravo), Some(token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "version restore failed: {}", r.text);
    let r = s
        .call(Method::POST, &format!("/api/envs/{}/restore-point", env), Some(token), Some(json!({"timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64})))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let list = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await;
    assert!(list.body["secrets"].as_array().expect("secrets").iter().any(|x| x["key"] == "BRAVO"), "a manually restored secret must survive a point-in-time restore: {}", list.text);
}
