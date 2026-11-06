// Integration tests hit the real router, middleware and SQLite storage by
// spawning the server binary. Each test owns a private database and port.

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
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
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
        Server::start_with_public(None).await
    }

    async fn start_with_public(public_url: Option<&str>) -> Server {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-it-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let public = public_url.map(|s| s.to_string()).unwrap_or_else(|| base.clone());
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &public)
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY")
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
        finish(req.send().await).await
    }

    async fn form(&self, path: &str, form: &[(&str, String)], token: Option<&str>) -> Resp {
        let mut req = self.client.post(self.url(path)).form(form);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        finish(req.send().await).await
    }
}

async fn finish(result: Result<reqwest::Response, reqwest::Error>) -> Resp {
    let response = result.expect("http request");
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Resp { status, text, body, headers }
}

async fn register(s: &Server, email: &str) -> Value {
    let r = s
        .call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"})))
        .await;
    assert_eq!(r.status, 200, "register failed: {}", r.text);
    r.body.clone()
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

async fn oauth_token(s: &Server, session: &str, scope: &str, resource: &str) -> (String, String) {
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
    let client_id = r.body["client_id"].as_str().expect("client id").to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(verifier.as_bytes());
        base64url(&digest)
    };
    let form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.clone()),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", scope.to_string()),
        ("state", "state-1".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("resource", resource.to_string()),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, Some(session)).await;
    let location = r.header("location");
    let code = parse_query(&location).get("code").cloned();
    if code.is_none() {
        panic!("authorize did not issue a code (status {}): {} {}", r.status, location, r.text);
    }
    let exchange = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.unwrap()),
        ("client_id", client_id.clone()),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("code_verifier", verifier.to_string()),
    ];
    let r = s.form("/oauth/token", &exchange, None).await;
    assert_eq!(r.status, 200, "token exchange failed: {}", r.text);
    (
        r.body["access_token"].as_str().expect("access token").to_string(),
        client_id,
    )
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

#[tokio::test]
async fn scim_is_scoped_to_the_callers_organisation() {
    let s = Server::start().await;
    let victim = register(&s, "victim@test.invalid").await;
    let attacker = register(&s, "attacker@test.invalid").await;
    let (vt, vo, vu) = (
        victim["token"].as_str().unwrap(),
        victim["org_id"].as_str().unwrap(),
        victim["user_id"].as_str().unwrap(),
    );
    let (at, ao) = (attacker["token"].as_str().unwrap(), attacker["org_id"].as_str().unwrap());

    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}", vo), Some(at), None).await;
    assert_eq!(r.status, 403, "cross-org SCIM user list must be denied, got {} {}", r.status, r.text);

    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}", ao), Some(at), None).await;
    assert_eq!(r.status, 200, "own org list failed: {}", r.text);
    let ids: Vec<String> = r.body["Resources"].as_array().cloned().unwrap_or_default().iter().filter_map(|u| u["id"].as_str().map(|x| x.to_string())).collect();
    assert!(!ids.contains(&vu.to_string()), "SCIM list leaked a user from another organisation");

    let r = s.call(Method::PUT, &format!("/scim/v2/Users/{}?org_id={}", vu, ao), Some(at), Some(json!({"userName": "renamed@test.invalid"}))).await;
    assert!(matches!(r.status, 403 | 404), "cross-org SCIM user update must be denied, got {} {}", r.status, r.text);
    let me = s.call(Method::GET, "/api/me", Some(vt), None).await;
    assert_eq!(me.body["email"].as_str().unwrap_or(""), "victim@test.invalid");
}

#[tokio::test]
async fn oauth_consent_requires_mfa_when_enabled() {
    let s = Server::start().await;
    let victim = register(&s, "mfa@test.invalid").await;
    let token = victim["token"].as_str().unwrap().to_string();
    let r = s.call(Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    assert_eq!(r.status, 200, "totp setup failed: {}", r.text);
    let secret = r.body["secret"].as_str().unwrap().to_string();
    let code = totp(&secret);
    let r = s.call(Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": code}))).await;
    assert_eq!(r.status, 200, "totp verify failed: {}", r.text);

    let r = s.call(Method::POST, "/oauth/register", None, Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none", "scope": "secrets:read"}))).await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = { use sha2::{Digest, Sha256}; base64url(&Sha256::digest(verifier.as_bytes())) };
    let mut form = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()),
        ("scope", "secrets:read".to_string()),
        ("state", "s".to_string()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("email", "mfa@test.invalid".to_string()),
        ("password", "correct-horse-battery".to_string()),
        ("approve", "1".to_string()),
    ];
    let r = s.form("/oauth/authorize/decision", &form, None).await;
    assert!(r.status >= 400, "password alone must not issue an OAuth code when TOTP is enabled, got {} {}", r.status, r.header("location"));

    form.push(("otp", totp(&secret)));
    let r = s.form("/oauth/authorize/decision", &form, None).await;
    assert_eq!(r.status, 307, "valid TOTP should issue a code, got {} {}", r.status, r.text);
    assert!(r.header("location").contains("code="), "expected an authorization code, got {}", r.header("location"));
}

#[tokio::test]
async fn oauth_read_scope_cannot_write_over_rest() {
    let s = Server::start().await;
    let u = register(&s, "scope@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, token, org).await;
    let (oat, _) = oauth_token(&s, token, "secrets:read", &format!("{}/mcp", s.base)).await;

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&oat), None).await;
    assert_eq!(r.status, 200, "read scope should allow reads: {}", r.text);
    let r = s
        .call(
            Method::PUT,
            &format!("/api/envs/{}/secrets", envs[0]),
            Some(&oat),
            Some(json!({"secrets": [{"key": "WRITE_ATTEMPT", "value": "x"}]})),
        )
        .await;
    assert_eq!(r.status, 403, "read-only OAuth token must not write, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn env_scoped_token_cannot_escape_through_mcp_or_mint_tokens() {
    let s = Server::start().await;
    let u = register(&s, "scoped@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, envs) = app_with_envs(&s, token, org).await;
    set_secret(&s, token, &envs[1], "OTHER_ENV_SECRET", "hidden-value").await;

    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(token), Some(json!({"name": "ci", "env_id": envs[0]}))).await;
    assert_eq!(r.status, 200, "token creation failed: {}", r.text);
    let pat = r.body["token"].as_str().unwrap().to_string();

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[1]), Some(&pat), None).await;
    assert_eq!(r.status, 403, "REST scope escape should already be blocked");

    let r = s
        .call(
            Method::POST,
            "/mcp",
            Some(&pat),
            Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_secrets", "arguments": {"env_id": envs[1]}}})),
        )
        .await;
    assert!(!r.text.contains("hidden-value"), "env-scoped token read another environment over MCP: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&pat), Some(json!({"name": "wider"}))).await;
    assert_eq!(r.status, 403, "a scoped token must not mint an unscoped token, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn ip_allowlist_covers_mcp_and_scim() {
    let s = Server::start().await;
    let u = register(&s, "ip@test.invalid").await;
    let token = u["token"].as_str().unwrap().to_string();
    let org = u["org_id"].as_str().unwrap().to_string();
    let (_, envs) = app_with_envs(&s, &token, &org).await;
    set_secret(&s, &token, &envs[0], "IP_SECRET", "ip-value").await;
    let r = s.call(Method::PUT, &format!("/api/orgs/{}/settings", org), Some(&token), Some(json!({"ip_allowlist": "192.0.2.0/24"}))).await;
    assert_eq!(r.status, 200, "settings failed: {}", r.text);

    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(&token), None).await;
    assert_eq!(r.status, 403, "REST should be blocked by the allowlist");

    let r = s
        .call(
            Method::POST,
            "/mcp",
            Some(&token),
            Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_secrets", "arguments": {"env_id": envs[0]}}})),
        )
        .await;
    assert!(!r.text.contains("ip-value"), "MCP bypassed the IP allowlist: {}", r.text);

    let r = s.call(Method::GET, &format!("/scim/v2/Users?org_id={}", org), Some(&token), None).await;
    assert_eq!(r.status, 403, "SCIM bypassed the IP allowlist, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn authorize_page_escapes_untrusted_parameters() {
    let s = Server::start().await;
    let r = s.call(Method::POST, "/oauth/register", None, Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none"}))).await;
    let client_id = r.body["client_id"].as_str().unwrap().to_string();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = { use sha2::{Digest, Sha256}; base64url(&Sha256::digest(verifier.as_bytes())) };
    let payload = "%22%3E%3Cscript%3Ealert(1)%3C/script%3E%3Cinput%20name%3D%22";
    let path = format!(
        "/oauth/authorize?client_id={}&redirect_uri=http%3A%2F%2F127.0.0.1%3A8917%2Fcallback&response_type=code&scope=secrets%3Aread&code_challenge={}&code_challenge_method=S256&{}=1",
        client_id, challenge, payload
    );
    let r = s.call(Method::GET, &path, None, None).await;
    assert_eq!(r.status, 200, "authorize page failed: {}", r.text);
    assert!(!r.text.contains("<script>alert(1)</script>"), "authorize page rendered an injected script tag");
    assert!(r.text.contains("&lt;script&gt;"), "expected escaped script text in the authorize page");
    assert!(!r.header("content-security-policy").is_empty(), "authorize pages need a Content-Security-Policy");
}

#[tokio::test]
async fn identity_role_cannot_exceed_the_creating_admin() {
    let s = Server::start().await;
    let owner = register(&s, "owner@test.invalid").await;
    let member = register(&s, "member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();

    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(ot), Some(json!({"name": "reader", "permissions": ["secrets:read"]}))).await;
    assert_eq!(r.status, 200, "role create failed: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "member@test.invalid", "role": "reader"}))).await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);

    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(mt), Some(json!({"name": "sneaky", "role": "owner"}))).await;
    assert_eq!(r.status, 403, "custom-role member must not create a privileged identity, got {} {}", r.status, r.text);

    let r = s.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(ot), Some(json!({"name": "escalate", "role": "owner"}))).await;
    assert_eq!(r.status, 400, "owner role must not be assignable to machine identities, got {} {}", r.status, r.text);
}

#[tokio::test]
async fn mcp_write_tools_respect_custom_role_permissions() {
    let s = Server::start().await;
    let owner = register(&s, "owner@test.invalid").await;
    let member = register(&s, "member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let (_, envs) = app_with_envs(&s, ot, org).await;
    set_secret(&s, ot, &envs[0], "KEEP_ME", "value").await;
    let mt = member["token"].as_str().unwrap();

    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(ot), Some(json!({"name": "editor", "permissions": ["secrets:read", "secrets:write"]}))).await;
    assert_eq!(r.status, 200, "role create failed: {}", r.text);
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "member@test.invalid", "role": "editor"}))).await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);

    let (oat, _) = oauth_token(&s, mt, "secrets:read secrets:write", &format!("{}/mcp", s.base)).await;
    let r = s
        .call(
            Method::POST,
            "/mcp",
            Some(&oat),
            Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "delete_secret", "arguments": {"env_id": envs[0], "key": "KEEP_ME"}}})),
        )
        .await;
    assert!(r.body["error"].is_object() || r.text.contains("\"isError\":true"), "delete_secret must be denied without secrets:delete, got {}", r.text);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), Some(ot), None).await;
    assert!(r.text.contains("KEEP_ME"), "secret was deleted despite the missing permission");
}

#[tokio::test]
async fn members_can_be_listed_and_removed() {
    let s = Server::start().await;
    let owner = register(&s, "owner@test.invalid").await;
    let member = register(&s, "member@test.invalid").await;
    let ot = owner["token"].as_str().unwrap();
    let org = owner["org_id"].as_str().unwrap();
    let mu = member["user_id"].as_str().unwrap();

    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(ot), Some(json!({"email": "member@test.invalid", "role": "developer"}))).await;
    assert_eq!(r.status, 200, "invite failed: {}", r.text);

    let r = s.call(Method::GET, &format!("/api/orgs/{}/members", org), Some(ot), None).await;
    assert_eq!(r.status, 200, "member listing failed: {}", r.text);
    let emails: Vec<String> = r.body.as_array().cloned().unwrap_or_default().iter().filter_map(|m| m["email"].as_str().map(|x| x.to_string())).collect();
    assert!(emails.contains(&"member@test.invalid".to_string()), "member missing from list: {}", r.text);

    let r = s.call(Method::DELETE, &format!("/api/orgs/{}/members/{}", org, mu), Some(ot), None).await;
    assert_eq!(r.status, 200, "member removal failed: {}", r.text);
    let r = s.call(Method::GET, "/api/orgs", Some(member["token"].as_str().unwrap()), None).await;
    assert!(!r.text.contains(org), "removed member still sees the organisation");
}

#[tokio::test]
async fn apps_and_envs_can_be_renamed_and_deleted() {
    let s = Server::start().await;
    let u = register(&s, "rename@test.invalid").await;
    let token = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (app, envs) = app_with_envs(&s, token, org).await;

    let r = s.call(Method::PATCH, &format!("/api/apps/{}", app), Some(token), Some(json!({"name": "renamed-app"}))).await;
    assert_eq!(r.status, 200, "app rename failed: {}", r.text);
    let r = s.call(Method::PATCH, &format!("/api/envs/{}", envs[0]), Some(token), Some(json!({"name": "qa"}))).await;
    assert_eq!(r.status, 200, "env rename failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(token), None).await;
    assert!(r.text.contains("qa"), "env rename not persisted: {}", r.text);

    let r = s.call(Method::DELETE, &format!("/api/apps/{}", app), Some(token), None).await;
    assert_eq!(r.status, 200, "app delete failed: {}", r.text);
    let r = s.call(Method::GET, &format!("/api/orgs/{}/apps", org), Some(token), None).await;
    assert!(!r.text.contains("renamed-app"), "app still listed after delete");
}

#[tokio::test]
async fn login_is_rate_limited() {
    let s = Server::start().await;
    register(&s, "brute@test.invalid").await;
    let mut last = 0;
    for _ in 0..8 {
        let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "brute@test.invalid", "password": "wrong-password"}))).await;
        last = r.status;
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429, "repeated failed logins were not rate limited");
}

#[tokio::test]
async fn production_requires_an_external_master_key() {
    let dir = std::env::temp_dir().join(format!("openwarp-it-prod-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
        .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
        .env("ADDR", format!("127.0.0.1:{}", port))
        .env("OPENWARP_ENV", "production")
        .env_remove("OPENWARP_MASTER_KEY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut exited = None;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            exited = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    let status = exited.expect("production start without OPENWARP_MASTER_KEY must fail fast");
    assert!(!status.success(), "production start must refuse to persist a generated master key in the database");
}

#[tokio::test]
async fn secure_cookie_flag_follows_the_public_url() {
    let plain = Server::start().await;
    let r = plain.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "cookie@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "register failed: {}", r.text);
    let cookie = r.header("set-cookie");
    assert!(cookie.contains("HttpOnly"), "session cookie must be HttpOnly: {}", cookie);
    assert!(cookie.contains("SameSite=Lax"), "session cookie must set SameSite: {}", cookie);
    assert!(!cookie.contains("Secure"), "plain HTTP should not set Secure: {}", cookie);

    let tls = Server::start_with_public(Some("https://openwarp.example")).await;
    let r = tls.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "cookie2@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "register failed: {}", r.text);
    assert!(r.header("set-cookie").contains("Secure"), "https public URL must set the Secure flag: {}", r.header("set-cookie"));
}
