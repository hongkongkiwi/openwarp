use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const PASSWORD: &str = "account-merge-test-password";
const REDIRECT: &str = "http://127.0.0.1:8917/callback";
const VERIFIER: &str = "account-merge-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";

struct Resp { status: u16, body: Value, location: String }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>>, sessions: Mutex<HashMap<String, String>> }
struct User { id: String, org: String, session: String }
struct OAuth { access: String, refresh: String, client: String }

impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("inbox bind");
    let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection");
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = stream.read(&mut chunk).expect("mail read");
                if n == 0 { break; }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
            if let Ok(v) = serde_json::from_slice::<Value>(&buf[end..]) { sink.lock().unwrap().push(v); }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", addr), inbox)
}

impl Server {
    async fn start() -> Self {
        let _lock = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-account-merge-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let (relay, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", relay).env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_SIGNUPS").stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client, inbox, sessions: Mutex::new(HashMap::new()) };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }

    async fn response(response: reqwest::Response) -> Resp {
        let status = response.status().as_u16();
        let location = response.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let text = response.text().await.unwrap();
        Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null), location }
    }

    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = req.bearer_auth(token); }
        if let Some(body) = body { req = req.json(&body); }
        Self::response(req.send().await.expect("HTTP request")).await
    }

    async fn form(&self, path: &str, token: &str, form: &[(&str, String)]) -> Resp {
        let mut req = self.client.post(format!("{}{}", self.base, path)).form(form);
        if !token.is_empty() { req = req.bearer_auth(token); }
        Self::response(req.send().await.expect("form request")).await
    }

    async fn register_raw(&self, email: &str) -> Resp {
        let r = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "register account");
        assert_eq!(r.body["verification_required"], true);
        r
    }

    async fn verify(&self, email: &str) {
        for _ in 0..60 {
            let link = { self.inbox.lock().unwrap().iter().rev().filter(|m| m["to"] == email).filter_map(|m| m["text"].as_str())
                .find(|text| text.contains("/api/auth/verify?token="))
                .and_then(|text| text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string()))) };
            if let Some(link) = link { assert_eq!(self.call(Method::GET, &link, "", None).await.status, 200, "verify account"); return; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("verification mail did not arrive");
    }

    async fn register(&self, email: &str) -> User {
        let r = self.register_raw(email).await;
        self.verify(email).await;
        let login = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(login.status, 200, "verified password login");
        let session = field(&login.body, "token");
        self.sessions.lock().unwrap().insert(email.trim().to_lowercase(), session.clone());
        User { id: field(&r.body, "user_id"), org: field(&r.body, "org_id"), session }
    }

    async fn add_member(&self, owner: &User, email: &str, role: &str) {
        let session = self.sessions.lock().unwrap().get(&email.trim().to_lowercase()).expect("registered invitee session").clone();
        let invite = self.call(Method::POST, &format!("/api/orgs/{}/members", owner.org), &owner.session,
            Some(json!({"email": email, "role": role}))).await;
        assert_eq!(invite.status, 200, "add member");
        assert_eq!(self.call(Method::POST, "/api/auth/accept-invite", &session,
            Some(json!({"token": field(&invite.body, "invite_token")}))).await.status, 200, "accept member invitation");
    }

    async fn app(&self, user: &User, org: &str) -> String {
        let r = self.call(Method::POST, &format!("/api/orgs/{}/apps", org), &user.session, Some(json!({"name": "test-app"}))).await;
        assert_eq!(r.status, 200, "create app"); field(&r.body, "id")
    }

    async fn consent_form(&self, scope: &str, resource: Option<&str>) -> Vec<(&'static str, String)> {
        let r = self.call(Method::POST, "/oauth/register", "", Some(json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "scope": scope}))).await;
        assert_eq!(r.status, 201, "register OAuth client");
        use base64ct::{Base64UrlUnpadded, Encoding};
        use sha2::{Digest, Sha256};
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()));
        let mut form = vec![("response_type", "code".into()), ("client_id", field(&r.body, "client_id")),
            ("redirect_uri", REDIRECT.into()), ("scope", scope.into()), ("state", "account-merge".into()),
            ("code_challenge", challenge), ("code_challenge_method", "S256".into()), ("approve", "1".into())];
        if let Some(resource) = resource { form.push(("resource", resource.into())); }
        form
    }

    async fn exchange(&self, decision: Resp, client: &str) -> OAuth {
        assert_eq!(decision.status, 303, "OAuth consent must issue an authorization code");
        let code = query(&decision.location, "code");
        assert!(!code.is_empty(), "consent redirect must contain a code");
        let r = self.form("/oauth/token", "", &[("grant_type", "authorization_code".into()), ("client_id", client.into()),
            ("redirect_uri", REDIRECT.into()), ("code_verifier", VERIFIER.into()), ("code", code)]).await;
        assert_eq!(r.status, 200, "exchange authorization code");
        OAuth { access: field(&r.body, "access_token"), refresh: field(&r.body, "refresh_token"), client: client.into() }
    }

    async fn oauth(&self, user: &User, scope: &str, resource: Option<&str>) -> OAuth {
        let form = self.consent_form(scope, resource).await;
        let client = form.iter().find(|(k, _)| *k == "client_id").unwrap().1.clone();
        let decision = self.form("/oauth/authorize/decision", &user.session, &form).await;
        self.exchange(decision, &client).await
    }
}

fn field(body: &Value, key: &str) -> String { body[key].as_str().expect("response field").to_string() }
fn query(location: &str, key: &str) -> String {
    location.split_once('?').map(|(_, q)| q).unwrap_or("").split('&').filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key).map(|(_, v)| v.to_string()).unwrap_or_default()
}

#[tokio::test]
async fn account_delete_refuses_even_a_co_owner_until_transfer() {
    let s = Server::start().await;
    let first = s.register("first@test.invalid").await;
    let second = s.register("second@test.invalid").await;
    s.add_member(&second, "first@test.invalid", "owner").await;
    let r = s.call(Method::DELETE, "/api/me?confirm=true", &second.session, None).await;
    assert_eq!(r.status, 409, "owning any workspace blocks deletion, even with another owner");
    assert!(r.body["workspaces"].as_array().expect("owned workspace list").iter().any(|w| w["id"] == second.org));
    assert_eq!(s.call(Method::GET, "/api/me", &second.session, None).await.status, 200, "refusal preserves session");
    assert_eq!(s.call(Method::POST, &format!("/api/orgs/{}/transfer", second.org), &second.session, Some(json!({"user_id": first.id}))).await.status, 200);
    assert_eq!(s.call(Method::DELETE, "/api/me", &second.session, None).await.status, 200, "transfer releases account");
    let orgs = s.call(Method::GET, "/api/orgs", &first.session, None).await;
    assert!(orgs.body.as_array().unwrap().iter().any(|o| o["id"] == second.org && o["role"] == "owner"), "transferred workspace survives");
}

#[tokio::test]
async fn account_delete_rejects_service_and_oauth_credentials() {
    let s = Server::start().await;
    let u = s.register("credentials@test.invalid").await;
    let app = s.app(&u, &u.org).await;
    let key = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), &u.session, Some(json!({"name": "ci"}))).await;
    assert_eq!(key.status, 200);
    let oauth = s.oauth(&u, "secrets:read secrets:write", Some(&s.base)).await;
    let mut statuses = Vec::new();
    for token in [field(&key.body, "token"), oauth.access] {
        assert_eq!(s.call(Method::GET, "/api/me", &token, None).await.status, 200, "credential is valid before delete");
        statuses.push(s.call(Method::DELETE, "/api/me?confirm=true", &token, None).await.status);
    }
    assert_eq!(statuses, vec![403, 403], "only an account session may delete an account");
    assert_eq!(s.call(Method::GET, "/api/me", &u.session, None).await.status, 200);
}

#[tokio::test]
async fn account_delete_warns_then_revokes_all_personal_credentials() {
    let s = Server::start().await;
    let first = s.register("owner@test.invalid").await;
    let second = s.register("departing@test.invalid").await;
    s.add_member(&second, "owner@test.invalid", "developer").await;
    assert_eq!(s.call(Method::POST, &format!("/api/orgs/{}/transfer", second.org), &second.session, Some(json!({"user_id": first.id}))).await.status, 200);
    let app = s.app(&second, &second.org).await;
    let key = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), &second.session, Some(json!({"name": "ci"}))).await;
    assert_eq!(key.status, 200);
    let key = field(&key.body, "token");
    let oauth = s.oauth(&second, "secrets:read secrets:write", Some(&s.base)).await;
    let r = s.call(Method::DELETE, "/api/me", &second.session, None).await;
    assert_eq!(r.status, 409, "live credentials require confirmation");
    assert_eq!(r.body["confirmation_required"], true);
    assert_eq!(r.body["api_keys"], 1);
    assert_eq!(r.body["oauth_sessions"], 1);
    for token in [&second.session, &key, &oauth.access] {
        assert_eq!(s.call(Method::GET, "/api/me", token, None).await.status, 200, "warning must not revoke credentials");
    }
    let r = s.call(Method::DELETE, "/api/me?confirm=true", &second.session, None).await;
    assert_eq!(r.status, 200, "confirmed account deletion");
    assert_eq!(r.body["deleted"], true);
    assert_eq!(r.body["revoked_api_keys"], 1);
    assert_eq!(r.body["revoked_oauth_sessions"], 1);
    for token in [&second.session, &key, &oauth.access] {
        assert_eq!(s.call(Method::GET, "/api/me", token, None).await.status, 401, "deleted account credentials are unusable");
    }
    assert_eq!(s.form("/oauth/token", "", &[("grant_type", "refresh_token".into()), ("client_id", oauth.client), ("refresh_token", oauth.refresh)]).await.status, 400, "refresh credential is revoked");
    assert_eq!(s.call(Method::POST, "/api/auth/login", "", Some(json!({"email": "departing@test.invalid", "password": PASSWORD}))).await.status, 401);
    assert_eq!(s.call(Method::GET, "/api/me", &first.session, None).await.status, 200, "other account survives");
}

#[tokio::test]
async fn solo_owner_can_confirm_workspace_deletion_then_release_instance() {
    let s = Server::start().await;
    let u = s.register("solo@test.invalid").await;
    let path = format!("/api/orgs/{}", u.org);
    let r = s.call(Method::DELETE, &path, &u.session, None).await;
    assert_eq!(r.status, 409, "workspace deletion requires explicit confirmation");
    assert_eq!(r.body["confirmation_required"], true);
    assert_eq!(s.call(Method::DELETE, &format!("{}?confirm=true", path), &u.session, None).await.status, 200);
    assert_eq!(s.call(Method::GET, "/api/orgs", &u.session, None).await.body, json!([]));
    assert_eq!(s.call(Method::DELETE, "/api/me", &u.session, None).await.status, 200, "last account may close instance");
    assert_eq!(s.call(Method::GET, "/api/me", &u.session, None).await.status, 401);
    let next = s.register("new-bootstrap@test.invalid").await;
    assert_eq!(s.call(Method::GET, "/api/instance", &next.session, None).await.body["instance_owner"], true);
}

#[tokio::test]
async fn oauth_password_consent_requires_verification_and_valid_password() {
    let s = Server::start().await;
    s.register_raw("consent@test.invalid").await;
    let mut form = s.consent_form("secrets:read", Some(&s.base)).await;
    let client = form.iter().find(|(k, _)| *k == "client_id").unwrap().1.clone();
    form.extend([("email", "consent@test.invalid".into()), ("password", PASSWORD.into())]);
    let unverified = s.form("/oauth/authorize/decision", "", &form).await;
    s.verify("consent@test.invalid").await;
    let mut wrong = form.clone(); wrong.iter_mut().find(|(k, _)| *k == "password").unwrap().1 = "wrong-password".into();
    assert_eq!(s.form("/oauth/authorize/decision", "", &wrong).await.status, 401, "verification does not bypass password validation");
    let valid = s.form("/oauth/authorize/decision", "", &form).await;
    let oauth = s.exchange(valid, &client).await;
    assert_eq!(s.call(Method::GET, "/api/me", &oauth.access, None).await.status, 200, "verified password authorizes normally");
    assert_eq!(unverified.status, 403, "an unverified password account must not issue an OAuth code");
    assert!(query(&unverified.location, "code").is_empty(), "refusal must not leak a usable code");
}

#[tokio::test]
async fn oauth_secret_scopes_do_not_authorize_workspace_administration() {
    let s = Server::start().await;
    let u = s.register("scopes@test.invalid").await;
    let app = s.app(&u, &u.org).await;
    let oauth = s.oauth(&u, "secrets:read secrets:write", Some(&s.base)).await;
    assert_eq!(s.call(Method::GET, &format!("/api/orgs/{}/apps", u.org), &oauth.access, None).await.status, 200, "secret discovery remains allowed");
    assert_eq!(s.call(Method::POST, &format!("/api/apps/{}/envs", app), &oauth.access, Some(json!({"name": "dev"}))).await.status, 200, "secret write scope remains useful");
    let members = s.call(Method::GET, &format!("/api/orgs/{}/members", u.org), &oauth.access, None).await;
    let rename = s.call(Method::PATCH, &format!("/api/orgs/{}", u.org), &oauth.access, Some(json!({"name": "renamed"}))).await;
    let mint = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), &oauth.access, Some(json!({"name": "escalated"}))).await;
    assert_eq!([members.status, rename.status, mint.status], [403, 403, 403], "secrets scopes cannot read membership, rename or mint credentials");
}

#[tokio::test]
async fn oauth_org_admin_scope_is_supported_but_does_not_imply_secret_read() {
    let s = Server::start().await;
    let u = s.register("admin-scope@test.invalid").await;
    let oauth = s.oauth(&u, "org:admin", Some(&s.base)).await;
    assert_eq!(s.call(Method::GET, &format!("/api/orgs/{}/members", u.org), &oauth.access, None).await.status, 200);
    assert_eq!(s.call(Method::PATCH, &format!("/api/orgs/{}", u.org), &oauth.access, Some(json!({"name": "admin-renamed"}))).await.status, 200);
    assert_eq!(s.call(Method::GET, &format!("/api/orgs/{}/apps", u.org), &oauth.access, None).await.status, 403, "administrative consent is not secret consent");
}

#[tokio::test]
async fn oauth_audiences_remain_bound_after_refresh() {
    let s = Server::start().await;
    let u = s.register("audiences@test.invalid").await;
    let api = s.oauth(&u, "secrets:read", Some(&s.base)).await;
    let mcp = s.oauth(&u, "secrets:read mcp", Some(&format!("{}/mcp", s.base))).await;
    let initialize = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    assert_eq!(s.call(Method::GET, "/api/me", &api.access, None).await.status, 200);
    assert_eq!(s.call(Method::POST, "/mcp", &api.access, Some(initialize.clone())).await.status, 401, "API audience cannot reach MCP");
    assert_eq!(s.call(Method::POST, "/mcp", &mcp.access, Some(initialize.clone())).await.status, 200, "MCP audience works at MCP");
    let refreshed = s.form("/oauth/token", "", &[("grant_type", "refresh_token".into()), ("client_id", mcp.client), ("refresh_token", mcp.refresh)]).await;
    assert_eq!(refreshed.status, 200);
    let refreshed = field(&refreshed.body, "access_token");
    assert_eq!(s.call(Method::POST, "/mcp", &refreshed, Some(initialize)).await.status, 200);
    let original_api = s.call(Method::GET, "/api/me", &mcp.access, None).await;
    assert_eq!(original_api.status, 401, "refresh revokes the original access token");
    assert_eq!(s.call(Method::GET, "/api/me", &refreshed, None).await.status, 403, "refresh must not convert an MCP audience into API access");
}

#[tokio::test]
async fn oauth_consent_rejects_an_unrelated_resource() {
    let s = Server::start().await;
    let u = s.register("resource@test.invalid").await;
    let form = s.consent_form("secrets:read", Some(REDIRECT)).await;
    let r = s.form("/oauth/authorize/decision", &u.session, &form).await;
    assert_eq!(r.status, 400, "only this issuer and its MCP endpoint are valid resources");
    assert!(query(&r.location, "code").is_empty());
}
