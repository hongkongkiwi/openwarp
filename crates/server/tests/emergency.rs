// Workspace and project lockdowns distinguish human cookie sessions from automation.
use base64ct::{Base64UrlUnpadded, Encoding};
use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const PASSWORD: &str = "correct-horse-battery";
const SECRET: &str = "emergency-test-value";

struct Resp { status: u16, body: Value, headers: reqwest::header::HeaderMap }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill(); let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mail relay bind");
    let address = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection");
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0; 8192];
            loop {
                let n = match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(n) => n };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let len = head.lines().find_map(|line| { let (key, value) = line.split_once(':')?; if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                if let Ok(body) = serde_json::from_slice(&buf[end + 4..]) { sink.lock().unwrap().push(body); }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", address), inbox)
}

impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-emergency-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        Self::start_at(dir).await
    }

    async fn start_at(dir: PathBuf) -> Self {
        let _start = START_LOCK.lock().await;
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (mail_url, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", mail_url).env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ALLOWED_DB_HOSTS")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let server = Self { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(format!("{}/health", server.base)).send().await {
                if r.status().is_success() { return server; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("test server did not become healthy");
    }

    async fn restart(self) -> Self {
        let mut old = self;
        old.child.kill().unwrap(); old.child.wait().unwrap();
        // Keep the same database while the replacement process starts.
        let server = Self::start_at(old.dir.clone()).await;
        old.dir = old.dir.join("already-stopped");
        server
    }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = token { req = req.bearer_auth(token); }
        if let Some(body) = body { req = req.json(&body); }
        Self::finish(req.send().await.expect("HTTP request")).await
    }

    async fn cookie(&self, method: Method, path: &str, session: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path))
            .header("cookie", format!("ow_session={}", session)).header("origin", &self.base);
        if let Some(body) = body { req = req.json(&body); }
        Self::finish(req.send().await.expect("cookie HTTP request")).await
    }

    async fn project_status(&self, session: &str, app: &str, direct: bool, workspace: bool) {
        let r = self.cookie(Method::GET, &format!("/api/apps/{}/emergency", app), session, None).await;
        assert_eq!(r.status, 200, "project emergency status must be available to its owner cookie session");
        assert_eq!(r.body["locked"], json!(direct || workspace), "effective project lock is the OR of both locks");
        assert_eq!(r.body["direct_locked"], json!(direct));
        assert_eq!(r.body["workspace_locked"], json!(workspace));
    }

    async fn project_lock(&self, session: &str, app: &str, locked: bool) {
        let r = self.cookie(Method::PUT, &format!("/api/apps/{}/emergency", app), session, Some(json!({"locked": locked}))).await;
        assert_eq!(r.status, 200, "workspace owner cookie session controls project lockdown");
    }

    async fn machine(&self, session: &str, org: &str) -> String {
        let r = self.call(Method::POST, &format!("/api/orgs/{}/identities", org), Some(session), Some(json!({"name": "machine", "role": "admin"}))).await;
        assert_eq!(r.status, 200, "machine identity setup");
        let r = self.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id": r.body["client_id"], "client_secret": r.body["client_secret"]}))).await;
        assert_eq!(r.status, 200, "machine credential setup"); field(&r.body, "accessToken")
    }

    async fn delegated(&self, session: &str, public_key: &str, app: &str, runner: &str, runner_public: &str) -> (String, String) {
        let key = openwarp_crypto::random_key();
        let r = self.call(Method::POST, &format!("/api/apps/{}/envs", app), Some(session), Some(json!({"name": "delegated", "mode": "delegated", "runner_id": runner,
            "wrapped_key": openwarp_crypto::encrypt_to(public_key, &key).unwrap(), "runner_wrapped_key": openwarp_crypto::encrypt_to(runner_public, &key).unwrap()}))).await;
        assert_eq!(r.status, 200, "delegated environment setup"); let env = field(&r.body, "id");
        let r = self.call(Method::POST, &format!("/api/envs/{}/integrations", env), Some(session), Some(json!({"kind": "webhook", "config": {"url": "https://example.invalid/hook", "auto_sync": true}}))).await;
        assert_eq!(r.status, 200, "delegated integration setup"); (env, field(&r.body, "id"))
    }

    async fn finish(r: reqwest::Response) -> Resp {
        let status = r.status().as_u16(); let headers = r.headers().clone();
        let text = r.text().await.expect("HTTP body");
        Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null), headers }
    }

    async fn login(&self, email: &str) -> String {
        let r = self.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "verified user must be able to sign in");
        field(&r.body, "token")
    }

    async fn register(&self, email: &str) -> Value {
        let r = self.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "registration setup");
        let mut user = r.body;
        if user["verification_required"] == json!(true) {
            let mut link = None;
            for _ in 0..60 {
                {
                    let inbox = self.inbox.lock().unwrap();
                    link = inbox.iter().rev().filter_map(|mail| mail["text"].as_str()).flat_map(str::split_whitespace)
                        .find(|word| word.contains("/api/auth/verify?token=")).map(str::to_string);
                }
                if link.is_some() { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let link = link.expect("verification email");
            let index = link.find("/api/auth/verify?token=").unwrap();
            let r = self.call(Method::GET, &link[index..], None, None).await;
            assert_eq!(r.status, 200, "email verification setup");
            let r = self.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": PASSWORD}))).await;
            assert_eq!(r.status, 200, "registration sign-in setup");
            for key in ["token", "user_id", "public_key"] { user[key] = r.body[key].clone(); }
        }
        user
    }

    async fn invite(&self, token: &str, org: &str, email: &str, role: &str) {
        let r = self.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(token), Some(json!({"email": email, "role": role}))).await;
        assert_eq!(r.status, 200, "membership setup");
    }

    async fn app(&self, token: &str, org: &str) -> (String, String) {
        let r = self.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name": "app"}))).await;
        assert_eq!(r.status, 200, "application setup"); let app = field(&r.body, "id");
        let r = self.call(Method::GET, &format!("/api/apps/{}/envs", app), Some(token), None).await;
        assert_eq!(r.status, 200, "environment setup");
        let env = field(&r.body[0], "id"); (app, env)
    }

    async fn deploy(&self, token: &str, env: &str, value: &str) -> Resp {
        self.call(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(token), Some(json!({"secrets": [{"key": "PASSWORD", "value": value}]}))).await
    }

    async fn status(&self, token: &str, org: &str, locked: bool) {
        let r = self.cookie(Method::GET, &format!("/api/orgs/{}/emergency", org), token, None).await;
        assert_eq!(r.status, 200, "GET emergency status must exist for workspace owners");
        assert_eq!(r.body["locked"], json!(locked), "persisted emergency state");
    }

    async fn lock(&self, token: &str, org: &str, locked: bool) {
        let r = self.cookie(Method::PUT, &format!("/api/orgs/{}/emergency", org), token, Some(json!({"locked": locked}))).await;
        assert_eq!(r.status, 200, "owner session PUT emergency must support lock and restore");
        self.status(token, org, locked).await;
    }

    async fn oauth(&self, session: &str, resource: &str) -> String {
        let r = self.call(Method::POST, "/oauth/register", None, Some(json!({"redirect_uris": ["http://127.0.0.1:8917/callback"], "token_endpoint_auth_method": "none", "scope": "secrets:read secrets:write"}))).await;
        assert_eq!(r.status, 201, "OAuth client setup"); let client = field(&r.body, "client_id");
        let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
        let form = [("response_type", "code".to_string()), ("client_id", client.clone()),
            ("redirect_uri", "http://127.0.0.1:8917/callback".to_string()), ("scope", "secrets:read secrets:write".to_string()),
            ("state", "emergency".to_string()), ("code_challenge", Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()))),
            ("code_challenge_method", "S256".to_string()), ("resource", resource.to_string()), ("approve", "1".to_string())];
        let r = Self::finish(self.client.post(format!("{}/oauth/authorize/decision", self.base)).bearer_auth(session).form(&form).send().await.unwrap()).await;
        let location = r.headers.get("location").expect("OAuth redirect").to_str().unwrap();
        let url = reqwest::Url::parse(location).expect("OAuth redirect URL");
        let code = url.query_pairs().find(|(key, _)| key == "code").expect("OAuth authorization code").1.to_string();
        let form = [("grant_type", "authorization_code"), ("code", code.as_str()), ("client_id", client.as_str()),
            ("redirect_uri", "http://127.0.0.1:8917/callback"), ("code_verifier", verifier)];
        let r = Self::finish(self.client.post(format!("{}/oauth/token", self.base)).form(&form).send().await.unwrap()).await;
        assert_eq!(r.status, 200, "OAuth token setup"); field(&r.body, "access_token")
    }
    async fn oauth_api(&self, session: &str) -> String { self.oauth(session, &self.base).await }
    async fn oauth_mcp(&self, session: &str) -> String { self.oauth(session, &format!("{}/mcp", self.base)).await }

    async fn mcp(&self, token: &str, tool: &str, arguments: Value) -> Resp {
        self.call(Method::POST, "/mcp", Some(token), Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}))).await
    }
}

fn field(body: &Value, key: &str) -> String { body[key].as_str().filter(|v| !v.is_empty()).expect("nonempty response field").to_string() }
fn denied(r: &Resp, action: &str) { assert!(matches!(r.status, 401 | 403 | 423), "{} must be denied by lockdown, got {}", action, r.status); }
fn rpc_denied(r: &Resp) {
    assert!(matches!(r.status, 401 | 403 | 423) || (r.status == 200 && (!r.body["error"].is_null() || r.body["result"]["isError"] == json!(true))), "MCP must explicitly deny the operation, got status {}", r.status);
    assert!(!r.body.to_string().contains(SECRET), "MCP must not disclose secret values");
}

#[tokio::test]
async fn emergency_transitions_require_an_owner_interactive_session() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let admin = s.register("admin@test.invalid").await;
    let custom = s.register("custom@test.invalid").await;
    let outsider = s.register("outsider@test.invalid").await;
    s.invite(&ot, &org, "admin@test.invalid", "admin").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&ot), Some(json!({"name": "super", "permissions": ["*"]}))).await;
    assert_eq!(r.status, 200, "privileged custom role setup");
    s.invite(&ot, &org, "custom@test.invalid", "super").await;
    let (app, env) = s.app(&ot, &org).await;
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&ot), Some(json!({"name": "owner-service"}))).await;
    assert_eq!(r.status, 200, "service token setup"); let service = field(&r.body, "token");
    let oauth = s.oauth_api(&ot).await;
    for token in [&service, &oauth] {
        assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(token), None).await.status, 200, "automation credentials must be valid before lockdown");
    }
    s.status(&ot, &org, false).await;
    let path = format!("/api/orgs/{}/emergency", org);
    for path in [&path, &format!("/api/apps/{}/emergency", app)] {
        for locked in [true, false] {
            for token in [None, Some("invalid"), Some(ot.as_str()), admin["token"].as_str(), custom["token"].as_str(), outsider["token"].as_str(), Some(service.as_str()), Some(oauth.as_str())] {
                let r = s.call(Method::PUT, path, token, Some(json!({"locked": locked}))).await;
                assert!(matches!(r.status, 401 | 403), "only an owner cookie session may transition emergency state, got {}", r.status);
            }
            for token in [field(&admin, "token"), field(&custom, "token"), field(&outsider, "token"), service.clone(), oauth.clone()] {
                let r = s.cookie(Method::PUT, path, &token, Some(json!({"locked": locked}))).await;
                assert!(matches!(r.status, 401 | 403), "cookie transport cannot grant workspace ownership or turn a token into a session, got {}", r.status);
            }
            s.status(&ot, &org, false).await;
        }
    }
    s.lock(&ot, &org, true).await;
    let fresh_admin = s.login("admin@test.invalid").await;
    let fresh_custom = s.login("custom@test.invalid").await;
    for token in [&ot, &service, &oauth, &fresh_admin, &fresh_custom] {
        let r = s.call(Method::PUT, &path, Some(token), Some(json!({"locked": false}))).await;
        denied(&r, "bearer restore");
    }
    for token in [&service, &oauth, &fresh_admin, &fresh_custom] {
        denied(&s.cookie(Method::PUT, &path, token, Some(json!({"locked": false}))).await, "non-owner or non-session cookie restore");
    }
    s.status(&ot, &org, true).await;
    s.lock(&ot, &org, false).await;
}

#[tokio::test]
async fn emergency_persists_revokes_nonowner_sessions_and_isolates_workspaces() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let coowner = s.register("coowner@test.invalid").await; let cot = field(&coowner, "token");
    let member = s.register("member@test.invalid").await; let mt = field(&member, "token"); let other_org = field(&member, "org_id");
    let second_session = s.login("member@test.invalid").await;
    s.invite(&ot, &org, "coowner@test.invalid", "owner").await;
    s.invite(&ot, &org, "member@test.invalid", "developer").await;
    let (app, env) = s.app(&ot, &org).await;
    let (_, other_env) = s.app(&mt, &other_org).await;
    assert_eq!(s.deploy(&ot, &env, SECRET).await.status, 200);
    assert_eq!(s.deploy(&mt, &other_env, "other-value").await.status, 200);
    assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&mt), None).await.status, 200, "member access setup");
    s.lock(&ot, &org, true).await;
    // Repeating the same transition must not log the owners out.
    s.lock(&ot, &org, true).await;
    for token in [&ot, &cot] {
        assert_eq!(s.call(Method::GET, "/api/me", Some(token), None).await.status, 200, "all workspace owners retain sessions");
        s.status(token, &org, true).await;
    }
    for token in [&mt, &second_session] {
        assert_eq!(s.call(Method::GET, "/api/me", Some(token), None).await.status, 401, "every preexisting non-owner session is revoked globally");
    }
    let fresh = s.login("member@test.invalid").await;
    let metadata = format!("/api/orgs/{}/apps", org);
    assert_eq!(s.cookie(Method::GET, &metadata, &fresh, None).await.status, 200, "fresh member cookie may inspect read-only metadata");
    denied(&s.call(Method::GET, &metadata, Some(&fresh), None).await, "bearer session is automation during lockdown");
    denied(&s.cookie(Method::GET, &format!("/api/envs/{}/secrets", env), &fresh, None).await, "fresh member cookie secret read");
    denied(&s.cookie(Method::POST, &metadata, &fresh, Some(json!({"name": "blocked"}))).await, "fresh member cookie mutation");
    denied(&s.cookie(Method::PUT, &format!("/api/orgs/{}/emergency", org), &fresh, Some(json!({"locked": false}))).await, "fresh member cookie restore");
    assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", other_env), Some(&fresh), None).await.status, 200, "another workspace remains readable");
    assert_eq!(s.deploy(&fresh, &other_env, "other-updated").await.status, 200, "another workspace remains writable");
    let s = s.restart().await;
    s.status(&ot, &org, true).await; s.status(&cot, &org, true).await;
    denied(&s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&ot), None).await, "owner secret read after restart");
    s.lock(&cot, &org, false).await;
    assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&fresh), None).await.status, 200, "restore retains membership");
    assert_eq!(s.deploy(&ot, &env, "restored").await.status, 200, "restore permits writes");
    assert_eq!(s.call(Method::POST, &format!("/api/apps/{}/envs", app), Some(&ot), Some(json!({"name": "restored"}))).await.status, 200);
    for token in [&mt, &second_session] {
        assert_eq!(s.call(Method::GET, "/api/me", Some(token), None).await.status, 401, "restore must never resurrect revoked sessions");
    }
    let s = s.restart().await;
    s.status(&ot, &org, false).await;
}

#[tokio::test]
async fn emergency_blocks_owner_and_token_secret_reads_and_workspace_mutations() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, env) = s.app(&ot, &org).await;
    assert_eq!(s.deploy(&ot, &env, SECRET).await.status, 200);
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&ot), None).await;
    assert_eq!(r.status, 200); let sid = field(&r.body["secrets"][0], "id");
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&ot), Some(json!({"name": "service"}))).await;
    assert_eq!(r.status, 200); let service = field(&r.body, "token");
    let oauth = s.oauth_api(&ot).await; let oauth_mcp = s.oauth_mcp(&ot).await;
    let key = openwarp_crypto::random_key();
    let wrapped = openwarp_crypto::encrypt_to(owner["public_key"].as_str().unwrap(), &key).unwrap();
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs/e2e", app), Some(&ot), Some(json!({"name": "e2e", "wrapped_key": wrapped}))).await;
    assert_eq!(r.status, 200); let e2e = field(&r.body, "id");
    let ciphertext = json!({"secrets": [{"key_hash": openwarp_crypto::hash_token("PASSWORD"), "key_enc": openwarp_crypto::encrypt_symmetric(&key, b"PASSWORD"), "value_enc": openwarp_crypto::encrypt_symmetric(&key, SECRET.as_bytes())}]});
    assert_eq!(s.call(Method::PUT, &format!("/api/envs/{}/e2e/secrets", e2e), Some(&ot), Some(ciphertext.clone())).await.status, 200);
    let original_e2e = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", e2e), Some(&ot), None).await;
    assert_eq!(original_e2e.status, 200); assert_eq!(original_e2e.body["wrapped_key"], json!(wrapped));
    for token in [&ot, &service, &oauth_mcp] {
        let r = s.mcp(token, "list_secrets", json!({"env_id": env})).await;
        assert_eq!(r.status, 200); assert!(r.body.to_string().contains(SECRET), "MCP credential setup must really read the secret");
    }
    for token in [&ot, &service, &oauth] {
        let r = s.call(Method::GET, &format!("/api/envs/{}/export", env), Some(token), None).await;
        assert_eq!(r.status, 200, "export credential setup");
    }
    let machine = s.machine(&ot, &org).await;
    let metadata = format!("/api/apps/{}/envs", app);
    for token in [&ot, &service, &oauth, &machine] {
        assert_eq!(s.call(Method::GET, &metadata, Some(token), None).await.status, 200, "metadata credential setup");
    }
    s.lock(&ot, &org, true).await;
    assert_eq!(s.cookie(Method::GET, &metadata, &ot, None).await.status, 200, "owner cookie can inspect metadata during lockdown");
    for token in [&ot, &service, &oauth, &machine] {
        denied(&s.call(Method::GET, &metadata, Some(token), None).await, "automation metadata read");
        if token != &ot { denied(&s.cookie(Method::GET, &metadata, token, None).await, "automation token disguised as cookie session"); }
        for path in [format!("/api/envs/{}/secrets", env), format!("/api/envs/{}/export", env), format!("/api/secrets/{}/history", sid)] {
            let r = s.call(Method::GET, &path, Some(token), None).await;
            denied(&r, &path); assert!(!r.body.to_string().contains(SECRET), "denial must not include plaintext");
        }
        denied(&s.deploy(token, &env, "blocked").await, "secret deploy");
    }
    for token in [&ot, &service, &oauth_mcp, &machine] {
        rpc_denied(&s.mcp(token, "list_secrets", json!({"env_id": env})).await);
        rpc_denied(&s.mcp(token, "set_secret", json!({"env_id": env, "key": "PASSWORD", "value": "blocked"})).await);
    }
    for path in [format!("/api/envs/{}/secrets", env), format!("/api/envs/{}/export", env), format!("/api/secrets/{}/history", sid), format!("/api/envs/{}/e2e/secrets", e2e)] {
        denied(&s.cookie(Method::GET, &path, &ot, None).await, "owner cookie cannot read passwords or E2E keys and ciphertext");
    }
    denied(&s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", e2e), Some(&ot), None).await, "E2E wrapped key and ciphertext read");
    for (method, path, body) in [
        (Method::PATCH, format!("/api/orgs/{}", org), Some(json!({"name": "blocked"}))),
        (Method::PUT, format!("/api/orgs/{}/settings", org), Some(json!({"reuse_check": false}))),
        (Method::POST, format!("/api/orgs/{}/apps", org), Some(json!({"name": "blocked"}))),
        (Method::POST, format!("/api/apps/{}/envs", app), Some(json!({"name": "blocked"}))),
        (Method::POST, format!("/api/apps/{}/tokens", app), Some(json!({"name": "blocked"}))),
        (Method::POST, format!("/api/envs/{}/import", env), Some(json!({"secrets": [{"key": "PASSWORD", "value": "blocked"}]}))),
        (Method::PUT, format!("/api/envs/{}/e2e/secrets", e2e), Some(ciphertext)),
        (Method::DELETE, format!("/api/secrets/{}", sid), None),
        (Method::DELETE, format!("/api/apps/{}", app), None),
    ] {
        denied(&s.call(method.clone(), &path, Some(&ot), body.clone()).await, &path);
        denied(&s.cookie(method, &path, &ot, body).await, &path);
    }
    s.lock(&ot, &org, false).await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), Some(&ot), None).await;
    assert_eq!(r.status, 200); assert_eq!(r.body["secrets"][0]["value"], json!(SECRET), "blocked mutations must not change data");
    let r = s.call(Method::GET, &format!("/api/envs/{}/e2e/secrets", e2e), Some(&ot), None).await;
    assert_eq!(r.status, 200); assert_eq!(r.body, original_e2e.body, "E2E data and key grants survive lockdown");
    assert_eq!(s.deploy(&ot, &env, "restored").await.status, 200);
}

#[tokio::test]
async fn emergency_pauses_queued_syncs_and_denies_new_syncs_until_restore() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, _) = s.app(&ot, &org).await;
    let runner_key = openwarp_crypto::Keypair::generate(); let key = openwarp_crypto::random_key();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&ot), Some(json!({"name": "runner", "public_key": runner_key.public}))).await;
    assert_eq!(r.status, 200); let runner = field(&r.body, "id"); let runner_token = field(&r.body, "token");
    let r = s.call(Method::POST, &format!("/api/apps/{}/envs", app), Some(&ot), Some(json!({"name": "delegated", "mode": "delegated", "runner_id": runner,
        "wrapped_key": openwarp_crypto::encrypt_to(owner["public_key"].as_str().unwrap(), &key).unwrap(), "runner_wrapped_key": openwarp_crypto::encrypt_to(&runner_key.public, &key).unwrap()}))).await;
    assert_eq!(r.status, 200); let env = field(&r.body, "id");
    let config = json!({"url": "https://example.invalid/hook", "auto_sync": true});
    let r = s.call(Method::POST, &format!("/api/envs/{}/integrations", env), Some(&ot), Some(json!({"kind": "webhook", "config": config}))).await;
    assert_eq!(r.status, 200); let integration = field(&r.body, "id");
    let sync_path = format!("/api/integrations/{}/sync", integration);
    assert_eq!(s.call(Method::POST, &sync_path, Some(&ot), Some(json!({}))).await.status, 200, "queue sync setup");
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1, "runner queue must work before lockdown");
    let job = &jobs.body["jobs"][0];
    let r = s.call(Method::POST, &format!("/api/runner/jobs/{}/result", field(job, "id")), Some(&runner_token), Some(json!({"ok": true, "claim": field(job, "claim")}))).await;
    assert_eq!(r.status, 200, "complete setup job");
    assert_eq!(s.call(Method::POST, &sync_path, Some(&ot), Some(json!({}))).await.status, 200, "leave an existing sync pending");
    s.lock(&ot, &org, true).await;
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    if jobs.status == 200 {
        assert_eq!(jobs.body["jobs"], json!([]), "a paused sync must never disclose a runnable payload");
    } else { denied(&jobs, "runner polling during lockdown"); }
    for (method, path, body) in [
        (Method::POST, sync_path.clone(), json!({})),
        (Method::POST, format!("/api/integrations/{}/test", integration), json!({})),
        (Method::POST, format!("/api/envs/{}/integrations", env), json!({"kind": "webhook", "config": config})),
        (Method::PATCH, format!("/api/integrations/{}", integration), json!({"config": {"url": "https://example.invalid/hook", "auto_sync": true}})),
    ] {
        denied(&s.call(method.clone(), &path, Some(&ot), Some(body.clone())).await, &path);
        denied(&s.cookie(method, &path, &ot, Some(body)).await, &path);
    }
    rpc_denied(&s.mcp(&ot, "sync_integration", json!({"integration_id": integration})).await);
    let s = s.restart().await;
    s.status(&ot, &org, true).await;
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    if jobs.status == 200 { assert_eq!(jobs.body["jobs"], json!([]), "sync pause survives restart"); }
    else { denied(&jobs, "runner polling after restart"); }
    s.lock(&ot, &org, false).await;
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1, "restore resumes the previously pending sync, without duplicates");
    assert_eq!(jobs.body["jobs"][0]["integration_id"], json!(integration));
    assert_eq!(s.call(Method::POST, &sync_path, Some(&ot), Some(json!({}))).await.status, 200, "manual sync works after restore");
}

#[tokio::test]
async fn project_emergency_layers_persist_and_cookie_metadata_keeps_role_boundaries() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let member = s.register("member@test.invalid").await; let mt = field(&member, "token");
    s.register("admin@test.invalid").await;
    s.register("custom@test.invalid").await;
    let outsider = s.register("outsider@test.invalid").await; let outsider_token = field(&outsider, "token");
    s.invite(&ot, &org, "member@test.invalid", "developer").await;
    s.invite(&ot, &org, "admin@test.invalid", "admin").await;
    let r = s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(&ot), Some(json!({"name": "super", "permissions": ["*"]}))).await;
    assert_eq!(r.status, 200); s.invite(&ot, &org, "custom@test.invalid", "super").await;
    let (app, env) = s.app(&ot, &org).await; let (sibling, sibling_env) = s.app(&ot, &org).await;
    let (_, other_env) = s.app(&outsider_token, outsider["org_id"].as_str().unwrap()).await;
    assert_eq!(s.deploy(&ot, &env, SECRET).await.status, 200);
    assert_eq!(s.deploy(&ot, &sibling_env, "sibling").await.status, 200);
    let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), Some(&ot), Some(json!({"name": "project-service"}))).await;
    assert_eq!(r.status, 200); let service = field(&r.body, "token");
    let oauth = s.oauth_api(&ot).await; let oauth_mcp = s.oauth_mcp(&ot).await; let machine = s.machine(&ot, &org).await;
    let metadata = format!("/api/apps/{}/envs", app);
    for token in [&ot, &service, &oauth, &machine] {
        assert_eq!(s.call(Method::GET, &metadata, Some(token), None).await.status, 200, "valid project metadata credential setup");
    }
    s.project_status(&ot, &app, false, false).await;
    s.project_lock(&ot, &app, true).await;
    s.project_status(&ot, &app, true, false).await;
    s.project_status(&ot, &sibling, false, false).await;
    s.status(&ot, &org, false).await;
    assert_eq!(s.cookie(Method::GET, "/api/me", &ot, None).await.status, 200, "project lockdown retains owner sessions");
    assert_eq!(s.cookie(Method::GET, "/api/me", &mt, None).await.status, 401, "project lockdown revokes existing non-owner sessions");
    let fresh = s.login("member@test.invalid").await;
    let fresh_admin = s.login("admin@test.invalid").await; let fresh_custom = s.login("custom@test.invalid").await;
    for token in [&ot, &fresh, &fresh_admin, &fresh_custom] {
        let r = s.cookie(Method::GET, &metadata, token, None).await;
        assert_eq!(r.status, 200, "authorized human sessions retain read-only project metadata");
        assert!(!r.body.to_string().contains(SECRET));
        denied(&s.cookie(Method::GET, &format!("/api/envs/{}/secrets", env), token, None).await, "project password read");
        denied(&s.cookie(Method::POST, &metadata, token, Some(json!({"name": "blocked"}))).await, "project environment mutation");
    }
    for token in [&fresh, &fresh_admin, &fresh_custom, &outsider_token] {
        denied(&s.cookie(Method::PUT, &format!("/api/apps/{}/emergency", app), token, Some(json!({"locked": false}))).await, "only actual workspace owner may restore a project");
    }
    denied(&s.cookie(Method::GET, &metadata, &outsider_token, None).await, "cookie metadata must preserve tenant isolation");
    denied(&s.cookie(Method::GET, &format!("/api/orgs/{}/settings", org), &fresh, None).await, "cookie metadata must preserve developer administrative restrictions");
    for token in [&ot, &service, &oauth, &machine] {
        denied(&s.call(Method::GET, &metadata, Some(token), None).await, "project bearer metadata read");
        denied(&s.call(Method::GET, &format!("/api/envs/{}/export", env), Some(token), None).await, "project automation export");
        denied(&s.deploy(token, &env, "blocked").await, "project automation write");
        if token != &ot { denied(&s.cookie(Method::GET, &metadata, token, None).await, "project automation disguised as cookie"); }
    }
    for token in [&ot, &service, &oauth_mcp, &machine] {
        rpc_denied(&s.mcp(token, "list_secrets", json!({"env_id": env})).await);
    }
    for token in [&ot, &oauth, &machine] {
        assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", sibling_env), Some(token), None).await.status, 200, "project lock must not block sibling project automation");
    }
    assert_eq!(s.deploy(&fresh, &sibling_env, "sibling-updated").await.status, 200, "fresh member can mutate an unlocked sibling");
    assert_eq!(s.deploy(&outsider_token, &other_env, "other-updated").await.status, 200, "unrelated workspace session is not revoked");
    s.lock(&ot, &org, true).await;
    s.project_status(&ot, &app, true, true).await;
    s.project_status(&ot, &sibling, false, true).await;
    denied(&s.cookie(Method::GET, &format!("/api/envs/{}/secrets", sibling_env), &ot, None).await, "workspace lock overrides sibling project");
    let s = s.restart().await;
    s.project_status(&ot, &app, true, true).await;
    s.lock(&ot, &org, false).await;
    s.project_status(&ot, &app, true, false).await;
    s.project_status(&ot, &sibling, false, false).await;
    denied(&s.cookie(Method::GET, &format!("/api/envs/{}/secrets", env), &ot, None).await, "workspace restore retains the direct project lock");
    s.lock(&ot, &org, true).await;
    s.project_lock(&ot, &app, false).await;
    s.project_status(&ot, &app, false, true).await;
    denied(&s.cookie(Method::GET, &format!("/api/envs/{}/secrets", env), &ot, None).await, "restoring project cannot bypass workspace lockdown");
    let s = s.restart().await;
    s.project_status(&ot, &app, false, true).await;
    s.lock(&ot, &org, false).await;
    s.project_status(&ot, &app, false, false).await;
    assert_eq!(s.deploy(&ot, &env, "restored").await.status, 200, "clearing both locks restores project writes");
    assert_eq!(s.cookie(Method::GET, "/api/me", &mt, None).await.status, 401, "layered restore must not resurrect original non-owner sessions");
}

#[tokio::test]
async fn project_emergency_filters_only_locked_project_runner_payloads() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, _) = s.app(&ot, &org).await; let (sibling, _) = s.app(&ot, &org).await;
    let runner_key = openwarp_crypto::Keypair::generate();
    let r = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&ot), Some(json!({"name": "shared-runner", "public_key": runner_key.public}))).await;
    assert_eq!(r.status, 200); let runner = field(&r.body, "id"); let runner_token = field(&r.body, "token");
    let public = owner["public_key"].as_str().unwrap();
    let (env, integration) = s.delegated(&ot, public, &app, &runner, &runner_key.public).await;
    let (_, sibling_integration) = s.delegated(&ot, public, &sibling, &runner, &runner_key.public).await;
    // Complete one real job first so an empty locked queue cannot hide invalid runner setup.
    let sync_path = format!("/api/integrations/{}/sync", integration);
    assert_eq!(s.call(Method::POST, &sync_path, Some(&ot), Some(json!({}))).await.status, 200);
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1);
    let job = &jobs.body["jobs"][0];
    assert_eq!(s.call(Method::POST, &format!("/api/runner/jobs/{}/result", field(job, "id")), Some(&runner_token), Some(json!({"ok": true, "claim": field(job, "claim")}))).await.status, 200);
    for integration in [&integration, &sibling_integration] {
        assert_eq!(s.call(Method::POST, &format!("/api/integrations/{}/sync", integration), Some(&ot), Some(json!({}))).await.status, 200);
    }
    s.project_lock(&ot, &app, true).await;
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200, "shared runner remains usable for the unlocked sibling");
    assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1, "only sibling job may be disclosed");
    assert_eq!(jobs.body["jobs"][0]["integration_id"], json!(sibling_integration));
    let job = &jobs.body["jobs"][0];
    assert_eq!(s.call(Method::POST, &format!("/api/runner/jobs/{}/result", field(job, "id")), Some(&runner_token), Some(json!({"ok": true, "claim": field(job, "claim")}))).await.status, 200, "unlocked sibling job result remains writable");
    for (method, path, body) in [
        (Method::POST, sync_path.clone(), json!({})),
        (Method::POST, format!("/api/integrations/{}/test", integration), json!({})),
        (Method::POST, format!("/api/envs/{}/integrations", env), json!({"kind": "webhook", "config": {"url": "https://example.invalid/hook"}})),
        (Method::PATCH, format!("/api/integrations/{}", integration), json!({"config": {"url": "https://example.invalid/hook", "auto_sync": true}})),
    ] { denied(&s.cookie(method, &path, &ot, Some(body)).await, "project sync control during lockdown"); }
    rpc_denied(&s.mcp(&ot, "sync_integration", json!({"integration_id": integration})).await);
    denied(&s.cookie(Method::GET, &format!("/api/envs/{}/integrations", env), &runner_token, None).await, "runner token cannot impersonate human metadata session");
    let s = s.restart().await;
    s.project_status(&ot, &app, true, false).await;
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"], json!([]), "pending locked-project job remains withheld after restart");
    s.project_lock(&ot, &app, false).await;
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&runner_token), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1, "restore returns the pending project job once");
    assert_eq!(jobs.body["jobs"][0]["integration_id"], json!(integration));
}

async fn review_halt(s: &Server, owner: &str, org: &str, app: &str, project: bool, locked: bool) {
    if project { s.project_lock(owner, app, locked).await; } else { s.lock(owner, org, locked).await; }
}

fn review_no_credentials(body: &Value) {
    let text = body.to_string();
    for credential in ["review-url-user", "review-url-password", "review-url-query-secret"] {
        assert!(!text.contains(credential), "locked metadata must not expose synthetic URL credentials");
    }
}

async fn review_settings_redaction(project: bool) {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, _) = s.app(&ot, &org).await;
    let path = format!("/api/orgs/{}/settings", org);
    let url = "https://review-url-user:review-url-password@example.invalid/audit?token=review-url-query-secret";
    assert_eq!(s.call(Method::PUT, &path, Some(&ot), Some(json!({"audit_webhook": url, "reuse_check": false}))).await.status, 200, "credential-bearing webhook setup");
    assert_eq!(s.cookie(Method::GET, &path, &ot, None).await.status, 200, "owner settings access setup");
    review_halt(&s, &ot, &org, &app, project, true).await;
    s.project_status(&ot, &app, project, !project).await;
    let r = s.cookie(Method::GET, &path, &ot, None).await;
    assert_eq!(r.status, 200, "owner must retain safe workspace settings metadata");
    assert_eq!(r.body["reuse_check"], json!(false), "ordinary settings metadata remains usable");
    review_no_credentials(&r.body);
    review_halt(&s, &ot, &org, &app, project, false).await;
    assert_eq!(s.call(Method::PUT, &path, Some(&ot), Some(json!({"reuse_check": true}))).await.status, 200, "settings mutations resume after restoration");
}

#[tokio::test]
async fn review_workspace_settings_hide_url_credentials() { review_settings_redaction(false).await; }

#[tokio::test]
async fn review_project_settings_hide_url_credentials() { review_settings_redaction(true).await; }

async fn review_audit_redaction(project: bool) {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let member = s.register("member@test.invalid").await;
    s.invite(&ot, &org, "member@test.invalid", "developer").await;
    let (app, _) = s.app(&ot, &org).await;
    let hook = format!("/api/orgs/{}/rotation-hook", org); let audit = format!("/api/orgs/{}/audit", org);
    let url = "https://review-url-user:review-url-password@example.invalid/rotate?token=review-url-query-secret";
    assert_eq!(s.call(Method::PUT, &hook, Some(&ot), Some(json!({"url": url}))).await.status, 200, "credential-bearing rotation hook setup");
    let before = s.cookie(Method::GET, &audit, &field(&member, "token"), None).await;
    assert_eq!(before.status, 200, "member audit access setup");
    assert!(before.body.as_array().unwrap().iter().any(|row| row["action"] == json!("rotation_hook.set")), "rotation hook setup must produce an audit event");
    review_halt(&s, &ot, &org, &app, project, true).await;
    let fresh = s.login("member@test.invalid").await;
    let status = s.cookie(Method::GET, &format!("/api/apps/{}/emergency", app), &fresh, None).await;
    assert_eq!(status.status, 200); assert_eq!(status.body["locked"], json!(true), "member status remains available");
    let r = s.cookie(Method::GET, &audit, &fresh, None).await;
    assert_eq!(r.status, 200, "reauthenticated member must retain safe audit access");
    assert!(r.body.as_array().unwrap().iter().any(|row| row["action"] == json!("rotation_hook.set")), "audit events must remain inspectable rather than disappearing");
    review_no_credentials(&r.body);
}

#[tokio::test]
async fn review_workspace_member_audit_hides_url_credentials() { review_audit_redaction(false).await; }

#[tokio::test]
async fn review_project_member_audit_hides_url_credentials() { review_audit_redaction(true).await; }

async fn review_machine_lockbox(project: bool) {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, _) = s.app(&ot, &org).await; let machine = s.machine(&ot, &org).await;
    let body = json!({"secrets": [{"key": "PASSWORD", "value": SECRET}]});
    let before = s.call(Method::POST, "/api/lockbox", Some(&machine), Some(body.clone())).await;
    assert_eq!(before.status, 200, "machine token can create a share before lockdown");
    let share = field(&before.body, "id"); let key = field(&before.body, "key");
    review_halt(&s, &ot, &org, &app, project, true).await;
    let blocked = s.call(Method::POST, "/api/lockbox", Some(&machine), Some(body.clone())).await;
    denied(&blocked, "machine identity unscoped Lockbox creation");
    assert!(blocked.body["key"].is_null(), "denied share creation cannot return a decryption key");
    let existing = Server::finish(s.client.get(format!("{}/api/lockbox/{}", s.base, share)).header("x-lockbox-key", key).send().await.unwrap()).await;
    assert_eq!(existing.status, 200, "preexisting unscoped shares remain outside workspace lockdown");
    assert_eq!(existing.body["value"], json!(SECRET));
    review_halt(&s, &ot, &org, &app, project, false).await;
    assert_eq!(s.call(Method::POST, "/api/lockbox", Some(&machine), Some(body)).await.status, 200, "valid machine token resumes share creation after restoration");
}

#[tokio::test]
async fn review_workspace_machine_cannot_create_lockbox() { review_machine_lockbox(false).await; }

#[tokio::test]
async fn review_project_machine_cannot_create_lockbox() { review_machine_lockbox(true).await; }

#[tokio::test]
async fn review_machine_token_can_revoke_itself_without_org_column() {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, _) = s.app(&ot, &org).await; let machine = s.machine(&ot, &org).await;
    let metadata = format!("/api/apps/{}/envs", app);
    assert_eq!(s.call(Method::GET, &metadata, Some(&machine), None).await.status, 200, "machine token authentication setup");
    // Universal Auth does not return a token id; inspect only this harness's private database.
    let token_id: String = rusqlite::Connection::open(s.dir.join("test.db")).unwrap().query_row(
        "SELECT id FROM tokens WHERE token_hash=?", [openwarp_crypto::hash_token(&machine)], |row| row.get(0)).unwrap();
    let r = s.call(Method::DELETE, &format!("/api/tokens/{}", token_id), Some(&machine), None).await;
    assert_eq!(r.status, 200, "authenticated machine principal can revoke its own token");
    assert_eq!(s.call(Method::GET, &metadata, Some(&machine), None).await.status, 401, "revoked machine token must stop authenticating");
    assert_eq!(s.call(Method::GET, &metadata, Some(&ot), None).await.status, 200, "self-revocation leaves owner access intact");
}

async fn review_claim_fencing(project: bool) {
    let s = Server::start().await;
    let owner = s.register("owner@test.invalid").await; let ot = field(&owner, "token"); let org = field(&owner, "org_id");
    let (app, _) = s.app(&ot, &org).await; let key = openwarp_crypto::Keypair::generate();
    let runner = s.call(Method::POST, &format!("/api/orgs/{}/runners", org), Some(&ot), Some(json!({"name": "runner", "public_key": key.public}))).await;
    assert_eq!(runner.status, 200); let rt = field(&runner.body, "token");
    let (_, integration) = s.delegated(&ot, owner["public_key"].as_str().unwrap(), &app, &field(&runner.body, "id"), &key.public).await;
    let sync = format!("/api/integrations/{}/sync", integration);
    assert_eq!(s.call(Method::POST, &sync, Some(&ot), Some(json!({}))).await.status, 200, "claimed job setup");
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&rt), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1);
    let job = &jobs.body["jobs"][0]; let old_claim = field(job, "claim");
    let result = format!("/api/runner/jobs/{}/result", field(job, "id"));
    review_halt(&s, &ot, &org, &app, project, true).await;
    denied(&s.call(Method::POST, &result, Some(&rt), Some(json!({"ok": true, "claim": old_claim}))).await, "claimed result during lockdown");
    review_halt(&s, &ot, &org, &app, project, false).await;
    assert_eq!(s.call(Method::POST, &result, Some(&rt), Some(json!({"ok": true, "claim": old_claim}))).await.status, 409, "restoration must not revive a pre-lockdown claim");
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&rt), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"].as_array().unwrap().len(), 1, "restored claimed work is immediately available without waiting for stale-claim timeout");
    let fresh = &jobs.body["jobs"][0]; assert_eq!(fresh["integration_id"], json!(integration));
    let claim = field(fresh, "claim"); assert_ne!(claim, old_claim, "restored work needs a fresh fencing token");
    assert_eq!(s.call(Method::POST, &result, Some(&rt), Some(json!({"ok": true, "claim": old_claim}))).await.status, 409, "old claim cannot supersede the replacement");
    let result = format!("/api/runner/jobs/{}/result", field(fresh, "id"));
    assert_eq!(s.call(Method::POST, &result, Some(&rt), Some(json!({"ok": true, "claim": claim}))).await.status, 200, "replacement claim completes normally");
    let jobs = s.call(Method::GET, "/api/runner/jobs", Some(&rt), None).await;
    assert_eq!(jobs.status, 200); assert_eq!(jobs.body["jobs"], json!([]), "completed restored job is not duplicated");
}

#[tokio::test]
async fn review_workspace_restore_fences_claimed_runner_work() { review_claim_fencing(false).await; }

#[tokio::test]
async fn review_project_restore_fences_claimed_runner_work() { review_claim_fencing(true).await; }
