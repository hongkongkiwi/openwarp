use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
const PASSWORD: &str = "override-reader-test-password";
const REDIRECT: &str = "http://127.0.0.1:8917/callback";
const VERIFIER: &str = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";

struct Resp { status: u16, body: Value, location: String }
struct User { org: String, token: String }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }

impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("inbox bind");
    let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection");
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = stream.read(&mut chunk).expect("mail read");
                if n == 0 { break; } buf.extend_from_slice(&chunk[..n]);
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
        let dir = std::env::temp_dir().join(format!("openwarp-override-reader-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (relay, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", relay)
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_SIGNUPS").env_remove("OPENWARP_TRUST_PROXY")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let s = Self { child, base, dir, client, inbox };
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

    async fn register(&self, email: &str) -> User {
        let r = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "register account"); assert_eq!(r.body["verification_required"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let link = { self.inbox.lock().unwrap().iter().rev().filter(|m| m["to"] == email).filter_map(|m| m["text"].as_str())
                .find_map(|text| text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string()))) };
            if let Some(link) = link { assert_eq!(self.call(Method::GET, &link, "", None).await.status, 200, "verify account"); break; }
            assert!(Instant::now() < deadline, "verification mail did not arrive");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let login = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(login.status, 200, "verified account session");
        User { org: field(&r.body, "org_id"), token: field(&login.body, "token") }
    }

    async fn secret(&self, owner: &User) -> (String, String, String) {
        let app = self.call(Method::POST, &format!("/api/orgs/{}/apps", owner.org), &owner.token, Some(json!({"name": "override-reader"}))).await;
        assert_eq!(app.status, 200, "create app"); let app = field(&app.body, "id");
        let envs = self.call(Method::GET, &format!("/api/apps/{}/envs", app), &owner.token, None).await;
        assert_eq!(envs.status, 200, "list environments");
        let env = envs.body.as_array().unwrap().iter().find(|e| e["name"] == "Development").expect("Development environment");
        let env = field(env, "id");
        let deployed = self.call(Method::PUT, &format!("/api/envs/{}/secrets", env), &owner.token, Some(secret_body("base-value"))).await;
        assert_eq!(deployed.status, 200, "create shared secret");
        let listed = self.call(Method::GET, &format!("/api/envs/{}/secrets", env), &owner.token, None).await;
        assert_eq!(listed.status, 200, "list shared secret");
        (app, env, field(&listed.body["secrets"][0], "id"))
    }

    async fn oauth(&self, session: &str, scope: &str) -> String {
        let r = self.call(Method::POST, "/oauth/register", "", Some(json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "scope": scope}))).await;
        assert_eq!(r.status, 201, "register OAuth client"); let client = field(&r.body, "client_id");
        use base64ct::{Base64UrlUnpadded, Encoding};
        use sha2::{Digest, Sha256};
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()));
        let decision = self.form("/oauth/authorize/decision", session, &[
            ("response_type", "code".into()), ("client_id", client.clone()), ("redirect_uri", REDIRECT.into()),
            ("scope", scope.into()), ("state", "override-reader".into()), ("resource", self.base.clone()),
            ("code_challenge", challenge), ("code_challenge_method", "S256".into()), ("approve", "1".into())
        ]).await;
        assert_eq!(decision.status, 303, "authorize API credential");
        let code = decision.location.split_once('?').map(|(_, q)| q).unwrap_or("").split('&').filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "code").map(|(_, v)| v.to_string()).expect("authorization code");
        let exchanged = self.form("/oauth/token", "", &[("grant_type", "authorization_code".into()), ("client_id", client),
            ("redirect_uri", REDIRECT.into()), ("code_verifier", VERIFIER.into()), ("code", code)]).await;
        assert_eq!(exchanged.status, 200, "exchange API credential"); field(&exchanged.body, "access_token")
    }
}

fn field(v: &Value, key: &str) -> String { v[key].as_str().expect(key).to_string() }
fn secret_body(value: &str) -> Value { json!({"secrets": [{"key": "SHARED", "value": value}]}) }

#[tokio::test]
async fn session_reader_can_delete_only_own_override_without_shared_write_permission() {
    let s = Server::start().await; let owner = s.register("owner@test.invalid").await;
    let reader = s.register("reader@test.invalid").await;
    let role = s.call(Method::POST, &format!("/api/orgs/{}/roles", owner.org), &owner.token,
        Some(json!({"name": "reader", "permissions": ["secrets:read"]}))).await;
    assert_eq!(role.status, 200, "create read-only custom role");
    let invited = s.call(Method::POST, &format!("/api/orgs/{}/members", owner.org), &owner.token,
        Some(json!({"email": "reader@test.invalid", "role": "reader"}))).await;
    assert_eq!(invited.status, 200, "add read-only member");
    let accepted = s.call(Method::POST, "/api/auth/accept-invite", &reader.token, Some(json!({"token": field(&invited.body, "invite_token")}))).await;
    assert_eq!(accepted.status, 200, "accept read-only member invitation");
    let (_, env, sid) = s.secret(&owner).await; let path = format!("/api/secrets/{}/override", sid);
    for (token, value) in [(&owner.token, "owner-personal"), (&reader.token, "reader-personal")] {
        assert_eq!(s.call(Method::POST, &path, token, Some(secret_body(value))).await.status, 200, "set own override");
        let read = s.call(Method::GET, &path, token, None).await;
        assert_eq!(read.status, 200, "read own override"); assert_eq!(read.body["value"], value);
    }
    assert_eq!(s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), &reader.token, Some(secret_body("must-not-land"))).await.status, 403, "reader cannot deploy shared secrets");
    assert_eq!(s.call(Method::DELETE, &format!("/api/secrets/{}", sid), &reader.token, None).await.status, 403, "reader cannot delete a shared secret");
    let deleted = s.call(Method::DELETE, &path, &reader.token, None).await;
    assert_eq!(deleted.status, 200, "session reader must be able to remove an override it can set: {}", deleted.body);
    assert_eq!(deleted.body["deleted"], true);
    assert_eq!(s.call(Method::GET, &path, &reader.token, None).await.status, 404, "own override was removed");
    assert_eq!(s.call(Method::DELETE, &path, &reader.token, None).await.status, 404, "another user's override is not a deletable fallback");
    let other = s.call(Method::GET, &path, &owner.token, None).await;
    assert_eq!(other.status, 200); assert_eq!(other.body["value"], "owner-personal", "reader deletion must preserve another user's override");
    let listed = s.call(Method::GET, &format!("/api/envs/{}/secrets", env), &reader.token, None).await;
    assert_eq!(listed.status, 200); assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["secrets"][0]["id"], sid); assert_eq!(listed.body["secrets"][0]["value"], "base-value", "reader falls back to unchanged shared value");
    let base = s.call(Method::GET, &format!("/api/envs/{}/export?base=1", env), &owner.token, None).await;
    assert_eq!(base.status, 200); assert_eq!(base.body["secrets"][0]["value"], "base-value");
}

#[tokio::test]
async fn oauth_and_pat_override_mutations_still_require_credential_write_scope() {
    let s = Server::start().await; let owner = s.register("scope-owner@test.invalid").await;
    let (app, _, sid) = s.secret(&owner).await; let path = format!("/api/secrets/{}/override", sid);
    let oauth_read = s.oauth(&owner.token, "secrets:read").await;
    let oauth_write = s.oauth(&owner.token, "secrets:read secrets:write").await;
    let mut pats = Vec::new();
    for scope in ["secrets:read", "secrets:read secrets:write"] {
        let r = s.call(Method::POST, &format!("/api/apps/{}/tokens", app), &owner.token, Some(json!({"name": "override-scope", "scopes": scope}))).await;
        assert_eq!(r.status, 200, "mint disposable PAT"); pats.push(field(&r.body, "token"));
    }
    for (read, write, label) in [(&oauth_read, &oauth_write, "OAuth"), (&pats[0], &pats[1], "PAT")] {
        assert_eq!(s.call(Method::POST, &path, write, Some(secret_body("scoped-personal"))).await.status, 200, "{} write scope can set an override", label);
        let before = s.call(Method::GET, &path, read, None).await;
        assert_eq!(before.status, 200, "{} read scope can read its owner's override", label); assert_eq!(before.body["value"], "scoped-personal");
        assert_eq!(s.call(Method::POST, &path, read, Some(secret_body("must-not-land"))).await.status, 403, "{} read scope cannot set an override", label);
        assert_eq!(s.call(Method::DELETE, &path, read, None).await.status, 403, "{} read scope cannot delete an override", label);
        let after = s.call(Method::GET, &path, &owner.token, None).await;
        assert_eq!(after.status, 200); assert_eq!(after.body["value"], "scoped-personal", "{} rejected mutations leave the override unchanged", label);
        let deleted = s.call(Method::DELETE, &path, write, None).await;
        assert_eq!(deleted.status, 200, "{} write scope can delete an override", label); assert_eq!(deleted.body["deleted"], true);
        assert_eq!(s.call(Method::GET, &path, &owner.token, None).await.status, 404, "{} successful deletion removed the override", label);
    }
}
