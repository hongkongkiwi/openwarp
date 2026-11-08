use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASSWORD: &str = "ssh-scope-test-password";
const REDIRECT: &str = "http://127.0.0.1:8917/callback";
const VERIFIER: &str = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
const SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYQJZ7VR/OW5fqVOvmn+BRt5SLWDPx2UVO3ALmn21ZE openwarp-test";
struct Resp { status: u16, body: Value, location: String }
struct User { org: String, session: String }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection"); stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = stream.read(&mut chunk).expect("mail read"); if n == 0 { break; } buf.extend_from_slice(&chunk[..n]);
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr); let (relay, inbox) = start_inbox();
        let dir = std::env::temp_dir().join(format!("openwarp-ssh-scope-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir(&dir).unwrap(); drop(listener);
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server")).env_clear()
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "1")
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", relay)
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let s = Self { child, base, dir, client, inbox }; let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    async fn response(response: reqwest::Response) -> Resp {
        let status = response.status().as_u16();
        let location = response.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let text = response.text().await.unwrap(); Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null), location }
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = req.bearer_auth(token); }
        if let Some(body) = body { req = req.json(&body); }
        Self::response(req.send().await.expect("HTTP request")).await
    }
    async fn form(&self, path: &str, token: &str, form: &[(&str, String)]) -> Resp {
        let mut req = self.client.post(format!("{}{}", self.base, path)).form(form);
        if !token.is_empty() { req = req.bearer_auth(token); } Self::response(req.send().await.expect("form request")).await
    }
    async fn register(&self) -> User {
        let email = "ssh-owner@test.invalid";
        let r = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(r.status, 200, "register owner"); assert_eq!(r.body["verification_required"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let link = { self.inbox.lock().unwrap().iter().rev().filter(|m| m["to"] == email).filter_map(|m| m["text"].as_str())
                .find_map(|text| text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string()))) };
            if let Some(link) = link { assert_eq!(self.call(Method::GET, &link, "", None).await.status, 200, "verify owner"); break; }
            assert!(Instant::now() < deadline, "verification mail did not arrive"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let login = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email": email, "password": PASSWORD}))).await;
        assert_eq!(login.status, 200, "verified owner session"); User { org: field(&r.body, "org_id"), session: field(&login.body, "token") }
    }
    async fn oauth(&self, session: &str, scope: &str) -> String {
        let r = self.call(Method::POST, "/oauth/register", "", Some(json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "scope": scope}))).await;
        assert_eq!(r.status, 201, "register OAuth client"); let client = field(&r.body, "client_id");
        use base64ct::{Base64UrlUnpadded, Encoding}; use sha2::{Digest, Sha256};
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()));
        let decision = self.form("/oauth/authorize/decision", session, &[("response_type", "code".into()), ("client_id", client.clone()),
            ("redirect_uri", REDIRECT.into()), ("scope", scope.into()), ("state", "ssh-scope".into()), ("resource", self.base.clone()),
            ("code_challenge", challenge), ("code_challenge_method", "S256".into()), ("approve", "1".into())]).await;
        assert_eq!(decision.status, 303, "authorize API credential");
        let code = decision.location.split_once('?').map(|(_, q)| q).unwrap_or("").split('&').filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "code").map(|(_, v)| v.to_string()).expect("authorization code");
        let r = self.form("/oauth/token", "", &[("grant_type", "authorization_code".into()), ("client_id", client),
            ("redirect_uri", REDIRECT.into()), ("code_verifier", VERIFIER.into()), ("code", code)]).await;
        assert_eq!(r.status, 200, "exchange API credential"); field(&r.body, "access_token")
    }
    async fn pat(&self, session: &str, app: &str, scope: &str) -> String {
        let r = self.call(Method::POST, &format!("/api/apps/{}/tokens", app), session, Some(json!({"name": "ssh-scope", "scopes": scope}))).await;
        assert_eq!(r.status, 200, "mint disposable PAT"); field(&r.body, "token")
    }
}
fn field(v: &Value, key: &str) -> String { v[key].as_str().expect(key).to_string() }

async fn scope_contract(oauth: bool) {
    let s = Server::start().await; let owner = s.register().await;
    let app = s.call(Method::POST, &format!("/api/orgs/{}/apps", owner.org), &owner.session, Some(json!({"name": "ssh-scopes"}))).await;
    assert_eq!(app.status, 200, "create token app"); let app = field(&app.body, "id");
    let mut tokens = Vec::new();
    for scope in ["secrets:read secrets:write", "org:admin"] {
        tokens.push(if oauth { s.oauth(&owner.session, scope).await } else { s.pat(&owner.session, &app, scope).await });
    }
    let (secret, admin) = (&tokens[0], &tokens[1]); let path = format!("/api/orgs/{}/ssh/cas", owner.org);
    let forbidden_create = s.call(Method::POST, &path, secret, Some(json!({"name": "must-not-create"}))).await;
    let forbidden_list = s.call(Method::GET, &path, secret, None).await;
    let created = s.call(Method::POST, &path, admin, Some(json!({"name": "admin-ca"}))).await;
    assert_eq!((forbidden_create.status, forbidden_list.status), (403, 403), "secret-only consent cannot create or list SSH CAs, even for a workspace owner");
    assert_eq!(created.status, 200, "org:admin authorizes CA creation"); let ca = field(&created.body, "id");
    assert!(created.body["public_key"].as_str().unwrap().starts_with("ssh-ed25519 "));
    let listed = s.call(Method::GET, &path, admin, None).await;
    assert_eq!(listed.status, 200, "org:admin authorizes CA listing"); assert!(listed.body.as_array().unwrap().iter().any(|c| c["id"] == ca));
    let grant = s.call(Method::PUT, &format!("/api/ssh/cas/{}/grants", ca), admin,
        Some(json!({"grants": [{"role": "owner", "principals": ["web-1"], "max_ttl": 600}]}))).await;
    assert_eq!(grant.status, 200, "admin sets principal grant");
    let signing = format!("/api/ssh/cas/{}/sign", ca); let body = json!({"principal": "web-1", "public_key": SSH_PUBKEY, "ttl": 300});
    let signed = s.call(Method::POST, &signing, secret, Some(body.clone())).await;
    assert_eq!(signed.status, 200, "signing remains a secrets:write operation, not CA administration");
    assert_eq!(signed.body["verified"]["principals"], json!(["web-1"]));
    assert_eq!(s.call(Method::POST, &signing, admin, Some(body)).await.status, 403, "org:admin alone does not imply signing write scope");
    let final_list = s.call(Method::GET, &path, admin, None).await;
    assert_eq!(final_list.status, 200); assert_eq!(final_list.body.as_array().unwrap().len(), 1, "rejected creation leaves no extra CA");
}

#[tokio::test]
async fn oauth_secret_scopes_cannot_administer_ssh_cas() { scope_contract(true).await; }

#[tokio::test]
async fn pat_secret_scopes_cannot_administer_ssh_cas() { scope_contract(false).await; }
