use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static SUITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SECRET_KEY: &str = "SYNC_EGRESS_TEST";
const SECRET_VALUE: &str = "disposable-sync-value";
const PROVIDER_TOKEN: &str = "disposable-provider-token";

struct Resp { status: u16, body: Value, text: String }
#[derive(Clone)]
struct Recorded { method: Method, uri: String, headers: reqwest::header::HeaderMap, body: Vec<u8> }
struct Fixture { base: String, requests: Arc<Mutex<Vec<Recorded>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Fixture { fn drop(&mut self) { self.task.abort(); } }
impl Fixture {
    async fn start(bind: &str, redirect: Option<String>) -> Self {
        let listener = tokio::net::TcpListener::bind(bind).await.expect("bind local sync fixture (IPv6 must be available for IPv6 cases)");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new())); let sink = requests.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); let redirect = redirect.clone(); async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, 1024 * 1024).await.expect("read fixture request body");
                let path = parts.uri.path().to_string();
                // Record before replying: completion of /sync is the barrier for negative assertions.
                sink.lock().unwrap().push(Recorded { method: parts.method, uri: parts.uri.to_string(), headers: parts.headers, body: body.to_vec() });
                let mut response = axum::http::Response::builder().header("content-type", "application/json");
                let body = if let Some(location) = redirect {
                    response = response.status(307).header("location", location); "{}"
                } else if path == "/token" {
                    "{\"access_token\":\"disposable-provider-token\"}"
                } else { "{}" };
                response.body(axum::body::Body::from(body)).unwrap()
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve sync fixture"); });
        Self { base, requests, task }
    }
    fn recorded(&self) -> Vec<Recorded> {
        assert!(!self.task.is_finished(), "sync fixture stopped unexpectedly");
        self.requests.lock().unwrap().clone()
    }
    fn clear(&self) { self.requests.lock().unwrap().clear(); }
}

struct Server { child: Child, dir: PathBuf, base: String, client: Client, inbox: Fixture }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start(production: bool, allow_private_egress: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-sync-egress-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("create private test directory");
        let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve API port");
        let address = reserved.local_addr().unwrap(); let base = format!("http://{address}");
        let inbox = Fixture::start("127.0.0.1:0", None).await;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("OPENWARP_") || name.to_ascii_uppercase().ends_with("_PROXY") || name == "REDIS_URL" { cmd.env_remove(key); }
        }
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", address.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", format!("{}/mail", inbox.base))
            .env("TOKIO_WORKER_THREADS", "1").stdout(Stdio::null()).stderr(Stdio::null());
        if production { cmd.env("OPENWARP_ENV", "production").env("OPENWARP_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); }
        if allow_private_egress { cmd.env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1"); }
        drop(reserved);
        let child = cmd.spawn().expect("spawn current openwarp-server binary");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let mut s = Self { child, dir, base, client, inbox }; let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            assert!(s.child.try_wait().unwrap().is_none(), "sync egress test server exited before readiness");
            if let Ok(response) = s.client.get(format!("{}/health", s.base)).send().await {
                if response.status().is_success() && response.json::<Value>().await.is_ok_and(|v| v["ok"] == true && v["service"] == "openwarp") {
                    assert!(s.child.try_wait().unwrap().is_none(), "sync egress test server exited during readiness");
                    return s;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("sync egress test server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.expect("API request must complete");
        let status = response.status().as_u16(); let text = response.text().await.expect("read API response");
        let body = serde_json::from_str(&text).unwrap_or(Value::Null); Resp { status, body, text }
    }
    async fn setup(&self) -> (String, String) {
        let email = "owner@sync-egress.test.invalid";
        let response = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(response.status, 200, "register: {}", response.text);
        let org = id(&response.body, "org_id");
        let deadline = Instant::now() + Duration::from_secs(10);
        let link = loop {
            let link = self.inbox.recorded().iter().filter_map(|r| serde_json::from_slice::<Value>(&r.body).ok()).find_map(|v| {
                v["text"].as_str().and_then(|text| text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string())))
            });
            if let Some(link) = link { break link; }
            assert!(Instant::now() < deadline, "verification email missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let response = self.call(Method::GET, &link, "", None).await;
        assert_eq!(response.status, 200, "verify account: {}", response.text);
        let response = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(response.status, 200, "login: {}", response.text); let token = id(&response.body, "token");
        let response = self.call(Method::POST, &format!("/api/orgs/{org}/apps"), &token, Some(json!({"name":"sync-egress"}))).await;
        assert_eq!(response.status, 200, "create app: {}", response.text); let app = id(&response.body, "id");
        let response = self.call(Method::GET, &format!("/api/apps/{app}/envs"), &token, None).await;
        assert_eq!(response.status, 200, "list envs: {}", response.text); let env = id(&response.body[0], "id");
        let response = self.call(Method::PUT, &format!("/api/envs/{env}/secrets"), &token, Some(json!({"secrets":[{"key":SECRET_KEY,"value":SECRET_VALUE}]}))).await;
        assert_eq!(response.status, 200, "store disposable secret: {}", response.text);
        (token, env)
    }
    async fn sync(&self, token: &str, env: &str, kind: &str, mut config: Value) -> Resp {
        config["auto_sync"] = json!(false);
        let response = self.call(Method::POST, &format!("/api/envs/{env}/integrations"), token, Some(json!({"kind":kind,"name":"sync-egress-target","config":config}))).await;
        assert_eq!(response.status, 200, "create integration: {}", response.text);
        let iid = id(&response.body, "id");
        self.call(Method::POST, &format!("/api/integrations/{iid}/sync"), token, None).await
    }
}
fn id(value: &Value, key: &str) -> String { value[key].as_str().filter(|s| !s.is_empty()).unwrap_or_else(|| panic!("missing {key}")).to_string() }
fn assert_success(response: &Resp) {
    assert_eq!(response.status, 200, "sync: {}", response.text);
    assert_eq!(response.body["ok"], json!(true), "sync: {}", response.text);
}
fn assert_denied(response: &Resp) {
    assert_eq!(response.status, 400, "sync must fail: {}", response.text);
    assert!(response.body["error"].as_str().is_some_and(|s| !s.is_empty()), "sync must explain failure: {}", response.text);
}
fn assert_webhook_request(requests: &[Recorded]) {
    assert_eq!(requests.len(), 1, "sync must send exactly one provider request");
    let request = &requests[0];
    assert_eq!(request.method, Method::POST); assert_eq!(request.uri, "/sync");
    assert_eq!(request.headers.get("authorization").unwrap(), &format!("Bearer {PROVIDER_TOKEN}"));
    assert_eq!(serde_json::from_slice::<Value>(&request.body).unwrap(), json!({"secrets":{SECRET_KEY:SECRET_VALUE}}));
}

async fn assert_private_sync_blocked(bind: &str, hosts: &[&str]) {
    let fixture = Fixture::start(bind, None).await;
    let port = reqwest::Url::parse(&fixture.base).unwrap().port().unwrap();
    {
        let control = Server::start(true, true).await; let (token, env) = control.setup().await;
        for host in hosts {
            fixture.clear();
            let response = control.sync(&token, &env, "webhook", json!({"url":format!("http://{host}:{port}/sync"),"token":PROVIDER_TOKEN})).await;
            assert_success(&response); assert_webhook_request(&fixture.recorded());
        }
    }
    let server = Server::start(true, false).await; let (token, env) = server.setup().await;
    for host in hosts {
        fixture.clear();
        let response = server.sync(&token, &env, "webhook", json!({"url":format!("http://{host}:{port}/sync"),"token":PROVIDER_TOKEN})).await;
        assert_eq!(fixture.recorded().len(), 0, "production sync to {host} crossed the private-network boundary; API HTTP {}: {}", response.status, response.text);
        assert_denied(&response);
    }
}

#[tokio::test]
async fn production_sync_blocks_literal_ipv4_without_override() {
    let _serial = SUITE_LOCK.lock().await;
    assert_private_sync_blocked("127.0.0.1:0", &["127.0.0.1"]).await;
}

#[tokio::test]
async fn production_sync_blocks_literal_ipv6_without_override() {
    let _serial = SUITE_LOCK.lock().await;
    assert_private_sync_blocked("[::1]:0", &["[::1]"]).await;
}

#[tokio::test]
async fn production_sync_blocks_ipv4_mapped_loopback_without_override() {
    let _serial = SUITE_LOCK.lock().await;
    assert_private_sync_blocked("127.0.0.1:0", &["[::ffff:127.0.0.1]"]).await;
}

#[tokio::test]
async fn production_sync_blocks_localhost_dns_without_override() {
    let _serial = SUITE_LOCK.lock().await;
    assert_private_sync_blocked("127.0.0.1:0", &["localhost", "localhost."]).await;
}

#[tokio::test]
async fn development_sync_without_override_delivers_secret_and_provider_token() {
    let _serial = SUITE_LOCK.lock().await;
    let fixture = Fixture::start("127.0.0.1:0", None).await;
    let server = Server::start(false, false).await; let (token, env) = server.setup().await;
    let response = server.sync(&token, &env, "webhook", json!({"url":format!("{}/sync", fixture.base),"token":PROVIDER_TOKEN})).await;
    assert_success(&response); assert_webhook_request(&fixture.recorded());
}

#[tokio::test]
async fn production_sync_blocks_secondary_azure_token_endpoint_without_override() {
    let _serial = SUITE_LOCK.lock().await;
    let fixture = Fixture::start("127.0.0.1:0", None).await;
    let config = json!({"base_url":fixture.base,"token_endpoint":format!("{}/token", fixture.base),"tenant_id":"test-tenant","client_id":"test-client","client_secret":"disposable-client-secret"});
    {
        let control = Server::start(true, true).await; let (token, env) = control.setup().await;
        let response = control.sync(&token, &env, "azure_key_vault", config.clone()).await;
        assert_success(&response);
        let requests = fixture.recorded(); assert_eq!(requests.len(), 2, "Azure sync must exchange token then write the secret");
        assert_eq!(requests[0].method, Method::POST); assert_eq!(requests[0].uri, "/token");
        let form = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(form.contains("client_id=test-client") && form.contains("client_secret=disposable-client-secret") && form.contains("grant_type=client_credentials"), "token exchange must use configured dummy credentials");
        assert_eq!(requests[1].method, Method::PUT); assert_eq!(requests[1].uri, "/secrets/sync-egress-test?api-version=7.4");
        assert_eq!(requests[1].headers.get("authorization").unwrap(), &format!("Bearer {PROVIDER_TOKEN}"));
        assert_eq!(serde_json::from_slice::<Value>(&requests[1].body).unwrap()["value"], json!(SECRET_VALUE));
    }
    fixture.clear();
    let server = Server::start(true, false).await; let (token, env) = server.setup().await;
    let response = server.sync(&token, &env, "azure_key_vault", config).await;
    assert_eq!(fixture.recorded().len(), 0, "production Azure sync sent client credentials to a private token endpoint; API HTTP {}: {}", response.status, response.text);
    assert_denied(&response);
}

#[tokio::test]
async fn production_private_override_does_not_enable_sync_redirects() {
    let _serial = SUITE_LOCK.lock().await;
    let destination = Fixture::start("127.0.0.1:0", None).await;
    let redirect = Fixture::start("127.0.0.1:0", Some(format!("{}/redirected", destination.base))).await;
    let server = Server::start(true, true).await; let (token, env) = server.setup().await;
    let response = server.sync(&token, &env, "webhook", json!({"url":format!("{}/sync", redirect.base),"token":PROVIDER_TOKEN})).await;
    assert_webhook_request(&redirect.recorded());
    assert_eq!(destination.recorded().len(), 0, "sync followed a 307 redirect and forwarded the provider payload");
    assert_denied(&response);
}
