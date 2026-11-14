use openwarp_crypto as oc;
use openwarp_server::{clock::now, db::Db, seed_epoch};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const MASTER: [u8;32] = [81;32];
const ENV_KEY: [u8;32] = [82;32];
const SESSION: &str = "pr32-disposable-inference-owner";
const PARENT: &str = "pr32-disposable-parent-key";
const CREATE_PATH: &str = "/v1/accounts/fixture-account/users/fixture-user/apiKeys";
const REVOKE_PATH: &str = "/v1/accounts/fixture-account/users/fixture-user/apiKeys:delete";

#[derive(Clone)]
struct Recorded { method: Method, path: String, headers: reqwest::header::HeaderMap, body: Value }
struct Provider { base: String, requests: Arc<Mutex<Vec<Recorded>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Provider { fn drop(&mut self) { self.task.abort(); } }
impl Provider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = local_dns_host(port).await;
        let requests = Arc::new(Mutex::new(Vec::new())); let sink = requests.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, 65536).await.unwrap();
                let path = parts.uri.path().to_string();
                let response = match (parts.method.as_str(), path.as_str()) {
                    ("POST", CREATE_PATH) => json!({"key":"pr32-disposable-child-key","keyId":"fixture-child","expireTime":"2030-01-01T00:00:00Z"}),
                    ("POST", REVOKE_PATH) => json!({}),
                    _ => panic!("unexpected local inference fixture request"),
                };
                // A completed API call is the barrier for checking that no credentials arrived.
                sink.lock().unwrap().push(Recorded { method: parts.method, path, headers: parts.headers, body: serde_json::from_slice(&body).unwrap() });
                axum::Json(response)
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { base: format!("http://{host}:{port}"), requests, task }
    }
    fn recorded(&self) -> Vec<Recorded> { assert!(!self.task.is_finished(), "local provider fixture stopped"); self.requests.lock().unwrap().clone() }
    fn clear(&self) { self.requests.lock().unwrap().clear(); }
    fn assert_cycle(&self) {
        let requests = self.recorded(); assert_eq!(requests.len(), 2, "create and revoke both reach the allowed local fixture");
        for r in &requests { assert_eq!(r.method, Method::POST); assert_eq!(r.headers.get("authorization").unwrap(), &format!("Bearer {PARENT}")); }
        assert_eq!(requests[0].path, CREATE_PATH); assert_eq!(requests[0].body["apiKey"]["displayName"], "private-dns-boundary");
        assert_eq!(requests[1].path, REVOKE_PATH); assert_eq!(requests[1].body, json!({"keyId":"fixture-child"}));
    }
}
async fn local_dns_host(port: u16) -> String {
    let mut names = vec!["pr32-inference.localhost".to_string()];
    if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
        for line in hosts.lines() {
            let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
            if fields.next().and_then(|s| s.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback()) {
                names.extend(fields.filter(|s| s.parse::<std::net::IpAddr>().is_err() && !s.trim_end_matches('.').eq_ignore_ascii_case("localhost")).map(str::to_string));
            }
        }
    }
    for name in names {
        if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((name.as_str(), port))).await {
            let addrs: Vec<_> = addrs.collect();
            if !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()) && addrs.iter().any(|a| a.ip().is_ipv4()) { return name.clone(); }
        }
    }
    panic!("fixture prerequisite: a nonliteral hostname other than localhost must actually resolve to loopback; no hosts file changes or external provider is permitted");
}

struct PrivateDb { dir: PathBuf, url: String }
impl Drop for PrivateDb { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }
impl PrivateDb {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-pr32-inference-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap(); let url = format!("sqlite://{}/test.db", dir.display());
        let db = Db::open(&url).await.unwrap(); seed_epoch(&db, &MASTER).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("org"),json!("inference fixture"),json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,?)", &[json!("owner"),json!("owner@pr32.test.invalid"),json!("unused"),json!("unused"),json!("unused"),json!(now()),json!(1)]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!("org"),json!("owner"),json!("owner")]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(SESSION)),json!("owner"),json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!("app"),json!("org"),json!("inference fixture"),json!(now())]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,?,?,?)", &[json!("env"),json!("app"),json!("test"),json!(oc::encrypt_symmetric(&MASTER,&ENV_KEY)),json!("sse"),json!(now())]).await.unwrap();
        Self { dir, url }
    }
}
struct Reply { status: u16, body: Value }
struct Server { child: Child, base: String, client: Client }
impl Drop for Server { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }
impl Server {
    async fn start(db: &PrivateDb, production: bool, allow_private: bool) -> Self {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let addr = reserved.local_addr().unwrap(); let base = format!("http://{addr}");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL", &db.url).env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_MASTER_KEY", oc::b64(&MASTER)).env("OPENWARP_ENV", if production { "production" } else { "test" }).env("TOKIO_WORKER_THREADS", "1");
        if allow_private { cmd.env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1"); }
        drop(reserved); let child = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("start private API server");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let mut s = Self { child, base, client }; let deadline = Instant::now()+Duration::from_secs(30);
        loop {
            assert!(s.child.try_wait().unwrap().is_none(), "private API server exited before health");
            if let Ok(r) = s.client.get(format!("{}/health",s.base)).send().await { if r.status().is_success() { break; } }
            assert!(Instant::now()<deadline,"private API server readiness timeout"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
        s
    }
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Reply {
        let mut r = self.client.request(method,format!("{}{}",self.base,path)).bearer_auth(SESSION);
        if let Some(body) = body { r = r.json(&body); }
        let r = r.send().await.expect("local API request completes"); let status = r.status().as_u16();
        Reply { status, body: r.json().await.expect("API JSON response") }
    }
    async fn create(&self, provider: &Provider) -> Reply {
        self.call(Method::POST,"/api/envs/env/dynamic",Some(json!({"name":"private-dns-boundary","type":"fireworks","ttl_secs":3600,"config":{"api_key":PARENT,"account_id":"fixture-account","user_id":"fixture-user","base_url":provider.base}}))).await
    }
    async fn revoke(&self, id: &str) -> Reply { self.call(Method::DELETE,&format!("/api/leases/{id}"),None).await }
}
fn issued(reply: &Reply) -> &str { assert_eq!(reply.status,200,"local provider issuance positive control"); assert_eq!(reply.body["value"],"pr32-disposable-child-key"); reply.body["id"].as_str().expect("issued lease id") }
fn assert_denied(reply: &Reply) { assert!((400..600).contains(&reply.status),"private DNS destination must be denied, HTTP {}",reply.status); assert!(reply.body["error"].is_string(),"denial must return an API error"); }

#[tokio::test]
async fn production_inference_create_blocks_private_dns_before_sending_parent_credentials() {
    let _serial = SERIAL.lock().await;
    let provider = Provider::start().await; let db = PrivateDb::new().await; let s = Server::start(&db,true,false).await;
    let reply = s.create(&provider).await;
    assert_eq!(provider.recorded().len(),0,"production inference creation sent parent authorization to a hostname resolving to loopback (HTTP {})",reply.status);
    assert_denied(&reply);
}

#[tokio::test]
async fn production_inference_revoke_blocks_private_dns_for_an_existing_lease() {
    let _serial = SERIAL.lock().await;
    let provider = Provider::start().await; let db = PrivateDb::new().await;
    let lid = {
        let dev = Server::start(&db,false,false).await; let reply = dev.create(&provider).await; issued(&reply).to_string()
    };
    assert_eq!(provider.recorded().len(),1,"development issuance must reach the local fixture"); provider.clear();
    let s = Server::start(&db,true,false).await; let reply = s.revoke(&lid).await;
    assert_eq!(provider.recorded().len(),0,"production revocation sent stored parent authorization to private DNS (HTTP {})",reply.status);
    assert_denied(&reply);
    let metadata = s.call(Method::GET,&format!("/api/leases/{lid}"),None).await;
    assert_eq!(metadata.status,200); assert_eq!(metadata.body["revoked"],false,"blocked remote revocation must not mark the local credential revoked");
}

#[tokio::test]
async fn development_and_explicit_production_override_allow_inference_create_and_revoke() {
    let _serial = SERIAL.lock().await;
    let provider = Provider::start().await;
    for (production, allow_private) in [(false,false),(true,true)] {
        provider.clear(); let db = PrivateDb::new().await; let s = Server::start(&db,production,allow_private).await;
        let reply = s.create(&provider).await; let lid = issued(&reply);
        assert_eq!(s.revoke(lid).await.status,200,"allowed provider revocation positive control"); provider.assert_cycle();
    }
}
