use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const PASSWORD: &str = "hardening-merge-test-password";

struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
struct User { org: String, token: String }

impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

// The suites' existing mail helpers are private to their integration binaries.
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
        let _lock = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-hardening-merge-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (relay, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", relay)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_SIGNUPS").stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { drop(_lock); return Box::pin(Server::start()).await; }
        panic!("server did not become healthy");
    }

    async fn response(response: reqwest::Response) -> Resp {
        let status = response.status().as_u16(); let text = response.text().await.unwrap();
        Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }

    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = req.bearer_auth(token); }
        if let Some(body) = body { req = req.json(&body); }
        Self::response(req.send().await.expect("HTTP request")).await
    }

    async fn register(&self) -> User {
        let email = "hardening@test.invalid";
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
        assert_eq!(login.status, 200, "verified login");
        User { org: field(&r.body, "org_id"), token: field(&login.body, "token") }
    }

    async fn environment(&self, u: &User) -> String {
        let r = self.call(Method::POST, &format!("/api/orgs/{}/apps", u.org), &u.token, Some(json!({"name": "hardening"}))).await;
        assert_eq!(r.status, 200, "create app");
        let envs = self.call(Method::GET, &format!("/api/apps/{}/envs", field(&r.body, "id")), &u.token, None).await;
        assert_eq!(envs.status, 200, "list environments");
        let env = envs.body.as_array().expect("environment list").iter().find(|e| e["name"] == "Development").expect("default Development environment");
        field(env, "id")
    }

    async fn deploy(&self, u: &User, env: &str, secrets: Value) {
        let r = self.call(Method::PUT, &format!("/api/envs/{}/secrets", env), &u.token, Some(json!({"secrets": secrets}))).await;
        assert_eq!(r.status, 200, "valid deploy: {}", r.body);
    }

    async fn list(&self, u: &User, env: &str, query: &str) -> Value {
        let r = self.call(Method::GET, &format!("/api/envs/{}/secrets{}", env, query), &u.token, None).await;
        assert_eq!(r.status, 200, "list secrets: {}", r.body); r.body
    }

    async fn open_lockbox(&self, id: &str, key: &str) -> Resp {
        Self::response(self.client.get(format!("{}/api/lockbox/{}", self.base, id)).header("x-lockbox-key", key).send().await.expect("open lockbox")).await
    }
}

fn field(v: &Value, key: &str) -> String { v[key].as_str().expect(key).to_string() }
fn unix_now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }

#[tokio::test]
async fn wrong_lockbox_key_does_not_consume_the_single_view() {
    let s = Server::start().await; let u = s.register().await;
    let created = s.call(Method::POST, "/api/lockbox", &u.token, Some(json!({"text": "one-time payload"}))).await;
    assert_eq!(created.status, 200, "create single-view share");
    let id = field(&created.body, "id"); let key = field(&created.body, "key");
    let mut wrong = openwarp_crypto::unb64(&key).unwrap(); wrong[0] ^= 1;
    assert_eq!(s.open_lockbox(&id, &openwarp_crypto::b64(&wrong)).await.status, 400, "a well-formed but wrong key must be rejected");
    let opened = s.open_lockbox(&id, &key).await;
    assert_eq!(opened.status, 200, "wrong-key rejection must leave the share readable");
    assert_eq!(opened.body["value"], "one-time payload");
    assert_eq!(s.open_lockbox(&id, &key).await.status, 404, "a successful single view must consume the share");
}

#[tokio::test]
async fn lockbox_honors_configured_views_and_expiry_metadata() {
    let s = Server::start().await; let u = s.register().await;
    let before = unix_now();
    let created = s.call(Method::POST, "/api/lockbox", &u.token, Some(json!({"text": "two-view payload", "max_views": 2, "expires_in": 3600}))).await;
    let after = unix_now();
    assert_eq!(created.status, 200, "create configured share");
    assert_eq!(created.body["max_views"], 2, "creation must report the configured view budget");
    let expires = created.body["expires_at"].as_i64().expect("expiry timestamp");
    assert!((before + 3600..=after + 3600).contains(&expires), "expiry must use the requested lifetime");
    let id = field(&created.body, "id"); let key = field(&created.body, "key");
    for remaining in [1, 0] {
        let opened = s.open_lockbox(&id, &key).await;
        assert_eq!(opened.status, 200, "both configured views must succeed");
        assert_eq!(opened.body["value"], "two-view payload");
        assert_eq!(opened.body["views_remaining"], remaining);
    }
    assert_eq!(s.open_lockbox(&id, &key).await.status, 410, "the exhausted multi-view share must be gone");
}

#[tokio::test]
async fn export_omits_sealed_entries_and_reports_the_omission() {
    let s = Server::start().await; let u = s.register().await; let env = s.environment(&u).await;
    s.deploy(&u, &env, json!([
        {"key": "VISIBLE", "value": "ordinary"}, {"key": "HIDDEN", "value": "sealed-payload", "type": "sealed"}
    ])).await;
    let listed = s.list(&u, &env, "").await;
    assert_eq!(listed["total"], 2, "sealed secrets must remain stored");
    for query in ["", "?base=1"] {
        let r = s.call(Method::GET, &format!("/api/envs/{}/export{}", env, query), &u.token, None).await;
        assert_eq!(r.status, 200, "export readable environment");
        assert_eq!(r.body["omitted_sealed"], 1, "exports must count omitted sealed entries");
        assert_eq!(r.body["text"], "VISIBLE=ordinary", "sealed entries must not become empty assignments");
        let secrets = r.body["secrets"].as_array().expect("exported secrets");
        assert_eq!(secrets.len(), 1); assert_eq!(secrets[0]["key"], "VISIBLE"); assert_eq!(secrets[0]["value"], "ordinary");
    }
}

#[tokio::test]
async fn invalid_later_secret_leaves_the_entire_deploy_unapplied() {
    let s = Server::start().await; let u = s.register().await; let env = s.environment(&u).await;
    s.deploy(&u, &env, json!([{"key": "KEEP", "value": "original"}])).await;
    let failed = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), &u.token, Some(json!({"secrets": [
        {"key": "ALPHA", "value": "must-not-land"}, {"key": "INVALID<KEY>", "value": "invalid"}
    ]}))).await;
    assert_eq!(failed.status, 400, "a later invalid key must reject the batch");
    let listed = s.list(&u, &env, "").await;
    assert!(!listed["secrets"].as_array().unwrap().iter().any(|v| v["key"] == "ALPHA"), "rejected batch must not leave ALPHA behind");
    assert_eq!(listed["total"], 1); assert_eq!(listed["secrets"][0]["value"], "original");
    s.deploy(&u, &env, json!([{"key": "ALPHA", "value": "accepted"}, {"key": "BETA", "value": "also-accepted"}])).await;
    assert_eq!(s.list(&u, &env, "").await["total"], 3, "a valid multi-secret batch must still land");
}

async fn tagged_environment(s: &Server, u: &User) -> String {
    let env = s.environment(u).await;
    s.deploy(u, &env, json!([
        {"key": "ALPHA", "value": "a", "tags": "prod,db"},
        {"key": "BETA", "value": "b", "tags": "prod shared"},
        {"key": "GAMMA", "value": "c", "tags": "production"},
        {"key": "DELTA", "value": "d"}
    ])).await;
    assert_eq!(s.list(u, &env, "").await["total"], 4); env
}

#[tokio::test]
async fn tag_filter_matches_whole_tags_before_pagination() {
    let s = Server::start().await; let u = s.register().await; let env = tagged_environment(&s, &u).await;
    let page = s.list(&u, &env, "?tag=PROD&limit=1&offset=1").await;
    assert_eq!(page["total"], 2, "tag filter must be case-insensitive and exclude prefix-only matches");
    let secrets = page["secrets"].as_array().unwrap(); assert_eq!(secrets.len(), 1);
    assert!(secrets[0]["key"] == "ALPHA" || secrets[0]["key"] == "BETA");
    let db = s.list(&u, &env, "?tag=db").await;
    assert_eq!(db["total"], 1); assert_eq!(db["secrets"][0]["key"], "ALPHA");
    let missing = s.list(&u, &env, "?tag=missing").await;
    assert_eq!(missing["total"], 0); assert_eq!(missing["secrets"], json!([]));
}

#[tokio::test]
async fn tag_catalog_counts_comma_and_whitespace_separated_tags() {
    let s = Server::start().await; let u = s.register().await; let env = tagged_environment(&s, &u).await;
    let r = s.call(Method::GET, &format!("/api/envs/{}/tags", env), &u.token, None).await;
    assert_eq!(r.status, 200, "tag catalog endpoint must exist");
    assert_eq!(r.body["tags"], json!([
        {"tag": "db", "count": 1}, {"tag": "prod", "count": 2},
        {"tag": "production", "count": 1}, {"tag": "shared", "count": 1}
    ]));
}

#[tokio::test]
async fn personal_override_can_be_read_and_deleted_without_changing_base() {
    let s = Server::start().await; let u = s.register().await; let env = s.environment(&u).await;
    s.deploy(&u, &env, json!([{"key": "SHARED", "value": "base-value"}])).await;
    let listed = s.list(&u, &env, "").await; let sid = field(&listed["secrets"][0], "id");
    let path = format!("/api/secrets/{}/override", sid);
    let set = s.call(Method::POST, &path, &u.token, Some(json!({"secrets": [{"key": "SHARED", "value": "personal-value"}]}))).await;
    assert_eq!(set.status, 200, "set personal override");
    assert_eq!(s.list(&u, &env, "").await["secrets"][0]["value"], "personal-value");
    let base = s.call(Method::GET, &format!("/api/envs/{}/export?base=1", env), &u.token, None).await;
    assert_eq!(base.status, 200); assert_eq!(base.body["secrets"][0]["value"], "base-value", "override must not change shared export");
    let read = s.call(Method::GET, &path, &u.token, None).await;
    assert_eq!(read.status, 200, "read personal override");
    assert_eq!(read.body["key"], "SHARED"); assert_eq!(read.body["value"], "personal-value");
    let deleted = s.call(Method::DELETE, &path, &u.token, None).await;
    assert_eq!(deleted.status, 200, "delete personal override"); assert_eq!(deleted.body["deleted"], true);
    assert_eq!(s.call(Method::GET, &path, &u.token, None).await.status, 404, "deleted override must no longer be readable");
    assert_eq!(s.call(Method::DELETE, &path, &u.token, None).await.status, 404, "deleting an absent override must report not found");
    let listed = s.list(&u, &env, "").await;
    assert_eq!(listed["total"], 1); assert_eq!(listed["secrets"][0]["id"], sid);
    assert_eq!(listed["secrets"][0]["value"], "base-value", "deleting override must reveal the unchanged base");
}
