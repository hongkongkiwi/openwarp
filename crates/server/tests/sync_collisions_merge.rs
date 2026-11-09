use axum::{body::{to_bytes, Body}, extract::State, http::Request, routing::any, Json, Router};
use openwarp_server::integrations::sync_managed_with_tags;
use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};

static START_RETRIES: AtomicU32 = AtomicU32::new(0);
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct Call { method: String, path: String, target: String, body: Value }
struct Mock { base: String, calls: Arc<Mutex<Vec<Call>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Mock { fn drop(&mut self) { self.task.abort(); } }
impl Mock {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        async fn capture(State((base, calls)): State<(String, Arc<Mutex<Vec<Call>>>)>, request: Request<Body>) -> Json<Value> {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            let target = parts.headers.get("x-amz-target").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let response = if target == "secretsmanager.ListSecrets" { json!({"SecretList": []}) }
                else if parts.method == "GET" && parts.uri.path().starts_with("/secrets/") && parts.uri.path().ends_with("/versions") {
                    let secret = parts.uri.path().trim_end_matches("/versions");
                    json!({"value": [{"id": format!("{}{}/1234567890abcdef1234567890abcdef", base, secret), "attributes": {"enabled": true}}], "nextLink": null})
                } else { json!({}) };
            calls.lock().unwrap().push(Call { method: parts.method.to_string(), path: parts.uri.path().to_string(), target,
                body: if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("mock request JSON") } });
            Json(response)
        }
        let router = Router::new().fallback(any(capture)).with_state((base.clone(), calls.clone()));
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        Self { base, calls, task }
    }
    fn calls(&self) -> Vec<Call> { self.calls.lock().unwrap().clone() }
}

async fn azure_retains_canonical_target(disable: bool) {
    let mut unsafe_calls = Vec::new();
    for current in ["API-KEY", "api_key"] {
        let mock = Mock::start().await;
        let mut config = json!({"base_url": mock.base, "token": "dummy-azure-token"});
        if disable { config["absent"] = json!("disable"); } else { config["mode"] = json!("mirror"); }
        let secrets = vec![("/".into(), current.into(), "shared-value".into(), "secret".into())];
        sync_managed_with_tags("azure_key_vault", &config, &secrets, &HashMap::new(), &["API_KEY".into(), "OLD_KEY".into()])
            .await.expect("stateful Azure adapter").expect("Azure mock sync");
        let calls = mock.calls();
        let writes: Vec<_> = calls.iter().filter(|c| c.method == "PUT").collect();
        assert_eq!(writes.len(), 1, "one current target: {:?}", calls);
        assert_eq!(writes[0].path, "/secrets/api-key"); assert_eq!(writes[0].body["value"], "shared-value");
        let pruned: Vec<_> = calls.iter().filter(|c| (c.path == "/secrets/old-key" || c.path.starts_with("/secrets/old-key/")) && (c.method == "PATCH" || c.method == "DELETE")).collect();
        assert_eq!(pruned.len(), 1, "a genuinely absent owned target must still be pruned: {:?}", calls);
        assert_eq!(writes[0].body["attributes"]["enabled"], true, "current target must be enabled by its new-version PUT");
        if disable {
            assert!(calls.iter().any(|c| c.method == "GET" && c.path == "/secrets/old-key/versions"), "discover the absent target's version");
            assert_eq!(pruned[0].method, "PATCH");
            assert_eq!(pruned[0].path, "/secrets/old-key/1234567890abcdef1234567890abcdef");
            assert_eq!(pruned[0].body["attributes"]["enabled"], false);
            assert!(calls.iter().filter(|c| c.method == "PATCH").all(|c| c.path.trim_matches('/').split('/').count() == 3), "Key Vault PATCH must target a version");
        } else { assert_eq!(pruned[0].method, "DELETE"); assert_eq!(pruned[0].path, "/secrets/old-key"); }
        unsafe_calls.extend(calls.into_iter().filter(|c| (c.path == "/secrets/api-key" || c.path.starts_with("/secrets/api-key/")) &&
            (c.method == "DELETE" || (c.method == "PATCH" && c.body["attributes"]["enabled"] == false))));
    }
    assert!(unsafe_calls.is_empty(), "renaming an owned logical key must not prune its still-desired canonical Azure target: {:?}", unsafe_calls);
}

#[tokio::test]
async fn azure_mirror_retains_targets_after_punctuation_or_case_rename() { azure_retains_canonical_target(false).await; }
#[tokio::test]
async fn azure_disable_retains_targets_after_punctuation_or_case_rename() { azure_retains_canonical_target(true).await; }

struct Server { child: Child, base: String, dir: PathBuf, client: Client, mail: Mock }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start() -> Self {
        let mail = Mock::start().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let dir = std::env::temp_dir().join(format!("openwarp-sync-collisions-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir(&dir).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", &mail.base)
            .env("TOKIO_WORKER_THREADS", "1").env("NO_PROXY", "127.0.0.1,localhost")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_SIGNUPS").env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let s = Self { child, base, dir, client, mail }; let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { return Box::pin(Server::start()).await; }
        panic!("server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Value {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.expect("HTTP request"); let status = response.status();
        let body: Value = response.json().await.expect("HTTP JSON response");
        assert_eq!(status, 200, "HTTP fixture request {} failed: {}", path, body); body
    }
    async fn register(&self) -> (String, String) {
        let registered = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email": "sync-owner@test.invalid", "password": "sync-collision-test-password"}))).await;
        assert_eq!(registered["verification_required"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let link = self.mail.calls().iter().filter_map(|c| c.body["text"].as_str()).find_map(|text| text.split_whitespace()
                .find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string())));
            if let Some(link) = link {
                let response = self.client.get(format!("{}{}", self.base, link)).send().await.expect("verify account");
                assert_eq!(response.status(), 200, "verify account HTML response"); break;
            }
            assert!(Instant::now() < deadline, "verification mail did not arrive");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let login = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email": "sync-owner@test.invalid", "password": "sync-collision-test-password"}))).await;
        (field(&registered, "org_id"), field(&login, "token"))
    }
}
fn field(value: &Value, key: &str) -> String { value[key].as_str().expect(key).to_string() }

async fn http_sync_keeps_winning_record_metadata(kind: &str) {
    let s = Server::start().await; let provider = Mock::start().await;
    let (org, token) = s.register().await;
    let app = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), &token, Some(json!({"name": "sync-collisions"}))).await;
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", field(&app, "id")), &token, None).await;
    let env = field(envs.as_array().unwrap().iter().find(|e| e["name"] == "Development").expect("Development environment"), "id");
    let deployed = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), &token, Some(json!({"secrets": [
        {"key": "API_KEY", "path": "/alpha/", "value": "alpha-base", "tags": "owner=alpha"},
        {"key": "API_KEY", "path": "/beta/", "value": "beta-base", "tags": "owner=beta"},
        {"key": "CONTROL_KEY", "path": "/alpha/", "value": "control-base", "tags": "owner=control"},
        {"key": "API_KEY", "path": "/excluded/", "value": "excluded-base", "tags": "owner=excluded"},
        {"key": "OUTSIDE_ONLY", "path": "/excluded/", "value": "outside-base", "tags": "owner=excluded"},
        {"key": "API_KEY", "path": "/sealed/", "value": "sealed-base", "tags": "owner=sealed", "type": "sealed"},
        {"key": "SEALED_ONLY", "path": "/sealed/", "value": "sealed-only-base", "tags": "owner=sealed", "type": "sealed"}
    ]}))).await;
    assert_eq!(deployed["deployed"], 7); assert_eq!(deployed["sync_errors"], json!([]));
    let exported = s.call(Method::GET, &format!("/api/envs/{}/export?base=1", env), &token, None).await;
    assert_eq!(exported["omitted_sealed"], 2);
    let records = exported["secrets"].as_array().expect("base records");
    let selected: Vec<_> = records.iter().filter(|r| r["path"] == "/alpha/" || r["path"] == "/beta/").collect();
    let duplicates: Vec<_> = selected.iter().filter(|r| r["key"] == "API_KEY").collect();
    assert_eq!(duplicates.len(), 2); assert_ne!(duplicates[0]["value"], duplicates[1]["value"]); assert_ne!(duplicates[0]["tags"], duplicates[1]["tags"]);
    // Base export preserves the server's key_index/key_hash order, which is not insertion order.
    let winner = duplicates[0];
    for record in &selected {
        let path = format!("/api/secrets/{}/override", field(record, "id"));
        s.call(Method::POST, &path, &token, Some(json!({"secrets": [{"key": field(record, "key"), "value": "personal-must-not-sync"}]}))).await;
        assert_eq!(s.call(Method::GET, &path, &token, None).await["value"], "personal-must-not-sync");
    }
    let mut config = if kind == "azure_key_vault" { json!({"base_url": provider.base, "token": "dummy-azure-token"}) }
        else { json!({"endpoint": provider.base, "region": "us-east-1", "access_key_id": "dummy-access-key", "secret_access_key": "dummy-secret-key"}) };
    config["paths"] = json!(["/alpha/", "/beta/", "/sealed/"]); config["tags"] = json!({"deployment": "shared"});
    let integration = s.call(Method::POST, &format!("/api/envs/{}/integrations", env), &token,
        Some(json!({"kind": kind, "name": "collision-record", "config": config}))).await;
    let synced = s.call(Method::POST, &format!("/api/integrations/{}/sync", field(&integration, "id")), &token, None).await;
    assert_eq!(synced["ok"], true);
    let calls = provider.calls();
    let mut writes: Vec<(String, Value, Value)> = if kind == "azure_key_vault" {
        calls.iter().filter(|c| c.method == "PUT").map(|c| (c.path.clone(), c.body["value"].clone(), c.body["tags"].clone())).collect()
    } else {
        calls.iter().filter(|c| c.target == "secretsmanager.PutSecretValue").map(|c| {
            let name = field(&c.body, "SecretId");
            let tags: Vec<_> = calls.iter().filter(|t| t.target == "secretsmanager.TagResource" && t.body["SecretId"] == name).collect();
            assert_eq!(tags.len(), 1, "one metadata update per winning value");
            let tags: serde_json::Map<String, Value> = tags[0].body["Tags"].as_array().expect("AWS tags").iter().map(|t| (field(t, "Key"), t["Value"].clone())).collect();
            (name, c.body["SecretString"].clone(), Value::Object(tags))
        }).collect()
    };
    writes.sort_by(|a, b| a.0.cmp(&b.0));
    let (api, control) = if kind == "azure_key_vault" { ("/secrets/api-key", "/secrets/control-key") } else { ("API_KEY", "CONTROL_KEY") };
    assert_eq!(writes.iter().map(|w| w.0.as_str()).collect::<Vec<_>>(), vec![api, control], "unselected and sealed records must not be sent");
    assert_eq!(writes[1].1, "control-base", "personal overrides must not become deployed values");
    assert_eq!(writes[1].2, json!({"owner": "control", "deployment": "shared"}), "noncolliding metadata and static tags remain intact");
    assert_eq!(writes[0].1, winner["value"], "keep the first selected shared record, not a personal or excluded value");
    assert_eq!(writes[0].2["deployment"], "shared");
    let owner = field(winner, "tags").strip_prefix("owner=").expect("fixture owner tag").to_string();
    assert_eq!(writes[0].2["owner"], owner, "{} must send metadata from the same first-selected record as its value", kind);
}

#[tokio::test]
async fn azure_http_sync_keeps_value_and_tags_from_the_same_winning_record() { http_sync_keeps_winning_record_metadata("azure_key_vault").await; }
#[tokio::test]
async fn aws_http_sync_keeps_value_and_tags_from_the_same_winning_record() { http_sync_keeps_winning_record_metadata("aws_secrets_manager").await; }
