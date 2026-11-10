use axum::{body::{to_bytes, Body}, extract::State, http::{Request, StatusCode}, routing::any, Json, Router};
use openwarp_server::integrations::{sync_managed_with_tags, sync_with_tags};
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

const AZURE_VERSION: &str = "1234567890abcdef1234567890abcdef";
#[derive(Clone, Debug)]
struct Call { method: String, path: String, query: String, body: Value }
#[derive(Clone, Copy)]
enum Provider { Mail, Gcp, Azure }
#[derive(Clone)]
struct MockState { base: String, provider: Provider, calls: Arc<Mutex<Vec<Call>>> }
struct Mock { base: String, calls: Arc<Mutex<Vec<Call>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Mock { fn drop(&mut self) { self.task.abort(); } }
impl Mock {
    async fn start(provider: Provider) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        async fn capture(State(state): State<MockState>, request: Request<Body>) -> (StatusCode, Json<Value>) {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            let call = Call { method: parts.method.to_string(), path: parts.uri.path().to_string(), query: parts.uri.query().unwrap_or("").to_string(),
                body: if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("mock request JSON") } };
            state.calls.lock().unwrap().push(call.clone());
            let response = match state.provider {
                Provider::Mail => (StatusCode::OK, json!({})),
                Provider::Gcp => match (call.method.as_str(), call.path.as_str()) {
                    ("POST", "/v1/projects/review-project/secrets") => (StatusCode::CONFLICT, json!({"error": {"code": 409}})),
                    ("POST", path) if path.ends_with(":addVersion") => (StatusCode::OK, json!({"name": format!("{}/versions/1", path.trim_end_matches(":addVersion"))})),
                    ("PATCH", path) if path.starts_with("/v1/projects/review-project/secrets/") && call.query == "updateMask=labels" => (StatusCode::OK, call.body.clone()),
                    _ => (StatusCode::NOT_FOUND, json!({"error": "unexpected GCP request"})),
                },
                Provider::Azure => {
                    let segments: Vec<_> = call.path.trim_matches('/').split('/').collect();
                    let name = segments.get(1).copied().unwrap_or("");
                    let id = format!("{}/secrets/{}/{}", state.base, name, AZURE_VERSION);
                    if call.query != "api-version=7.4" || segments.first() != Some(&"secrets") {
                        (StatusCode::BAD_REQUEST, json!({"error": {"message": "expected Key Vault API 7.4"}}))
                    } else { match (call.method.as_str(), segments.len()) {
                        ("PUT", 2) => (StatusCode::OK, json!({"id": id, "value": call.body["value"], "attributes": {"enabled": call.body["attributes"]["enabled"]}})),
                        ("GET", 3) if segments[2] == "versions" => (StatusCode::OK, json!({"value": [{"id": id, "attributes": {"enabled": true}}], "nextLink": null})),
                        ("GET", 2) => (StatusCode::OK, json!({"id": id, "value": "dummy-old-value", "attributes": {"enabled": true}})),
                        ("GET", 3) if segments[2] == AZURE_VERSION => (StatusCode::OK, json!({"id": id, "value": "dummy-old-value", "attributes": {"enabled": true}})),
                        ("PATCH", 3) if segments[2] == AZURE_VERSION => (StatusCode::OK, json!({"id": id, "attributes": call.body["attributes"]})),
                        ("PATCH", _) => (StatusCode::BAD_REQUEST, json!({"error": {"message": "Key Vault 7.4 PATCH requires a secret version"}})),
                        _ => (StatusCode::NOT_FOUND, json!({"error": {"message": "unexpected Azure request"}})),
                    } }
                },
            };
            (response.0, Json(response.1))
        }
        let state = MockState { base: base.clone(), provider, calls: calls.clone() };
        let task = tokio::spawn(async move { axum::serve(listener, Router::new().fallback(any(capture)).with_state(state)).await.unwrap(); });
        Self { base, calls, task }
    }
    fn calls(&self) -> Vec<Call> { self.calls.lock().unwrap().clone() }
}

#[tokio::test]
async fn gcp_existing_secret_replaces_labels_even_when_all_metadata_is_cleared() {
    let mock = Mock::start(Provider::Gcp).await;
    let secrets = vec![("API_KEY".into(), "dummy-value".into())];
    let config = json!({"base_url": mock.base, "token": "dummy-gcp-token", "project": "review-project"});
    let tags = HashMap::from([("API_KEY".into(), "owner=before".into())]);
    sync_with_tags("gcp_secret_manager", &config, &secrets, &tags).await.expect("initial label sync");
    let initial = mock.calls();
    let patch = initial.iter().find(|c| c.method == "PATCH").expect("existing nonempty labels are updated");
    assert_eq!(patch.body["labels"], json!({"owner": "before"}));
    let offset = initial.len();
    sync_with_tags("gcp_secret_manager", &config, &secrets, &HashMap::new()).await.expect("cleared label sync");
    let calls = mock.calls(); let cleared = &calls[offset..];
    assert_eq!(cleared.iter().filter(|c| c.path.ends_with(":addVersion")).count(), 1, "metadata clearing must preserve value sync");
    let patches: Vec<_> = cleared.iter().filter(|c| c.method == "PATCH").collect();
    assert_eq!(patches.len(), 1, "a 409 existing secret must receive an explicit empty labels update: {:?}", cleared);
    assert_eq!(patches[0].path, "/v1/projects/review-project/secrets/api-key");
    assert_eq!(patches[0].query, "updateMask=labels"); assert_eq!(patches[0].body["labels"], json!({}));
}

struct Server { child: Child, base: String, dir: PathBuf, client: Client, mail: Mock }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start() -> Self {
        let mail = Mock::start(Provider::Mail).await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let dir = std::env::temp_dir().join(format!("openwarp-sync-review-{}-{}", std::process::id(), addr.port()));
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
    async fn response(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> (reqwest::StatusCode, Value) {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.expect("HTTP request"); let status = response.status();
        (status, response.json().await.expect("HTTP JSON response"))
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Value {
        let (status, body) = self.response(method, path, token, body).await;
        assert_eq!(status, 200, "HTTP fixture request {} failed: {}", path, body); body
    }
    async fn environment(&self) -> (String, String) {
        let credentials = json!({"email": "sync-review@test.invalid", "password": "dummy-review-password"});
        let registered = self.call(Method::POST, "/api/auth/register", "", Some(credentials.clone())).await;
        assert_eq!(registered["verification_required"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let link = self.mail.calls().iter().filter_map(|c| c.body["text"].as_str()).find_map(|text| text.split_whitespace()
                .find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string())));
            if let Some(link) = link {
                assert_eq!(self.client.get(format!("{}{}", self.base, link)).send().await.expect("verify account").status(), 200); break;
            }
            assert!(Instant::now() < deadline, "verification mail did not arrive"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let login = self.call(Method::POST, "/api/auth/login", "", Some(credentials)).await; let token = field(&login, "token");
        let app = self.call(Method::POST, &format!("/api/orgs/{}/apps", field(&registered, "org_id")), &token, Some(json!({"name": "sync-review"}))).await;
        let envs = self.call(Method::GET, &format!("/api/apps/{}/envs", field(&app, "id")), &token, None).await;
        (field(envs.as_array().unwrap().iter().find(|e| e["name"] == "Development").expect("Development environment"), "id"), token)
    }
}
fn field(value: &Value, key: &str) -> String { value[key].as_str().expect(key).to_string() }

#[tokio::test]
async fn gcp_http_duplicate_names_keep_first_shared_value_and_its_tags() {
    let s = Server::start().await; let provider = Mock::start(Provider::Gcp).await;
    let (env, token) = s.environment().await;
    let deployed = s.call(Method::PUT, &format!("/api/envs/{}/secrets", env), &token, Some(json!({"secrets": [
        {"key": "API_KEY", "path": "/alpha/", "value": "dummy-alpha", "tags": "owner=alpha"},
        {"key": "API_KEY", "path": "/beta/", "value": "dummy-beta", "tags": "owner=beta"},
        {"key": "CONTROL_KEY", "path": "/alpha/", "value": "dummy-control", "tags": "owner=control"}
    ]}))).await;
    assert_eq!(deployed["deployed"], 3); assert_eq!(deployed["sync_errors"], json!([]));
    let exported = s.call(Method::GET, &format!("/api/envs/{}/export?base=1", env), &token, None).await;
    let duplicates: Vec<_> = exported["secrets"].as_array().expect("base records").iter().filter(|r| r["key"] == "API_KEY").collect();
    assert_eq!(duplicates.len(), 2);
    // Base export exposes sync's stable ordering without assuming an insertion order for encrypted keys.
    let winner = duplicates[0];
    let config = json!({"base_url": provider.base, "token": "dummy-gcp-token", "project": "review-project", "tags": {"deployment": "shared"}});
    let integration = s.call(Method::POST, &format!("/api/envs/{}/integrations", env), &token,
        Some(json!({"kind": "gcp_secret_manager", "name": "duplicate-review", "config": config}))).await;
    assert_eq!(s.call(Method::POST, &format!("/api/integrations/{}/sync", field(&integration, "id")), &token, None).await["ok"], true);
    let calls = provider.calls();
    let writes: Vec<_> = calls.iter().filter(|c| c.path.ends_with(":addVersion")).collect();
    let control: Vec<_> = writes.iter().filter(|c| c.path.ends_with("/control-key:addVersion")).collect();
    assert_eq!(control.len(), 1); assert_eq!(control[0].body["payload"]["data"], openwarp_crypto::b64(b"dummy-control"));
    let api: Vec<_> = writes.iter().filter(|c| c.path.ends_with("/api-key:addVersion")).collect();
    assert!(!api.is_empty(), "duplicate name still needs a value write");
    assert_eq!(api.last().unwrap().body["payload"]["data"], openwarp_crypto::b64(field(winner, "value").as_bytes()), "the final remote value must be the first shared record, not the last duplicate");
    assert_eq!(api.len(), 1, "one version per selected remote name");
    let labels: Vec<_> = calls.iter().filter(|c| c.method == "PATCH" && c.path.ends_with("/api-key")).collect();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].body["labels"], json!({"owner": field(winner, "tags").strip_prefix("owner=").unwrap(), "deployment": "shared"}));
}

#[tokio::test]
async fn automatic_deploy_skips_invalid_disabled_config_but_manual_sync_validates() {
    let s = Server::start().await; let provider = Mock::start(Provider::Gcp).await; let (env, token) = s.environment().await;
    let mut config = json!({"base_url": provider.base, "token": "dummy-gcp-token", "project": "review-project", "paths": "not-an-array", "auto_sync": true});
    let integration = s.call(Method::POST, &format!("/api/envs/{}/integrations", env), &token,
        Some(json!({"kind": "gcp_secret_manager", "name": "disabled-review", "config": config}))).await;
    let deploy_path = format!("/api/envs/{}/secrets", env); let integration_path = format!("/api/integrations/{}", field(&integration, "id"));
    let body = json!({"secrets": [{"key": "API_KEY", "value": "dummy-deploy"}]});
    let enabled = s.call(Method::PUT, &deploy_path, &token, Some(body.clone())).await;
    assert_eq!(enabled["deployed"], 1); let errors = enabled["sync_errors"].as_array().expect("sync errors");
    assert_eq!(errors.len(), 1); assert!(errors[0].as_str().unwrap().contains("paths"), "enabled config must still validate");
    config["auto_sync"] = json!(false);
    s.call(Method::PATCH, &integration_path, &token, Some(json!({"config": config}))).await;
    let (status, error) = s.response(Method::POST, &format!("{}/sync", integration_path), &token, None).await;
    assert_eq!(status, 400, "manual sync must reject invalid disabled config");
    assert!(error["error"].as_str().unwrap().contains("paths"));
    let disabled = s.call(Method::PUT, &deploy_path, &token, Some(body)).await;
    assert_eq!(disabled["deployed"], 1);
    assert!(provider.calls().is_empty(), "invalid or disabled config must not contact a provider");
    assert_eq!(disabled["sync_errors"], json!([]), "auto_sync false must skip before validating an unused config");
}

#[tokio::test]
async fn azure_current_versions_are_explicitly_enabled_without_unversioned_patch() {
    let mut violations = Vec::new();
    for mapping in ["one_to_one", "many_to_one"] {
        let mock = Mock::start(Provider::Azure).await;
        let mut config = json!({"base_url": mock.base, "token": "dummy-azure-token", "mapping": mapping});
        if mapping == "many_to_one" { config["secret_name"] = json!("bundle"); } else { config["absent"] = json!("disable"); }
        let secrets = vec![("/".into(), "API_KEY".into(), "dummy-current".into(), "secret".into())];
        let result = sync_managed_with_tags("azure_key_vault", &config, &secrets, &HashMap::new(), &[]).await.expect("Azure adapter");
        let calls = mock.calls(); let puts: Vec<_> = calls.iter().filter(|c| c.method == "PUT").collect();
        assert_eq!(puts.len(), 1, "one current version for {}", mapping);
        if mapping == "many_to_one" {
            assert_eq!(puts[0].path, "/secrets/bundle");
            assert_eq!(serde_json::from_str::<Value>(puts[0].body["value"].as_str().unwrap()).unwrap(), json!({"API_KEY": "dummy-current"}));
        } else { assert_eq!(puts[0].path, "/secrets/api-key"); assert_eq!(puts[0].body["value"], "dummy-current"); }
        let enabled = puts[0].body["attributes"]["enabled"] == true || calls.iter().any(|c| c.method == "PATCH" && c.path == format!("{}/{}", puts[0].path, AZURE_VERSION) && c.body["attributes"]["enabled"] == true);
        if !enabled { violations.push(format!("{} did not explicitly enable the new version", mapping)); }
        if calls.iter().any(|c| c.method == "PATCH" && c.path.trim_matches('/').split('/').count() != 3) { violations.push(format!("{} sent an unversioned PATCH", mapping)); }
        if let Err(error) = result { violations.push(format!("{} failed Key Vault contract: {}", mapping, error)); }
    }
    assert!(violations.is_empty(), "current version enable contract: {:?}", violations);
}

#[tokio::test]
async fn azure_absent_disable_discovers_and_patches_a_version_not_the_secret_name() {
    let mock = Mock::start(Provider::Azure).await;
    let config = json!({"base_url": mock.base, "token": "dummy-azure-token", "absent": "disable"});
    let result = sync_managed_with_tags("azure_key_vault", &config, &[], &HashMap::new(), &["OLD_KEY".into()]).await.expect("Azure adapter");
    let calls = mock.calls();
    assert!(!calls.iter().any(|c| c.method == "PATCH" && c.path == "/secrets/old-key"), "Key Vault 7.4 forbids an unversioned PATCH: {:?}", calls);
    assert!(calls.len() <= 6, "single-version discovery must be bounded: {:?}", calls);
    assert!(calls.iter().all(|c| c.method == "GET" || c.method == "PATCH"), "disable must not delete or replace the absent value");
    let patches: Vec<_> = calls.iter().filter(|c| c.method == "PATCH").collect();
    assert_eq!(patches.len(), 1, "the discovered absent version must be disabled: {:?}", calls);
    assert_eq!(patches[0].path, format!("/secrets/old-key/{}", AZURE_VERSION));
    assert_eq!(patches[0].body["attributes"]["enabled"], false);
    result.expect("versioned disable succeeds");
}

#[tokio::test]
async fn azure_disable_dry_run_performs_no_version_discovery_or_mutation() {
    let mock = Mock::start(Provider::Azure).await;
    let config = json!({"base_url": mock.base, "token": "dummy-azure-token", "absent": "disable", "dry_run": true});
    let secrets = vec![("/".into(), "API_KEY".into(), "dummy-current".into(), "secret".into())];
    sync_managed_with_tags("azure_key_vault", &config, &secrets, &HashMap::new(), &["OLD_KEY".into()]).await.expect("Azure adapter").expect("dry run");
    assert!(mock.calls().is_empty(), "a dry run must not discover versions, write, enable or disable remote secrets");
}

#[tokio::test]
async fn azure_absent_secret_named_versions_disables_its_valid_version() {
    let mock = Mock::start(Provider::Azure).await;
    let config = json!({"base_url": mock.base, "token": "dummy-azure-token", "absent": "disable"});
    let result = sync_managed_with_tags("azure_key_vault", &config, &[], &HashMap::new(), &["VERSIONS".into()]).await.expect("Azure adapter");
    let (report, managed) = result.expect("VERSIONS is a valid secret name and its same-vault version must be disabled");
    assert!(report.contains("disabled=1"), "{}", report);
    assert_eq!(managed, vec!["VERSIONS".to_string()], "retain ownership of the disabled secret");
    let calls = mock.calls();
    assert!(calls.len() <= 6, "single-version discovery must be bounded: {:?}", calls);
    assert!(calls.iter().all(|c| c.method == "GET" || c.method == "PATCH"), "disable must not delete or replace the absent value");
    let patches: Vec<_> = calls.iter().filter(|c| c.method == "PATCH").collect();
    assert_eq!(patches.len(), 1, "disable the discovered version exactly once: {:?}", calls);
    assert_eq!(patches[0].path, format!("/secrets/versions/{}", AZURE_VERSION));
    assert_eq!(patches[0].query, "api-version=7.4");
    assert_eq!(patches[0].body, json!({"attributes": {"enabled": false}}));
}
