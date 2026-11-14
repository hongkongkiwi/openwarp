use axum::{body::{to_bytes, Body}, http::{HeaderMap, Method, StatusCode}, response::Response, Json, Router};
use openwarp_crypto as oc;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RUNNER_TOKEN: &str = "disposable-runner-parity-token";
const PROVIDER_TOKEN: &str = "disposable-parity-provider-token";
const AWS_SECRET: &str = "disposable-parity-aws-secret";
const VALUE: &str = "disposable-parity-secret-value";
const OLD_VALUE: &str = "disposable-parity-old-value";
const UNRELATED_VALUE: &str = "disposable-parity-unrelated-value";

fn clean_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let text = key.to_string_lossy();
        if text.starts_with("OPENWARP_") || text.to_ascii_uppercase().ends_with("_PROXY") || text == "DATABASE_URL" || text == "REDIS_URL" {
            command.env_remove(key);
        }
    }
    command.env("OPENWARP_ENV", "development").env("TOKIO_WORKER_THREADS", "1");
}

#[derive(Clone)]
struct Request { method: Method, path: String, headers: HeaderMap, body: Value }
#[derive(Default)]
struct Remote { values: BTreeMap<String, String>, tags: BTreeMap<String, BTreeMap<String, String>>, requests: Vec<Request>, unexpected: Vec<String> }
struct Provider { base: String, remote: Arc<Mutex<Remote>>, task: tokio::task::JoinHandle<()> }
impl Drop for Provider { fn drop(&mut self) { self.task.abort(); } }
impl Provider {
    async fn start(values: &[(&str, &str)]) -> Self {
        let remote = Arc::new(Mutex::new(Remote { values: values.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), ..Remote::default() }));
        let sink = remote.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
                let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("provider body must be JSON") };
                let path = parts.uri.path().to_string();
                let target = parts.headers.get("x-amz-target").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let mut remote = sink.lock().unwrap();
                remote.requests.push(Request { method: parts.method.clone(), path: path.clone(), headers: parts.headers, body: body.clone() });
                let reply = if !target.is_empty() {
                    match target.as_str() {
                        "secretsmanager.ListSecrets" => json!({"SecretList": remote.values.keys().map(|name| json!({"Name":name})).collect::<Vec<_>>()}),
                        "secretsmanager.PutSecretValue" => {
                            remote.values.insert(body["SecretId"].as_str().unwrap().into(), body["SecretString"].as_str().unwrap().into()); json!({})
                        }
                        "secretsmanager.TagResource" => {
                            let tags = body["Tags"].as_array().unwrap().iter().map(|v| (v["Key"].as_str().unwrap().into(), v["Value"].as_str().unwrap().into())).collect();
                            remote.tags.insert(body["SecretId"].as_str().unwrap().into(), tags); json!({})
                        }
                        "secretsmanager.DeleteSecret" => { remote.values.remove(body["SecretId"].as_str().unwrap()); json!({}) }
                        _ => { remote.unexpected.push(format!("AWS {target}")); return (StatusCode::NOT_FOUND, Json(json!({"error":"unexpected fixture operation"}))); }
                    }
                } else if path.starts_with("/project/gh/parity/app/envvar") {
                    match parts.method {
                        Method::GET => json!({"items":remote.values.keys().map(|name| json!({"name":name,"value":"********"})).collect::<Vec<_>>()}),
                        Method::POST => { remote.values.insert(body["name"].as_str().unwrap().into(), body["value"].as_str().unwrap().into()); json!({}) }
                        Method::DELETE => { remote.values.remove(path.rsplit('/').next().unwrap()); json!({}) }
                        _ => { remote.unexpected.push(format!("{} {path}", parts.method)); return (StatusCode::NOT_FOUND, Json(json!({"error":"unexpected fixture operation"}))); }
                    }
                } else if path.starts_with("/api/v1/projects/parity/envvars/prod") {
                    match parts.method {
                        Method::GET => json!(remote.values.iter().map(|(name, value)| json!({"name":name,"value":value})).collect::<Vec<_>>()),
                        Method::POST if path.ends_with("/import") => {
                            for item in body["variables"].as_array().unwrap() { remote.values.insert(item["name"].as_str().unwrap().into(), item["value"].as_str().unwrap().into()); } json!({})
                        }
                        Method::DELETE => { remote.values.remove(path.rsplit('/').next().unwrap()); json!({}) }
                        _ => { remote.unexpected.push(format!("{} {path}", parts.method)); return (StatusCode::NOT_FOUND, Json(json!({"error":"unexpected fixture operation"}))); }
                    }
                } else if path == "/webhook" && parts.method == Method::POST { json!({"ok":true}) }
                else { remote.unexpected.push(format!("{} {path}", parts.method)); return (StatusCode::NOT_FOUND, Json(json!({"error":"unexpected fixture operation"}))); };
                (StatusCode::OK, Json(reply))
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { base, remote, task }
    }
    fn config(&self, kind: &str) -> Value {
        match kind {
            "aws_secrets_manager" => json!({"endpoint":self.base,"region":"us-east-1","access_key_id":"DISPOSABLEPARITY","secret_access_key":AWS_SECRET}),
            "circleci" => json!({"base_url":self.base,"project_slug":"gh/parity/app","token":PROVIDER_TOKEN}),
            "trigger" => json!({"base_url":self.base,"project_ref":"parity","env":"prod","token":PROVIDER_TOKEN}),
            "webhook" => json!({"url":format!("{}/webhook", self.base),"token":PROVIDER_TOKEN}),
            _ => panic!("unsupported fixture kind"),
        }
    }
    fn assert_healthy(&self) {
        assert!(!self.task.is_finished(), "local provider fixture stopped");
        assert!(self.remote.lock().unwrap().unexpected.is_empty(), "adapter made an unexpected local provider request");
    }
}

struct Secret { key: String, value: String, path: String, tags: String, kind: String, encrypted_metadata: bool }
impl Secret {
    fn new(key: &str, value: &str) -> Self { Self { key:key.into(), value:value.into(), path:"/".into(), tags:String::new(), kind:"secret".into(), encrypted_metadata:false } }
    fn metadata(mut self, path: &str, tags: &str, kind: &str) -> Self {
        self.path = path.into(); self.tags = tags.into(); self.kind = kind.into(); self.encrypted_metadata = true; self
    }
}

#[derive(Default)]
struct Protocol { polls: Vec<Value>, results: Vec<Value>, acknowledgements: Vec<u16> }
struct Fixture {
    child: Child, dir: PathBuf, base: String, relay: String, client: reqwest::Client,
    relay_task: tokio::task::JoinHandle<()>, protocol: Arc<Mutex<Protocol>>, keypair: oc::Keypair,
    environment_key: [u8;32], ciphertexts: Vec<Value>, sensitive: Vec<String>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.relay_task.abort(); let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Fixture {
    async fn start(kind: &str, config: &Value, secrets: &[Secret], previous: &[(&str, &str)], job_kind: &str, context: &str) -> Self {
        let dir = std::env::temp_dir().join(oc::random_token("openwarp-runner-parity"));
        std::fs::create_dir(&dir).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{address}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        clean_env(&mut command);
        let child = command.env("DATABASE_URL", format!("sqlite://{}", dir.join("test.db").display())).env("ADDR", address.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn private app server");
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(5)).build().unwrap();
        let protocol = Arc::new(Mutex::new(Protocol::default()));
        let sink = protocol.clone(); let upstream = base.clone(); let relay_client = client.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = format!("http://{}", listener.local_addr().unwrap());
        // Observe the public protocol without supplying fields the real job endpoint omitted.
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); let upstream = upstream.clone(); let client = relay_client.clone(); async move {
                let (parts, body) = request.into_parts(); let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
                let path = parts.uri.path();
                if parts.method == Method::POST { sink.lock().unwrap().results.push(serde_json::from_slice(&bytes).unwrap()); }
                let mut request = client.request(parts.method.clone(), format!("{upstream}{path}"));
                for name in ["authorization", "content-type"] { if let Some(value) = parts.headers.get(name) { request = request.header(name, value); } }
                let response = request.body(bytes).send().await.expect("forward runner request to private server");
                let status = response.status(); let bytes = response.bytes().await.unwrap();
                if parts.method == Method::GET { sink.lock().unwrap().polls.push(serde_json::from_slice(&bytes).unwrap()); }
                else { sink.lock().unwrap().acknowledgements.push(status.as_u16()); }
                Response::builder().status(status).header("content-type", "application/json").body(Body::from(bytes)).unwrap()
            }
        });
        let relay_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let keypair = oc::Keypair::generate(); let environment_key = oc::random_key();
        let mut fixture = Self { child, dir, base, relay, client, relay_task, protocol, keypair, environment_key, ciphertexts:Vec::new(), sensitive:Vec::new() };
        let mut healthy = false;
        for _ in 0..200 {
            if fixture.client.get(format!("{}/health", fixture.base)).send().await.is_ok_and(|r| r.status().is_success()) { healthy = true; break; }
            assert!(fixture.child.try_wait().unwrap().is_none(), "private app server exited during startup");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(healthy, "private app server did not become healthy");
        let db = fixture.db();
        db.execute("INSERT INTO orgs(id,name,created_at) VALUES('parity-org','Runner parity',1)", []).unwrap();
        db.execute("INSERT INTO apps(id,org_id,name,created_at) VALUES('parity-app','parity-org','Runner parity',1)", []).unwrap();
        db.execute("INSERT INTO runners(id,org_id,name,pubkey,token_hash,created_at) VALUES('parity-runner','parity-org','Runner parity',?,?,1)", params![fixture.keypair.public, oc::hash_token(RUNNER_TOKEN)]).unwrap();
        db.execute("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,runner_id,created_at) VALUES('parity-env','parity-app','Production','','delegated','parity-runner',1)", []).unwrap();
        let wrapped_key = oc::encrypt_to(&fixture.keypair.public, &fixture.environment_key).unwrap();
        db.execute("INSERT INTO runner_env_keys(runner_id,env_id,wrapped_key) VALUES('parity-runner','parity-env',?)", [wrapped_key]).unwrap();
        let envelope = json!({"context":context,"config":config});
        let sealed = oc::encrypt_to(&fixture.keypair.public, envelope.to_string().as_bytes()).unwrap();
        db.execute("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES('parity-integration','parity-env',?,'Runner parity',?,1)", params![kind, format!("owrunner:parity-runner:{sealed}")]).unwrap();
        for (index, secret) in secrets.iter().enumerate() {
            let key_enc = oc::encrypt_symmetric(&fixture.environment_key, secret.key.as_bytes());
            let value_enc = oc::encrypt_symmetric(&fixture.environment_key, secret.value.as_bytes());
            let path_enc = if secret.encrypted_metadata { oc::encrypt_symmetric(&fixture.environment_key, secret.path.as_bytes()) } else { String::new() };
            let tags_enc = if secret.encrypted_metadata { oc::encrypt_symmetric(&fixture.environment_key, secret.tags.as_bytes()) } else { String::new() };
            let path = if secret.encrypted_metadata { "" } else { &secret.path };
            let tags = if secret.encrypted_metadata { "" } else { &secret.tags };
            db.execute("INSERT INTO secrets(id,env_id,path,path_enc,tags,tags_enc,key_enc,key_hash,key_index,value_enc,secret_type,e2e,updated_at) VALUES(?,'parity-env',?,?,?,?,?,?,?,?,?,1,1)",
                params![format!("parity-secret-{index}"), path, path_enc, tags, tags_enc, key_enc, oc::hash_token(&secret.key), oc::hash_token(&secret.key), value_enc, secret.kind]).unwrap();
            fixture.ciphertexts.push(json!({"key_enc":key_enc,"value_enc":value_enc,"path_enc":path_enc,"tags_enc":tags_enc}));
            fixture.sensitive.push(secret.value.clone());
        }
        for (name, hash) in previous { db.execute("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES('parity-integration',?,?)", params![name, hash]).unwrap(); }
        db.execute("INSERT INTO sync_jobs(id,env_id,integration_id,runner_id,kind,created_at) VALUES('parity-job','parity-env','parity-integration','parity-runner',?,1)", [job_kind]).unwrap();
        fixture.sensitive.extend([PROVIDER_TOKEN.into(), AWS_SECRET.into(), OLD_VALUE.into(), UNRELATED_VALUE.into(), fixture.keypair.secret_b64(), oc::b64(&fixture.environment_key)]);
        fixture
    }
    fn db(&self) -> Connection {
        let db = Connection::open(self.dir.join("test.db")).unwrap(); db.busy_timeout(Duration::from_secs(5)).unwrap(); db
    }
    fn ownership(&self) -> BTreeMap<String, String> {
        let db = self.db(); let mut stmt = db.prepare("SELECT remote_name,value_hash FROM integration_sync_state WHERE integration_id='parity-integration' ORDER BY remote_name").unwrap();
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap();
        rows
    }
    async fn run(&self) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-runner")); clean_env(&mut command);
        command.env("OPENWARP_URL", &self.relay).env("OPENWARP_RUNNER_TOKEN", RUNNER_TOKEN).env("OPENWARP_RUNNER_KEY", self.keypair.secret_b64()).env("OPENWARP_RUNNER_ONCE", "1")
            .stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut command = tokio::process::Command::from(command); command.kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(15), command.output()).await.expect("runner must finish its single local poll").expect("spawn actual openwarp-runner binary");
        assert!(output.status.success(), "runner process did not exit successfully");
        assert!(!self.relay_task.is_finished(), "runner protocol relay stopped");
        let protocol = self.protocol.lock().unwrap();
        assert_eq!(protocol.polls.len(), 1, "runner must poll once");
        assert_eq!(protocol.results.len(), 1, "runner must report the claimed job");
        assert_eq!(protocol.acknowledgements, vec![200], "real server must accept the runner's fenced result");
        let poll = &protocol.polls[0]; let result = &protocol.results[0];
        let jobs = poll["jobs"].as_array().expect("job endpoint must return jobs"); assert_eq!(jobs.len(), 1);
        assert_eq!(result["claim"], jobs[0]["claim"], "result must return the actual claim fencing token");
        let logs = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        for sensitive in &self.sensitive {
            assert!(!poll.to_string().contains(sensitive), "job endpoint exposed plaintext or runner key material");
            assert!(!result.to_string().contains(sensitive), "runner result exposed secret values, credentials or key material");
            assert!(!logs.contains(sensitive), "runner logged secret values, credentials or key material");
        }
        let (status, detail): (String, String) = self.db().query_row("SELECT status,detail FROM sync_jobs WHERE id='parity-job'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(status, if result["ok"] == true { "done" } else { "failed" });
        assert_eq!(detail, result["detail"].as_str().unwrap());
        result.clone()
    }
    fn assert_managed(&self, result: &Value, name: &str, value: &str) {
        assert_eq!(result["ok"], true, "managed runner sync must succeed: {}", result["detail"]);
        assert_eq!(result["managed"], json!([{"name":name,"value_hash":oc::hash_token(value)}]), "managed name and hash must describe the value actually sent");
        assert_eq!(self.ownership(), BTreeMap::from([(name.into(), oc::hash_token(value))]));
    }
}

const CONTEXT: &str = "ow-integration|parity-env|parity-integration";

#[tokio::test]
async fn aws_managed_runner_executes_and_reports_transformed_name_and_value_hash() {
    let provider = Provider::start(&[("APP_api_key_v1", OLD_VALUE)]).await;
    let mut config = provider.config("aws_secrets_manager"); config["prefix"] = json!("APP_"); config["suffix"] = json!("_v1"); config["case"] = json!("lower");
    let fixture = Fixture::start("aws_secrets_manager", &config, &[Secret::new("API_KEY", VALUE)], &[], "sync", CONTEXT).await;
    let result = fixture.run().await; provider.assert_healthy();
    fixture.assert_managed(&result, "APP_api_key_v1", VALUE);
    let remote = provider.remote.lock().unwrap();
    assert_eq!(remote.values, BTreeMap::from([("APP_api_key_v1".into(), VALUE.into())]));
    assert!(remote.requests.iter().any(|r| r.headers.get("x-amz-target").is_some_and(|v| v == "secretsmanager.PutSecretValue")), "actual AWS managed adapter must write the value");
}

#[tokio::test]
async fn circleci_managed_runner_preserves_unrelated_remote_names_and_prunes_only_previous_ownership() {
    let provider = Provider::start(&[("APP_OLD", OLD_VALUE), ("UNRELATED", UNRELATED_VALUE)]).await;
    let mut config = provider.config("circleci"); config["prefix"] = json!("APP_"); config["mode"] = json!("mirror");
    let fixture = Fixture::start("circleci", &config, &[Secret::new("API_KEY", VALUE)], &[("APP_OLD", "old-hash")], "sync", CONTEXT).await;
    let result = fixture.run().await; provider.assert_healthy(); fixture.assert_managed(&result, "APP_API_KEY", VALUE);
    let remote = provider.remote.lock().unwrap();
    assert_eq!(remote.values, BTreeMap::from([("APP_API_KEY".into(), VALUE.into()), ("UNRELATED".into(), UNRELATED_VALUE.into())]));
    assert!(remote.requests.iter().any(|r| r.method == Method::POST && r.headers.get("circle-token").is_some_and(|v| v == PROVIDER_TOKEN)), "second managed adapter must authenticate and write");
}

#[tokio::test]
async fn delegated_encrypted_paths_and_tags_select_one_secret_and_apply_naming_once() {
    let provider = Provider::start(&[("PRE_SELECTED_v1", OLD_VALUE), ("PRE_REMOVED_v1", OLD_VALUE), ("UNRELATED", UNRELATED_VALUE)]).await;
    let mut config = provider.config("aws_secrets_manager");
    config["paths"] = json!(["/selected"]); config["include_subfolders"] = json!(false); config["mode"] = json!("mirror");
    config["prefix"] = json!("PRE_"); config["suffix"] = json!("_v1"); config["tags"] = json!({"owner":"static-owner","application":"parity"});
    let secrets = [
        Secret::new("SELECTED", VALUE).metadata("/selected", "owner=metadata-owner,team=runtime", "config"),
        Secret::new("OTHER", "disposable-excluded-other-value").metadata("/other", "team=excluded", "secret"),
        Secret::new("NESTED", "disposable-excluded-nested-value").metadata("/selected/nested", "team=excluded", "secret"),
        Secret::new("SEALED", "disposable-sealed-value").metadata("/selected", "team=excluded", "sealed"),
    ];
    let fixture = Fixture::start("aws_secrets_manager", &config, &secrets, &[("PRE_REMOVED_v1", "old-hash")], "sync", CONTEXT).await;
    let result = fixture.run().await; provider.assert_healthy();
    {
        let protocol = fixture.protocol.lock().unwrap(); let poll = protocol.polls[0].to_string();
        assert!(poll.contains(fixture.ciphertexts[0]["path_enc"].as_str().unwrap()), "runner jobs must retain client-encrypted path metadata");
        assert!(poll.contains(fixture.ciphertexts[0]["tags_enc"].as_str().unwrap()), "runner jobs must retain client-encrypted tag metadata");
        assert!(!poll.contains(fixture.ciphertexts[3]["value_enc"].as_str().unwrap()), "sealed secret ciphertext must not enter runner jobs");
    }
    fixture.assert_managed(&result, "PRE_SELECTED_v1", VALUE);
    let remote = provider.remote.lock().unwrap();
    assert_eq!(remote.values, BTreeMap::from([("PRE_SELECTED_v1".into(), VALUE.into()), ("UNRELATED".into(), UNRELATED_VALUE.into())]));
    assert_eq!(remote.tags.get("PRE_SELECTED_v1"), Some(&BTreeMap::from([("owner".into(), "static-owner".into()), ("team".into(), "runtime".into()), ("application".into(), "parity".into())])));
}

#[tokio::test]
async fn delegated_dry_run_neither_writes_remote_values_nor_replaces_persisted_ownership() {
    let provider = Provider::start(&[("OLD", OLD_VALUE), ("UNRELATED", UNRELATED_VALUE)]).await;
    let mut config = provider.config("trigger"); config["mode"] = json!("mirror"); config["dry_run"] = json!(true);
    let fixture = Fixture::start("trigger", &config, &[Secret::new("NEW", VALUE)], &[("OLD", "previous-value-hash")], "sync", CONTEXT).await;
    let before = fixture.ownership(); let result = fixture.run().await; provider.assert_healthy();
    assert_eq!(result["ok"], true, "dry-run must execute successfully: {}", result["detail"]);
    {
        let remote = provider.remote.lock().unwrap();
        assert!(!remote.requests.is_empty(), "dry-run must inspect the local provider, not silently skip the job");
        assert!(remote.requests.iter().all(|r| r.method == Method::GET), "dry-run must not send provider mutations");
        assert_eq!(remote.values, BTreeMap::from([("OLD".into(), OLD_VALUE.into()), ("UNRELATED".into(), UNRELATED_VALUE.into())]));
    }
    assert_eq!(fixture.ownership(), before, "the real result endpoint must preserve pre-dry-run remote ownership and hashes");
}

#[tokio::test]
async fn delegated_initial_import_is_rejected_before_any_provider_effect() {
    for initial in ["import_local", "import_remote"] {
        let provider = Provider::start(&[("REMOTE_ONLY", OLD_VALUE)]).await;
        let mut config = provider.config("trigger"); config["initial_sync"] = json!(initial);
        let fixture = Fixture::start("trigger", &config, &[Secret::new("LOCAL", VALUE)], &[], "sync", CONTEXT).await;
        let result = fixture.run().await; provider.assert_healthy();
        assert_eq!(result["ok"], false, "unsupported delegated {initial} must not silently execute an overwrite");
        assert!(!result["detail"].as_str().unwrap().trim().is_empty(), "unsupported import must explain its rejection");
        let remote = provider.remote.lock().unwrap();
        assert!(remote.requests.is_empty(), "unsupported delegated import must be rejected before provider execution");
        assert_eq!(remote.values, BTreeMap::from([("REMOTE_ONLY".into(), OLD_VALUE.into())]));
        assert!(fixture.ownership().is_empty());
    }
}

#[tokio::test]
async fn nonmanaged_webhook_still_syncs_without_claiming_remote_ownership() {
    let provider = Provider::start(&[]).await;
    let mut config = provider.config("webhook"); config["prefix"] = json!("APP_");
    let fixture = Fixture::start("webhook", &config, &[Secret::new("API_KEY", VALUE)], &[], "sync", CONTEXT).await;
    let result = fixture.run().await; provider.assert_healthy();
    assert_eq!(result["ok"], true, "legacy nonmanaged sync must remain available: {}", result["detail"]);
    assert!(result["managed"].as_array().unwrap().is_empty()); assert!(fixture.ownership().is_empty());
    let remote = provider.remote.lock().unwrap(); assert_eq!(remote.requests.len(), 1);
    assert_eq!(remote.requests[0].path, "/webhook"); assert_eq!(remote.requests[0].method, Method::POST);
    assert_eq!(remote.requests[0].body["secrets"], json!({"APP_API_KEY":VALUE}));
}

#[tokio::test]
async fn runner_connection_test_does_not_sync_or_change_existing_ownership() {
    let provider = Provider::start(&[("OLD", OLD_VALUE)]).await;
    let fixture = Fixture::start("trigger", &provider.config("trigger"), &[Secret::new("NEW", VALUE)], &[("OLD", "previous-value-hash")], "test", CONTEXT).await;
    let before = fixture.ownership(); let result = fixture.run().await; provider.assert_healthy();
    assert_eq!(result["ok"], true, "runner connection test must remain separate from sync: {}", result["detail"]);
    assert_eq!(fixture.ownership(), before);
    let remote = provider.remote.lock().unwrap(); assert_eq!(remote.requests.len(), 1); assert_eq!(remote.requests[0].method, Method::GET);
    assert_eq!(remote.values, BTreeMap::from([("OLD".into(), OLD_VALUE.into())]));
}

#[tokio::test]
async fn copied_runner_config_context_is_rejected_without_provider_access() {
    let provider = Provider::start(&[]).await;
    let fixture = Fixture::start("trigger", &provider.config("trigger"), &[Secret::new("NEW", VALUE)], &[], "sync", "ow-integration|another-env|another-integration").await;
    let result = fixture.run().await; provider.assert_healthy();
    assert_eq!(result["ok"], false, "sealed config for another integration must remain unusable");
    assert!(provider.remote.lock().unwrap().requests.is_empty()); assert!(fixture.ownership().is_empty());
}
