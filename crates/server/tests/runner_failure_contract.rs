use axum::{body::{to_bytes, Body}, http::{Method, StatusCode}, response::Response, Json, Router};
use openwarp_crypto as oc;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RUNNER_TOKEN: &str = "disposable-failure-runner-token";
const PROVIDER_TOKEN: &str = "disposable-failure-provider-token";
const VALUE_A: &str = "disposable-failure-secret-a";
const VALUE_B: &str = "disposable-failure-secret-b";
const OLD_VALUE: &str = "disposable-failure-old-value";
const UNRELATED_VALUE: &str = "disposable-failure-unrelated-value";
const ROOT: &str = "/project/gh/failure/app/envvar";

fn clean_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let text = key.to_string_lossy();
        if text.starts_with("OPENWARP_") || text.to_ascii_uppercase().ends_with("_PROXY") || text == "DATABASE_URL" || text == "REDIS_URL" { command.env_remove(key); }
    }
    command.env("OPENWARP_ENV", "development").env("TOKIO_WORKER_THREADS", "1");
}

struct Remote {
    values: BTreeMap<String, String>, writes: Vec<String>, deleted: Vec<String>, fail_name: Option<String>,
    echo_failure: bool, rejected: usize, authenticated: usize, unexpected: Vec<String>,
}
struct Provider { base: String, remote: Arc<Mutex<Remote>>, task: tokio::task::JoinHandle<()> }
impl Drop for Provider { fn drop(&mut self) { self.task.abort(); } }
impl Provider {
    async fn start(fail_name: &str, echo_failure: bool) -> Self {
        let remote = Arc::new(Mutex::new(Remote {
            values: BTreeMap::from([("APP_OLD".into(), OLD_VALUE.into()), ("UNRELATED".into(), UNRELATED_VALUE.into())]),
            writes: Vec::new(), deleted: Vec::new(), fail_name: Some(fail_name.into()), echo_failure,
            rejected: 0, authenticated: 0, unexpected: Vec::new(),
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let sink = remote.clone(); let provider_base = base.clone();
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); let base = provider_base.clone(); async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
                let body: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
                let token = parts.headers.get("circle-token").and_then(|v| v.to_str().ok()).unwrap_or("");
                let path = parts.uri.path(); let mut remote = sink.lock().unwrap();
                if token != PROVIDER_TOKEN { remote.unexpected.push("missing CircleCI credential".into()); return (StatusCode::UNAUTHORIZED, Json(json!({"error":"fixture authentication failed"}))); }
                remote.authenticated += 1;
                let reply = match parts.method {
                    Method::GET if path == ROOT => json!({"items":remote.values.keys().map(|name| json!({"name":name,"value":"********"})).collect::<Vec<_>>()}),
                    Method::POST if path == ROOT => {
                        let name = body["name"].as_str().unwrap(); let value = body["value"].as_str().unwrap();
                        remote.writes.push(name.into());
                        if remote.fail_name.as_deref() == Some(name) {
                            remote.rejected += 1;
                            let error = if remote.echo_failure { format!("rejected value={value} credential={token} url={base}{path}") } else { "fixture rejected write".into() };
                            return (StatusCode::BAD_REQUEST, Json(json!({"error":error})));
                        }
                        remote.values.insert(name.into(), value.into()); json!({})
                    }
                    Method::DELETE if path.starts_with(&format!("{ROOT}/")) => {
                        let name = path.rsplit('/').next().unwrap(); remote.deleted.push(name.into()); remote.values.remove(name); json!({})
                    }
                    _ => { remote.unexpected.push(format!("{} {path}", parts.method)); return (StatusCode::NOT_FOUND, Json(json!({"error":"unexpected fixture operation"}))); }
                };
                (StatusCode::OK, Json(reply))
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { base, remote, task }
    }
    fn config(&self) -> Value { json!({"base_url":self.base,"project_slug":"gh/failure/app","token":PROVIDER_TOKEN,"prefix":"APP_","mode":"mirror"}) }
    fn assert_healthy(&self) {
        assert!(!self.task.is_finished(), "local provider fixture stopped");
        let remote = self.remote.lock().unwrap();
        assert!(remote.unexpected.is_empty(), "adapter made an unexpected local provider request");
        assert!(remote.authenticated > 0, "actual adapter must authenticate to the local provider");
    }
}

#[derive(Default)]
struct Protocol { polls: Vec<Value>, results: Vec<Value>, acknowledgements: Vec<u16> }
struct Fixture {
    child: Child, dir: PathBuf, relay: String, relay_task: tokio::task::JoinHandle<()>,
    protocol: Arc<Mutex<Protocol>>, keypair: oc::Keypair,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.relay_task.abort(); let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir);
    }
}
struct Run { result: Value, status: String, detail: String, audit: Vec<(String, String)>, logs: String }
impl Fixture {
    async fn start(config: &Value, secrets: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(oc::random_token("openwarp-runner-failure")); std::fs::create_dir(&dir).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let address = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{address}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server")); clean_env(&mut command);
        let stdout = std::fs::File::create(dir.join("server.stdout")).unwrap(); let stderr = std::fs::File::create(dir.join("server.stderr")).unwrap();
        let child = command.env("DATABASE_URL", format!("sqlite://{}", dir.join("test.db").display())).env("ADDR", address.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).stdout(stdout).stderr(stderr).spawn().expect("spawn private app server");
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(5)).build().unwrap();
        let protocol = Arc::new(Mutex::new(Protocol::default()));
        let sink = protocol.clone(); let upstream = base.clone(); let relay_client = client.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let relay = format!("http://{}", listener.local_addr().unwrap());
        // Forward the real job and result unchanged; only the runner can open the ciphertext.
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); let upstream = upstream.clone(); let client = relay_client.clone(); async move {
                let (parts, body) = request.into_parts(); let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
                if parts.method == Method::POST { sink.lock().unwrap().results.push(serde_json::from_slice(&bytes).unwrap()); }
                let mut request = client.request(parts.method.clone(), format!("{upstream}{}", parts.uri.path()));
                for name in ["authorization", "content-type"] { if let Some(value) = parts.headers.get(name) { request = request.header(name, value); } }
                let response = request.body(bytes).send().await.expect("forward actual runner request");
                let status = response.status(); let bytes = response.bytes().await.unwrap();
                if parts.method == Method::GET { sink.lock().unwrap().polls.push(serde_json::from_slice(&bytes).unwrap()); }
                else { sink.lock().unwrap().acknowledgements.push(status.as_u16()); }
                Response::builder().status(status).header("content-type", "application/json").body(Body::from(bytes)).unwrap()
            }
        });
        let relay_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let keypair = oc::Keypair::generate(); let environment_key = oc::random_key();
        let mut fixture = Self { child, dir, relay, relay_task, protocol, keypair };
        let mut healthy = false;
        for _ in 0..200 {
            if client.get(format!("{base}/health")).send().await.is_ok_and(|r| r.status().is_success()) { healthy = true; break; }
            assert!(fixture.child.try_wait().unwrap().is_none(), "private app server exited during startup");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(healthy, "private app server did not become healthy");
        let db = fixture.db();
        db.execute("INSERT INTO orgs(id,name,created_at) VALUES('failure-org','Runner failure contract',1)", []).unwrap();
        db.execute("INSERT INTO apps(id,org_id,name,created_at) VALUES('failure-app','failure-org','Runner failure contract',1)", []).unwrap();
        db.execute("INSERT INTO runners(id,org_id,name,pubkey,token_hash,created_at) VALUES('failure-runner','failure-org','Runner failure contract',?,?,1)", params![fixture.keypair.public, oc::hash_token(RUNNER_TOKEN)]).unwrap();
        db.execute("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,runner_id,created_at) VALUES('failure-env','failure-app','Production','','delegated','failure-runner',1)", []).unwrap();
        db.execute("INSERT INTO runner_env_keys(runner_id,env_id,wrapped_key) VALUES('failure-runner','failure-env',?)", [oc::encrypt_to(&fixture.keypair.public, &environment_key).unwrap()]).unwrap();
        let envelope = json!({"context":"ow-integration|failure-env|failure-integration","config":config});
        let sealed = oc::encrypt_to(&fixture.keypair.public, envelope.to_string().as_bytes()).unwrap();
        db.execute("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES('failure-integration','failure-env','circleci','Runner failure contract',?,1)", [format!("owrunner:failure-runner:{sealed}")]).unwrap();
        for (key, value) in secrets {
            db.execute("INSERT INTO secrets(id,env_id,path,key_enc,key_hash,key_index,value_enc,secret_type,e2e,updated_at) VALUES(?,'failure-env','/',?,?,?,?,'secret',1,1)",
                params![format!("failure-secret-{key}"), oc::encrypt_symmetric(&environment_key, key.as_bytes()), oc::hash_token(key), oc::hash_token(key), oc::encrypt_symmetric(&environment_key, value.as_bytes())]).unwrap();
        }
        db.execute("INSERT INTO integration_sync_state(integration_id,remote_name,value_hash) VALUES('failure-integration','APP_OLD',?)", [oc::hash_token(OLD_VALUE)]).unwrap();
        fixture.enqueue("failure-job-1"); fixture
    }
    fn db(&self) -> Connection { let db = Connection::open(self.dir.join("test.db")).unwrap(); db.busy_timeout(Duration::from_secs(5)).unwrap(); db }
    fn enqueue(&self, job: &str) {
        self.db().execute("INSERT INTO sync_jobs(id,env_id,integration_id,runner_id,kind,created_at) VALUES(?,'failure-env','failure-integration','failure-runner','sync',1)", [job]).unwrap();
    }
    fn ownership(&self) -> BTreeMap<String, String> {
        let db = self.db(); let mut statement = db.prepare("SELECT remote_name,value_hash FROM integration_sync_state WHERE integration_id='failure-integration'").unwrap();
        let rows = statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap();
        rows
    }
    async fn run(&self, job: &str) -> Run {
        let index = self.protocol.lock().unwrap().results.len();
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-runner")); clean_env(&mut command);
        command.env("OPENWARP_URL", &self.relay).env("OPENWARP_RUNNER_TOKEN", RUNNER_TOKEN).env("OPENWARP_RUNNER_KEY", self.keypair.secret_b64()).env("OPENWARP_RUNNER_ONCE", "1")
            .stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut command = tokio::process::Command::from(command); command.kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(15), command.output()).await.expect("runner must finish its single local poll").expect("spawn actual runner binary");
        assert!(output.status.success(), "runner process must finish reporting its job");
        assert!(!self.relay_task.is_finished(), "protocol relay stopped");
        let protocol = self.protocol.lock().unwrap();
        assert_eq!(protocol.polls.len(), index + 1, "runner must poll once per execution");
        assert_eq!(protocol.results.len(), index + 1, "runner must report the real claimed job");
        assert_eq!(protocol.acknowledgements[index], 200, "real server must accept the fenced result");
        let jobs = protocol.polls[index]["jobs"].as_array().unwrap(); assert_eq!(jobs.len(), 1); assert_eq!(jobs[0]["id"], job);
        let result = protocol.results[index].clone(); assert_eq!(result["claim"], jobs[0]["claim"]);
        let db = self.db();
        let (status, detail) = db.query_row("SELECT status,detail FROM sync_jobs WHERE id=?", [job], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        let mut statement = db.prepare("SELECT action,detail FROM audit WHERE env_id='failure-env'").unwrap();
        let audit = statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap();
        let logs = format!("{}{}{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr),
            std::fs::read_to_string(self.dir.join("server.stdout")).unwrap(), std::fs::read_to_string(self.dir.join("server.stderr")).unwrap());
        Run { result, status, detail, audit, logs }
    }
}

#[tokio::test]
async fn delegated_provider_rejection_never_returns_or_persists_plaintext_credentials_or_raw_url() {
    let provider = Provider::start("APP_A", true).await;
    let fixture = Fixture::start(&provider.config(), &[("A", VALUE_A)]).await;
    let run = fixture.run("failure-job-1").await; provider.assert_healthy();
    assert_eq!(provider.remote.lock().unwrap().rejected, 1, "actual adapter must encounter the provider's HTTP 400");
    assert_eq!(run.result["ok"], false); assert_eq!(run.status, "failed", "failure must remain observable");
    assert!(run.audit.iter().any(|(action, _)| action == "integration.sync_failed"), "provider failure must retain its audit event");
    let diagnostic = run.detail.to_ascii_lowercase();
    assert!(["provider", "http", "request", "reject", "fail", "sync"].iter().any(|category| diagnostic.contains(category)), "failed job must retain a safe error category");
    let payload = run.result.to_string(); let audit = serde_json::to_string(&run.audit).unwrap();
    let sensitive = [VALUE_A, PROVIDER_TOKEN, provider.base.as_str()];
    let leaks: Vec<&str> = [("sync_jobs.detail", run.detail.as_str()), ("audit", audit.as_str()), ("runner result", payload.as_str()), ("runner/server logs", run.logs.as_str())]
        .into_iter().filter_map(|(surface, text)| sensitive.iter().any(|value| text.contains(value)).then_some(surface)).collect();
    assert!(leaks.is_empty(), "provider rejection crossed the delegated plaintext boundary on surfaces: {leaks:?}");
}

#[tokio::test]
async fn delegated_partial_write_retains_candidate_ownership_so_next_mirror_prunes_it() {
    let provider = Provider::start("APP_B", false).await;
    let fixture = Fixture::start(&provider.config(), &[("A", VALUE_A), ("B", VALUE_B)]).await;
    let first = fixture.run("failure-job-1").await; provider.assert_healthy();
    assert_eq!(first.result["ok"], false); assert_eq!(first.status, "failed");
    {
        let remote = provider.remote.lock().unwrap();
        assert_eq!(remote.writes, ["APP_A", "APP_B"], "reproduce A acknowledged before B rejected");
        assert_eq!(remote.rejected, 1);
        assert_eq!(remote.values, BTreeMap::from([("APP_A".into(), VALUE_A.into()), ("APP_OLD".into(), OLD_VALUE.into()), ("UNRELATED".into(), UNRELATED_VALUE.into())]));
    }
    let failed_ownership = fixture.ownership();
    fixture.db().execute("UPDATE secrets SET deleted=1 WHERE id='failure-secret-A'", []).unwrap();
    provider.remote.lock().unwrap().fail_name = None;
    fixture.enqueue("failure-job-2");
    let second = fixture.run("failure-job-2").await; provider.assert_healthy();
    assert_eq!(second.result["ok"], true, "next real mirror must succeed"); assert_eq!(second.status, "done");
    let expected_candidates = BTreeMap::from([("APP_OLD".into(), oc::hash_token(OLD_VALUE)), ("APP_A".into(), oc::hash_token(VALUE_A)), ("APP_B".into(), oc::hash_token(VALUE_B))]);
    let remote = provider.remote.lock().unwrap();
    let candidates_retained = failed_ownership == expected_candidates;
    let partial_write_pruned = !remote.values.contains_key("APP_A") && remote.deleted.iter().any(|name| name == "APP_A");
    let unrelated_retained = remote.values.get("UNRELATED").is_some_and(|value| value == UNRELATED_VALUE) && !remote.deleted.iter().any(|name| name == "UNRELATED");
    assert!(candidates_retained && partial_write_pruned && unrelated_retained,
        "failed managed sync must merge previous and desired ownership with correct hashes for later mirror cleanup: candidates_retained={candidates_retained}, partial_write_pruned={partial_write_pruned}, unrelated_retained={unrelated_retained}");
    assert_eq!(remote.values, BTreeMap::from([("APP_B".into(), VALUE_B.into()), ("UNRELATED".into(), UNRELATED_VALUE.into())]));
    assert_eq!(fixture.ownership(), BTreeMap::from([("APP_B".into(), oc::hash_token(VALUE_B))]), "successful mirror must replace conservative ownership with the remaining desired name and hash");
}
