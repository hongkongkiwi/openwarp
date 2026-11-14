use axum::{body::to_bytes, http::{HeaderMap, Method, StatusCode}, Json, Router};
use base64ct::{Base64, Encoding};
use openwarp_server::integrations::sync;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::future::Future;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CHILD_CASE: &str = "OPENWARP_TEST_INTEGRATION_WRITE_CASE";
const SECRET_KEY: &str = "WRITE_RESULT_TEST";
const SECRET_VALUE: &str = "disposable-write-value";
const PROVIDER_TOKEN: &str = "disposable-write-provider-token";

// Keep the public sync transport in development without changing the test runner's environment.
fn isolated(name: &str, case: impl Future<Output = ()>) {
    if std::env::var(CHILD_CASE).as_deref() == Ok(name) {
        assert_eq!(std::env::var("OPENWARP_ENV").as_deref(), Ok("development"));
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(case);
        return;
    }
    let mut command = Command::new(std::env::current_exe().expect("locate integration test executable"));
    command.args(["--exact", name, "--nocapture", "--test-threads=1"]);
    for (key, _) in std::env::vars_os() {
        let text = key.to_string_lossy();
        if text.starts_with("OPENWARP_") || text.to_ascii_uppercase().ends_with("_PROXY") { command.env_remove(key); }
    }
    let output = command.env("OPENWARP_ENV", "development").env(CHILD_CASE, name)
        .output().expect("run isolated development sync case");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("running 1 test"), "isolated case {name} did not execute exactly one test\n{stdout}");
    assert!(output.status.success(), "isolated case {name} failed ({})\n{stdout}\n{}", output.status,
        String::from_utf8_lossy(&output.stderr));
}

#[derive(Clone)]
struct Recorded { method: Method, uri: String, headers: HeaderMap, body: Value }
struct State { replies: VecDeque<StatusCode>, requests: Vec<Recorded> }
struct Fixture { base: String, state: Arc<Mutex<State>>, task: tokio::task::JoinHandle<()> }
impl Drop for Fixture { fn drop(&mut self) { self.task.abort(); } }
impl Fixture {
    async fn start(statuses: &[u16]) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind local provider fixture");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            replies: statuses.iter().map(|status| StatusCode::from_u16(*status).unwrap()).collect(), requests: Vec::new(),
        }));
        let sink = state.clone();
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, 1024 * 1024).await.expect("read provider request body");
                let body = serde_json::from_slice(&body).expect("provider request must be JSON");
                let mut state = sink.lock().unwrap();
                state.requests.push(Recorded { method: parts.method, uri: parts.uri.to_string(), headers: parts.headers, body });
                let status = state.replies.pop_front().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                // Provider response bodies remain an accepted error diagnostic, so do not echo submitted secrets.
                (status, Json(json!({"message":"disposable provider response"})))
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve local provider fixture"); });
        Self { base, state, task }
    }
    async fn sync(&self, kind: &str) -> Result<String, String> {
        let config = match kind {
            "gitlab" => json!({"base_url":format!("{}/api/v4", self.base),"project_id":"123","token":PROVIDER_TOKEN}),
            "kubernetes" => json!({"api_server":self.base,"namespace":"write-results","secret_name":"app-secrets","token":PROVIDER_TOKEN}),
            _ => panic!("unsupported fixture provider"),
        };
        tokio::time::timeout(Duration::from_secs(5), sync(kind, &config, &[(SECRET_KEY.into(), SECRET_VALUE.into())]))
            .await.expect("local provider sync must finish")
    }
    fn requests(&self, expected: usize) -> Vec<Recorded> {
        assert!(!self.task.is_finished(), "provider fixture stopped unexpectedly");
        let state = self.state.lock().unwrap();
        assert_eq!(state.requests.len(), expected, "unexpected provider request count or fallback");
        assert!(state.replies.is_empty(), "sync did not consume its expected provider responses");
        state.requests.clone()
    }
}

fn assert_gitlab_requests(fixture: &Fixture, fallback: bool) {
    let requests = fixture.requests(if fallback { 2 } else { 1 });
    let create = &requests[0];
    assert_eq!(create.method, Method::POST); assert_eq!(create.uri, "/api/v4/projects/123/variables");
    assert_eq!(create.body, json!({"key":SECRET_KEY,"value":SECRET_VALUE,"masked":true}));
    if fallback {
        let update = &requests[1];
        assert_eq!(update.method, Method::PUT); assert_eq!(update.uri, format!("/api/v4/projects/123/variables/{SECRET_KEY}"));
        assert_eq!(update.body, json!({"value":SECRET_VALUE}));
    }
    for request in &requests {
        assert_eq!(request.headers.get("private-token").expect("GitLab private token"), PROVIDER_TOKEN);
        assert!(request.headers.get("authorization").is_none(), "GitLab must use its private-token header");
        assert_eq!(request.headers.get("content-type").unwrap(), "application/json");
    }
}

fn assert_kubernetes_requests(fixture: &Fixture, fallback: bool) {
    let requests = fixture.requests(if fallback { 2 } else { 1 });
    assert_eq!(requests[0].method, Method::PUT);
    assert_eq!(requests[0].uri, "/api/v1/namespaces/write-results/secrets/app-secrets");
    if fallback {
        assert_eq!(requests[1].method, Method::POST);
        assert_eq!(requests[1].uri, "/api/v1/namespaces/write-results/secrets");
    }
    let body = json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":"app-secrets","namespace":"write-results"},
        "type":"Opaque","data":{SECRET_KEY:Base64::encode_string(SECRET_VALUE.as_bytes())}});
    for request in &requests {
        assert_eq!(request.body, body);
        assert_eq!(request.headers.get("authorization").expect("Kubernetes bearer token"), &format!("Bearer {PROVIDER_TOKEN}"));
        assert!(request.headers.get("private-token").is_none(), "Kubernetes must use bearer authentication");
        assert_eq!(request.headers.get("content-type").unwrap(), "application/json");
    }
}

fn assert_safe_error(error: &str) {
    assert!(!error.trim().is_empty(), "provider rejection must explain failure");
    for sensitive in [PROVIDER_TOKEN.to_string(), SECRET_VALUE.to_string(), Base64::encode_string(SECRET_VALUE.as_bytes())] {
        assert!(!error.contains(&sensitive), "sync error exposed submitted credentials or secret material");
    }
}

#[test]
fn gitlab_post_201_succeeds_without_fallback() {
    isolated("gitlab_post_201_succeeds_without_fallback", async {
        let fixture = Fixture::start(&[201]).await;
        let result = fixture.sync("gitlab").await;
        assert_gitlab_requests(&fixture, false);
        assert!(result.is_ok(), "GitLab 201 must succeed: {result:?}");
    });
}

#[test]
fn gitlab_400_falls_back_to_successful_put() {
    isolated("gitlab_400_falls_back_to_successful_put", async {
        let fixture = Fixture::start(&[400, 200]).await;
        let result = fixture.sync("gitlab").await;
        assert_gitlab_requests(&fixture, true);
        assert!(result.is_ok(), "successful GitLab update must succeed: {result:?}");
    });
}

#[test]
fn gitlab_400_fallback_put_failure_is_rejected() {
    isolated("gitlab_400_fallback_put_failure_is_rejected", async {
        let fixture = Fixture::start(&[400, 403]).await;
        let result = fixture.sync("gitlab").await;
        assert_gitlab_requests(&fixture, true);
        assert_safe_error(&result.expect_err("GitLab fallback PUT rejection must fail sync"));
    });
}

#[test]
fn gitlab_non_400_failures_are_rejected_without_fallback() {
    isolated("gitlab_non_400_failures_are_rejected_without_fallback", async {
        let mut accepted = Vec::new();
        for status in [401, 403, 429, 500] {
            let fixture = Fixture::start(&[status]).await;
            let result = fixture.sync("gitlab").await;
            assert_gitlab_requests(&fixture, false);
            match result { Err(error) => assert_safe_error(&error), Ok(_) => accepted.push(status) }
        }
        assert!(accepted.is_empty(), "GitLab POST rejection incorrectly returned success for HTTP {accepted:?}");
    });
}

#[test]
fn kubernetes_put_200_succeeds_without_fallback() {
    isolated("kubernetes_put_200_succeeds_without_fallback", async {
        let fixture = Fixture::start(&[200]).await;
        let result = fixture.sync("kubernetes").await;
        assert_kubernetes_requests(&fixture, false);
        assert!(result.is_ok(), "Kubernetes PUT 200 must succeed: {result:?}");
    });
}

#[test]
fn kubernetes_404_falls_back_to_successful_post() {
    isolated("kubernetes_404_falls_back_to_successful_post", async {
        let fixture = Fixture::start(&[404, 201]).await;
        let result = fixture.sync("kubernetes").await;
        assert_kubernetes_requests(&fixture, true);
        assert!(result.is_ok(), "successful Kubernetes create must succeed: {result:?}");
    });
}

#[test]
fn kubernetes_404_fallback_post_failure_is_rejected() {
    isolated("kubernetes_404_fallback_post_failure_is_rejected", async {
        let fixture = Fixture::start(&[404, 403]).await;
        let result = fixture.sync("kubernetes").await;
        assert_kubernetes_requests(&fixture, true);
        assert_safe_error(&result.expect_err("Kubernetes fallback POST rejection must fail sync"));
    });
}

#[test]
fn kubernetes_non_404_failures_are_rejected_without_fallback() {
    isolated("kubernetes_non_404_failures_are_rejected_without_fallback", async {
        let mut accepted = Vec::new();
        for status in [403, 429, 500] {
            let fixture = Fixture::start(&[status]).await;
            let result = fixture.sync("kubernetes").await;
            assert_kubernetes_requests(&fixture, false);
            match result { Err(error) => assert_safe_error(&error), Ok(_) => accepted.push(status) }
        }
        assert!(accepted.is_empty(), "Kubernetes PUT rejection incorrectly returned success for HTTP {accepted:?}");
    });
}
