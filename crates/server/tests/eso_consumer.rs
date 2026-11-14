#![cfg(not(target_arch = "wasm32"))]

use axum::{extract::State, routing::post, Json, Router};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Inbox = Arc<Mutex<Vec<Value>>>;
struct Response { status: u16, body: Value }
struct Fixture {
    server: Option<Child>, bridge: Option<Child>, mail: tokio::task::JoinHandle<()>,
    dir: PathBuf, base: String, bridge_url: String, client: Client, inbox: Inbox,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for child in [&mut self.bridge, &mut self.server].into_iter().flatten() {
            let _ = child.kill(); let _ = child.wait();
        }
        self.mail.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn isolated_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    // No deployment configuration, mail provider credentials or proxy may escape into this fixture.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("OPENWARP_") || matches!(name.as_ref(), "DATABASE_URL" | "REDIS_URL" | "ADDR" | "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY" | "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy") {
            command.env_remove(key);
        }
    }
    command.env("TOKIO_WORKER_THREADS", "1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    command
}

async fn capture_mail(State(inbox): State<Inbox>, Json(body): Json<Value>) -> Json<Value> {
    inbox.lock().expect("private inbox lock").push(body); Json(json!({}))
}

impl Fixture {
    async fn start() -> Self {
        let binary = PathBuf::from(std::env::var_os("OPENWARP_ESO_BIN").expect("set OPENWARP_ESO_BIN to an explicitly built openwarp-eso binary"));
        assert!(binary.is_absolute() && binary.is_file(), "OPENWARP_ESO_BIN must name an existing absolute binary path");
        let server_socket = TcpListener::bind("127.0.0.1:0").expect("private server port");
        let bridge_socket = TcpListener::bind("127.0.0.1:0").expect("private bridge port");
        let server_addr = server_socket.local_addr().expect("server address");
        let bridge_addr = bridge_socket.local_addr().expect("bridge address");
        let mail_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("private mail port");
        let mail_addr = mail_socket.local_addr().expect("mail address");
        let dir = std::env::temp_dir().join(openwarp_crypto::random_token("openwarp-eso-consumer"));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
        builder.create(&dir).expect("create fresh private fixture directory");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().expect("local HTTP client");
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let mail_app = Router::new().route("/mail", post(capture_mail)).with_state(inbox.clone());
        let mail = tokio::spawn(async move { let _ = axum::serve(mail_socket, mail_app).await; });
        let mut s = Self { server: None, bridge: None, mail, dir, base: format!("http://{server_addr}"), bridge_url: format!("http://{bridge_addr}"), client, inbox };
        drop(server_socket);
        s.server = Some(isolated_command(Path::new(env!("CARGO_BIN_EXE_openwarp-server")))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", s.dir.display())).env("ADDR", server_addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &s.base).env("OPENWARP_EMAIL_PROVIDER", "webhook")
            .env("OPENWARP_EMAIL_WEBHOOK", format!("http://{mail_addr}/mail"))
            .spawn().unwrap_or_else(|_| panic!("spawn private openwarp-server")));
        Self::healthy(&s.client, s.server.as_mut().expect("server child"), &format!("{}/health", s.base)).await;
        drop(bridge_socket);
        s.bridge = Some(isolated_command(&binary).env("OPENWARP_URL", &s.base).env("OPENWARP_ESO_ADDR", bridge_addr.to_string())
            .spawn().unwrap_or_else(|_| panic!("spawn explicitly configured openwarp-eso")));
        Self::healthy(&s.client, s.bridge.as_mut().expect("bridge child"), &format!("{}/healthz", s.bridge_url)).await;
        s
    }

    async fn healthy(client: &Client, child: &mut Child, url: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(child.try_wait().expect("poll fixture child").is_none(), "fixture child exited before health readiness");
            if let Ok(response) = client.get(url).timeout(Duration::from_secs(1)).send().await {
                if response.status().as_u16() == 200 { return; }
            }
            assert!(Instant::now() < deadline, "fixture child health timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn raw(&self, method: Method, path: &str, token: Option<&str>, body: Option<&Value>, grant: Option<&str>) -> Response {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = token { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(body); }
        if let Some(grant) = grant { request = request.header("x-openwarp-step-up", grant); }
        response(request).await
    }

    async fn session(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Response {
        let result = self.raw(method.clone(), path, Some(token), body.as_ref(), None).await;
        if result.status != 428 { return result; }
        assert!(result.body["step_up_required"] == true && result.body["risk"] == "very_risky", "fixture action requires an emailed step-up challenge");
        assert!(result.body["totp_required"] == false, "fixture account has no configured TOTP");
        let before = self.inbox.lock().expect("private inbox lock").len();
        let started = good(self.raw(Method::POST, "/api/auth/step-up/start", Some(token), Some(&json!({"risk":"very_risky"})), None).await, "start fresh email proof");
        assert!(started["email_sent"] == true, "step-up must send a real local verification email");
        let text = self.mail_after(before, "Your verification code is ").await;
        let code = text.split_once("Your verification code is ").expect("emailed verification code").1
            .split(|c: char| !c.is_ascii_digit()).next().filter(|s| s.len() == 6).expect("six-digit email code");
        let verified = good(self.raw(Method::POST, "/api/auth/step-up/verify", Some(token), Some(&json!({"challenge":field(&started,"challenge"),"email_code":code})), None).await, "verify fresh email proof");
        self.raw(method, path, Some(token), body.as_ref(), Some(&field(&verified, "token"))).await
    }

    async fn mail_after(&self, before: usize, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let text = self.inbox.lock().expect("private inbox lock").iter().skip(before)
                .filter_map(|mail| mail["text"].as_str()).find(|text| text.contains(needle)).map(str::to_string);
            if let Some(text) = text { return text; }
            assert!(Instant::now() < deadline, "expected fresh local verification email");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn register(&self) -> String {
        let before = self.inbox.lock().expect("private inbox lock").len();
        let credentials = json!({"email":"eso-owner@example.invalid","password":"correct-horse-battery"});
        let registered = good(self.raw(Method::POST, "/api/auth/register", None, Some(&credentials), None).await, "register private account");
        assert!(registered["verification_required"] == true, "signup must require actual email verification");
        let text = self.mail_after(before, "/api/auth/verify?token=").await;
        let path = text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| &word[i..])).expect("signup verification link");
        good(self.raw(Method::GET, path, None, None, None).await, "verify signup through local mail");
        let login = good(self.raw(Method::POST, "/api/auth/login", None, Some(&credentials), None).await, "sign in verified owner");
        field(&login, "token")
    }

    async fn export(&self, token: Option<&str>, reference: &str) -> Response {
        let mut request = self.client.post(format!("{}/v1/export", self.bridge_url)).json(&json!({"ref":reference}));
        if let Some(token) = token { request = request.bearer_auth(token); }
        response(request).await
    }
}

async fn response(request: reqwest::RequestBuilder) -> Response {
    let response = request.send().await.unwrap_or_else(|_| panic!("local fixture HTTP request failed"));
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap_or_else(|_| panic!("read local fixture HTTP response"));
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Response { status, body }
}
fn good(response: Response, action: &str) -> Value { assert_eq!(response.status, 200, "{action}"); response.body }
fn field(value: &Value, key: &str) -> String { value[key].as_str().filter(|s| !s.is_empty()).expect(key).to_string() }

// The server package cannot supply another package's CARGO_BIN_EXE; explicit runs must supply the built bridge.
#[tokio::test]
#[ignore = "requires OPENWARP_ESO_BIN pointing to an explicitly built openwarp-eso binary"]
async fn scoped_service_token_exports_shared_values_and_preserves_deleted_environment_404() {
    let s = Fixture::start().await;
    let owner = s.register().await;
    let orgs = good(s.session(Method::GET, "/api/orgs", &owner, None).await, "list fixture workspaces");
    let org = orgs.as_array().and_then(|orgs| orgs.first()).expect("owner workspace");
    let workspace = field(org, "name");
    let app = good(s.session(Method::POST, &format!("/api/orgs/{}/apps", field(org,"id")), &owner,
        Some(json!({"name":"eso-consumer"}))).await, "create fixture application");
    let app = field(&app, "id");
    let envs = good(s.session(Method::GET, &format!("/api/apps/{app}/envs"), &owner, None).await, "list fixture environments");
    let env = envs.as_array().expect("environment list").iter().find(|env| env["name"] == "Development").expect("source environment");
    let env = field(env, "id");
    assert!(envs.as_array().expect("environment list").iter().any(|env| env["name"] == "Staging"), "wrong-reference guard needs another real environment");
    good(s.session(Method::PUT, &format!("/api/envs/{env}/secrets"), &owner,
        Some(json!({"secrets":[{"key":"ESO_SHARED","value":"shared-deployment-value"}]}))).await, "deploy shared fixture value");
    let listed = good(s.session(Method::GET, &format!("/api/envs/{env}/secrets"), &owner, None).await, "locate fixture secret");
    let secret = listed["secrets"].as_array().expect("secret list").iter().find(|secret| secret["key"] == "ESO_SHARED").expect("shared fixture secret");
    good(s.session(Method::POST, &format!("/api/secrets/{}/override", field(secret,"id")), &owner,
        Some(json!({"secrets":[{"key":"ESO_SHARED","value":"personal-override-value"}]}))).await, "set token owner's personal override");
    let minted = good(s.session(Method::POST, &format!("/api/apps/{app}/tokens"), &owner,
        Some(json!({"name":"eso-reader","env_id":env,"expires_in":600,"scopes":"secrets:read"}))).await, "mint environment-scoped service token");
    let token = field(&minted, "token");
    let me = good(s.raw(Method::GET, "/api/me", Some(&token), None, None).await, "authenticate service token");
    assert!(me["env_scope"].as_str() == Some(env.as_str()), "service token must be scoped to the source environment");
    let effective = good(s.raw(Method::GET, &format!("/api/envs/{env}/secrets"), Some(&token), None, None).await, "read ordinary token-owner view");
    assert!(effective["secrets"].as_array().expect("effective secret list").iter().any(|secret| secret["key"] == "ESO_SHARED" && secret["value"] == "personal-override-value"), "control read must see the personal override so canonical export is not vacuous");

    let reference = format!("{workspace}/eso-consumer/Development");
    assert_eq!(s.export(None, &reference).await.status, 401, "bridge must require a credential");
    let exported = good(s.export(Some(&token), &reference).await, "POST ref must resolve the token's matching named environment");
    assert!(exported == json!({"data":{"ESO_SHARED":"shared-deployment-value"}}), "bridge must return the ESO data map with only canonical shared values, never personal overrides");
    assert_eq!(s.export(Some(&token), &format!("{workspace}/eso-consumer/Staging")).await.status, 403, "a valid scoped token must not resolve a different environment");

    good(s.session(Method::DELETE, &format!("/api/envs/{env}"), &owner, None).await, "delete source through authenticated API");
    assert_eq!(s.raw(Method::GET, &format!("/api/envs/{env}/meta"), Some(&owner), None, None).await.status, 404, "source environment must actually be gone");
    // This is the webhook deletionPolicy signal, not a Kubernetes controller or Secret lifecycle test.
    assert_eq!(s.export(Some(&token), &reference).await.status, 404, "the original scoped reference must preserve not-found after source deletion for ESO deletionPolicy");
}
