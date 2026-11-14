#![cfg(feature = "scim")]

use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Resp { status: u16, text: String, body: Value }
struct Server {
    child: Child,
    base: String,
    dir: PathBuf,
    client: Client,
    inbox_url: String,
    inbox: Arc<Mutex<Vec<Value>>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    async fn start() -> Self {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-scim-patch-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("private test directory");
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral server port");
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let (inbox_url, inbox) = start_inbox();
        let child = Self::spawn(&dir, &base, &inbox_url, "development");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let mut server = Self { child, base, dir, client, inbox_url, inbox };
        server.wait_healthy().await;
        server
    }

    fn spawn(dir: &std::path::Path, base: &str, inbox_url: &str, license: &str) -> Child {
        Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env_clear()
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", base.strip_prefix("http://").unwrap())
            .env("OPENWARP_PUBLIC_URL", base)
            .env("OPENWARP_EMAIL_WEBHOOK", inbox_url)
            .env("OPENWARP_LICENSE", license)
            .env("TOKIO_WORKER_THREADS", "1")
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().expect("spawn openwarp-server")
    }

    async fn wait_healthy(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            assert!(self.child.try_wait().unwrap().is_none(), "server exited before becoming healthy");
            if let Ok(r) = self.client.get(format!("{}/health", self.base)).send().await {
                if r.status().is_success() { return; }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server did not become healthy");
    }

    async fn restart_without_license(&mut self) {
        self.child.kill().expect("stop licensed fixture");
        self.child.wait().expect("wait for fixture shutdown");
        self.child = Self::spawn(&self.dir, &self.base, &self.inbox_url, "none");
        self.wait_healthy().await;
    }

    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = token { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.expect("loopback HTTP request");
        let status = response.status().as_u16();
        let text = response.text().await.expect("HTTP body");
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, text, body }
    }

    async fn register(&self, email: &str) -> Value {
        let before = self.inbox.lock().unwrap().len();
        let reg = self.call(Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
        assert_eq!(reg.status, 200, "register: {}", reg.text);
        let mut body = reg.body;
        let text = wait_for_mail(&self.inbox, before, "/api/auth/verify?token=").await;
        let link = text.split_whitespace().find_map(|word| word.find("/api/auth/verify?token=").map(|i| &word[i..])).expect("verification link");
        let verified = self.call(Method::GET, link, None, None).await;
        assert_eq!(verified.status, 200, "verify: {}", verified.text);
        let login = self.call(Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": "correct-horse-battery"}))).await;
        assert_eq!(login.status, 200, "verified login failed");
        body["token"] = login.body["token"].clone();
        body["user_id"] = login.body["user_id"].clone();
        body
    }
}

fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mail relay port");
    let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming { Ok(stream) => stream, Err(_) => continue };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(n) => n };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..end]);
                    let len = headers.lines().find_map(|line| { let (key, value) = line.split_once(':')?; if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                if let Ok(body) = serde_json::from_slice::<Value>(&buf[end + 4..]) { sink.lock().unwrap().push(body); }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", addr), inbox)
}

async fn wait_for_mail(inbox: &Arc<Mutex<Vec<Value>>>, before: usize, needle: &str) -> String {
    for _ in 0..100 {
        {
            let mail = inbox.lock().unwrap();
            if let Some(text) = mail.iter().skip(before).filter_map(|m| m["text"].as_str()).find(|text| text.contains(needle)) { return text.to_string(); }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("verification email did not arrive");
}

fn patch(operations: Value) -> Value {
    json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": operations})
}

fn member_ids(group: &Value) -> Vec<String> {
    let mut ids: Vec<String> = group["members"].as_array().expect("SCIM members array").iter().map(|m| m["value"].as_str().expect("member id").to_string()).collect();
    ids.sort();
    ids
}

fn assert_members(group: &Value, expected: &[&str]) {
    let mut expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(member_ids(group), expected, "SCIM group must contain exactly the expected members");
}

struct Fixture {
    server: Server,
    owner: String,
    org: String,
    group: String,
    alice: String,
    bob: String,
    carol: String,
    alice_password: String,
}

impl Fixture {
    async fn new() -> Self {
        let server = Server::start().await;
        let owner = server.register("owner@test.invalid").await;
        let token = owner["token"].as_str().unwrap().to_string();
        let org = owner["org_id"].as_str().unwrap().to_string();
        grant(&server, &token, &org, true).await;
        let mut users = Vec::new();
        for email in ["alice@test.invalid", "bob@test.invalid", "carol@test.invalid"] {
            let user = server.call(Method::POST, &format!("/scim/v2/Users?org_id={}", org), Some(&token), Some(json!({"userName": email}))).await;
            assert_eq!(user.status, 200, "SCIM fixture user creation failed");
            users.push(user.body);
        }
        let created = server.call(Method::POST, &format!("/scim/v2/Groups?org_id={}", org), Some(&token), Some(json!({"displayName": "Operators", "members": [{"value": users[0]["id"]}, {"value": users[1]["id"]}]}))).await;
        assert_eq!(created.status, 200, "create group: {}", created.text);
        let fixture = Self { server, owner: token, org, group: created.body["id"].as_str().unwrap().to_string(), alice: users[0]["id"].as_str().unwrap().to_string(), bob: users[1]["id"].as_str().unwrap().to_string(), carol: users[2]["id"].as_str().unwrap().to_string(), alice_password: users[0]["temp_password"].as_str().unwrap().to_string() };
        fixture.assert_state("Operators", &[&fixture.alice, &fixture.bob]).await;
        fixture
    }

    fn path(&self) -> String { format!("/scim/v2/Groups/{}?org_id={}", self.group, self.org) }

    async fn get(&self) -> Value {
        let response = self.server.call(Method::GET, &self.path(), Some(&self.owner), None).await;
        assert_eq!(response.status, 200, "read group: {}", response.text);
        response.body
    }

    async fn apply(&self, operations: Value) -> Value {
        let response = self.server.call(Method::PATCH, &self.path(), Some(&self.owner), Some(patch(operations))).await;
        assert_eq!(response.status, 200, "PATCH group: {}", response.text);
        let stored = self.get().await;
        assert_eq!(response.body["displayName"], stored["displayName"], "PATCH response must match persisted displayName");
        assert_eq!(member_ids(&response.body), member_ids(&stored), "PATCH response must match persisted membership");
        stored
    }

    async fn assert_state(&self, name: &str, members: &[&str]) {
        let group = self.get().await;
        assert_eq!(group["displayName"], json!(name));
        assert_members(&group, members);
    }

    async fn assert_rejected(&self, body: Value, label: &str, statuses: &[u16]) {
        let before = self.get().await;
        let response = self.server.call(Method::PATCH, &self.path(), Some(&self.owner), Some(body)).await;
        let after = self.get().await;
        assert_eq!(after["displayName"], before["displayName"], "{}: rejected request changed displayName", label);
        assert_eq!(member_ids(&after), member_ids(&before), "{}: rejected request changed membership", label);
        assert!(statuses.contains(&response.status), "{}: expected rejection, got {} {}", label, response.status, response.text);
    }
}

async fn grant(server: &Server, token: &str, org: &str, enabled: bool) {
    let response = server.call(Method::PUT, "/api/instance/features", Some(token), Some(json!({"org": org, "features": if enabled { vec!["scim"] } else { vec![] }}))).await;
    assert_eq!(response.status, 200, "SCIM feature grant: {}", response.text);
}

#[tokio::test]
async fn add_preserves_existing_members_and_is_idempotent() {
    let f = Fixture::new().await;
    let op = json!([{"op": "add", "path": "members", "value": [{"value": f.carol}]}]);
    for _ in 0..2 {
        let group = f.apply(op.clone()).await;
        assert_members(&group, &[&f.alice, &f.bob, &f.carol]);
        assert_eq!(group["displayName"], json!("Operators"));
    }
}

#[tokio::test]
async fn remove_filtered_member_preserves_the_others() {
    let f = Fixture::new().await;
    let group = f.apply(json!([{"op": "remove", "path": format!("members[value eq \"{}\"]", f.alice)}])).await;
    assert_members(&group, &[&f.bob]);
    assert_eq!(group["displayName"], json!("Operators"));
}

#[tokio::test]
async fn replace_members_replaces_the_whole_array_and_can_clear_it() {
    let f = Fixture::new().await;
    let group = f.apply(json!([{"op": "replace", "path": "members", "value": [{"value": f.carol}]}])).await;
    assert_members(&group, &[&f.carol]);
    assert_eq!(group["displayName"], json!("Operators"));
    let cleared = f.apply(json!([{"op": "replace", "path": "members", "value": []}])).await;
    assert_members(&cleared, &[]);
}

#[tokio::test]
async fn display_name_update_does_not_replace_members() {
    let f = Fixture::new().await;
    f.apply(json!([{"op": "replace", "path": "displayName", "value": "Renamed"}])).await;
    f.assert_state("Renamed", &[&f.alice, &f.bob]).await;
}

#[tokio::test]
async fn valid_operations_apply_in_request_order() {
    let f = Fixture::new().await;
    f.apply(json!([
        {"op": "replace", "path": "members", "value": [{"value": f.carol}]},
        {"op": "add", "path": "members", "value": [{"value": f.alice}]},
        {"op": "remove", "path": format!("members[value eq \"{}\"]", f.carol)},
        {"op": "replace", "path": "displayName", "value": "Ordered"}
    ])).await;
    f.assert_state("Ordered", &[&f.alice]).await;
}

#[tokio::test]
async fn standard_pathless_value_objects_support_add_and_replace() {
    let f = Fixture::new().await;
    f.apply(json!([{"op": "add", "value": {"displayName": "Pathless", "members": [{"value": f.carol}]}}])).await;
    f.assert_state("Pathless", &[&f.alice, &f.bob, &f.carol]).await;
    f.apply(json!([{"op": "replace", "value": {"members": [{"value": f.bob}]}}])).await;
    f.assert_state("Pathless", &[&f.bob]).await;
}

#[tokio::test]
async fn operation_and_attribute_names_are_case_insensitive() {
    let f = Fixture::new().await;
    f.apply(json!([
        {"op": "AdD", "path": "MeMbErS", "value": [{"VaLuE": f.carol}]},
        {"op": "ReMoVe", "path": format!("MEMBERS[VALUE eq \"{}\"]", f.alice)},
        {"op": "RePlAcE", "path": "DISPLAYNAME", "value": "Mixed case"}
    ])).await;
    f.assert_state("Mixed case", &[&f.bob, &f.carol]).await;
}

#[tokio::test]
async fn malformed_or_unsupported_operation_rolls_back_every_prior_operation() {
    let f = Fixture::new().await;
    let invalid = [
        ("unsupported op", json!({"op": "merge", "path": "members", "value": [{"value": f.carol}]})),
        ("missing op", json!({"path": "members", "value": [{"value": f.carol}]})),
        ("unsupported path", json!({"op": "replace", "path": "externalId", "value": "external"})),
        ("members prefix is not a supported path", json!({"op": "replace", "path": "membersBogus", "value": []})),
        ("malformed filter", json!({"op": "remove", "path": "members[value eq]"})),
        ("unsupported filter", json!({"op": "remove", "path": "members[display eq \"Alice\"]"})),
        ("missing value", json!({"op": "add", "path": "members"})),
        ("members must be an array", json!({"op": "replace", "path": "members", "value": "not-an-array"})),
        ("displayName must be a string", json!({"op": "replace", "path": "displayName", "value": 42})),
        ("displayName is required", json!({"op": "remove", "path": "displayName"})),
    ];
    for (label, invalid_op) in invalid {
        f.assert_rejected(patch(json!([
            {"op": "replace", "path": "displayName", "value": "Must roll back"},
            {"op": "replace", "path": "members", "value": [{"value": f.carol}]},
            invalid_op
        ])), label, &[400]).await;
    }
    for (label, operations) in [("missing operations", Value::Null), ("operations is not an array", json!({})), ("empty operations", json!([]))] {
        let body = if operations.is_null() { json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}) } else { patch(operations) };
        f.assert_rejected(body, label, &[400]).await;
    }
}

#[tokio::test]
async fn invalid_and_cross_workspace_member_ids_reject_the_whole_request() {
    let f = Fixture::new().await;
    let outsider = f.server.register("outsider@test.invalid").await;
    let invalid = [
        ("missing member id", json!({})),
        ("empty member id", json!({"value": ""})),
        ("non-string member id", json!({"value": 42})),
        ("unknown member id", json!({"value": "00000000-0000-0000-0000-000000000000"})),
        ("existing user in another workspace", json!({"value": outsider["user_id"]})),
    ];
    for (label, member) in invalid {
        for op in ["add", "replace"] {
            f.assert_rejected(patch(json!([
                {"op": "replace", "path": "displayName", "value": "Must roll back"},
                {"op": op, "path": "members", "value": [{"value": f.carol}, member]}
            ])), label, &[400, 404]).await;
        }
    }
    for (label, id) in [("unknown remove target", "00000000-0000-0000-0000-000000000000"), ("foreign remove target", outsider["user_id"].as_str().unwrap()), ("workspace user not in this group", f.carol.as_str())] {
        f.assert_rejected(patch(json!([
            {"op": "replace", "path": "displayName", "value": "Must roll back"},
            {"op": "remove", "path": format!("members[value eq \"{}\"]", id)}
        ])), label, &[400, 404]).await;
    }
}

#[tokio::test]
async fn patch_keeps_tenant_admin_and_workspace_feature_boundaries() {
    let f = Fixture::new().await;
    let outsider = f.server.register("outsider@test.invalid").await;
    let other_org = outsider["org_id"].as_str().unwrap();
    let outsider_token = outsider["token"].as_str().unwrap();
    grant(&f.server, &f.owner, other_org, true).await;
    let login = f.server.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "alice@test.invalid", "password": f.alice_password}))).await;
    assert_eq!(login.status, 200, "SCIM member login failed");
    let member_token = login.body["token"].as_str().unwrap();
    let operation = patch(json!([{"op": "replace", "path": "displayName", "value": "Forbidden"}]));
    for (label, path, token, status) in [
        ("anonymous", f.path(), None, 401),
        ("outsider", f.path(), Some(outsider_token), 403),
        ("ordinary member", f.path(), Some(member_token), 403),
        ("missing workspace", format!("/scim/v2/Groups/{}", f.group), Some(f.owner.as_str()), 400),
        ("group from another workspace", format!("/scim/v2/Groups/{}?org_id={}", f.group, other_org), Some(outsider_token), 404),
    ] {
        let response = f.server.call(Method::PATCH, &path, token, Some(operation.clone())).await;
        assert_eq!(response.status, status, "{}: {}", label, response.text);
        f.assert_state("Operators", &[&f.alice, &f.bob]).await;
    }
    let promoted = f.server.call(Method::PATCH, &format!("/api/orgs/{}/members/{}", f.org, f.alice), Some(&f.owner), Some(json!({"role": "admin"}))).await;
    assert_eq!(promoted.status, 200, "grant workspace admin: {}", promoted.text);
    let allowed = f.server.call(Method::PATCH, &f.path(), Some(member_token), Some(patch(json!([{"op": "replace", "path": "displayName", "value": "Admin update"}])))).await;
    assert_eq!(allowed.status, 200, "workspace admins retain SCIM access: {}", allowed.text);
    f.assert_state("Admin update", &[&f.alice, &f.bob]).await;
    grant(&f.server, &f.owner, &f.org, false).await;
    let denied = f.server.call(Method::PATCH, &f.path(), Some(&f.owner), Some(operation)).await;
    assert_eq!(denied.status, 403, "license and ownership do not replace a feature grant: {}", denied.text);
    grant(&f.server, &f.owner, &f.org, true).await;
    f.assert_state("Admin update", &[&f.alice, &f.bob]).await;
}

#[tokio::test]
async fn a_workspace_feature_grant_does_not_bypass_the_enterprise_license() {
    let mut f = Fixture::new().await;
    f.server.restart_without_license().await;
    let edition = f.server.call(Method::GET, "/api/instance/edition", Some(&f.owner), None).await;
    assert_eq!(edition.status, 200);
    assert_eq!(edition.body["tier"], json!("self-hosted"));
    let denied = f.server.call(Method::PATCH, &f.path(), Some(&f.owner), Some(patch(json!([{"op": "replace", "path": "displayName", "value": "Unlicensed"}])))).await;
    assert_eq!(denied.status, 403, "unlicensed SCIM PATCH: {}", denied.text);
    assert_eq!(denied.body["code"], json!("enterprise_feature"));
    assert_eq!(denied.body["feature"], json!("directory_sync"));
    f.server.child.kill().expect("stop unlicensed fixture");
    f.server.child.wait().expect("wait for fixture shutdown");
    f.server.child = Server::spawn(&f.server.dir, &f.server.base, &f.server.inbox_url, "development");
    f.server.wait_healthy().await;
    f.assert_state("Operators", &[&f.alice, &f.bob]).await;
}
