use axum::{routing::post, Json, Router};
use openwarp_crypto as oc;
use openwarp_server::db::Db;
use reqwest::Client;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU32, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
struct Database { dir: PathBuf, db: Db }
impl Drop for Database { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }
impl Database {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-review-boundaries-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&format!("sqlite://{}", dir.join("test.db").display())).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','owner@test.invalid','unused','unused','unused',?,1)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token("owner")),json!(now())]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await.unwrap();
        Self { dir, db }
    }
    async fn root(&self) -> String { self.db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().unwrap()["v"].as_str().unwrap().to_string() }
}
struct Server { child: Child, base: String, log: PathBuf, client: Client }
impl Drop for Server { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }
impl Server {
    fn start(data: &Database, kms: Option<&str>, key_id: &str) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let log = data.dir.join(format!("server-{}.log", addr.port()));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env("DATABASE_URL", format!("sqlite://{}", data.dir.join("test.db").display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_ENV", if kms.is_some() { "production" } else { "test" })
            .env("TOKIO_WORKER_THREADS", "2").env("OPENWARP_ALLOWED_DB_HOSTS", "db.test.invalid:5432")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL").env_remove("OPENWARP_KMS_TOKEN")
            .env("OPENWARP_KMS_KEY_ID", key_id).env("NO_PROXY", "127.0.0.1,localhost")
            .stdout(Stdio::null()).stderr(Stdio::from(std::fs::File::create(&log).unwrap()));
        if let Some(url) = kms { cmd.env("OPENWARP_KMS_URL", url); } else { cmd.env_remove("OPENWARP_KMS_URL"); }
        let child = cmd.spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(20)).build().unwrap();
        Self { child, base, log, client }
    }
    async fn healthy(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() { panic!("server exited {}: {}", status, std::fs::read_to_string(&self.log).unwrap()); }
            if let Ok(r) = self.client.get(format!("{}/health", self.base)).send().await { if r.status().is_success() { return; } }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server failed health check: {}", std::fs::read_to_string(&self.log).unwrap());
    }
    async fn call(&self, method: &str, path: &str, cookie: &str, input: Value) -> (u16, Value) {
        let mut request = self.client.request(method.parse().unwrap(), format!("{}{}", self.base, path));
        if !cookie.is_empty() { request = request.header("cookie", format!("ow_session={}", cookie)); }
        if !input.is_null() { request = request.json(&input); }
        let response = request.send().await.unwrap(); let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw":text})))
    }
    async fn ok(&self, method: &str, path: &str, input: Value) -> Value {
        let (status, body) = self.call(method, path, "owner", input).await;
        assert_eq!(status, 200, "{} {}: {}", method, path, body); body
    }
    async fn environment(&self) -> String {
        let app = self.ok("POST", "/api/orgs/org/apps", json!({"name":"boundary"})).await;
        let env = self.ok("POST", &format!("/api/apps/{}/envs", app["id"].as_str().unwrap()), json!({"name":"test"})).await;
        env["id"].as_str().unwrap().to_string()
    }
}
struct Mock { url: String, task: tokio::task::JoinHandle<()> }
impl Drop for Mock { fn drop(&mut self) { self.task.abort(); } }
async fn serve(app: Router) -> Mock {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    Mock { url, task }
}

#[test]
fn static_postgres_admin_cannot_be_its_own_rotation_target() {
    let prior = std::env::var_os("OPENWARP_ALLOWED_DB_HOSTS");
    std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", "db.test.invalid:5432");
    let connection = "postgres://rotation_admin:fake-password@db.test.invalid:5432/test?sslmode=require";
    let distinct = openwarp_server::pglease::validate_static(connection, "application_login");
    let same = openwarp_server::pglease::validate_static(connection, "rotation_admin");
    match prior { Some(v) => std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", v), None => std::env::remove_var("OPENWARP_ALLOWED_DB_HOSTS") }
    assert!(distinct.is_ok(), "valid TLS and allowlist fixture rejected: {:?}", distinct);
    assert!(same.is_err(), "rotating the admin's own password strands the configured credential");
}

#[tokio::test]
async fn stale_and_revoked_session_cookies_do_not_block_public_authentication() {
    let data = Database::new().await;
    data.db.exec("UPDATE users SET auth_version=2 WHERE id='owner'", &[]).await.unwrap();
    data.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token("revoked")),json!(now())]).await.unwrap();
    data.db.exec("DELETE FROM sessions WHERE token_hash=?", &[json!(oc::hash_token("revoked"))]).await.unwrap();
    let mut server = Server::start(&data, None, "test"); server.healthy().await;
    let (status, providers) = server.call("GET", "/api/auth/providers", "", Value::Null).await;
    assert_eq!(status, 200); assert!(providers["signups"].is_string());
    for cookie in ["stale-never-issued", "revoked"] {
        assert_eq!(server.call("GET", "/api/me", cookie, Value::Null).await.0, 401);
        let response = server.call("GET", "/api/auth/providers", cookie, Value::Null).await;
        assert_eq!(response, (200, providers.clone()), "public provider handler blocked by {}", cookie);
        let (status, body) = server.call("POST", "/api/auth/forgot", cookie, json!({"email":"absent@test.invalid"})).await;
        assert_eq!(status, 200, "{}", body); assert_eq!(body["ok"], true);
        let (status, body) = server.call("POST", "/api/auth/challenge", cookie, json!({"email":"owner@test.invalid"})).await;
        assert_eq!(status, 200, "{}", body);
        let challenge = body["challenge_id"].as_str().unwrap(); assert!(!body["challenge"].as_str().unwrap().is_empty());
        assert!(data.db.one("SELECT id_hash FROM auth_challenges WHERE id_hash=?", &[json!(oc::hash_token(challenge))]).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn oauth_transit_scopes_are_discoverable_and_explicitly_authorizable() {
    let data = Database::new().await;
    let mut server = Server::start(&data, None, "test"); server.healthy().await;
    let scopes = ["transit:manage", "transit:encrypt", "transit:decrypt", "transit:rewrap"];
    let (status, discovery) = server.call("GET", "/.well-known/oauth-authorization-server", "", Value::Null).await;
    assert_eq!(status, 200);
    let supported = discovery["scopes_supported"].as_array().unwrap();
    for scope in scopes { assert!(supported.contains(&json!(scope)), "discovery omits {}: {}", scope, discovery); }
    let redirect = format!("{}/callback", server.base);
    let (status, default) = server.call("POST", "/oauth/register", "", json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none"})).await;
    assert_eq!(status, 201, "{}", default);
    assert_eq!(default["scope"], "secrets:read");
    let stored = data.db.one("SELECT scopes FROM oauth_clients WHERE client_id=?", &[default["client_id"].clone()]).await.unwrap().unwrap();
    assert_eq!(stored["scopes"], "secrets:read");
    for scope in scopes {
        let (status, client) = server.call("POST", "/oauth/register", "", json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope})).await;
        assert_eq!(status, 201, "{}", client);
        let response = server.client.post(format!("{}/oauth/authorize/decision", server.base)).header("cookie", "ow_session=owner")
            .form(&[("client_id", client["client_id"].as_str().unwrap()),("redirect_uri", redirect.as_str()),("response_type","code"),("scope",scope),("code_challenge","0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"),("code_challenge_method","S256"),("approve","1")]).send().await.unwrap();
        let status = response.status(); let location = response.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let body = response.text().await.unwrap();
        assert!(status.is_redirection() && location.contains("code="), "{} consent rejected: {} {} {}", scope, status, location, body);
        let code = data.db.one("SELECT scope FROM oauth_codes WHERE client_id=?", &[client["client_id"].clone()]).await.unwrap().unwrap();
        assert_eq!(code["scope"], scope);
    }
}

#[tokio::test]
async fn path_policy_rejects_noncanonical_role_whitespace_before_storage() {
    let data = Database::new().await;
    let mut server = Server::start(&data, None, "test"); server.healthy().await;
    let eid = server.environment().await;
    let rules = json!({"rules":[{"prefix":"/allowed/","capabilities":["read"]}]});
    server.ok("PUT", &format!("/api/envs/{}/path-policy/developer", eid), rules.clone()).await;
    for role in ["developer%20", "%20developer"] {
        let response = server.call("PUT", &format!("/api/envs/{}/path-policy/{}", eid, role), "owner", rules.clone()).await;
        assert_eq!(response.0, 400, "noncanonical role stored: {:?}", response);
    }
    let rows = data.db.query("SELECT role,rules FROM path_policies WHERE env_id=?", &[json!(eid)]).await.unwrap();
    assert_eq!(rows.len(), 1); assert_eq!(rows[0]["role"], "developer");
    assert_eq!(serde_json::from_str::<Value>(rows[0]["rules"].as_str().unwrap()).unwrap(), rules["rules"]);
}

#[tokio::test]
async fn kms_bootstrap_verifies_wrapped_root_before_deleting_plaintext() {
    for good in [false, true] {
        let data = Database::new().await; let root = oc::b64(&[31;32]);
        data.db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(root)]).await.unwrap();
        let calls = Arc::new(Mutex::new(Vec::<String>::new())); let sink = calls.clone();
        let bridge = serve(Router::new().route("/{op}", post(move |axum::extract::Path(op): axum::extract::Path<String>, Json(body): Json<Value>| {
            let sink = sink.clone(); async move {
                sink.lock().unwrap().push(op.clone()); assert_eq!(body["context"], "master");
                if op == "wrap" { (axum::http::StatusCode::OK, Json(json!({"wrapped":if good { body["plaintext"].clone() } else { json!("junk") }}))) }
                else if good { (axum::http::StatusCode::OK, Json(json!({"plaintext":body["wrapped"]}))) }
                else { (axum::http::StatusCode::BAD_REQUEST, Json(json!({"error":"cannot unwrap junk"}))) }
            }
        }))).await;
        let mut server = Server::start(&data, Some(&bridge.url), "test");
        if good {
            server.healthy().await;
            assert!(calls.lock().unwrap().iter().any(|op| op == "unwrap"), "bootstrap skipped the root roundtrip");
            assert!(data.db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().is_none());
            drop(server);
            let mut restarted = Server::start(&data, Some(&bridge.url), "test"); restarted.healthy().await;
        } else {
            let deadline = Instant::now() + Duration::from_secs(20);
            let status = loop {
                if let Some(status) = server.child.try_wait().unwrap() { break status; }
                assert!(Instant::now() < deadline, "startup accepted an unusable wrapped root: {}", std::fs::read_to_string(&server.log).unwrap());
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            assert!(!status.success(), "bad KMS bootstrap exited successfully");
            assert!(calls.lock().unwrap().iter().any(|op| op == "unwrap"));
            assert_eq!(data.root().await, root, "bootstrap destroyed the recoverable plaintext root");
        }
    }
}

#[tokio::test]
async fn instance_rewrap_updates_root_key_id_and_restarts_without_old_key() {
    let data = Database::new().await;
    let old_disabled = Arc::new(AtomicBool::new(false)); let disabled = old_disabled.clone();
    let bridge = serve(Router::new().route("/{op}", post(move |axum::extract::Path(op): axum::extract::Path<String>, Json(body): Json<Value>| {
        let disabled = disabled.clone(); async move {
            if disabled.load(Ordering::SeqCst) && body["key_id"] == "old" { return (axum::http::StatusCode::FORBIDDEN, Json(json!({"error":"old key disabled"}))); }
            (axum::http::StatusCode::OK, Json(if op == "wrap" { json!({"wrapped":body["plaintext"]}) } else { json!({"plaintext":body["wrapped"]}) }))
        }
    }))).await;
    let mut first = Server::start(&data, Some(&bridge.url), "old"); first.healthy().await; drop(first);
    let original = data.db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap().unwrap()["v"].as_str().unwrap().to_string();
    assert!(original.starts_with("owkms:old:"));
    let mut second = Server::start(&data, Some(&bridge.url), "new"); second.healthy().await;
    second.ok("POST", "/api/instance/rewrap", json!({})).await;
    let root = data.db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap().unwrap()["v"].as_str().unwrap().to_string();
    assert!(root.starts_with("owkms:new:"), "root still depends on retired key: {}", root);
    drop(second); old_disabled.store(true, Ordering::SeqCst);
    let mut restarted = Server::start(&data, Some(&bridge.url), "new"); restarted.healthy().await;
}

#[tokio::test]
async fn pending_static_rotation_blocks_sealing_target_without_losing_candidate() {
    let data = Database::new().await;
    let mut server = Server::start(&data, None, "test"); server.healthy().await;
    let eid = server.environment().await; let path = format!("/api/envs/{}/secrets", eid);
    server.ok("PUT", &path, json!({"secrets":[{"key":"PASSWORD","value":"before","type":"secret"}]})).await;
    let config = json!({"kind":"postgres-static","connection":"postgres://rotation_admin:fake-password@db.test.invalid:5432/test?sslmode=require","username":"application_login"});
    let rotation = server.ok("POST", &format!("/api/envs/{}/rotations", eid), json!({"key":"PASSWORD","interval_secs":86400,"config":config})).await;
    let rid = rotation["id"].as_str().unwrap();
    let root: [u8;32] = oc::unb64(&data.root().await).unwrap().try_into().unwrap();
    let row = data.db.one("SELECT env_key_wrapped FROM envs WHERE id=?", &[json!(eid)]).await.unwrap().unwrap();
    let key: [u8;32] = oc::decrypt_symmetric(&root, row["env_key_wrapped"].as_str().unwrap()).unwrap().try_into().unwrap();
    let aad = json!(["postgres-static-pending-v1",eid,rid]).to_string();
    let pending = oc::encrypt_symmetric_aad(&key, aad.as_bytes(), b"pending-password");
    data.db.exec("UPDATE rotation_schedules SET pending_enc=?,execution_token='held-execution' WHERE id=?", &[json!(pending),json!(rid)]).await.unwrap();
    let before = data.db.one("SELECT id,secret_type,value_enc,version FROM secrets WHERE env_id=? AND deleted=0", &[json!(eid)]).await.unwrap().unwrap();
    let response = server.call("PUT", &path, "owner", json!({"secrets":[{"key":"PASSWORD","value":"sealed-replacement","type":"sealed"}]})).await;
    assert_eq!(response.0, 409, "pending rotation target changed type: {:?}", response);
    let after = data.db.one("SELECT id,secret_type,value_enc,version FROM secrets WHERE env_id=? AND deleted=0", &[json!(eid)]).await.unwrap().unwrap();
    assert_eq!(after, before);
    let schedule = data.db.one("SELECT pending_enc,execution_token FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.unwrap().unwrap();
    assert_eq!(schedule["pending_enc"], pending); assert_eq!(schedule["execution_token"], "held-execution");
    assert_eq!(oc::decrypt_symmetric_aad(&key, aad.as_bytes(), schedule["pending_enc"].as_str().unwrap()).unwrap(), b"pending-password");
}
