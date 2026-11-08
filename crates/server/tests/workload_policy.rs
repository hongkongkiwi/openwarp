use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU32, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

struct Reply { status: u16, body: Value, text: String }
impl Reply {
    fn ok(self) -> Value { assert_eq!(self.status, 200, "HTTP {}: {}", self.status, self.text); self.body }
    fn forbidden(self) { assert_eq!(self.status, 403, "HTTP {}: {}", self.status, self.text); }
    fn rejected(self) { assert!(matches!(self.status, 400 | 401 | 403 | 422), "expected contract rejection, HTTP {}: {}", self.status, self.text); }
}
struct Fixture { app: Router, state: S }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.unwrap();
        for org in ["org", "foreign"] {
            db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(org), json!(org), json!(now())]).await.unwrap();
        }
        for (uid, org, role) in [("owner", "org", "owner"), ("admin", "org", "admin"), ("dev", "org", "developer"), ("outsider", "foreign", "owner"), ("encryptor", "org", "encryptor"), ("decryptor", "org", "decryptor")] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?, 'unused','unused','unused',?,1)", &[json!(uid), json!(format!("{}@test.invalid", uid)), json!(now())]).await.unwrap();
            db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(org), json!(uid), json!(role)]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(uid)), json!(uid), json!(now())]).await.unwrap();
        }
        for (role, permission) in [("encryptor", "transit:encrypt"), ("decryptor", "transit:decrypt")] {
            db.exec("INSERT INTO roles(id,org_id,name,permissions) VALUES(?,'org',?,?)", &[json!(role), json!(role), json!(json!([permission]).to_string())]).await.unwrap();
        }
        db.exec("INSERT INTO identities(id,org_id,name,role,created_at) VALUES('machine','org','ci','developer',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','app',?)", &[json!(now())]).await.unwrap();
        for (eid, mode) in [("env", "sse"), ("target", "sse"), ("e2e", "e2e")] {
            let wrapped = if mode == "sse" { oc::encrypt_symmetric(&[7;32], &[8;32]) } else { String::new() };
            db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,'app',?,?,?,?)", &[json!(eid), json!(eid), json!(wrapped), json!(mode), json!(now())]).await.unwrap();
        }
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "tests".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature = "redis-cache")] None);
        let app = router(state.clone());
        let f = Self { app, state };
        f.call("GET", "/api/envs/env/secrets", "owner", None).await.ok();
        f
    }
    async fn call(&self, method: &str, path: &str, user: &str, body: Option<Value>) -> Reply {
        let mut req = Request::builder().method(method).uri(path)
            .extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127, 0, 0, 1])));
        if let Some(cookie) = user.strip_prefix("cookie:") { req = req.header("cookie", format!("ow_session={}", cookie)); }
        else if !user.is_empty() { req = req.header("authorization", format!("Bearer {}", user)); }
        let body = if let Some(body) = body { req = req.header("content-type", "application/json"); Body::from(body.to_string()) } else { Body::empty() };
        let response = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let text = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await.unwrap().to_vec()).unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Reply { status, body, text }
    }
    async fn mcp(&self, user: &str, name: &str, arguments: Value) -> Value {
        self.call("POST", "/mcp", user, Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}}))).await.ok()
    }
    async fn policy(&self, rules: Value) {
        self.call("PUT", "/api/envs/env/path-policy/developer", "owner", Some(json!({"rules":rules}))).await.ok();
    }
    async fn restricted(&self) { self.policy(json!([{"prefix":"/team/","capabilities":["read","write","delete"]}])).await; }
    async fn seed(&self) {
        self.call("PUT", "/api/envs/env/secrets", "owner", Some(json!({"secrets":[
            {"key":"VISIBLE","value":"allowed-value","path":"/team/"},
            {"key":"NESTED","value":"nested-value","path":"/team/sub/"},
            {"key":"PRIVATE","value":"foreign-canary-value","path":"/team-other/"},
            {"key":"REFERENCE","value":"${/team-other/PRIVATE}","path":"/team/"}
        ]}))).await.ok();
    }
    async fn sid(&self, key: &str) -> String {
        let body = self.call("GET", "/api/envs/env/secrets", "owner", None).await.ok();
        body["secrets"].as_array().unwrap().iter().find(|s| s["key"] == key).unwrap()["id"].as_str().unwrap().into()
    }
    async fn key(&self, name: &str) -> String {
        let body = self.call("POST", "/api/orgs/org/transit-compat/keys", "owner", Some(json!({"name":name}))).await.ok();
        body["id"].as_str().expect("created transit key id").into()
    }
}

#[tokio::test]
async fn workload_trust_is_owner_only_and_malformed_assertions_never_mint_tokens() {
    let f = Fixture::new().await;
    let trust = json!({"issuer":"https://issuer.test","jwks_url":"https://issuer.test/jwks","audience":"openwarp","subject":"system:serviceaccount:team:runner","max_ttl_secs":300});
    let path = "/api/orgs/org/identities/machine/workload";
    f.call("PUT", path, "owner", Some(trust.clone())).await.ok();
    for user in ["admin", "dev", "outsider"] { f.call("PUT", path, user, Some(trust.clone())).await.forbidden(); }
    f.call("PUT", "/api/orgs/foreign/identities/machine/workload", "outsider", Some(trust)).await.rejected();
    for jwt in ["", "not.a.jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6dGVhbTpydW5uZXIifQ."] {
        let before = f.state.db().query("SELECT token_hash FROM tokens", &[]).await.unwrap().len();
        f.call("POST", "/api/v1/machine/auth/workload/login", "", Some(json!({"identity_id":"machine","jwt":jwt}))).await.rejected();
        assert_eq!(f.state.db().query("SELECT token_hash FROM tokens", &[]).await.unwrap().len(), before, "invalid assertion minted a token");
    }
}

#[tokio::test]
async fn path_policy_administration_is_owner_only_and_rejects_noncanonical_rules() {
    let f = Fixture::new().await;
    f.restricted().await;
    let rules = json!({"rules":[{"prefix":"/team/","capabilities":["read"]}]});
    for user in ["admin", "dev", "outsider"] { f.call("PUT", "/api/envs/env/path-policy/developer", user, Some(rules.clone())).await.forbidden(); }
    for prefix in ["/team/../", "/team//", "/team/./", "/team/\n"] {
        f.call("PUT", "/api/envs/env/path-policy/developer", "owner", Some(json!({"rules":[{"prefix":prefix,"capabilities":["read"]}]}))).await.rejected();
    }
}

#[tokio::test]
async fn path_lists_and_base_exports_filter_before_reference_expansion_for_bearer_and_cookie() {
    let f = Fixture::new().await;
    f.seed().await;
    f.restricted().await;
    for user in ["dev", "cookie:dev"] {
        for path in ["/api/envs/env/secrets", "/api/envs/env/export", "/api/envs/env/export?base=1"] {
            let body = f.call("GET", path, user, None).await.ok();
            let items = body["secrets"].as_array().unwrap();
            assert_eq!(items.len(), 3, "{}: {}", path, body);
            assert!(items.iter().all(|s| s["path"].as_str().unwrap().starts_with("/team/")), "{}", body);
            assert!(!body.to_string().contains("foreign-canary-value"), "forbidden reference expanded: {}", body);
            assert!(items.iter().any(|s| s["key"] == "VISIBLE" && s["value"] == "allowed-value"));
        }
    }
}

#[tokio::test]
async fn direct_ids_history_restore_delete_and_personal_overrides_obey_stored_paths() {
    let f = Fixture::new().await;
    f.seed().await;
    let forbidden = f.sid("PRIVATE").await;
    let allowed = f.sid("VISIBLE").await;
    f.restricted().await;
    f.call("GET", &format!("/api/secrets/{}/history", allowed), "dev", None).await.ok();
    f.call("POST", &format!("/api/secrets/{}/override", allowed), "dev", Some(json!({"secrets":[{"key":"VISIBLE","value":"personal","path":"/team/"}]}))).await.ok();
    for (method, suffix, body) in [("GET", "history", None), ("POST", "restore/1", Some(json!({}))), ("POST", "override", Some(json!({"secrets":[{"key":"PRIVATE","value":"stolen"}]})))] {
        f.call(method, &format!("/api/secrets/{}/{}", forbidden, suffix), "dev", body).await.forbidden();
    }
    f.call("DELETE", &format!("/api/secrets/{}", forbidden), "dev", None).await.forbidden();
    f.call("DELETE", &format!("/api/secrets/{}", allowed), "dev", None).await.ok();
    let owner = f.call("GET", "/api/envs/env/secrets", "owner", None).await.ok();
    assert!(owner["secrets"].as_array().unwrap().iter().any(|s| s["id"] == forbidden));
}

#[tokio::test]
async fn bulk_preflight_is_atomic_and_restricted_callers_cannot_clone_whole_environments() {
    let f = Fixture::new().await;
    f.seed().await;
    f.restricted().await;
    f.call("PUT", "/api/envs/env/secrets", "dev", Some(json!({"secrets":[{"key":"VISIBLE","value":"changed","path":"/team/"}]}))).await.ok();
    f.call("PUT", "/api/envs/env/secrets", "dev", Some(json!({"secrets":[
        {"key":"VISIBLE","value":"partial-write","path":"/team/"},
        {"key":"PRIVATE","value":"forbidden-write","path":"/team-other/"}
    ]}))).await.forbidden();
    let body = f.call("GET", "/api/envs/env/secrets", "owner", None).await.ok();
    assert!(body["secrets"].as_array().unwrap().iter().any(|s| s["key"] == "VISIBLE" && s["value"] == "changed"), "bulk write partially committed: {}", body);
    f.call("POST", "/api/envs/env/clone", "dev", Some(json!({"target_env_id":"target"}))).await.forbidden();
    let target = f.call("GET", "/api/envs/target/secrets", "owner", None).await.ok();
    assert!(target["secrets"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn absent_policy_retains_existing_secret_access() {
    let f = Fixture::new().await;
    f.seed().await;
    let body = f.call("GET", "/api/envs/env/export?base=1", "dev", None).await.ok();
    assert_eq!(body["secrets"].as_array().unwrap().len(), 4);
    assert!(body.to_string().contains("foreign-canary-value"));
    let sid = f.sid("PRIVATE").await;
    f.call("GET", &format!("/api/secrets/{}/history", sid), "dev", None).await.ok();
    f.call("DELETE", &format!("/api/secrets/{}", sid), "dev", None).await.ok();
}

#[tokio::test]
async fn empty_policy_denies_every_path_and_client_encrypted_modes_reject_policy() {
    let f = Fixture::new().await;
    f.seed().await;
    f.policy(json!([])).await;
    let body = f.call("GET", "/api/envs/env/secrets", "dev", None).await.ok();
    assert!(body["secrets"].as_array().unwrap().is_empty());
    f.call("PUT", "/api/envs/env/secrets", "dev", Some(json!({"secrets":[{"key":"NEW","value":"no","path":"/team/"}]}))).await.forbidden();
    f.call("PUT", "/api/envs/e2e/path-policy/developer", "owner", Some(json!({"rules":[]}))).await.rejected();
    f.state.db().exec("UPDATE envs SET mode='delegated' WHERE id='e2e'", &[]).await.unwrap();
    f.call("PUT", "/api/envs/e2e/path-policy/developer", "owner", Some(json!({"rules":[]}))).await.rejected();
}

#[tokio::test]
async fn transit_roundtrip_rotation_old_decrypt_rewrap_and_authenticated_bindings() {
    let f = Fixture::new().await;
    let kid = f.key("payload").await;
    let other = f.key("other").await;
    let base = format!("/api/orgs/org/transit-compat/keys/{}", kid);
    let list = f.call("GET", "/api/orgs/org/transit-compat/keys", "owner", None).await.ok();
    assert!(list.to_string().contains(&kid));
    let payload = oc::b64(b"binary\0payload\xff");
    let first = f.call("POST", &format!("{}/encrypt", base), "owner", Some(json!({"plaintext":payload,"context":"invoice:42"}))).await.ok();
    let ciphertext = first["ciphertext"].as_str().unwrap();
    assert_ne!(ciphertext, payload);
    let decode = json!({"ciphertext":ciphertext,"context":"invoice:42"});
    let plain = f.call("POST", &format!("{}/decrypt", base), "owner", Some(decode.clone())).await.ok();
    assert_eq!(plain["plaintext"], payload);
    f.call("POST", &format!("{}/rotate", base), "owner", Some(json!({}))).await.ok();
    assert_eq!(f.call("POST", &format!("{}/decrypt", base), "owner", Some(decode.clone())).await.ok()["plaintext"], payload);
    let updated = f.call("POST", &format!("{}/rewrap", base), "owner", Some(decode.clone())).await.ok();
    assert_ne!(updated["ciphertext"], first["ciphertext"]);
    assert_eq!(f.call("POST", &format!("{}/decrypt", base), "owner", Some(json!({"ciphertext":updated["ciphertext"],"context":"invoice:42"}))).await.ok()["plaintext"], payload);
    for (path, user, input) in [
        (format!("{}/decrypt", base), "owner", json!({"ciphertext":ciphertext,"context":"invoice:43"})),
        (format!("/api/orgs/org/transit-compat/keys/{}/decrypt", other), "owner", decode.clone()),
        (format!("/api/orgs/foreign/transit-compat/keys/{}/decrypt", kid), "outsider", decode.clone()),
        (format!("{}/decrypt", base), "owner", json!({"ciphertext":"garbage","context":"invoice:42"}))
    ] { f.call("POST", &path, user, Some(input)).await.rejected(); }
}

#[tokio::test]
async fn transit_manage_encrypt_and_decrypt_permissions_are_separate() {
    let f = Fixture::new().await;
    let kid = f.key("permissions").await;
    let base = format!("/api/orgs/org/transit-compat/keys/{}", kid);
    let encrypted = f.call("POST", &format!("{}/encrypt", base), "encryptor", Some(json!({"plaintext":oc::b64(b"secret"),"context":"ctx"}))).await.ok();
    let input = json!({"ciphertext":encrypted["ciphertext"],"context":"ctx"});
    assert_eq!(f.call("POST", &format!("{}/decrypt", base), "decryptor", Some(input.clone())).await.ok()["plaintext"], oc::b64(b"secret"));
    f.call("POST", &format!("{}/decrypt", base), "encryptor", Some(input)).await.forbidden();
    f.call("POST", &format!("{}/encrypt", base), "decryptor", Some(json!({"plaintext":oc::b64(b"secret"),"context":"ctx"}))).await.forbidden();
    for user in ["encryptor", "decryptor", "outsider"] {
        f.call("POST", "/api/orgs/org/transit-compat/keys", user, Some(json!({"name":"denied"}))).await.forbidden();
        f.call("POST", &format!("{}/rotate", base), user, Some(json!({}))).await.forbidden();
    }
}

fn rpc_ok(body: &Value) -> Value {
    assert!(body.get("error").is_none(), "MCP rejected allowed call: {}", body);
    assert_ne!(body["result"]["isError"], true, "{}", body);
    serde_json::from_str(body["result"]["content"][0]["text"].as_str().expect("MCP text result")).unwrap()
}
fn rpc_denied(body: &Value) {
    assert!(body.get("error").is_some() || body["result"]["isError"] == true, "MCP accepted forbidden call: {}", body);
}

#[tokio::test]
async fn reuse_check_does_not_reveal_forbidden_path_fingerprints() {
    let f = Fixture::new().await;
    f.seed().await;
    f.restricted().await;
    let input = json!({"secrets":[{"key":"GUESS","value":"foreign-canary-value","path":"/team/"}]});
    let owner = f.call("POST", "/api/envs/env/secrets/reuse-check", "owner", Some(input.clone())).await.ok();
    assert!(!owner["matches"].as_array().unwrap().is_empty(), "oracle fixture did not match: {}", owner);
    let restricted = f.call("POST", "/api/envs/env/secrets/reuse-check", "dev", Some(input)).await.ok();
    assert!(restricted["matches"].as_array().unwrap().is_empty(), "forbidden fingerprint leaked: {}", restricted);
    let allowed = f.call("POST", "/api/envs/env/secrets/reuse-check", "dev", Some(json!({"secrets":[{"key":"GUESS","value":"allowed-value","path":"/team/"}]}))).await.ok();
    assert!(!allowed["matches"].as_array().unwrap().is_empty(), "allowed reuse match lost: {}", allowed);
}

#[tokio::test]
async fn restricted_admin_cannot_escape_through_self_role_identity_token_or_grants() {
    let f = Fixture::new().await;
    f.state.db().exec("INSERT INTO teams(id,org_id,name) VALUES('team','org','team')", &[]).await.unwrap();
    let rules = json!({"rules":[{"prefix":"/team/","capabilities":["read","write","delete"]}]});
    f.call("PUT", "/api/envs/env/path-policy/admin", "owner", Some(rules)).await.ok();
    for (method, path, body) in [
        ("PATCH", "/api/orgs/org/members/admin", json!({"role":"developer"})),
        ("POST", "/api/orgs/org/identities", json!({"name":"escape","role":"developer"})),
        ("POST", "/api/apps/app/tokens", json!({"name":"escape","scopes":"*"})),
        ("POST", "/api/envs/target/team-grants", json!({"team_id":"team"}))
    ] { f.call(method, path, "admin", Some(body)).await.forbidden(); }
    let row = f.state.db().one("SELECT role FROM org_members WHERE org_id='org' AND user_id='admin'", &[]).await.unwrap().unwrap();
    assert_eq!(row["role"], "admin");
    assert_eq!(f.state.db().query("SELECT id FROM identities", &[]).await.unwrap().len(), 1);
    assert!(f.state.db().query("SELECT id FROM tokens", &[]).await.unwrap().is_empty());
    assert!(f.state.db().query("SELECT team_id FROM team_env_grants", &[]).await.unwrap().is_empty());
}

#[tokio::test]
async fn mcp_filters_reads_checks_write_delete_paths_and_blocks_whole_environment_sync() {
    let f = Fixture::new().await;
    f.seed().await;
    f.state.db().exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES('sync','env','webhook','sync','unused',?)", &[json!(now())]).await.unwrap();
    f.restricted().await;
    let listed = rpc_ok(&f.mcp("dev", "list_secrets", json!({"env_id":"env"})).await);
    assert_eq!(listed.as_array().unwrap().len(), 3);
    assert!(!listed.to_string().contains("foreign-canary-value"), "MCP reference leak: {}", listed);
    rpc_ok(&f.mcp("dev", "set_secret", json!({"env_id":"env","key":"VISIBLE","value":"mcp-allowed","path":"/team/"})).await);
    rpc_denied(&f.mcp("dev", "set_secret", json!({"env_id":"env","key":"PRIVATE","value":"mcp-denied","path":"/team-other/"})).await);
    rpc_denied(&f.mcp("dev", "delete_secret", json!({"env_id":"env","key":"PRIVATE"})).await);
    rpc_denied(&f.mcp("dev", "sync_integration", json!({"integration_id":"sync"})).await);
    rpc_ok(&f.mcp("dev", "delete_secret", json!({"env_id":"env","key":"VISIBLE"})).await);
    let owner = f.call("GET", "/api/envs/env/secrets", "owner", None).await.ok();
    assert!(owner["secrets"].as_array().unwrap().iter().any(|s| s["key"] == "PRIVATE" && s["value"] == "foreign-canary-value"));
}

#[tokio::test]
async fn path_capabilities_never_grant_missing_role_or_token_scope_permissions() {
    let f = Fixture::new().await;
    f.seed().await;
    let sid = f.sid("VISIBLE").await;
    f.state.db().exec("INSERT INTO roles(id,org_id,name,permissions) VALUES('reader','org','reader',?)", &[json!(json!(["secrets:read"]).to_string())]).await.unwrap();
    f.state.db().exec("UPDATE org_members SET role='reader' WHERE org_id='org' AND user_id='dev'", &[]).await.unwrap();
    f.call("PUT", "/api/envs/env/path-policy/reader", "owner", Some(json!({"rules":[{"prefix":"/team/","capabilities":["read","write","delete"]}]}))).await.ok();
    let body = f.call("GET", "/api/envs/env/secrets", "dev", None).await.ok();
    assert_eq!(body["secrets"].as_array().unwrap().len(), 3);
    let write = json!({"secrets":[{"key":"VISIBLE","value":"denied","path":"/team/"}]});
    f.call("PUT", "/api/envs/env/secrets", "dev", Some(write.clone())).await.forbidden();
    f.call("POST", &format!("/api/secrets/{}/override", sid), "dev", Some(write.clone())).await.forbidden();
    f.call("DELETE", &format!("/api/secrets/{}", sid), "dev", None).await.forbidden();
    rpc_denied(&f.mcp("dev", "set_secret", json!({"env_id":"env","key":"VISIBLE","value":"denied","path":"/team/"})).await);
    rpc_denied(&f.mcp("dev", "delete_secret", json!({"env_id":"env","key":"VISIBLE"})).await);
    f.state.db().exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,scopes,created_at,created_by) VALUES('scoped','org','app','env','scoped',?,'secrets:read',?,'owner')", &[json!(oc::hash_token("scoped")), json!(now())]).await.unwrap();
    f.call("GET", "/api/envs/env/secrets", "scoped", None).await.ok();
    f.call("PUT", "/api/envs/env/secrets", "scoped", Some(write)).await.forbidden();
    rpc_denied(&f.mcp("scoped", "set_secret", json!({"env_id":"env","key":"VISIBLE","value":"denied","path":"/team/"})).await);
}

static SEQ: AtomicU32 = AtomicU32::new(0);
struct Native { child: Option<Child>, dir: PathBuf, base: String }
impl Drop for Native {
    fn drop(&mut self) { self.stop(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Native {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-workload-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        Self { child: None, dir, base: String::new() }
    }
    fn stop(&mut self) { if let Some(mut c) = self.child.take() { let _ = c.kill(); let _ = c.wait(); } }
    fn start(&mut self, kms: &str) { self.start_mode(kms, true); }
    fn start_mode(&mut self, kms: &str, production: bool) {
        assert!(self.child.is_none());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        self.base = format!("http://{}", addr);
        let log = std::fs::File::create(self.dir.join("server.log")).unwrap();
        self.child = Some(Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}", self.dir.join("test.db").display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_ENV", if production { "production" } else { "test" })
            .env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1")
            .env("OPENWARP_PUBLIC_URL", &self.base).env("OPENWARP_KMS_URL", kms)
            .env("TOKIO_WORKER_THREADS", "2").env_remove("OPENWARP_MASTER_KEY")
            .env_remove("OPENWARP_KMS_TOKEN").env_remove("REDIS_URL")
            .stdout(Stdio::null()).stderr(Stdio::from(log)).spawn().unwrap());
    }
    async fn healthy(&mut self) {
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(1)).build().unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() { panic!("production KMS startup exited {}: {}", status, std::fs::read_to_string(self.dir.join("server.log")).unwrap()); }
            if let Ok(r) = client.get(format!("{}/health", self.base)).send().await { if r.status().is_success() { return; } }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("production KMS startup did not become healthy");
    }
}
struct Bridge { url: String, task: tokio::task::JoinHandle<()>, calls: Arc<Mutex<Vec<(String, Value)>>>, bad: Arc<AtomicBool> }
impl Drop for Bridge { fn drop(&mut self) { self.task.abort(); } }
impl Bridge {
    async fn new() -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let bad = Arc::new(AtomicBool::new(false));
        let sink = calls.clone(); let fail = bad.clone();
        let app = Router::new().route("/{operation}", axum::routing::post(move |axum::extract::Path(op): axum::extract::Path<String>, axum::Json(body): axum::Json<Value>| {
            let sink = sink.clone(); let fail = fail.clone(); async move {
                sink.lock().unwrap().push((op.clone(), body.clone()));
                // The mock blob preserves the random root so a restart must unwrap the same bytes.
                axum::Json(if op == "wrap" { json!({"wrapped":body["plaintext"]}) }
                    else if fail.load(Ordering::SeqCst) { json!({"plaintext":oc::b64(b"short")}) }
                    else { json!({"plaintext":body["wrapped"]}) })
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { url, task, calls, bad }
    }
}

#[tokio::test]
async fn restricted_secret_mutations_do_not_automatically_sync_the_whole_environment() {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sink = calls.clone();
    let app = Router::new().route("/hook", axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
        let sink = sink.clone(); async move { sink.lock().unwrap().push(body); axum::Json(json!({"ok":true})) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook = format!("http://{}/hook", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort { fn drop(&mut self) { self.0.abort(); } }
    let _hook_task = Abort(task);
    let f = Fixture::new().await;
    f.seed().await;
    let sid = f.sid("VISIBLE").await;
    let mut server = Native::new();
    let db = Db::open(&format!("sqlite://{}", server.dir.join("test.db").display())).await.unwrap();
    db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&[7;32]))]).await.unwrap();
    for table in ["orgs", "users", "org_members", "sessions", "apps", "envs", "secrets", "secret_versions"] {
        for row in f.state.db().query(&format!("SELECT * FROM {}", table), &[]).await.unwrap() {
            let columns: Vec<_> = row.keys().cloned().collect();
            let values: Vec<_> = columns.iter().map(|k| row[k].clone()).collect();
            db.exec(&format!("INSERT INTO {}({}) VALUES({})", table, columns.join(","), vec!["?"; columns.len()].join(",")), &values).await.unwrap();
        }
    }
    server.start_mode("", false); server.healthy().await;
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10)).build().unwrap();
    let response = client.post(format!("{}/api/envs/env/integrations", server.base)).bearer_auth("owner")
        .json(&json!({"kind":"webhook","name":"probe","config":{"url":hook}})).send().await.unwrap();
    let status = response.status(); let integration: Value = response.json().await.unwrap();
    assert_eq!(status.as_u16(), 200, "{}", integration);
    let response = client.post(format!("{}/api/integrations/{}/sync", server.base, integration["id"].as_str().unwrap())).bearer_auth("owner").json(&json!({})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200, "owner sync must exercise mock provider");
    assert!(!calls.lock().unwrap().is_empty(), "mock provider never received positive-control sync");
    calls.lock().unwrap().clear();
    let response = client.put(format!("{}/api/envs/env/path-policy/developer", server.base)).bearer_auth("owner")
        .json(&json!({"rules":[{"prefix":"/team/","capabilities":["read","write","delete"]}]})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200, "policy setup failed");
    let response = client.put(format!("{}/api/envs/env/secrets", server.base)).bearer_auth("dev")
        .json(&json!({"secrets":[{"key":"VISIBLE","value":"restricted-change","path":"/team/"}]})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200, "allowed path write failed");
    assert!(calls.lock().unwrap().is_empty(), "restricted PUT triggered whole-environment sync");
    let response = client.delete(format!("{}/api/secrets/{}", server.base, sid)).bearer_auth("dev").send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200, "allowed path deletion failed");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(calls.lock().unwrap().is_empty(), "restricted deletion triggered whole-environment sync");
}

#[tokio::test]
async fn signed_workload_assertions_require_exact_claims_and_reject_replay() {
    use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts};
    let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let pem = private.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let url64 = |bytes: &[u8]| oc::b64(bytes).trim_end_matches('=').replace('+', "-").replace('/', "_");
    let jwks = json!({"keys":[{"kty":"RSA","kid":"test-key","alg":"RS256","use":"sig","n":url64(&private.n().to_bytes_be()),"e":url64(&private.e().to_bytes_be())}]});
    let app = Router::new().route("/jwks", axum::routing::get(move || { let jwks = jwks.clone(); async move { axum::Json(jwks) } }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort { fn drop(&mut self) { self.0.abort(); } }
    let _issuer_task = Abort(task);
    // Private egress is an operator setting confined to this child, not a process-global test override.
    let mut server = Native::new();
    server.start_mode("", false); server.healthy().await;
    let fixture = Fixture::new().await;
    let source = fixture.state.db();
    let target = Db::open(&format!("sqlite://{}", server.dir.join("test.db").display())).await.unwrap();
    for table in ["orgs", "users", "org_members", "sessions", "identities"] {
        for row in source.query(&format!("SELECT * FROM {}", table), &[]).await.unwrap() {
            let columns: Vec<_> = row.keys().cloned().collect();
            let values: Vec<_> = columns.iter().map(|k| row[k].clone()).collect();
            target.exec(&format!("INSERT INTO {}({}) VALUES({})", table, columns.join(","), vec!["?"; columns.len()].join(",")), &values).await.unwrap();
        }
    }
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10)).build().unwrap();
    let trust = client.put(format!("{}/api/orgs/org/identities/machine/workload", server.base)).bearer_auth("owner")
        .json(&json!({"issuer":issuer,"jwks_url":format!("{}/jwks", issuer),"audience":"openwarp","subject":"system:serviceaccount:team:runner","max_ttl_secs":300})).send().await.unwrap();
    let status = trust.status(); let text = trust.text().await.unwrap();
    assert_eq!(status.as_u16(), 200, "trust setup: {} {}", status, text);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256); header.kid = Some("test-key".into());
    let claims = json!({"iss":issuer,"aud":"openwarp","sub":"system:serviceaccount:team:runner","iat":now(),"nbf":now()-1,"exp":now()+120,"jti":"valid"});
    let endpoint = format!("{}/api/v1/machine/auth/workload/login", server.base);
    for (claim, value) in [("iss", json!("https://other.test")), ("aud", json!("other")), ("sub", json!("system:serviceaccount:other:runner")), ("exp", json!(now()-1)), ("nbf", json!(now()+120)), ("iat", Value::Null)] {
        let mut wrong = claims.clone(); wrong[claim] = value;
        if claim == "iat" { wrong.as_object_mut().unwrap().remove("iat"); }
        let jwt = jsonwebtoken::encode(&header, &wrong, &encoding).unwrap();
        let r = client.post(&endpoint).json(&json!({"identity_id":"machine","jwt":jwt})).send().await.unwrap();
        let status = r.status().as_u16(); let text = r.text().await.unwrap();
        assert!(matches!(status, 400 | 401 | 403 | 422), "wrong {} accepted or endpoint missing: {} {}", claim, status, text);
    }
    let jwt = jsonwebtoken::encode(&header, &claims, &encoding).unwrap();
    let input = json!({"identity_id":"machine","jwt":jwt});
    let first = client.post(&endpoint).json(&input).send().await.unwrap();
    let status = first.status(); let body: Value = first.json().await.unwrap();
    assert_eq!(status.as_u16(), 200, "signed login: {} {}", status, body);
    assert!(body["accessToken"].as_str().is_some_and(|s| !s.is_empty()), "{}", body);
    assert!(body["expiresIn"].as_i64().is_some_and(|ttl| ttl > 0 && ttl <= 120), "access token outlives assertion: {}", body);
    let replay = client.post(&endpoint).json(&input).send().await.unwrap();
    assert!(matches!(replay.status().as_u16(), 400 | 401 | 403 | 409), "replay accepted: {}", replay.status());
}

#[tokio::test]
async fn production_kms_boots_without_master_env_and_restart_unwraps_the_same_root() {
    let bridge = Bridge::new().await;
    let mut server = Native::new();
    server.start(&bridge.url); server.healthy().await;
    let conn = rusqlite::Connection::open(server.dir.join("test.db")).unwrap();
    let root: String = conn.query_row("SELECT v FROM meta WHERE k='kms_root'", [], |r| r.get(0)).unwrap();
    let plaintext_rows: i64 = conn.query_row("SELECT count(*) FROM meta WHERE k='master'", [], |r| r.get(0)).unwrap();
    assert_eq!(plaintext_rows, 0);
    server.stop();
    server.start(&bridge.url); server.healthy().await;
    let after: String = conn.query_row("SELECT v FROM meta WHERE k='kms_root'", [], |r| r.get(0)).unwrap();
    assert_eq!(root, after);
    let calls = bridge.calls.lock().unwrap();
    let wraps: Vec<_> = calls.iter().filter(|(op, _)| op == "wrap").collect();
    assert_eq!(wraps.len(), 1, "restart must not generate a root");
    let unwraps: Vec<_> = calls.iter().filter(|(op, _)| op == "unwrap").collect();
    assert!(!unwraps.is_empty(), "restart did not recover the persisted root");
    assert_eq!(unwraps[0].1["wrapped"], wraps[0].1["plaintext"]);
    assert_eq!(unwraps[0].1["context"], "master");
}

#[tokio::test]
async fn production_kms_bad_unwrap_is_fatal_without_replacing_the_persisted_root() {
    let bridge = Bridge::new().await;
    let mut server = Native::new();
    let db = Db::open(&format!("sqlite://{}", server.dir.join("test.db").display())).await.unwrap();
    let root = format!("owkms:primary:{}", oc::b64(&[9;32]));
    db.exec("INSERT INTO meta(k,v) VALUES('kms_root',?)", &[json!(root)]).await.unwrap();
    bridge.bad.store(true, Ordering::SeqCst);
    server.start(&bridge.url);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() { assert!(!status.success()); break; }
        assert!(Instant::now() < deadline, "bad unwrap did not stop startup");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(bridge.calls.lock().unwrap().iter().any(|(op, _)| op == "unwrap"), "startup must reach KMS unwrap rather than rejecting absent master env first");
    assert_eq!(db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap().unwrap()["v"], root);
    assert!(db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().is_none());
}
