use axum::{extract::State, routing::post, Json, Router};
use hmac::Mac;
use openwarp_crypto as oc;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
const AUTH_KEY: [u8; 32] = [3; 32];
struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, mail: Arc<Mutex<Vec<Value>>>, mail_task: tokio::task::JoinHandle<()> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); self.mail_task.abort(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-hardening-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{}", port);
        let log = std::fs::File::create(dir.join("server.log")).unwrap();
        let mail_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mail_url = format!("http://{}/mail", mail_listener.local_addr().unwrap());
        let mail = Arc::new(Mutex::new(Vec::new()));
        async fn receive(State(inbox): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>) -> Json<Value> { inbox.lock().unwrap().push(body); Json(json!({})) }
        let mail_app = Router::new().route("/mail", post(receive)).with_state(mail.clone());
        let mail_task = tokio::spawn(async move { axum::serve(mail_listener, mail_app).await.unwrap(); });
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port)).env("OPENWARP_PUBLIC_URL", &base)
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL").env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_KMS_URL").env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", mail_url)
            .env_remove("OPENWARP_AUTH_PROVIDERS").env_remove("OPENWARP_SIGNUPS")
            .env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_REQUIRE_EMAIL_VERIFICATION")
            .stdout(Stdio::null()).stderr(Stdio::from(log)).spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let s = Self { child, base, dir, client, mail, mail_task };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    fn db(&self) -> rusqlite::Connection { rusqlite::Connection::open(self.dir.join("test.db")).unwrap() }
    async fn request(&self, method: Method, path: &str, token: &str, cookie: bool, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = if cookie { req.header("Cookie", format!("ow_session={}", token)) } else { req.bearer_auth(token) }; }
        if let Some(body) = body { req = req.json(&body); }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp { self.request(method, path, token, false, body).await }
    async fn ok(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Value {
        let r = self.call(method, path, token, body).await;
        assert_eq!(r.status, 200, "fixture request failed: {}", path); r.body
    }
    async fn register(&self, email: &str) -> Value {
        self.ok(Method::POST, "/api/auth/register-v2", "", Some(json!({
            "email": email, "salt": oc::b64(&[1; 16]), "iterations": 600000, "algo": "pbkdf2-sha256",
            "auth_key": oc::b64(&AUTH_KEY), "public_key": oc::Keypair::generate().public,
            "wrapped_privkey": format!("owv2:{}", oc::b64(&[9; 40]))
        }))).await
    }
    fn verification_path(&self) -> String {
        self.mail.lock().unwrap().iter().rev().filter_map(|m| m["text"].as_str()).find_map(|text| text.split_whitespace()
            .find_map(|word| word.find("/api/auth/verify?token=").map(|i| word[i..].to_string()))).expect("verification link in mail")
    }
    async fn ok_stepped_up(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Value {
        let before = self.mail.lock().unwrap().len();
        let start = self.ok(Method::POST, "/api/auth/step-up/start", token, Some(json!({"risk": "very_risky"}))).await;
        assert_eq!(start["email_sent"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        let code = loop {
            let code = self.mail.lock().unwrap().iter().skip(before).filter_map(|m| m["text"].as_str())
                .find_map(|text| text.split(|c: char| !c.is_ascii_digit()).find(|s| s.len() == 6).map(str::to_string));
            if let Some(code) = code { break code; }
            assert!(Instant::now() < deadline, "fresh step-up mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let verified = self.ok(Method::POST, "/api/auth/step-up/verify", token, Some(json!({"challenge": start["challenge"], "email_code": code}))).await;
        let mut request = self.client.request(method, format!("{}{}", self.base, path)).bearer_auth(token).header("x-openwarp-step-up", verified["token"].as_str().unwrap());
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.unwrap(); assert_eq!(response.status(), 200, "fixture request failed: {}", path);
        response.json().await.unwrap()
    }
    async fn login(&self, email: &str) -> Value {
        let ch = self.ok(Method::POST, "/api/auth/challenge", "", Some(json!({"email": email}))).await;
        let id = ch["challenge_id"].as_str().unwrap();
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&AUTH_KEY).unwrap();
        mac.update(format!("{}|{}", ch["challenge"].as_str().unwrap(), id).as_bytes());
        let proof: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        self.ok(Method::POST, "/api/auth/login-v2", "", Some(json!({"email": email, "challenge_id": id, "proof": proof}))).await
    }
    async fn user(&self, email: &str) -> Value {
        let mut u = self.register(email).await;
        self.ok(Method::GET, &self.verification_path(), "", None).await;
        u["token"] = self.login(email).await["token"].clone(); u
    }
    async fn app(&self, u: &Value) -> (String, Vec<String>) {
        let token = u["token"].as_str().unwrap();
        let a = self.ok(Method::POST, &format!("/api/orgs/{}/apps", u["org_id"].as_str().unwrap()), token, Some(json!({"name": "app"}))).await;
        let app = a["id"].as_str().unwrap().to_string();
        let envs = self.ok(Method::GET, &format!("/api/apps/{}/envs", app), token, None).await;
        (app, envs.as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap().to_string()).collect())
    }
    async fn member(&self, owner: &Value, role: &str) -> Value {
        let u = self.user("member@test.invalid").await;
        let inv = self.ok(Method::POST, &format!("/api/orgs/{}/members", owner["org_id"].as_str().unwrap()), owner["token"].as_str().unwrap(), Some(json!({"email": "member@test.invalid", "role": role}))).await;
        let invite = inv["invite_token"].as_str().unwrap().to_string();
        self.ok(Method::POST, "/api/auth/accept-invite-v2", u["token"].as_str().unwrap(), Some(json!({"token": invite}))).await; u
    }
    async fn pat(&self, app: &str, token: &str, env: &str, scopes: &str) -> String {
        self.ok(Method::POST, &format!("/api/apps/{}/tokens", app), token, Some(json!({"name": "bounded", "env_id": env, "scopes": scopes}))).await["token"].as_str().unwrap().to_string()
    }
    async fn secret(&self, token: &str, env: &str, value: &str) {
        self.ok(Method::PUT, &format!("/api/envs/{}/secrets", env), token, Some(json!({"secrets": [{"key": "PINNED", "value": value}]}))).await;
    }
}

#[tokio::test]
async fn first_verified_account_owns_instance_even_after_an_earlier_v2_signup() {
    let s = Server::start().await;
    s.register("unverified@test.invalid").await;
    let earlier_link = s.verification_path();
    let owner = s.user("verified@test.invalid").await;
    let token = owner["token"].as_str().unwrap();
    let before = s.ok(Method::GET, "/api/instance", token, None).await;
    s.ok(Method::GET, &earlier_link, "", None).await;
    let earlier = s.login("unverified@test.invalid").await;
    let later = s.ok(Method::GET, "/api/instance", earlier["token"].as_str().unwrap(), None).await;
    let after = s.ok(Method::GET, "/api/instance", token, None).await;
    assert_eq!((before["instance_owner"].clone(), after["instance_owner"].clone(), later["instance_owner"].clone()),
        (json!(true), json!(true), json!(false)), "first verification must claim ownership permanently, not first registration");
}

#[tokio::test]
async fn cookie_cannot_bypass_service_token_environment_scope() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let ot = u["token"].as_str().unwrap();
    let (app, envs) = s.app(&u).await;
    let pat = s.pat(&app, ot, &envs[0], "*").await;
    let source = format!("/api/envs/{}/secrets", envs[0]);
    let target = format!("/api/envs/{}/secrets", envs[1]);
    assert_eq!(s.call(Method::GET, &source, &pat, None).await.status, 200);
    assert_eq!(s.request(Method::GET, &target, ot, true, None).await.status, 200, "real session cookies must work");
    assert_eq!(s.call(Method::GET, &target, &pat, None).await.status, 403);
    let r = s.request(Method::GET, &target, &pat, true, None).await;
    assert!(matches!(r.status, 401 | 403), "service token in cookie must not escape its environment; got {}", r.status);
}

#[tokio::test]
async fn cookie_cannot_bypass_service_or_oauth_read_only_scopes() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let ot = u["token"].as_str().unwrap();
    let (app, envs) = s.app(&u).await;
    let pat = s.pat(&app, ot, "", "secrets:read").await;
    // Seed an issued OAuth credential, not an OAuth server implementation detail.
    let oauth = "disposable-oauth-access";
    s.db().execute("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,expires_at,created_at) VALUES(?,?,?,?,?,?,?)",
        rusqlite::params![oc::hash_token(oauth), "fixture-client", u["user_id"].as_str().unwrap(), "secrets:read", s.base, 4_000_000_000i64, 0i64]).unwrap();
    let path = format!("/api/envs/{}/secrets", envs[0]);
    let mut cookie_statuses = Vec::new();
    for token in [pat.as_str(), oauth] {
        assert_eq!(s.call(Method::GET, &path, token, None).await.status, 200);
        let body = json!({"secrets": [{"key": "FORBIDDEN", "value": "value"}]});
        assert_eq!(s.call(Method::PUT, &path, token, Some(body.clone())).await.status, 403);
        cookie_statuses.push(s.request(Method::PUT, &path, token, true, Some(body)).await.status);
    }
    assert!(cookie_statuses.iter().all(|s| matches!(s, 401 | 403)), "read-only PAT and OAuth cookies must not write; got {:?}", cookie_statuses);
}

#[tokio::test]
async fn cookie_cannot_convert_a_machine_token_into_a_permanent_service_token() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let ot = u["token"].as_str().unwrap();
    let (app, _) = s.app(&u).await;
    let identity = s.ok(Method::POST, &format!("/api/orgs/{}/identities", u["org_id"].as_str().unwrap()), ot, Some(json!({"name": "machine", "role": "developer"}))).await;
    let machine = s.ok(Method::POST, "/api/v1/machine/auth/universal/login", "", Some(json!({"client_id": identity["client_id"], "client_secret": identity["client_secret"]}))).await;
    let mt = machine["accessToken"].as_str().unwrap();
    let path = format!("/api/apps/{}/tokens", app);
    let body = json!({"name": "must-not-exist"});
    assert_eq!(s.call(Method::POST, &path, mt, Some(body.clone())).await.status, 403);
    let r = s.request(Method::POST, &path, mt, true, Some(body)).await;
    assert!(matches!(r.status, 401 | 403), "machine cookie must not mint a permanent credential; got {}", r.status);
}

async fn scoped_secondary_target(clone: bool) {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let ot = u["token"].as_str().unwrap();
    let (app, envs) = s.app(&u).await;
    s.secret(ot, &envs[0], "source").await;
    s.secret(ot, &envs[1], "target").await;
    let pat = s.pat(&app, ot, &envs[0], "*").await;
    assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), &pat, None).await.status, 200);
    assert_eq!(s.call(Method::GET, &format!("/api/envs/{}/secrets", envs[1]), &pat, None).await.status, 403);
    let r = if clone {
        s.call(Method::POST, &format!("/api/envs/{}/clone", envs[0]), &pat, Some(json!({"target_env_id": envs[1], "overwrite": true}))).await
    } else {
        s.call(Method::GET, &format!("/api/envs/{}/compare?other={}", envs[0], envs[1]), &pat, None).await
    };
    let target = s.ok(Method::GET, &format!("/api/envs/{}/secrets", envs[1]), ot, None).await;
    assert_eq!(r.status, 403, "secondary environment must obey source token scope (clone={})", clone);
    assert_eq!(target["secrets"][0]["value"], "target", "denied request must not mutate target");
    let compare = s.ok(Method::GET, &format!("/api/envs/{}/compare?other={}", envs[0], envs[1]), ot, None).await;
    assert_eq!(compare["changed"].as_array().unwrap().len(), 1);
    s.ok(Method::POST, &format!("/api/envs/{}/clone", envs[0]), ot, Some(json!({"target_env_id": envs[1], "overwrite": true}))).await;
}
#[tokio::test]
async fn clone_checks_target_environment_scope() { scoped_secondary_target(true).await; }
#[tokio::test]
async fn compare_checks_other_environment_scope() { scoped_secondary_target(false).await; }

#[tokio::test]
async fn clone_source_environment_obeys_token_scope() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let ot = u["token"].as_str().unwrap();
    let (app, envs) = s.app(&u).await;
    s.secret(ot, &envs[0], "target").await;
    s.secret(ot, &envs[1], "source").await;
    let pat = s.pat(&app, ot, &envs[0], "*").await;
    let r = s.call(Method::POST, &format!("/api/envs/{}/clone", envs[1]), &pat, Some(json!({"target_env_id": envs[0], "overwrite": true}))).await;
    assert_eq!(r.status, 403, "the source environment must obey the credential scope, not only the target");
    let after = s.ok(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), ot, None).await;
    assert_eq!(after["secrets"][0]["value"], "target", "denied clone must not overwrite the target");
}

#[tokio::test]
async fn approval_required_env_blocks_every_direct_write_path() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let member = s.member(&u, "developer").await;
    let ot = u["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let (_, envs) = s.app(&u).await;
    s.secret(ot, &envs[0], "v1").await;
    let sid = {
        s.ok(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), ot, Some(json!({"secrets": [{"key": "SECOND", "value": "v2"}]}))).await;
        let listed = s.ok(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), ot, None).await;
        listed["secrets"].as_array().unwrap().iter().find(|x| x["key"] == "PINNED").unwrap()["id"].as_str().unwrap().to_string()
    };
    // Give the pinned secret a second version so restore has a prior value to roll back to.
    s.ok(Method::PUT, &format!("/api/envs/{}/secrets", envs[0]), ot, Some(json!({"secrets": [{"key": "PINNED", "value": "v2"}]}))).await;
    s.ok(Method::PUT, &format!("/api/envs/{}/policy", envs[0]), ot, Some(json!({"require_approval": true}))).await;
    let rotate = s.call(Method::POST, &format!("/api/envs/{}/rotate", envs[0]), mt, Some(json!({"key": "PINNED", "value": "rotated"}))).await;
    let restore = s.call(Method::POST, &format!("/api/secrets/{}/restore/1", sid), mt, None).await;
    let pitr = s.call(Method::POST, &format!("/api/envs/{}/restore-point", envs[0]), mt, Some(json!({"timestamp": 0}))).await;
    assert_eq!((rotate.status, restore.status, pitr.status), (403, 403, 403), "the approval policy must gate rotate, restore and point-in-time restore");
    let after = s.ok(Method::GET, &format!("/api/envs/{}/secrets", envs[0]), ot, None).await;
    let values: Vec<&str> = after["secrets"].as_array().unwrap().iter().filter_map(|s| s["value"].as_str()).collect();
    assert_eq!(values.len(), 2, "denied writes must not remove secrets");
    assert!(!values.contains(&"rotated"), "denied rotation must not change the value");
    assert!(values.contains(&"v2"), "denied restore must not roll the value back to v1");
    // Tombstoning stays deliberately open (the undelete gate covers reversal);
    // undeleting around the policy must still be denied.
    let undelete = s.call(Method::POST, &format!("/api/secrets/{}/undelete", sid), mt, None).await;
    assert_eq!(undelete.status, 403, "a developer must not undelete around the approval policy");
    s.ok(Method::DELETE, &format!("/api/secrets/{}", sid), mt, None).await;
    s.ok(Method::POST, &format!("/api/secrets/{}/undelete", sid), ot, None).await;
}

#[tokio::test]
async fn e2e_rekey_needs_approval() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let member = s.member(&u, "developer").await;
    let ot = u["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let (app, _) = s.app(&u).await;
    let key = oc::random_key();
    let env = s.ok(Method::POST, &format!("/api/apps/{}/envs/e2e", app), ot, Some(json!({"name": "encrypted", "wrapped_key": oc::encrypt_to(u["public_key"].as_str().unwrap(), &key).unwrap()}))).await;
    let eid = env["id"].as_str().unwrap();
    s.ok(Method::POST, &format!("/api/envs/{}/e2e/grant", eid), ot, Some(json!({"email": "member@test.invalid", "wrapped_key": oc::encrypt_to(member["public_key"].as_str().unwrap(), &key).unwrap()}))).await;
    let path = format!("/api/envs/{}/e2e/secrets", eid);
    let body = json!({"secrets": [{"key_hash": oc::hash_token("KEY"), "key_enc": oc::encrypt_symmetric(&key, b"KEY"), "value_enc": oc::encrypt_symmetric(&key, b"original")}]});
    s.ok(Method::PUT, &path, mt, Some(body.clone())).await;
    s.ok(Method::PUT, &format!("/api/envs/{}/policy", eid), ot, Some(json!({"require_approval": true}))).await;
    let r = s.call(Method::POST, &format!("/api/envs/{}/e2e/rekey", eid), mt, Some(json!({"secrets": [{"key_hash": oc::hash_token("KEY"), "key_enc": "x", "value_enc": "attacker-replacement", "path_enc": "x"}], "grants": [{"user_id": member["user_id"], "wrapped_key": "x"}]}))).await;
    assert_eq!(r.status, 403, "rekeying must obey the approval policy like any other write, got {}", r.body);
    let after = s.ok(Method::GET, &path, mt, None).await;
    assert_eq!(after["secrets"][0]["value_enc"], body["secrets"][0]["value_enc"], "denied rekey must preserve ciphertext");
}

#[tokio::test]
async fn clone_respects_target_approval_policy() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let member = s.member(&u, "developer").await;
    let ot = u["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let (_, envs) = s.app(&u).await;
    s.secret(ot, &envs[0], "source").await;
    s.secret(ot, &envs[1], "target").await;
    s.ok(Method::PUT, &format!("/api/envs/{}/policy", envs[1]), ot, Some(json!({"require_approval": true}))).await;
    let path = format!("/api/envs/{}/clone", envs[0]);
    let body = json!({"target_env_id": envs[1], "overwrite": true});
    let r = s.call(Method::POST, &path, mt, Some(body.clone())).await;
    assert_eq!(r.status, 403, "developer clone must not bypass target approval policy");
    let target = s.ok(Method::GET, &format!("/api/envs/{}/secrets", envs[1]), ot, None).await;
    assert_eq!(target["secrets"][0]["value"], "target");
    s.ok(Method::POST, &path, ot, Some(body)).await;
}

#[tokio::test]
async fn admin_cannot_rotate_privileged_machine_credentials() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let admin = s.member(&u, "admin").await;
    let ot = u["token"].as_str().unwrap();
    let at = admin["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    s.ok(Method::POST, &format!("/api/orgs/{}/roles", org), ot, Some(json!({"name": "operator", "permissions": ["org:admin"]}))).await;
    let mut denied = Vec::new();
    for role in ["developer", "admin", "operator"] {
        let identity = s.ok(Method::POST, &format!("/api/orgs/{}/identities", org), ot, Some(json!({"name": role, "role": role}))).await;
        let path = format!("/api/orgs/{}/identities/{}/rotate", org, identity["id"].as_str().unwrap());
        let r = s.call(Method::POST, &path, at, Some(json!({}))).await;
        if role == "developer" { assert_eq!(r.status, 200, "admins may rotate nonprivileged identities"); }
        else { denied.push(r.status); }
        s.ok(Method::POST, &path, ot, Some(json!({}))).await;
    }
    assert_eq!(denied, vec![403, 403], "only owners may rotate admin-equivalent machine credentials");
}

#[tokio::test]
async fn e2e_developer_with_a_key_still_needs_approval() {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let member = s.member(&u, "developer").await;
    let ot = u["token"].as_str().unwrap();
    let mt = member["token"].as_str().unwrap();
    let (app, _) = s.app(&u).await;
    let key = oc::random_key();
    let env = s.ok(Method::POST, &format!("/api/apps/{}/envs/e2e", app), ot, Some(json!({"name": "encrypted", "wrapped_key": oc::encrypt_to(u["public_key"].as_str().unwrap(), &key).unwrap()}))).await;
    let eid = env["id"].as_str().unwrap();
    s.ok(Method::POST, &format!("/api/envs/{}/e2e/grant", eid), ot, Some(json!({"email": "member@test.invalid", "wrapped_key": oc::encrypt_to(member["public_key"].as_str().unwrap(), &key).unwrap()}))).await;
    let path = format!("/api/envs/{}/e2e/secrets", eid);
    let body = json!({"secrets": [{"key_hash": oc::hash_token("KEY"), "key_enc": oc::encrypt_symmetric(&key, b"KEY"), "value_enc": oc::encrypt_symmetric(&key, b"original")}]});
    s.ok(Method::PUT, &path, mt, Some(body.clone())).await;
    s.ok(Method::PUT, &format!("/api/envs/{}/policy", eid), ot, Some(json!({"require_approval": true}))).await;
    let before = s.ok(Method::GET, &path, mt, None).await;
    let mut changed = body.clone(); changed["secrets"][0]["value_enc"] = json!(oc::encrypt_symmetric(&key, b"changed"));
    let r = s.call(Method::PUT, &path, mt, Some(changed.clone())).await;
    assert_eq!(r.status, 403, "having an E2E key must not bypass approval policy");
    let after = s.ok(Method::GET, &path, mt, None).await;
    assert_eq!(after["secrets"], before["secrets"], "denied E2E write must preserve ciphertext and version");
    s.ok(Method::PUT, &path, ot, Some(changed)).await;
}

async fn runner_allowlist(result: bool) {
    let s = Server::start().await;
    let u = s.user("owner@test.invalid").await;
    let ot = u["token"].as_str().unwrap();
    let org = u["org_id"].as_str().unwrap();
    let (_, envs) = s.app(&u).await;
    let runner = s.ok(Method::POST, &format!("/api/orgs/{}/runners", org), ot, Some(json!({"name": "runner", "public_key": oc::Keypair::generate().public}))).await;
    let rt = runner["token"].as_str().unwrap(); let rid = runner["id"].as_str().unwrap();
    let conn = s.db();
    conn.execute("UPDATE envs SET mode='delegated',runner_id=? WHERE id=?", rusqlite::params![rid, envs[0]]).unwrap();
    conn.execute("INSERT INTO runner_env_keys(runner_id,env_id,wrapped_key) VALUES(?,?,?)", rusqlite::params![rid, envs[0], "fixture-wrapped-key"]).unwrap();
    conn.execute("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES('fixture-integration',?,'webhook','fixture','sealed-fixture',0)", [&envs[0]]).unwrap();
    conn.execute("INSERT INTO sync_jobs(id,env_id,integration_id,runner_id,created_at) VALUES('fixture-job',?,'fixture-integration',?,0)", rusqlite::params![envs[0], rid]).unwrap();
    let claim = if result {
        let jobs = s.ok(Method::GET, "/api/runner/jobs", rt, None).await;
        assert_eq!(jobs["jobs"].as_array().unwrap().len(), 1);
        jobs["jobs"][0]["claim"].as_str().unwrap().to_string()
    } else { String::new() };
    s.ok_stepped_up(Method::PUT, &format!("/api/orgs/{}/settings", org), ot, Some(json!({"ip_allowlist": "192.0.2.0/24"}))).await;
    assert_eq!(s.call(Method::GET, &format!("/api/orgs/{}/settings", org), ot, None).await.status, 403, "fixture must exclude loopback");
    let r = if result {
        s.call(Method::POST, "/api/runner/jobs/fixture-job/result", rt, Some(json!({"ok": true, "claim": claim}))).await
    } else { s.call(Method::GET, "/api/runner/jobs", rt, None).await };
    assert_eq!(r.status, 403, "runner route must enforce its organisation IP allowlist (result={})", result);
    // Re-open the disposable fixture to inspect the queue through the runner API.
    conn.execute("UPDATE orgs SET ip_allowlist='' WHERE id=?", [org]).unwrap();
    let jobs = s.ok(Method::GET, "/api/runner/jobs", rt, None).await;
    if result {
        assert!(jobs["jobs"].as_array().unwrap().is_empty(), "denied result must leave the live claim intact");
        s.ok(Method::POST, "/api/runner/jobs/fixture-job/result", rt, Some(json!({"ok": true, "claim": claim}))).await;
    } else { assert_eq!(jobs["jobs"].as_array().unwrap().len(), 1, "denied polling must not claim a job"); }
}
#[tokio::test]
async fn runner_polling_enforces_organisation_ip_allowlist() { runner_allowlist(false).await; }
#[tokio::test]
async fn runner_results_enforce_organisation_ip_allowlist() { runner_allowlist(true).await; }

async fn sibling_reset_links(v2: bool) {
    let s = Server::start().await;
    let u = if v2 { s.user("reset@test.invalid").await } else {
        let mut u = s.ok(Method::POST, "/api/auth/register", "", Some(json!({"email": "reset@test.invalid", "password": "correct-horse-battery"}))).await;
        s.ok(Method::GET, &s.verification_path(), "", None).await;
        u["token"] = s.ok(Method::POST, "/api/auth/login", "", Some(json!({"email": "reset@test.invalid", "password": "correct-horse-battery"}))).await["token"].clone(); u
    };
    for token in ["reset-first", "reset-sibling"] {
        s.db().execute("INSERT INTO auth_tokens(token_hash,user_id,kind,created_at,expires_at,used) VALUES(?,?,'reset',0,?,0)",
            rusqlite::params![oc::hash_token(token), u["user_id"].as_str().unwrap(), 4_000_000_000i64]).unwrap();
    }
    let path = if v2 { "/api/auth/reset-v2" } else { "/api/auth/reset" };
    let payload = |token: &str| if v2 { json!({"token": token, "salt": oc::b64(&[2; 16]), "iterations": 600000, "algo": "pbkdf2-sha256", "auth_key": oc::b64(&AUTH_KEY), "public_key": u["public_key"], "wrapped_privkey": format!("owv2:{}", oc::b64(&[9; 40]))}) }
        else { json!({"token": token, "password": "replacement-password", "recovery_kit": u["recovery_kit"]}) };
    s.ok(Method::POST, path, "", Some(payload("reset-first"))).await;
    assert_eq!(s.call(Method::GET, "/api/me", u["token"].as_str().unwrap(), None).await.status, 401, "reset revokes old sessions");
    assert_eq!(s.call(Method::POST, path, "", Some(payload("reset-first"))).await.status, 400, "same link cannot be replayed");
    let r = s.call(Method::POST, path, "", Some(payload("reset-sibling"))).await;
    assert_eq!(r.status, 400, "successful reset invalidates other outstanding reset links (v2={})", v2);
}
#[tokio::test]
async fn v1_reset_invalidates_other_outstanding_reset_links() { sibling_reset_links(false).await; }
#[tokio::test]
async fn v2_reset_invalidates_other_outstanding_reset_links() { sibling_reset_links(true).await; }
