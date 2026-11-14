use axum::{body::{to_bytes, Body}, extract::State, http::Request, routing::post, Json, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, process_maintenance, router, S};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static SEQ: AtomicU32 = AtomicU32::new(0);
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OLD: &str = "openwarp-regression-old-password";
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
type Inbox = Arc<Mutex<Vec<Value>>>;
async fn capture_mail(State(inbox): State<Inbox>, Json(body): Json<Value>) -> Json<Value> {
    inbox.lock().unwrap().push(body); Json(json!({}))
}
async fn read_mail(State(inbox): State<Inbox>) -> Json<Value> { Json(json!(inbox.lock().unwrap().clone())) }
struct MailRelay(tokio::task::JoinHandle<()>);
impl Drop for MailRelay { fn drop(&mut self) { self.0.abort(); } }
async fn isolated_case(name: &'static str, target: &str) {
    if std::env::var("OPENWARP_ROTATION_REGRESSION_CHILD").as_deref() == Ok(name) {
        pending_password_blocks_delete(target).await; return;
    }
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mail", socket.local_addr().unwrap());
    let app = Router::new().route("/mail", post(capture_mail).get(read_mail)).with_state(Inbox::default());
    let _relay = MailRelay(tokio::spawn(async move { axum::serve(socket, app).await.unwrap(); }));
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    // Isolate mail configuration in this exact test's child, never the shared test process.
    for (key, _) in std::env::vars_os() {
        let key_name = key.to_string_lossy();
        if (key_name.starts_with("OPENWARP_") && key_name != "OPENWARP_TEST_STATIC_PG") || matches!(key_name.as_ref(), "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY" | "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy") { command.env_remove(key); }
    }
    command.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("OPENWARP_ROTATION_REGRESSION_CHILD", name).env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", url);
    let output = tokio::task::spawn_blocking(move || command.output().expect("run isolated rotation fixture")).await.unwrap();
    assert!(output.status.success(), "isolated rotation fixture failed ({:?})", output.status.code());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().any(|line| line == "running 1 test")
        && stdout.lines().any(|line| line == format!("test {name} ... ok"))
        && stdout.lines().any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; ")),
        "isolated rotation fixture must execute exactly its selected test with one pass and no ignored tests");
}
struct Allow(Option<String>);
impl Drop for Allow {
    fn drop(&mut self) { match &self.0 { Some(v) => std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", v), None => std::env::remove_var("OPENWARP_ALLOWED_DB_HOSTS") } }
}
async fn connect(config: &tokio_postgres::Config) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(async move { let _ = connection.await; });
    Ok(client)
}
struct Role { admin: tokio_postgres::Client, name: String, config: tokio_postgres::Config }
impl Role {
    async fn new(url: &str) -> Self {
        let config: tokio_postgres::Config = url.parse().unwrap();
        let admin = connect(&config).await.expect("connect dedicated test database");
        let name = format!("ow_regression_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst));
        admin.batch_execute(&format!("CREATE ROLE \"{}\" LOGIN PASSWORD '{}'", name, OLD)).await.unwrap();
        Self { admin, name, config }
    }
    async fn authenticates(&self, password: &str) -> bool {
        let mut config = self.config.clone(); config.user(&self.name).password(password);
        match connect(&config).await { Ok(client) => client.simple_query("SELECT 1").await.is_ok(), Err(_) => false }
    }
    async fn cleanup(&self) { self.admin.batch_execute(&format!("DROP ROLE \"{}\"", self.name)).await.unwrap(); }
}
struct Fixture { state: S, app: Router }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','owner@test.invalid','unused','unused','unused',?,1)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token("owner")),json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','app',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES('env','app','env',?,'sse',?)", &[json!(oc::encrypt_symmetric(&[7;32], &[8;32])),json!(now())]).await.unwrap();
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "rotation-regressions".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature="redis-cache")] None);
        let app = router(state.clone()); let f = Self { state, app };
        assert_eq!(f.call("PUT", "/api/envs/env/secrets", json!({"secrets":[{"key":"DB_PASSWORD","value":OLD,"path":"/"}]})).await.0, 200);
        f
    }
    async fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) { self.call_with_grant(method, path, body, None).await }
    async fn call_with_grant(&self, method: &str, path: &str, body: Value, grant: Option<&str>) -> (u16, Value) {
        let mut request = Request::builder().method(method).uri(path).header("authorization", "Bearer owner")
            .header("content-type", "application/json").extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])));
        if let Some(grant) = grant { request = request.header("x-openwarp-step-up", grant); }
        let request = request.body(if body.is_null() { Body::empty() } else { Body::from(body.to_string()) }).unwrap();
        let r = self.app.clone().oneshot(request).await.unwrap(); let status = r.status().as_u16();
        let bytes = to_bytes(r.into_body(), 1024*1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
    async fn run(&self, rid: &str) {
        let r = self.call("POST", &format!("/api/rotations/{}/run", rid), json!({})).await;
        assert_eq!(r.0, 200, "manual schedule: {:?}", r);
        assert_eq!(r.1["scheduled"], true);
        process_maintenance(&self.state).await;
    }
    async fn pending(&self, rid: &str) -> Option<String> {
        self.state.db().one("SELECT pending_enc FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.unwrap()
            .map(|r| r["pending_enc"].as_str().unwrap().into())
    }
    async fn export_grant(&self) -> String {
        let relay = std::env::var("OPENWARP_EMAIL_WEBHOOK").expect("isolated mail relay");
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
        let before: Vec<Value> = client.get(&relay).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        let (status, started) = self.call("POST", "/api/auth/step-up/start", json!({"risk":"very_risky"})).await;
        assert_eq!(status, 200, "start positive export email proof");
        assert_eq!(started["email_sent"], true, "export proof must send email");
        let inbox: Vec<Value> = client.get(&relay).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        let mail = inbox.get(before.len()).expect("fresh verification email");
        assert_eq!(mail["to"], "owner@test.invalid", "proof belongs to the exporting owner");
        let text = mail["text"].as_str().unwrap();
        let code = text.split_once("Your verification code is ").expect("email verification code").1
            .split(|c: char| !c.is_ascii_digit()).next().filter(|s| s.len() == 6).expect("six-digit email proof");
        let (status, verified) = self.call("POST", "/api/auth/step-up/verify", json!({"challenge":started["challenge"],"email_code":code})).await;
        assert_eq!(status, 200, "verify positive export email proof");
        verified["token"].as_str().filter(|s| !s.is_empty()).expect("fresh export grant").into()
    }
    async fn value(&self) -> String {
        let grant = self.export_grant().await;
        let (status, body) = self.call_with_grant("GET", "/api/envs/env/export?base=1", Value::Null, Some(&grant)).await;
        assert_eq!(status,200,"{}",body);
        body["secrets"].as_array().unwrap().iter().find(|s| s["key"]=="DB_PASSWORD").unwrap()["value"].as_str().unwrap().into()
    }
}

async fn pending_password_blocks_delete(target: &str) {
    let url = std::env::var("OPENWARP_TEST_STATIC_PG").expect("regression qualification requires OPENWARP_TEST_STATIC_PG pointing at a disposable PostgreSQL database");
    let _lock = ENV_LOCK.lock().await;
    let config: tokio_postgres::Config = url.parse().unwrap();
    let host = match &config.get_hosts()[0] { tokio_postgres::config::Host::Tcp(h) => h, _ => panic!("test requires TCP PostgreSQL") };
    let _allow = Allow(std::env::var("OPENWARP_ALLOWED_DB_HOSTS").ok());
    std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", host);
    let role = std::sync::Arc::new(Role::new(&url).await);
    let worker = role.clone(); let target = target.to_string();
    let f = Fixture::new().await;
    // Clean up the isolated remote role even when the regression assertion fails.
    let outcome = tokio::spawn(async move {
        assert!(worker.authenticates(OLD).await, "old login positive control");
        let (status, body) = f.call("POST", "/api/envs/env/rotations", json!({"key":"DB_PASSWORD","path":"/","interval_secs":3600,"config":{"kind":"postgres-static","connection":url,"username":worker.name}})).await;
        assert_eq!(status,200,"schedule: {}",body);
        let rid = body["id"].as_str().unwrap();
        f.state.db().exec("CREATE TRIGGER reject_static_secret BEFORE UPDATE ON secrets BEGIN SELECT RAISE(ABORT,'injected local store failure'); END", &[]).await.unwrap();
        f.run(rid).await;
        let pending = f.pending(rid).await.unwrap();
        assert!(!pending.is_empty(), "failed local write must retain pending credential");
        let aad = json!(["postgres-static-pending-v1","env",rid]).to_string();
        let password = String::from_utf8(oc::decrypt_symmetric_aad(&[8;32],aad.as_bytes(),&pending).unwrap()).unwrap();
        assert!(worker.authenticates(&password).await, "remote ALTER positive control");
        assert!(!worker.authenticates(OLD).await, "old remote password must be invalid");
        assert_eq!(f.value().await,OLD,"local failure positive control");
        eprintln!("QUALIFIED: remote accepts pending credential; local secret still old; deletion target={}", target);
        let path = if target == "schedule" { format!("/api/rotations/{}",rid) } else { format!("/api/{}", target) };
        let deleted = f.call("DELETE", &path, Value::Null).await;
        let retained = f.pending(rid).await;
        assert_eq!((deleted.0,retained.as_deref()),(409,Some(pending.as_str())),"deletion must reject and preserve the only recoverable remote password: {:?}",deleted);
        assert_eq!(f.value().await,OLD,"rejected deletion must not partially remove secrets");
        f.state.db().exec("DROP TRIGGER reject_static_secret", &[]).await.unwrap();
        f.run(rid).await;
        assert_eq!(f.value().await,password,"retry must reconcile the same remote password");
        assert_eq!(f.pending(rid).await.as_deref(),Some(""));
        assert!(worker.authenticates(&password).await);
        assert_eq!(f.call("DELETE", &path, Value::Null).await.0,200,"resolved rotations must not permanently block deletion");
    }).await;
    role.cleanup().await;
    outcome.unwrap();
}

#[tokio::test]
async fn pending_remote_password_blocks_schedule_deletion() { isolated_case("pending_remote_password_blocks_schedule_deletion", "schedule").await; }
#[tokio::test]
async fn pending_remote_password_blocks_environment_deletion() { isolated_case("pending_remote_password_blocks_environment_deletion", "envs/env").await; }
#[tokio::test]
async fn pending_remote_password_blocks_application_deletion() { isolated_case("pending_remote_password_blocks_application_deletion", "apps/app").await; }
