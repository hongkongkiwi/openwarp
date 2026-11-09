use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, integrations::validate_rotation_config, new_state, process_rotations, router, S};
use serde_json::{json, Value};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Environment(Vec<(&'static str, Option<String>)>);
impl Environment {
    fn new() -> Self {
        let names = ["OPENWARP_ALLOWED_DB_HOSTS", "OPENWARP_ENV"];
        let saved = Self(names.into_iter().map(|n| (n, std::env::var(n).ok())).collect());
        std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", "db.example.invalid,127.0.0.1,::1,localhost");
        std::env::set_var("OPENWARP_ENV", "development");
        saved
    }
}
impl Drop for Environment {
    fn drop(&mut self) { for (name, old) in &self.0 { match old { Some(v) => std::env::set_var(name, v), None => std::env::remove_var(name) } } }
}
fn config(connection: &str) -> Value { json!({"kind":"postgres-static","connection":connection,"username":"app_login"}) }

#[tokio::test]
async fn static_postgres_requires_parsed_require_mode_not_default_prefer() {
    let _lock = ENV_LOCK.lock().await; let _env = Environment::new();
    let secure = "postgres://admin:pw@db.example.invalid/db?sslmode=require";
    assert!(validate_rotation_config(&config(secure)).is_ok(), "Require positive control");
    for connection in [
        "postgres://admin:pw@db.example.invalid/db",
        "postgres://admin:pw@db.example.invalid/db?sslmode=prefer",
        "postgres://admin:pw@db.example.invalid/db?sslmode=disable",
        "postgres://admin:pw@127.0.0.1/db",
        "postgres://admin:pw@localhost/db?sslmode=disable",
        "postgres://admin:pw@db.example.invalid/db?application_name=sslmode%3Drequire",
    ] {
        assert!(validate_rotation_config(&config(connection)).is_err(), "unsafe transport accepted: {connection}");
    }
}

#[tokio::test]
async fn explicit_plaintext_is_only_for_literal_loopback_outside_production() {
    let _lock = ENV_LOCK.lock().await; let _env = Environment::new();
    // Development exception is explicit Disable on one literal loopback, never DNS or Prefer.
    for connection in ["postgres://admin:pw@127.0.0.1/db?sslmode=disable", "postgres://admin:pw@[::1]/db?sslmode=disable"] {
        assert!(validate_rotation_config(&config(connection)).is_ok(), "local development positive control: {connection}");
        std::env::set_var("OPENWARP_ENV", "production");
        assert!(validate_rotation_config(&config(connection)).is_err(), "production accepted plaintext: {connection}");
        std::env::set_var("OPENWARP_ENV", "development");
    }
    assert!(validate_rotation_config(&config("postgres://admin:pw@db.example.invalid/db?sslmode=require")).is_ok());
}

#[tokio::test]
async fn transport_validation_keeps_hostaddr_and_multihost_denied() {
    let _lock = ENV_LOCK.lock().await; let _env = Environment::new();
    assert!(validate_rotation_config(&config("postgres://admin:pw@db.example.invalid/db?sslmode=require")).is_ok());
    for connection in [
        "postgres://admin:pw@db.example.invalid/db?sslmode=require&hostaddr=127.0.0.1",
        "postgres://admin:pw@db.example.invalid,127.0.0.1/db?sslmode=require",
        "postgres://admin:pw@db.example.invalid/db?sslmode=require&host=db.example.invalid,127.0.0.1",
    ] { assert!(validate_rotation_config(&config(connection)).is_err(), "driver destination bypass accepted: {connection}"); }
}

fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
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
        let state = new_state(db, "sqlite::memory:".into(), "transport-review".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature="redis-cache")] None);
        let app = router(state.clone()); let f = Self { state, app };
        assert_eq!(f.call("PUT", "/api/envs/env/secrets", json!({"secrets":[{"key":"DB_PASSWORD","value":"original","path":"/"}]})).await.0, 200);
        f
    }
    async fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let request = Request::builder().method(method).uri(path).header("authorization", "Bearer owner")
            .header("content-type", "application/json").extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])))
            .body(Body::from(body.to_string())).unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap(); let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024*1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
    async fn schedule(&self, connection: &str) -> (u16, Value) {
        self.call("POST", "/api/envs/env/rotations", json!({"key":"DB_PASSWORD","path":"/","interval_secs":3600,"config":config(connection)})).await
    }
    async fn set_type(&self, kind: &str) {
        self.state.db().exec("UPDATE secrets SET secret_type=? WHERE env_id='env'", &[json!(kind)]).await.unwrap();
    }
    async fn run(&self, rid: &str) {
        assert_eq!(self.call("POST", &format!("/api/rotations/{rid}/run"), json!({})).await.0, 200);
        process_rotations(&self.state).await;
    }
    async fn pending(&self, rid: &str) -> String {
        self.state.db().one("SELECT pending_enc FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.unwrap().unwrap()["pending_enc"].as_str().unwrap().into()
    }
}

#[tokio::test]
async fn ssh_key_target_is_rejected_at_schedule_creation() {
    let _lock = ENV_LOCK.lock().await; let _env = Environment::new();
    let f = Fixture::new().await;
    let connection = "postgres://admin:pw@db.example.invalid/db?sslmode=require";
    let control = f.schedule(connection).await;
    assert_eq!(control.0, 200, "ordinary secret positive control: {control:?}");
    let rid = control.1["id"].as_str().unwrap();
    assert_eq!(f.call("DELETE", &format!("/api/rotations/{rid}"), Value::Null).await.0, 200);
    f.set_type("ssh_key").await;
    let rejected = f.schedule(connection).await;
    assert_eq!(rejected.0, 400, "SSH key must not become a PostgreSQL password target: {rejected:?}");
    assert!(f.state.db().query("SELECT id FROM rotation_schedules", &[]).await.unwrap().is_empty());
}

struct PgProbe { connection: String, calls: Arc<AtomicUsize>, stop: Arc<AtomicBool>, worker: Option<std::thread::JoinHandle<()>> }
impl PgProbe {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let connection = format!("postgres://admin:pw@{}/db?sslmode=require", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0)); let stop = Arc::new(AtomicBool::new(false));
        let (c, s) = (calls.clone(), stop.clone());
        let worker = std::thread::spawn(move || { while !s.load(Ordering::SeqCst) {
            match listener.accept() { Ok((stream, _)) => { c.fetch_add(1, Ordering::SeqCst); drop(stream); }, Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)), Err(e) => panic!("probe: {e}") }
        } });
        Self { connection, calls, stop, worker: Some(worker) }
    }
}
impl Drop for PgProbe { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); self.worker.take().unwrap().join().unwrap(); } }

#[tokio::test]
async fn ssh_key_execution_is_rejected_before_any_postgres_connection_or_pending_password() {
    let _lock = ENV_LOCK.lock().await; let _env = Environment::new();
    let probe = PgProbe::new(); let f = Fixture::new().await;
    let scheduled = f.schedule(&probe.connection).await;
    assert_eq!(scheduled.0, 200, "schedule positive control: {scheduled:?}");
    let rid = scheduled.1["id"].as_str().unwrap();
    f.run(rid).await;
    assert!(probe.calls.load(Ordering::SeqCst)>0, "ordinary secret must reach PostgreSQL probe");
    assert!(!f.pending(rid).await.is_empty(), "failed connection retains ordinary target's candidate");
    f.state.db().exec("UPDATE rotation_schedules SET pending_enc='' WHERE id=?", &[json!(rid)]).await.unwrap();
    let before = probe.calls.load(Ordering::SeqCst);
    f.set_type("ssh_key").await;
    f.run(rid).await;
    assert_eq!(probe.calls.load(Ordering::SeqCst), before, "SSH target reached remote transport before type validation");
    assert!(f.pending(rid).await.is_empty(), "SSH target generated a pending database password");
    let secret = f.state.db().one("SELECT secret_type FROM secrets WHERE env_id='env'", &[]).await.unwrap().unwrap();
    assert_eq!(secret["secret_type"], "ssh_key");
}
