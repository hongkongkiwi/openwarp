use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, process_maintenance, router, S};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static SEQ: AtomicU32 = AtomicU32::new(0);
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OLD: &str = "openwarp-isolated-old-password";
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
struct Allow(Option<String>);
impl Drop for Allow {
    fn drop(&mut self) { match &self.0 { Some(v) => std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", v), None => std::env::remove_var("OPENWARP_ALLOWED_DB_HOSTS") } }
}
fn live_url() -> Option<String> {
    match std::env::var("OPENWARP_TEST_STATIC_PG") {
        Ok(url) => Some(url),
        Err(_) => { eprintln!("NOT RUN: live PostgreSQL case requires OPENWARP_TEST_STATIC_PG pointing at a disposable database"); None }
    }
}
fn allow(url: &str) -> Allow {
    let config: tokio_postgres::Config = url.parse().expect("test PostgreSQL URL");
    let host = match &config.get_hosts()[0] { tokio_postgres::config::Host::Tcp(h) => h, _ => panic!("test requires TCP PostgreSQL") };
    let old = std::env::var("OPENWARP_ALLOWED_DB_HOSTS").ok();
    std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", host);
    Allow(old)
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
        let name = format!("ow_static_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst));
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
        let state = new_state(db, "sqlite::memory:".into(), "static-live".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature="redis-cache")] None);
        let app = router(state.clone()); let f = Self { state, app };
        assert_eq!(f.call("PUT", "/api/envs/env/secrets", json!({"secrets":[{"key":"DB_PASSWORD","value":OLD,"path":"/"}]})).await.0, 200);
        f
    }
    async fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let request = Request::builder().method(method).uri(path).header("authorization", "Bearer owner")
            .header("content-type", "application/json").extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])))
            .body(if body.is_null() { Body::empty() } else { Body::from(body.to_string()) }).unwrap();
        let r = self.app.clone().oneshot(request).await.unwrap(); let status = r.status().as_u16();
        let bytes = to_bytes(r.into_body(), 1024*1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
    async fn schedule(&self, url: &str, role: &str) -> String {
        let (status, body) = self.call("POST", "/api/envs/env/rotations", json!({"key":"DB_PASSWORD","path":"/","interval_secs":3600,"config":{"kind":"postgres-static","connection":url,"username":role}})).await;
        assert_eq!(status, 200, "schedule: {}", body); body["id"].as_str().unwrap().into()
    }
    async fn run(&self, rid: &str) {
        let (status, body) = self.call("POST", &format!("/api/rotations/{}/run", rid), json!({})).await;
        assert_eq!(status, 200, "manual schedule: {}", body);
        assert_eq!(body["scheduled"], true);
        process_maintenance(&self.state).await;
    }
    async fn value(&self) -> String {
        let (status, body) = self.call("GET", "/api/envs/env/export?base=1", Value::Null).await;
        assert_eq!(status,200,"{}",body);
        body["secrets"].as_array().unwrap().iter().find(|s| s["key"]=="DB_PASSWORD").unwrap()["value"].as_str().unwrap().into()
    }
    async fn pending(&self, rid: &str) -> String {
        self.state.db().one("SELECT pending_enc FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.unwrap().unwrap()["pending_enc"].as_str().unwrap().into()
    }
}

#[tokio::test]
async fn live_static_rotation_changes_postgres_login_and_matches_sse_secret() {
    let Some(url) = live_url() else { return; };
    let _lock = ENV_LOCK.lock().await; let _allow = allow(&url);
    let role = std::sync::Arc::new(Role::new(&url).await);
    let worker = role.clone();
    let result = async move {
        assert!(worker.authenticates(OLD).await, "old credential positive control");
        let f = Fixture::new().await; let rid = f.schedule(&url,&worker.name).await;
        f.run(&rid).await;
        let password = f.value().await; assert_ne!(password, OLD);
        assert!(worker.authenticates(&password).await, "stored SSE password cannot authenticate");
        assert!(!worker.authenticates(OLD).await, "remote password unchanged");
        assert!(f.pending(&rid).await.is_empty());
    };
    // Catch assertion panics so even a failing regression removes only its own role.
    let outcome = tokio::spawn(result).await;
    role.cleanup().await; outcome.unwrap();
}

#[tokio::test]
async fn live_remote_success_local_failure_retains_same_pending_password_until_retry() {
    let Some(url) = live_url() else { return; };
    let _lock = ENV_LOCK.lock().await; let _allow = allow(&url);
    let role = std::sync::Arc::new(Role::new(&url).await);
    let worker = role.clone(); let connection = url.clone();
    let outcome = tokio::spawn(async move {
        let f = Fixture::new().await; let rid = f.schedule(&connection,&worker.name).await;
        f.state.db().exec("CREATE TRIGGER reject_static_secret BEFORE UPDATE ON secrets BEGIN SELECT RAISE(ABORT,'injected local store failure'); END", &[]).await.unwrap();
        f.run(&rid).await;
        let pending = f.pending(&rid).await; assert!(!pending.is_empty(), "remote/local failure lost durable pending state");
        let aad = json!(["postgres-static-pending-v1","env",rid]).to_string();
        let password = String::from_utf8(oc::decrypt_symmetric_aad(&[8;32],aad.as_bytes(),&pending).unwrap()).unwrap();
        assert!(worker.authenticates(&password).await, "remote ALTER did not succeed before local failure");
        assert!(!worker.authenticates(OLD).await);
        assert_eq!(f.value().await, OLD, "injected local failure did not retain old stored value");
        f.run(&rid).await;
        assert_eq!(f.pending(&rid).await,pending,"retry replaced an uncertain credential");
        assert!(worker.authenticates(&password).await);
        f.state.db().exec("DROP TRIGGER reject_static_secret", &[]).await.unwrap();
        f.run(&rid).await;
        assert_eq!(f.value().await,password,"successful retry generated another password");
        assert!(worker.authenticates(&password).await);
        assert!(f.pending(&rid).await.is_empty(),"confirmed local write did not clear pending");
    }).await;
    role.cleanup().await; outcome.unwrap();
}

#[tokio::test]
async fn live_static_schedule_and_execution_reject_client_encrypted_sealed_and_driver_override_targets() {
    let Some(url) = live_url() else { return; };
    let _lock = ENV_LOCK.lock().await; let _allow = allow(&url);
    let role = std::sync::Arc::new(Role::new(&url).await);
    let worker = role.clone();
    let outcome = tokio::spawn(async move {
        let f = Fixture::new().await;
        let rid = f.schedule(&url,&worker.name).await;
        let input = json!({"key":"DB_PASSWORD","interval_secs":3600,"config":{"kind":"postgres-static","connection":url,"username":worker.name}});
        for mode in ["e2e","delegated"] {
            f.state.db().exec("UPDATE envs SET mode=? WHERE id='env'", &[json!(mode)]).await.unwrap();
            let r = f.call("POST","/api/envs/env/rotations",input.clone()).await;
            assert!(matches!(r.0,400|403|409|422),"client encrypted schedule accepted: {:?}",r);
            f.run(&rid).await;
            assert!(worker.authenticates(OLD).await,"manual execution rotated a client-encrypted target");
            assert!(f.pending(&rid).await.is_empty());
        }
        f.state.db().exec("UPDATE envs SET mode='sse' WHERE id='env'", &[]).await.unwrap();
        f.state.db().exec("UPDATE secrets SET secret_type='sealed' WHERE env_id='env'", &[]).await.unwrap();
        let r=f.call("POST","/api/envs/env/rotations",input.clone()).await;
        assert!(matches!(r.0,400|403|409|422),"sealed schedule accepted: {:?}",r);
        f.run(&rid).await;
        assert!(worker.authenticates(OLD).await,"manual execution rotated sealed target");
        f.state.db().exec("UPDATE secrets SET secret_type='secret' WHERE env_id='env'", &[]).await.unwrap();
        let mut override_url = reqwest::Url::parse(&url).unwrap(); override_url.query_pairs_mut().append_pair("host","127.0.0.1");
        let mut denied=input; denied["config"]["connection"]=json!(override_url.as_str());
        let r=f.call("POST","/api/envs/env/rotations",denied).await;
        assert!(matches!(r.0,400|403|409|422),"driver host override accepted: {:?}",r);
        assert!(worker.authenticates(OLD).await);
    }).await;
    role.cleanup().await; outcome.unwrap();
}
