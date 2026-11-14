use axum::{body::{to_bytes, Body}, http::Request, Router};
use openwarp_crypto as oc;
use openwarp_server::{clock::now, db::{self, Db}, new_state, process_maintenance, router, seed_epoch, S};
use serde_json::{json, Value};
use tower::ServiceExt;

const MASTER: [u8;32] = [71;32];
const ENV_KEY: [u8;32] = [72;32];
struct Fixture { state: S, app: Router }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.unwrap();
        seed_epoch(&db, &MASTER).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','lease operations',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','owner@test.invalid','unused','unused','unused',?,1)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token("lease-operation-owner")),json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','lease operations',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES('env','app','test',?,'sse',?)", &[json!(oc::encrypt_symmetric(&MASTER, &ENV_KEY)),json!(now())]).await.unwrap();
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "lease-operation-regressions".into(), "https://lease-operations.test.invalid".into(), MASTER, live, #[cfg(feature="redis-cache")] None);
        let app = router(state.clone()); Self { state, app }
    }
    async fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let request = Request::builder().method(method).uri(path).header("authorization", "Bearer lease-operation-owner")
            .header("content-type", "application/json").extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])))
            .body(if body.is_null() { Body::empty() } else { Body::from(body.to_string()) }).unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap(); let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024*1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
    async fn seed_generic(&self, lid: &str, expires: i64) {
        self.state.db().exec("INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES(?,'env',?,?,?,?)", &[json!(lid),json!(lid),json!(oc::encrypt_symmetric(&ENV_KEY,b"dummy-lease-credential")),json!(expires),json!(now())]).await.unwrap();
    }
    async fn revoked(&self, lid: &str) -> i64 {
        db::n(&self.state.db().one("SELECT revoked FROM leases WHERE id=?", &[json!(lid)]).await.unwrap().expect("seeded lease"), "revoked")
    }
}

#[tokio::test]
async fn fifty_unresolved_operation_claims_do_not_starve_unclaimed_expired_leases() {
    let f = Fixture::new().await; let db = f.state.db(); let current = now();
    let (status, _) = f.call("GET", "/api/envs/env/dynamic", Value::Null).await;
    assert_eq!(status,200,"private fixture must admit the owner's lease reads");
    for index in 0..50 {
        let lid = format!("claimed-{index:02}"); f.seed_generic(&lid,current-1000+index).await;
        // Expired claims are still unresolved, not available for automatic takeover.
        let deadline = if index%2==0 { current-7200 } else { current+3600 };
        db.exec("INSERT INTO instance_leases(name,owner,expires_at) VALUES(?,?,?)", &[json!(format!("lease-op:{lid}")),json!(format!("interrupted-owner-{index}")),json!(deadline)]).await.unwrap();
    }
    f.seed_generic("unclaimed-expired",current-100).await;
    f.seed_generic("unclaimed-future",current+86400).await;
    let claims = db.query("SELECT name,owner,expires_at FROM instance_leases WHERE name LIKE 'lease-op:%' ORDER BY name", &[]).await.unwrap();
    process_maintenance(&f.state).await;
    let after = db.query("SELECT name,owner,expires_at FROM instance_leases WHERE name LIKE 'lease-op:%' ORDER BY name", &[]).await.unwrap();
    assert_eq!(after,claims,"maintenance must neither retire nor take over unresolved operation claims, including expired ones");
    for index in 0..50 { assert_eq!(f.revoked(&format!("claimed-{index:02}")).await,0,"claimed credentials must remain untouched until reconciled"); }
    assert_eq!(f.revoked("unclaimed-future").await,0,"expiry cleanup must leave a future lease active");
    assert_eq!(f.revoked("unclaimed-expired").await,1,"50 earlier unresolved operation claims must not occupy the expiry page and starve a due unclaimed lease");
}

#[cfg(feature="live-db-tests")]
struct AllowHosts(Option<String>);
#[cfg(feature="live-db-tests")]
impl Drop for AllowHosts {
    fn drop(&mut self) { match &self.0 { Some(value) => std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS",value), None => std::env::remove_var("OPENWARP_ALLOWED_DB_HOSTS") } }
}

#[cfg(feature="live-db-tests")]
#[tokio::test]
async fn postgres_revoke_connection_refusal_releases_claim_and_restored_target_can_retry() {
    let url = std::env::var("OPENWARP_TEST_LEASE_PG").expect("live-db-tests requires OPENWARP_TEST_LEASE_PG for the disposable PostgreSQL cluster on 127.0.0.1:54289");
    let config: tokio_postgres::Config = url.parse().expect("test PostgreSQL URL");
    assert_eq!(config.get_hosts(), &[tokio_postgres::config::Host::Tcp("127.0.0.1".into())],"refusing any database except the dedicated literal loopback fixture");
    assert!(config.get_hostaddrs().is_empty()); assert_eq!(config.get_ports(), &[54289],"refusing any PostgreSQL service except the dedicated private cluster");
    assert_eq!(config.get_ssl_mode(),tokio_postgres::config::SslMode::Disable,"local fixture must explicitly disable TLS");
    let (admin, connection) = config.connect(tokio_postgres::NoTls).await.expect("connect dedicated PostgreSQL fixture");
    tokio::spawn(async move { let _ = connection.await; });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let refused_port = listener.local_addr().unwrap().port(); drop(listener);
    let refused = std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127,0,0,1],refused_port)),std::time::Duration::from_secs(1)).expect_err("closed local endpoint must refuse TCP before PostgreSQL can send SQL");
    assert_eq!(refused.kind(),std::io::ErrorKind::ConnectionRefused,"fixture must fail before a PostgreSQL connection exists");
    let mut down = reqwest::Url::parse(&url).expect("PostgreSQL URL"); down.set_port(Some(refused_port)).unwrap();
    let _allow = AllowHosts(std::env::var("OPENWARP_ALLOWED_DB_HOSTS").ok());
    std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS",format!("127.0.0.1:54289,127.0.0.1:{refused_port}"));
    let f = Fixture::new().await;
    let (status, lease) = f.call("POST","/api/envs/env/dynamic",json!({"name":"refused-revoke-retry","type":"postgres","ttl_secs":3600,"config":{"connection":url}})).await;
    assert_eq!(status,200,"private PostgreSQL issuance positive control");
    let lid = lease["id"].as_str().expect("lease id").to_string();
    let username = lease["username"].as_str().expect("issued PostgreSQL role").to_string(); let role = username.clone();
    // A caught assertion still removes only the role issued by this fixture.
    let local = tokio::task::LocalSet::new();
    let result = local.run_until(async move { tokio::task::spawn_local(async move {
        let db = f.state.db(); let route = format!("/api/leases/{lid}"); let claim = format!("lease-op:{lid}");
        let stored = db.one("SELECT config_enc FROM leases WHERE id=?", &[json!(&lid)]).await.unwrap().unwrap();
        let original = db::s(&stored,"config_enc");
        let config_aad = format!("ow-lease:v1|env|{lid}|config");
        let outage = oc::encrypt_symmetric_aad(&ENV_KEY,config_aad.as_bytes(),json!({"type":"postgres","connection":down.as_str()}).to_string().as_bytes());
        assert_eq!(db.exec("UPDATE leases SET config_enc=? WHERE id=?", &[json!(outage),json!(&lid)]).await.unwrap(),1);
        let (status, before) = f.call("GET",&route,Value::Null).await;
        assert_eq!(status,200); assert_eq!(before["type"],"postgres"); assert_eq!(before["renewable"],true,"closed but allowed target remains a valid direct lease configuration");
        let (status, failure) = f.call("DELETE",&route,Value::Null).await;
        assert!((400..600).contains(&status),"connection refusal must not report successful revocation");
        assert!(failure["error"].is_string(),"failed revocation must return an API error");
        assert_eq!(f.revoked(&lid).await,0,"no remote SQL was sent, so the lease must remain active");
        let retained = db.one("SELECT name FROM instance_leases WHERE name=?", &[json!(&claim)]).await.unwrap().is_some();
        assert!(!retained,"a refused PostgreSQL connection sent no DROP ROLE and must release the operation claim instead of requiring operator reconciliation");
        let (status, after_failure) = f.call("GET",&route,Value::Null).await;
        assert_eq!(status,200); assert_eq!(after_failure["renewable"],true,"known pre-effect failure must not advertise an unresolved operation");
        assert_eq!(after_failure["expires_at"],before["expires_at"],"failed revoke must retain the original deadline");
        assert_eq!(db.exec("UPDATE leases SET config_enc=? WHERE id=?", &[json!(original),json!(&lid)]).await.unwrap(),1);
        let (status, revoked) = f.call("DELETE",&route,Value::Null).await;
        assert_eq!(status,200,"restored PostgreSQL target must revoke without operator deletion of a claim"); assert_eq!(revoked["revoked"],lid);
        let (status, metadata) = f.call("GET",&route,Value::Null).await;
        assert_eq!(status,200); assert_eq!(metadata["revoked"],true); assert_eq!(metadata["renewable"],false);
        assert!(db.one("SELECT name FROM instance_leases WHERE name=?", &[json!(&claim)]).await.unwrap().is_none(),"successful revocation must release its operation claim");
    }).await }).await;
    let exists = admin.query_opt("SELECT rolname FROM pg_roles WHERE rolname=$1", &[&role]).await.expect("inspect only the fixture role").is_some();
    admin.batch_execute(&format!("DROP ROLE IF EXISTS \"{}\"",role.replace('"',"\"\""))).await.expect("cleanup only the fixture role");
    if let Err(error) = result { std::panic::resume_unwind(error.into_panic()); }
    assert!(!exists,"successful retry must actually drop the PostgreSQL role, not merely mark local metadata revoked");
}
