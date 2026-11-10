use axum::{body::{to_bytes, Body}, http::{Method, Request}, Router};
use openwarp_crypto as oc;
use openwarp_server::{app::{new_state, process_rotations, router, PeerAddr, S}, db::{self, Db}};
use serde_json::{json, Value};
use std::{path::PathBuf, process::{Child, Command, Stdio}, sync::{Arc, atomic::{AtomicBool, AtomicU32, Ordering}}, time::{Duration, Instant}};
use tower::ServiceExt;

const OWNER: &str = "final-consistency-owner";
const LOGIN: &str = "/api/v1/machine/auth/universal/login";
static SEQ: AtomicU32 = AtomicU32::new(0);
fn now() -> i64 { openwarp_server::clock::now() }

struct Fixture { st: S, app: Router }
impl Fixture {
    async fn new(db: Db) -> Self {
        let (live, _) = tokio::sync::broadcast::channel(16);
        let st = new_state(db, ":memory:".into(), "final-consistency".into(), "https://openwarp.test.invalid".into(), [7;32], live,
            #[cfg(feature = "redis-cache")] None);
        let f = Self { app: router(st.clone()), st };
        f.sql("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES('owner','final@test.invalid','','','',?,1,1)", &[json!(now())]).await;
        f.sql("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token(OWNER)),json!(now())]).await;
        f.sql("INSERT INTO orgs(id,name,created_at) VALUES('org','final',?)", &[json!(now())]).await;
        f.sql("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await;
        f.sql("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','final',?)", &[json!(now())]).await;
        f.sql("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES('env','app','final',?,'sse',?)", &[json!(oc::encrypt_symmetric(&[7;32], &[11;32])),json!(now())]).await;
        f.sql("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await;
        f.sql("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&[7;32]))]).await;
        f
    }
    async fn sql(&self, sql: &str, args: &[Value]) { self.st.db().exec(sql,args).await.expect("fixture SQL"); }
    async fn call(&self, method: Method, path: &str, body: Option<Value>, cookie: Option<&str>, owner: bool) -> (u16,Value) {
        let mut req = Request::builder().method(method).uri(path).header("host","openwarp.test.invalid");
        if owner { req=req.header("authorization",format!("Bearer {OWNER}")); }
        if let Some(cookie)=cookie { req=req.header("cookie",format!("ow_session={cookie}")); }
        if body.is_some() { req=req.header("content-type","application/json"); }
        let mut req=req.body(body.map(|v| Body::from(v.to_string())).unwrap_or_else(Body::empty)).unwrap();
        req.extensions_mut().insert(PeerAddr("192.0.2.10".parse().unwrap()));
        let response=self.app.clone().oneshot(req).await.unwrap(); let status=response.status().as_u16();
        let bytes=to_bytes(response.into_body(),4*1024*1024).await.unwrap();
        (status,serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
    async fn put(&self, key: &str, value: &str) {
        let (status,body)=self.call(Method::PUT,"/api/envs/env/secrets",Some(json!({"secrets":[{"key":key,"value":value}]})),None,true).await;
        assert_eq!(status,200,"seed secret: {body}");
    }
    async fn snapshot(&self, sql: &str) -> Value {
        json!(self.st.db().query(sql,&[]).await.unwrap().iter().map(db::obj).collect::<Vec<_>>())
    }
}

#[tokio::test]
async fn pitr_pending_rotation_conflict_preserves_entire_environment() {
    let f=Fixture::new(Db::open_memory().await.unwrap()).await;
    for name in ["FIRST","SECOND"] { f.put(name,"old-history").await; }
    let timestamp=now()-10;
    f.sql("UPDATE secret_versions SET created_at=?", &[json!(timestamp)]).await;
    for name in ["FIRST","SECOND"] { f.put(name,"current-value").await; }
    // SQLite preserves this unchanged scan's row layout; select the blocker last rather than guessing random IDs.
    let rows=f.st.db().query("SELECT id,version,deleted_at,path FROM secrets WHERE env_id=?", &[json!("env")]).await.unwrap();
    assert_eq!(rows.len(),2);
    let first=db::s(&rows[0],"id"); let blocked=db::s(&rows[1],"id");
    let (status,list)=f.call(Method::GET,"/api/envs/env/secrets",None,None,true).await;
    assert_eq!(status,200);
    let name=list["secrets"].as_array().unwrap().iter().find(|s| s["id"]==blocked).unwrap()["key"].as_str().unwrap();
    f.sql("UPDATE secrets SET deleted=1,deleted_at=? WHERE id=?", &[json!(now()),json!(first)]).await;
    let config=json!({"kind":"postgres-static","connection":"postgres://fixture:unused@db.test.invalid/disposable?sslmode=require","username":"fixture_role"});
    let pending=oc::encrypt_symmetric_aad(&[11;32],json!(["postgres-static-pending-v1","env","pitr-pending"]).to_string().as_bytes(),b"pending-password");
    f.sql("INSERT INTO rotation_schedules(id,env_id,key_name,path,interval_secs,next_run,config_enc,created_at,static_target,pending_enc) VALUES('pitr-pending','env',?,'/',3600,?,?,?,'pitr-target',?)", &[json!(name),json!(now()+3600),json!(oc::encrypt_symmetric(&[11;32],config.to_string().as_bytes())),json!(now()),json!(pending)]).await;
    let before=f.snapshot("SELECT * FROM secrets ORDER BY id").await;
    let history=f.snapshot("SELECT * FROM secret_versions ORDER BY secret_id,version,id").await;
    let schedule=f.snapshot("SELECT * FROM rotation_schedules ORDER BY id").await;
    let (status,body)=f.call(Method::POST,"/api/envs/env/restore-point",Some(json!({"timestamp":timestamp})),None,true).await;
    assert_eq!(status,409,"pending rotation must reject PITR: {body}");
    let after=f.snapshot("SELECT * FROM secrets ORDER BY id").await;
    let after_history=f.snapshot("SELECT * FROM secret_versions ORDER BY secret_id,version,id").await;
    assert_eq!(f.snapshot("SELECT * FROM rotation_schedules ORDER BY id").await,schedule);
    assert!(after==before && after_history==history,
        "409 PITR changed state: secrets_changed={}, history_changed={}, first_version_before={}, first_version_after={}, tombstone_before={}, tombstone_after={}",
        after!=before,after_history!=history,
        before.as_array().unwrap().iter().find(|s| s["id"]==first).unwrap()["version"],
        after.as_array().unwrap().iter().find(|s| s["id"]==first).unwrap()["version"],
        before.as_array().unwrap().iter().find(|s| s["id"]==first).unwrap()["deleted"],
        after.as_array().unwrap().iter().find(|s| s["id"]==first).unwrap()["deleted"]);
}

#[tokio::test]
async fn universal_login_ignores_stale_cookie_without_opening_protected_routes() {
    let f=Fixture::new(Db::open_memory().await.unwrap()).await;
    let (status,credentials)=f.call(Method::POST,"/api/orgs/org/identities",Some(json!({"name":"final-machine","role":"developer"})),None,true).await;
    assert_eq!(status,200,"create real machine credentials: {credentials}");
    let body=json!({"client_id":credentials["client_id"],"client_secret":credentials["client_secret"]});
    let (status,plain)=f.call(Method::POST,LOGIN,Some(body.clone()),None,false).await;
    assert_eq!(status,200,"no-cookie positive control: {plain}"); assert!(plain["accessToken"].is_string());
    let (protected,_)=f.call(Method::GET,"/api/envs/env/secrets",None,Some("expired-browser-session"),false).await;
    assert_eq!(protected,401,"stale cookies must not authenticate protected routes");
    let (invalid,_)=f.call(Method::POST,LOGIN,Some(json!({"client_id":credentials["client_id"],"client_secret":"wrong"})),Some("expired-browser-session"),false).await;
    assert_eq!(invalid,401,"public login still verifies machine credentials");
    let (status,reply)=f.call(Method::POST,LOGIN,Some(body),Some("expired-browser-session"),false).await;
    assert_eq!(status,200,"valid machine JSON must not be shadowed by stale account cookie: {reply}");
    assert!(reply["accessToken"].is_string()); assert_eq!(reply["identity_id"],credentials["id"]);
}

#[tokio::test]
async fn missing_static_rotation_target_backs_off_and_audits_without_claim() {
    let f=Fixture::new(Db::open_memory().await.unwrap()).await;
    let due=now()-100;
    let config=json!({"kind":"postgres-static","connection":"postgres://fixture:unused@db.test.invalid/disposable?sslmode=require","username":"fixture_role"});
    f.sql("INSERT INTO rotation_schedules(id,env_id,key_name,path,interval_secs,next_run,config_enc,created_at,static_target) VALUES('missing','env','MISSING','/',3600,?,?,?,'missing-target')", &[json!(due),json!(oc::encrypt_symmetric(&[11;32],config.to_string().as_bytes())),json!(now())]).await;
    let before=now(); process_rotations(&f.st).await;
    let row=f.st.db().one("SELECT next_run,pending_enc,execution_token FROM rotation_schedules WHERE id='missing'",&[]).await.unwrap().unwrap();
    let audits=f.st.db().query("SELECT action,detail FROM audit WHERE env_id='env' AND actor='rotation-scheduler'",&[]).await.unwrap();
    assert_eq!(db::s(&row,"pending_enc"),""); assert_eq!(db::s(&row,"execution_token"),"");
    assert_eq!(f.snapshot("SELECT * FROM secrets").await,json!([]));
    let failure=audits.iter().any(|r| db::s(r,"action")=="rotation.failed" && db::s(r,"detail")=="MISSING");
    assert!(db::n(&row,"next_run")>=before+3600 && failure,
        "invalid due static rotation must back off and audit generic failure: next_run={}, due={}, actions={:?}",db::n(&row,"next_run"),due,audits.iter().map(|r| db::s(r,"action")).collect::<Vec<_>>());
    assert!(!audits.iter().any(|r| db::s(r,"action")=="rotation.failed_pending_retained"));
}

struct OwnedDir(PathBuf);
impl OwnedDir {
    fn new() -> Self {
        let path=std::env::temp_dir().join(format!("openwarp-final-consistency-{}-{}",std::process::id(),SEQ.fetch_add(1,Ordering::SeqCst)));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
}
impl Drop for OwnedDir { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.0); } }
struct Server(Child);
impl Drop for Server { fn drop(&mut self) { let _=self.0.kill(); let _=self.0.wait(); } }
struct Bridge { url: String, reject: Arc<AtomicBool>, task: tokio::task::JoinHandle<()> }
impl Drop for Bridge { fn drop(&mut self) { self.task.abort(); } }
impl Bridge {
    async fn new() -> Self {
        let reject=Arc::new(AtomicBool::new(false)); let state=reject.clone();
        let app=Router::new().route("/{operation}",axum::routing::post(move |axum::extract::Path(op): axum::extract::Path<String>, axum::Json(body): axum::Json<Value>| {
            let reject=state.clone(); async move {
                if op=="wrap" {
                    let blob=if reject.load(Ordering::SeqCst) && body["context"]=="env:env" { json!("bad-candidate") } else { body["plaintext"].clone() };
                    axum::Json(json!({"wrapped":blob}))
                } else {
                    let raw=if body["wrapped"]=="bad-candidate" { json!(oc::b64(&[99;32])) } else { body["wrapped"].clone() };
                    axum::Json(json!({"plaintext":raw}))
                }
            }
        }));
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url=format!("http://{}",listener.local_addr().unwrap());
        let task=tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
        Self { url,reject,task }
    }
}

#[tokio::test]
async fn failed_kms_rewrap_preserves_legacy_environment_and_root() {
    let bridge=Bridge::new().await;
    let client=reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10)).build().unwrap();
    // A successful roundtrip must migrate the same legacy fixture before the rejection case.
    for reject in [false,true] {
        bridge.reject.store(false,Ordering::SeqCst);
        let dir=OwnedDir::new(); let url=format!("sqlite://{}",dir.0.join("fixture.db").display());
        let f=Fixture::new(Db::open(&url).await.unwrap()).await;
        let env_before=f.snapshot("SELECT * FROM envs ORDER BY id").await;
        let port=std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let base=format!("http://127.0.0.1:{port}"); let log=dir.0.join("server.log");
        let mut server=Server(Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL",&url).env("ADDR",format!("127.0.0.1:{port}")).env("OPENWARP_PUBLIC_URL",&base)
            .env("OPENWARP_KMS_URL",&bridge.url).env("TOKIO_WORKER_THREADS","2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_KMS_TOKEN").env_remove("OPENWARP_KMS_KEY_ID")
            .env_remove("REDIS_URL").env_remove("OPENWARP_ENV").stdout(Stdio::null()).stderr(Stdio::from(std::fs::File::create(&log).unwrap())).spawn().unwrap());
        let deadline=Instant::now()+Duration::from_secs(20);
        loop {
            assert!(server.0.try_wait().unwrap().is_none(),"child startup failed: {}",std::fs::read_to_string(&log).unwrap());
            if client.get(format!("{base}/health")).send().await.is_ok_and(|r| r.status().is_success()) { break; }
            assert!(Instant::now()<deadline,"child health timeout"); tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(f.snapshot("SELECT * FROM envs ORDER BY id").await,env_before,"startup must leave the unused legacy env intact");
        let root_before=f.snapshot("SELECT * FROM meta WHERE k IN ('master','kms_root') ORDER BY k").await;
        assert!(root_before.as_array().unwrap().iter().any(|r| r["k"]=="kms_root"));
        bridge.reject.store(reject,Ordering::SeqCst);
        let response=client.post(format!("{base}/api/instance/rewrap")).bearer_auth(OWNER).send().await.unwrap();
        let status=response.status(); let body: Value=response.json().await.unwrap();
        let env_after=f.snapshot("SELECT * FROM envs ORDER BY id").await;
        let root_after=f.snapshot("SELECT * FROM meta WHERE k IN ('master','kms_root') ORDER BY k").await;
        if reject {
            assert!(!status.is_success(),"bad KMS verification must fail: {body}");
            assert!(body["error"].as_str().unwrap_or("").contains("roundtrip"),"must reach candidate verification: {body}");
            assert!(env_after==env_before && root_after==root_before,
                "rejected rewrap mutated persisted state: env_changed={}, root_changed={}",env_after!=env_before,root_after!=root_before);
        } else {
            assert_eq!(status,200,"normal KMS roundtrip: {body}"); assert_eq!(body["rewrapped"],1);
            let wrapped=env_after[0]["env_key_wrapped"].as_str().unwrap();
            assert_eq!(wrapped,format!("owkms:primary:{}",oc::b64(&[11;32])));
            assert_eq!(root_after,root_before,"positive bridge preserves original root bytes");
        }
        drop(server);
    }
}
