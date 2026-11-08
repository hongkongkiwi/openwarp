//! PR8 review tests: F7 migration-22 restart resume, F10 mixed-root startup
//! safety, and F3 MySQL/MariaDB KMS adoption. MySQL/Postgres variants are
//! opt-in via OPENWARP_TEST_MYSQL_URL / OPENWARP_TEST_POSTGRES_URL and skip when
//! unset; SQLite cases run unconditionally.

use openwarp_crypto as oc;
use openwarp_server::db::Db;
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "openwarp-kmsreview-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A provider-neutral KMS mock that preserves the wrapped bytes so a seeded
/// `owkms:primary:<b64(root)>` value unwraps back to the same 32-byte root.
struct KmsBridge {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for KmsBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl KmsBridge {
    async fn new() -> KmsBridge {
        let app = axum::Router::new().route(
            "/{operation}",
            axum::routing::post(
                |axum::extract::Path(op): axum::extract::Path<String>, axum::Json(body): axum::Json<Value>| async move {
                    if op == "wrap" {
                        axum::Json(json!({"wrapped": body["plaintext"].clone()}))
                    } else {
                        axum::Json(json!({"plaintext": body["wrapped"].clone()}))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        KmsBridge { url, task }
    }
}

/// A spawned `openwarp-server` process pointed at an existing database.
struct Spawned {
    child: Child,
    base: String,
    log: PathBuf,
}
impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Spawned {
    fn start(db_url: &str, kms_url: &str, dir: &Path) -> Spawned {
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let log = dir.join("server.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", db_url)
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_KMS_URL", kms_url)
            .env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1")
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("OPENWARP_KMS_TOKEN")
            .env_remove("OPENWARP_KMS_KEY_ID")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn openwarp-server");
        Spawned { child, base, log }
    }
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    async fn wait_healthy(&mut self) {
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("server exited {} before becoming healthy: {}", status, self.log_text());
            }
            if let Ok(r) = client.get(format!("{}/health", self.base)).send().await {
                if r.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server did not become healthy: {}", self.log_text());
    }
    /// Startup must exit nonzero and never serve /health (used for mixed roots).
    async fn wait_refused(&mut self) {
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(!status.success(), "startup must exit nonzero: {}", self.log_text());
                return;
            }
            assert!(Instant::now() < deadline, "startup neither exited nor refused: {}", self.log_text());
            if let Ok(r) = client.get(format!("{}/health", self.base)).send().await {
                if r.status().is_success() {
                    panic!("mixed roots were accepted and the server became healthy");
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[tokio::test]
async fn migration22_resumes_when_lifecycle_row_exists_but_ledger_absent() {
    let dir = tmp_dir("f7-sqlite");
    let url = format!("sqlite://{}", dir.join("test.db").display());
    {
        let db = Db::open(&url).await.expect("open fresh sqlite database");
        assert_eq!(db.version().await.unwrap(), 23, "a fresh database lands on the current version");
        // Simulate an interrupted first run of migration 22: the lifecycle meta
        // row was inserted but the schema_migrations ledger entry never landed.
        db.exec("DELETE FROM schema_migrations WHERE version=22", &[]).await.unwrap();
        assert!(
            db.one("SELECT v FROM meta WHERE k='rotation_lifecycle'", &[]).await.unwrap().is_some(),
            "precondition: the lifecycle row must already exist"
        );
    }
    // Reopening replays migration 22; the duplicate lifecycle row must not abort.
    {
        let reopened = Db::open(&url).await;
        assert!(reopened.is_ok(), "migration 22 resume failed: {:?}", reopened.err());
        let reopened = reopened.unwrap();
        assert_eq!(reopened.version().await.unwrap(), 23, "the ledger must record the current version");
        let replayed = reopened.one("SELECT COUNT(*) AS n FROM schema_migrations WHERE version=22", &[]).await.unwrap().unwrap();
        assert_eq!(replayed["n"].as_i64(), Some(1), "the replayed migration 22 is recorded exactly once");
        let rows = reopened.query("SELECT v FROM meta WHERE k='rotation_lifecycle'", &[]).await.unwrap();
        assert_eq!(rows.len(), 1, "the lifecycle row must remain a single row");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn mixed_kms_root_and_master_abort_startup_without_deleting_either() {
    let bridge = KmsBridge::new().await;
    let dir = tmp_dir("f10-mixed");
    let url = format!("sqlite://{}", dir.join("test.db").display());
    let root_a = [0x41u8; 32];
    let root_b = [0x42u8; 32];
    let wrapped_a = format!("owkms:primary:{}", oc::b64(&root_a));
    let plain_b = oc::b64(&root_b);
    {
        let db = Db::open(&url).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('kms_root',?)", &[json!(wrapped_a.clone())]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(plain_b.clone())]).await.unwrap();
    }
    {
        let mut server = Spawned::start(&url, &bridge.url, &dir);
        server.wait_refused().await;
    }
    {
        let db = Db::open(&url).await.unwrap();
        let kms_root = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap();
        assert_eq!(kms_root.unwrap()["v"].as_str().unwrap(), wrapped_a.as_str(), "kms_root must be preserved");
        let master = db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap();
        assert_eq!(master.unwrap()["v"].as_str().unwrap(), plain_b.as_str(), "master must be preserved");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn equal_kms_root_and_master_allow_interrupted_adoption_cleanup() {
    let bridge = KmsBridge::new().await;
    let dir = tmp_dir("f10-equal");
    let url = format!("sqlite://{}", dir.join("test.db").display());
    let root = [0x43u8; 32];
    let wrapped = format!("owkms:primary:{}", oc::b64(&root));
    let plain = oc::b64(&root);
    {
        let db = Db::open(&url).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('kms_root',?)", &[json!(wrapped.clone())]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(plain.clone())]).await.unwrap();
    }
    {
        let mut server = Spawned::start(&url, &bridge.url, &dir);
        server.wait_healthy().await;
    }
    {
        let db = Db::open(&url).await.unwrap();
        let kms_root = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap();
        assert_eq!(kms_root.unwrap()["v"].as_str().unwrap(), wrapped.as_str(), "kms_root must be preserved");
        assert!(
            db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().is_none(),
            "the duplicate plaintext master must be cleaned up"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

async fn mysql_admin(admin_url: &str, statements: &[String]) -> Result<(), String> {
    use mysql_async::prelude::Queryable;
    let opts = mysql_async::Opts::from_url(admin_url).map_err(|e| e.to_string())?;
    let pool = mysql_async::Pool::new(opts);
    let result = async {
        let mut c = pool.get_conn().await.map_err(|e| e.to_string())?;
        for s in statements {
            c.query_drop(s.as_str()).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    .await;
    pool.disconnect().await.ok();
    result
}

struct MySqlDb {
    admin: String,
    name: String,
}
impl Drop for MySqlDb {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(r) => r,
                Err(_) => return,
            };
            rt.block_on(async move {
                let _ = mysql_admin(&admin, &[format!("DROP DATABASE IF EXISTS `{}`", name)]).await;
            });
        })
        .join();
    }
}

async fn pg_admin(admin_url: &str, statements: &[String]) -> Result<(), String> {
    let (client, connection) = tokio_postgres::connect(admin_url, tokio_postgres::NoTls)
        .await
        .map_err(|e| e.to_string())?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result = async {
        for s in statements {
            client.batch_execute(s.as_str()).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    .await;
    driver.abort();
    result
}

struct PgDb {
    admin: String,
    name: String,
}
impl Drop for PgDb {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(r) => r,
                Err(_) => return,
            };
            rt.block_on(async move {
                let _ = pg_admin(&admin, &[format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", name)]).await;
            });
        })
        .join();
    }
}

/// Derive a database URL from an admin URL that already names a database.
fn derive_db_url(admin_url: &str, name: &str) -> String {
    let (base, query) = admin_url.split_once('?').map(|(base, query)| (base, format!("?{}", query))).unwrap_or((admin_url, String::new()));
    match base.rfind('/') {
        Some(index) => format!("{}/{}{}", &base[..index], name, query),
        None => format!("{}/{}{}", base, name, query),
    }
}

#[test]
fn database_url_replacement_preserves_query_options() {
    assert_eq!(derive_db_url("mysql://root:pw@127.0.0.1/mysql?ssl-mode=REQUIRED", "test_db"), "mysql://root:pw@127.0.0.1/test_db?ssl-mode=REQUIRED");
    assert_eq!(derive_db_url("postgres://u:p@127.0.0.1/postgres?sslmode=disable&connect_timeout=5", "test_db"), "postgres://u:p@127.0.0.1/test_db?sslmode=disable&connect_timeout=5");
}

#[tokio::test]
async fn mysql_kms_adoption_wraps_the_existing_master_and_removes_the_plaintext_row() {
    let admin = match std::env::var("OPENWARP_TEST_MYSQL_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return,
    };
    let name = format!("openwarp_kms_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst));
    mysql_admin(&admin, &[format!("CREATE DATABASE `{}` DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_bin", name)])
        .await
        .expect("create test database");
    let _db_guard = MySqlDb { admin: admin.clone(), name: name.clone() };
    let db_url = derive_db_url(&admin, &name);
    let root = [7u8; 32];
    {
        let db = Db::open(&db_url).await.expect("open mysql test database");
        // A database that predates KMS carries a plaintext master row.
        db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&root))]).await.unwrap();
    }
    let bridge = KmsBridge::new().await;
    let dir = tmp_dir("f3-mysql");
    {
        let mut server = Spawned::start(&db_url, &bridge.url, &dir);
        server.wait_healthy().await;
    }
    {
        let db = Db::open(&db_url).await.unwrap();
        let kms_root = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap();
        let expected = format!("owkms:primary:{}", oc::b64(&root));
        assert_eq!(
            kms_root.expect("kms_root must be installed")["v"].as_str().unwrap(),
            expected.as_str(),
            "the adopted root must wrap the pre-existing master"
        );
        assert!(
            db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().is_none(),
            "the plaintext master must be removed after adoption"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn migration22_resumes_on_mysql_when_lifecycle_row_exists_but_ledger_absent() {
    let admin = match std::env::var("OPENWARP_TEST_MYSQL_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return,
    };
    let name = format!("openwarp_kms19_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst));
    mysql_admin(&admin, &[format!("CREATE DATABASE `{}` DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_bin", name)])
        .await
        .expect("create test database");
    let _db_guard = MySqlDb { admin: admin.clone(), name: name.clone() };
    let db_url = derive_db_url(&admin, &name);
    {
        let db = Db::open(&db_url).await.expect("open mysql test database");
        assert_eq!(db.version().await.unwrap(), 23);
        db.exec("DELETE FROM schema_migrations WHERE version=22", &[]).await.unwrap();
    }
    let reopened = Db::open(&db_url).await;
    assert!(reopened.is_ok(), "migration 22 resume failed on MySQL: {:?}", reopened.err());
    let reopened = reopened.unwrap();
    assert_eq!(reopened.version().await.unwrap(), 23);
    assert_eq!(
        reopened.query("SELECT v FROM meta WHERE k='rotation_lifecycle'", &[]).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn migration22_resumes_on_postgres_when_lifecycle_row_exists_but_ledger_absent() {
    let admin = match std::env::var("OPENWARP_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return,
    };
    let name = format!("openwarp_kms19_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst));
    pg_admin(&admin, &[format!("CREATE DATABASE {}", name)]).await.expect("create test database");
    let _db_guard = PgDb { admin: admin.clone(), name: name.clone() };
    let db_url = derive_db_url(&admin, &name);
    {
        let db = Db::open(&db_url).await.expect("open postgres test database");
        assert_eq!(db.version().await.unwrap(), 23);
        db.exec("DELETE FROM schema_migrations WHERE version=22", &[]).await.unwrap();
    }
    let reopened = Db::open(&db_url).await;
    assert!(reopened.is_ok(), "migration 22 resume failed on Postgres: {:?}", reopened.err());
    let reopened = reopened.unwrap();
    assert_eq!(reopened.version().await.unwrap(), 23);
    assert_eq!(
        reopened.query("SELECT v FROM meta WHERE k='rotation_lifecycle'", &[]).await.unwrap().len(),
        1
    );
}
