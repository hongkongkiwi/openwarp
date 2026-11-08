//! Migration engine failure modes and live-backend upgrade paths.
//!
//! SQLite runs unconditionally. PostgreSQL and MariaDB run when
//! OPENWARP_TEST_POSTGRES_URL / OPENWARP_TEST_MYSQL_URL name an admin
//! connection; each test creates and drops its own database.

use openwarp_server::db::{n, Db};
use openwarp_server::migrate::{self, Options, Repair, State, MIGRATIONS};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

fn unique() -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst))
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(path));
        }
    }
}

fn scratch_path() -> (PathBuf, Scratch) {
    let path = std::env::temp_dir().join(format!("openwarp_migrations_{}.db", unique()));
    (path.clone(), Scratch(path))
}

async fn sqlite(path: &Path) -> Db {
    Db::connect(&format!("sqlite://{}", path.display())).await.expect("open scratch database")
}

async fn fresh(db: &Db) -> migrate::Report {
    migrate::apply(db, MIGRATIONS, Options::default()).await.expect("apply migrations")
}

#[tokio::test]
async fn sqlite_fresh_apply_status_and_rerun() {
    let (path, scratch) = scratch_path();
    let db = sqlite(&path).await;

    let before = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(!before.ledger_present, "a new file has no ledger yet");
    assert_eq!(before.pending().len(), MIGRATIONS.len(), "everything is pending before the first apply");

    let report = fresh(&db).await;
    assert!(report.squashed, "a new database applies the consolidated baseline");
    assert_eq!(report.applied.first(), Some(&1));
    assert_eq!(report.applied.last(), Some(&29));

    assert_eq!(db.version().await.unwrap(), 29);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 29);
    assert!(status.problems.is_empty(), "{:?}", status.problems.iter().map(|p| p.describe()).collect::<Vec<_>>());
    assert!(status.pending().is_empty());
    assert!(status.entries.iter().any(|e| e.version == 1 && e.state == State::Applied));
    assert!(status.entries.iter().any(|e| e.version == 2 && e.state == State::Squashed));

    // The baseline must produce a usable schema, not just ledger rows.
    let count = db.one("SELECT COUNT(*) AS n FROM users", &[]).await.unwrap().unwrap();
    assert_eq!(n(&count, "n"), 0);
    let column = db.one("SELECT k FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap();
    assert!(column.is_some(), "the guarded backfill records itself");

    let again = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(again.applied.is_empty(), "a second apply is a no-op");
    drop(scratch);
}

#[tokio::test]
async fn sqlite_refuses_checksum_drift_and_accepts_repair() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    fresh(&db).await;

    db.exec("UPDATE schema_migrations SET checksum='deadbeef' WHERE version=18", &[]).await.unwrap();
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap_err();
    assert!(error.contains("checksum"), "{}", error);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(status.problems.iter().any(|p| matches!(p, migrate::Problem::Checksum { version: 18 })));

    migrate::repair(&db, MIGRATIONS, Repair::AcceptChecksum(18)).await.unwrap();
    migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
}

#[tokio::test]
async fn sqlite_refuses_a_newer_database() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    fresh(&db).await;

    db.exec("INSERT INTO schema_migrations(version,applied_at,name,checksum,success,execution_ms) VALUES(99,1,'future','x',1,0)", &[]).await.unwrap();
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap_err();
    assert!(error.contains("newer"), "{}", error);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(status.problems.iter().any(|p| matches!(p, migrate::Problem::Newer { version: 99, latest: 29 })));
}

#[tokio::test]
async fn sqlite_refuses_history_gaps() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    fresh(&db).await;

    db.exec("DELETE FROM schema_migrations WHERE version=10", &[]).await.unwrap();
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap_err();
    assert!(error.contains("missing"), "{}", error);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(status.problems.iter().any(|p| matches!(p, migrate::Problem::Gap { version: 10 })));
}

#[tokio::test]
async fn sqlite_marks_interrupted_migrations_and_repairs_them() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    let migrations = &MIGRATIONS[..18];
    migrate::apply(&db, migrations, Options::default()).await.expect("apply migrations");

    db.exec("UPDATE schema_migrations SET success=0 WHERE version=1", &[]).await.unwrap();
    db.exec("DELETE FROM schema_migrations WHERE version=18", &[]).await.unwrap();
    let error = migrate::apply(&db, migrations, Options::default()).await.unwrap_err();
    assert!(error.contains("did not complete"), "{}", error);

    migrate::repair(&db, migrations, Repair::SetApplied(1)).await.unwrap();
    let report = migrate::apply(&db, migrations, Options::default()).await.unwrap();
    assert_eq!(report.applied, vec![18]);

    // Removing a row makes the next apply run that migration again.
    db.exec("UPDATE schema_migrations SET success=0 WHERE version=18", &[]).await.unwrap();
    migrate::repair(&db, migrations, Repair::Remove(18)).await.unwrap();
    let report = migrate::apply(&db, migrations, Options::default()).await.unwrap();
    assert_eq!(report.applied, vec![18]);
}

#[tokio::test]
async fn sqlite_upgrades_a_legacy_ledger_without_data() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    fresh(&db).await;

    // A pre-engine database: versions exist, checksums and names do not, and
    // the binary is behind the current one.
    db.exec("UPDATE schema_migrations SET checksum='', name=''", &[]).await.unwrap();
    db.exec("DELETE FROM schema_migrations WHERE version > 9", &[]).await.unwrap();

    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    assert_eq!(report.applied, (10i64..=29).collect::<Vec<_>>());
    assert!(!report.squashed);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 29);
    assert!(status.problems.is_empty());
    // Versions that shipped as files are verified from now on; version 1 is
    // the consolidated baseline and stays unverified on an upgraded database.
    let row = db.one("SELECT checksum FROM schema_migrations WHERE version=2", &[]).await.unwrap().unwrap();
    assert!(!openwarp_server::db::s(&row, "checksum").is_empty());
    let row = db.one("SELECT checksum FROM schema_migrations WHERE version=1", &[]).await.unwrap().unwrap();
    assert!(openwarp_server::db::s(&row, "checksum").is_empty());
}

#[tokio::test]
async fn sqlite_upgrades_a_real_v9_schema() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    // The fixture is a genuine pre-engine database: the schema and seed rows
    // come from the commit before migration 10, and the ledger has two columns.
    let fixture = migrate::split_sql(include_str!("fixtures/schema_v9.sql"));
    db.exec_script(&fixture).await.expect("build the v9 schema");

    let before = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert_eq!(before.current, 9);
    assert!(before.entries.iter().any(|e| e.version == 9 && e.state == State::Legacy));
    assert!(before.entries.iter().any(|e| e.version == 10 && e.state == State::Pending));
    assert!(before.problems.is_empty());

    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    assert_eq!(report.applied, (10i64..=29).collect::<Vec<_>>());
    assert!(!report.squashed);
    assert_eq!(db.version().await.unwrap(), 29);
    assert!(migrate::status(&db, MIGRATIONS).await.unwrap().problems.is_empty());

    // Old rows survive, and objects added by later versions are usable.
    let org = db.one("SELECT name FROM orgs WHERE id='org-v9'", &[]).await.unwrap().unwrap();
    assert_eq!(openwarp_server::db::s(&org, "name"), "Legacy");
    let user = db.one("SELECT email FROM users WHERE id='user-v9'", &[]).await.unwrap().unwrap();
    assert_eq!(openwarp_server::db::s(&user, "email"), "v9@example.com");
    db.exec("INSERT INTO ldap_configs(org_id,url) VALUES('org-v9','ldaps://localhost')", &[]).await.unwrap();
    let ldap = db.one("SELECT count(*) AS n FROM ldap_configs", &[]).await.unwrap().unwrap();
    assert_eq!(openwarp_server::db::n(&ldap, "n"), 1);
    assert!(db.one("SELECT config_enc FROM rotation_schedules LIMIT 1", &[]).await.is_ok(), "version 11 added the column");
    let passkeys = db.one("SELECT count(*) AS n FROM passkeys", &[]).await.unwrap().unwrap();
    assert_eq!(openwarp_server::db::n(&passkeys, "n"), 0);
}

#[tokio::test]
async fn sqlite_persistent_owner_requires_explicit_recovery_even_when_old() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    // Model an older/custom runner's persistent claim before native protocol initialization.
    db.exec_raw("CREATE TABLE schema_migration_lock(id BIGINT PRIMARY KEY,owner TEXT NOT NULL,acquired_at BIGINT NOT NULL)").await.unwrap();
    let now = openwarp_server::clock::now();
    db.exec("INSERT INTO schema_migration_lock(id,owner,acquired_at) VALUES(1,'other',?)", &[json!(now)]).await.unwrap();
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap_err();
    assert!(error.contains("migration lock") && error.contains("other"), "{}", error);

    db.exec("UPDATE schema_migration_lock SET acquired_at=? WHERE id=1", &[json!(now - 3600)]).await.unwrap();
    let before = db.query("SELECT * FROM schema_migration_lock", &[]).await.unwrap();
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap_err();
    assert!(error.contains("migration lock") && error.contains("other"), "{}", error);
    assert_eq!(db.query("SELECT * FROM schema_migration_lock", &[]).await.unwrap(), before, "age does not prove abandonment");
    assert!(migrate::recover_lock(&db, "wrong-owner").await.is_err());
    assert_eq!(db.query("SELECT * FROM schema_migration_lock", &[]).await.unwrap(), before, "recovery must match the exact owner");
    // This fixture has no active runner or remotely submitted SQL.
    migrate::recover_lock(&db, "other").await.unwrap();
    migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    let lock = db.one("SELECT owner FROM schema_migration_lock WHERE id=1", &[]).await.unwrap().unwrap();
    assert_eq!(openwarp_server::db::s(&lock, "owner"), "native-session-v1", "native initialization retains its permanent protocol marker");
    assert!(migrate::status(&db, MIGRATIONS).await.unwrap().problems.is_empty());
}

#[tokio::test]
async fn sqlite_inspection_does_not_create_or_write() {
    let missing = std::env::temp_dir().join(format!("openwarp_missing_{}.db", unique()));
    let error = Db::connect_read_only(&format!("sqlite://{}", missing.display())).await.err().expect("a missing file is an error");
    assert!(error.to_lowercase().contains("unable to open"), "{}", error);
    assert!(!missing.exists(), "inspection must not leave an empty database behind");

    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    fresh(&db).await;
    let reader = Db::connect_read_only(&format!("sqlite://{}", path.display())).await.unwrap();
    let status = migrate::status(&reader, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 29);
    let error = reader.exec("DELETE FROM schema_migrations", &[]).await.unwrap_err();
    assert!(error.to_lowercase().contains("readonly"), "{}", error);
}

#[tokio::test]
async fn repair_refuses_a_database_without_a_ledger() {
    let (path, _scratch) = scratch_path();
    let db = sqlite(&path).await;
    let error = migrate::repair(&db, MIGRATIONS, Repair::SetApplied(18)).await.unwrap_err();
    assert!(error.contains("no schema_migrations ledger"), "{}", error);
    let ledger = db.one("SELECT version FROM schema_migrations LIMIT 1", &[]).await;
    assert!(ledger.is_err(), "repair must not create the ledger");
}

#[tokio::test]
async fn postgres_two_runners_serialize() {
    let Some(admin_url) = std::env::var("OPENWARP_TEST_POSTGRES_URL").ok().filter(|url| !url.trim().is_empty()) else { return };
    let db_name = format!("openwarp_race_{}", unique());
    let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.expect("connect admin");
    let driver = tokio::spawn(async move { let _ = connection.await; });
    admin.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", db_name)).await.ok();
    admin.batch_execute(&format!("CREATE DATABASE {}", db_name)).await.expect("create test database");
    let base = admin_url.split('?').next().unwrap_or(&admin_url);
    let db_url = match base.rfind('/') {
        Some(index) => format!("{}/{}", &base[..index], db_name),
        None => format!("{}/{}", base, db_name),
    };
    let guard = PgDatabase { admin_url: admin_url.clone(), name: db_name.clone() };

    // Both connections race on ledger creation, then on the migration lock.
    // One may be told another instance is running; that is the correct answer,
    // and the loser must not leave a partial schema behind.
    let first = Db::connect(&db_url).await.expect("open first");
    let second = Db::connect(&db_url).await.expect("open second");
    let (one, two) = tokio::join!(
        migrate::apply(&first, MIGRATIONS, Options::default()),
        migrate::apply(&second, MIGRATIONS, Options::default()),
    );
    for outcome in [one, two] {
        if let Err(error) = outcome {
            assert!(error.contains("another instance") || error.contains("could not acquire"), "unexpected error: {}", error);
        }
    }
    let status = migrate::status(&first, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 29);
    assert!(status.problems.is_empty(), "{:?}", status.problems.iter().map(|p| p.describe()).collect::<Vec<_>>());
    drop((first, second));
    drop(guard);
    driver.abort();
}

#[tokio::test]
async fn postgres_applies_the_same_manifest() {
    let Some(admin_url) = std::env::var("OPENWARP_TEST_POSTGRES_URL").ok().filter(|url| !url.trim().is_empty()) else { return };
    let db_name = format!("openwarp_migrations_{}", unique());
    let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.expect("connect admin");
    let driver = tokio::spawn(async move { let _ = connection.await; });
    admin.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", db_name)).await.ok();
    admin.batch_execute(&format!("CREATE DATABASE {}", db_name)).await.expect("create test database");
    let base = admin_url.split('?').next().unwrap_or(&admin_url);
    let db_url = match base.rfind('/') {
        Some(index) => format!("{}/{}", &base[..index], db_name),
        None => format!("{}/{}", base, db_name),
    };
    let guard = PgDatabase { admin_url: admin_url.clone(), name: db_name.clone() };

    let db = Db::connect(&db_url).await.expect("open postgres database");
    let report = fresh(&db).await;
    assert!(report.squashed);
    assert_eq!(db.version().await.unwrap(), 29);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(status.problems.is_empty(), "{:?}", status.problems.iter().map(|p| p.describe()).collect::<Vec<_>>());
    // A second process must see the same ledger and refuse drift.
    db.exec("UPDATE schema_migrations SET checksum='deadbeef' WHERE version=18", &[]).await.unwrap();
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap_err();
    assert!(error.contains("checksum"), "{}", error);
    drop(db);
    drop(guard);
    driver.abort();
}

struct PgDatabase { admin_url: String, name: String }

impl Drop for PgDatabase {
    fn drop(&mut self) {
        let admin = self.admin_url.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() { Ok(r) => r, Err(_) => return };
            runtime.block_on(async move {
                if let Ok((client, connection)) = tokio_postgres::connect(&admin, tokio_postgres::NoTls).await {
                    let driver = tokio::spawn(async move { let _ = connection.await; });
                    let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", name)).await;
                    driver.abort();
                }
            });
        }).join();
    }
}

#[tokio::test]
async fn mariadb_applies_the_same_manifest() {
    use mysql_async::prelude::Queryable;
    let Some(admin_url) = std::env::var("OPENWARP_TEST_MYSQL_URL").ok().filter(|url| !url.trim().is_empty()) else { return };
    let db_name = format!("openwarp_migrations_{}", unique());
    let opts = mysql_async::Opts::from_url(&admin_url).expect("admin URL");
    let pool = mysql_async::Pool::new(opts);
    {
        let mut conn = pool.get_conn().await.expect("connect admin");
        conn.query_drop(format!("DROP DATABASE IF EXISTS `{}`", db_name)).await.ok();
        conn.query_drop(format!("CREATE DATABASE `{}` DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_bin", db_name)).await.expect("create test database");
    }
    let base = admin_url.split('?').next().unwrap_or(&admin_url);
    let db_url = match base.rfind('/') {
        Some(index) => format!("{}/{}", &base[..index], db_name),
        None => format!("{}/{}", base, db_name),
    };
    let guard = MyDatabase { admin_url: admin_url.clone(), name: db_name.clone() };

    let db = Db::connect(&db_url).await.expect("open mariadb database");
    let report = fresh(&db).await;
    assert!(report.squashed);
    assert_eq!(db.version().await.unwrap(), 29);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(status.problems.is_empty(), "{:?}", status.problems.iter().map(|p| p.describe()).collect::<Vec<_>>());
    // MySQL rewrites keyed TEXT to VARCHAR; an insert against a rewritten
    // column proves the schema is usable, not just recorded.
    db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("o1"), json!("Acme"), json!(1)]).await.unwrap();
    let row = db.one("SELECT name FROM orgs WHERE id=?", &[json!("o1")]).await.unwrap().unwrap();
    assert_eq!(openwarp_server::db::s(&row, "name"), "Acme");
    drop(db);
    drop(pool);
    drop(guard);
}

struct MyDatabase { admin_url: String, name: String }

impl Drop for MyDatabase {
    fn drop(&mut self) {
        let admin = self.admin_url.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() { Ok(r) => r, Err(_) => return };
            runtime.block_on(async move {
                use mysql_async::prelude::Queryable;
                if let Ok(opts) = mysql_async::Opts::from_url(&admin) {
                    let pool = mysql_async::Pool::new(opts);
                    if let Ok(mut conn) = pool.get_conn().await {
                        let _ = conn.query_drop(format!("DROP DATABASE IF EXISTS `{}`", name)).await;
                    }
                    pool.disconnect().await.ok();
                }
            });
        }).join();
    }
}
