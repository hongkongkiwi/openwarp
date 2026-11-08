//! Read-only migration inspection must not certify unverified history.

use openwarp_server::db::{n, Db};
use openwarp_server::migrate::{self, LedgerRow, Problem, State, MIGRATIONS, SQUASHED_THROUGH};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("openwarp_ledger_review_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("create private fixture directory");
        Self(path)
    }

    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }

    fn verify(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_openwarp-migrate"))
            .env("DATABASE_URL", self.url()).arg("verify").output().expect("run migration verify")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn applied_rows() -> Vec<LedgerRow> {
    MIGRATIONS.iter().map(|migration| LedgerRow {
        version: migration.version, name: migration.name.into(), checksum: migrate::checksum(migration.sql), success: true, execution_ms: 0,
    }).collect()
}

#[test]
fn squash_markers_outside_baseline_coverage_are_checksum_errors() {
    for version in [22, 1, SQUASHED_THROUGH + 1] {
        let mut rows = applied_rows();
        rows.iter_mut().find(|row| row.version == version).unwrap().checksum = "squashed".into();
        assert_eq!(
            migrate::check(&rows, MIGRATIONS),
            vec![Problem::Checksum { version }],
            "version {version} was not replaced by the consolidated baseline",
        );
    }
}

#[test]
fn valid_checksums_and_covered_squash_markers_are_accepted() {
    let mut rows = applied_rows();
    assert!(migrate::check(&rows, MIGRATIONS).is_empty());
    for row in rows.iter_mut().filter(|row| (2..=SQUASHED_THROUGH).contains(&row.version)) {
        row.checksum = "squashed".into();
    }
    assert!(migrate::check(&rows, MIGRATIONS).is_empty(), "versions 2 through 17 are covered by the baseline");
}

#[tokio::test]
async fn partial_metadata_ledger_does_not_hide_an_incomplete_migration() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    db.exec_raw("CREATE TABLE schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL,name TEXT NOT NULL,checksum TEXT NOT NULL,success INTEGER NOT NULL)").await.unwrap();
    db.exec_raw("INSERT INTO schema_migrations VALUES(1,1,'baseline','',0)").await.unwrap();

    if let Ok(status) = migrate::status(&db, MIGRATIONS).await {
        assert!(status.has_problems(), "a ledger with success=0 but no execution_ms must not be reported as clean legacy history");
        assert_eq!(status.current, 0, "an incomplete migration must not advance the current version");
        assert!(status.entries.iter().any(|entry| entry.version == 1 && entry.state == State::Failed));
    }
    let row = db.one("SELECT success FROM schema_migrations WHERE version=1", &[]).await.unwrap().unwrap();
    assert_eq!(n(&row, "success"), 0, "status must not repair the ledger");
    let columns = db.query("PRAGMA table_info(schema_migrations)", &[]).await.unwrap();
    assert_eq!(columns.len(), 5, "status must not upgrade the ledger");
}

#[tokio::test]
async fn true_two_column_legacy_ledger_stays_readable_and_unmodified() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    db.exec_raw("CREATE TABLE schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL)").await.unwrap();
    db.exec_raw("INSERT INTO schema_migrations VALUES(1,1)").await.unwrap();

    let status = migrate::status(&db, MIGRATIONS).await.expect("read genuine legacy ledger");
    assert!(status.ledger_present);
    assert!(!status.has_problems());
    assert_eq!(status.current, 1);
    assert!(status.entries.iter().any(|entry| entry.version == 1 && entry.state == State::Legacy));
    assert_eq!(status.pending().len(), MIGRATIONS.len() - 1);
    assert_eq!(db.query("PRAGMA table_info(schema_migrations)", &[]).await.unwrap().len(), 2);
}

#[tokio::test]
async fn status_does_not_certify_application_schema_without_a_ledger() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    db.exec_raw("CREATE TABLE application_data(id INTEGER PRIMARY KEY)").await.unwrap();

    if let Ok(status) = migrate::status(&db, MIGRATIONS).await {
        assert!(status.has_problems(), "application tables without migration history are not a clean fresh database");
    }
    assert!(db.query("SELECT version FROM schema_migrations", &[]).await.is_err(), "status must not create a ledger");
}

#[tokio::test]
async fn verify_rejects_application_schema_without_a_ledger() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    db.exec_raw("CREATE TABLE application_data(id INTEGER PRIMARY KEY)").await.unwrap();

    let output = scratch.verify();
    assert_eq!(
        output.status.code(), Some(1),
        "verify must reject missing application history; stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr),
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fresh database"));
    assert!(db.query("SELECT version FROM schema_migrations", &[]).await.is_err(), "verify must not create a ledger");
}

#[tokio::test]
async fn empty_database_without_a_ledger_is_clean_and_verify_succeeds() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");

    let status = migrate::status(&db, MIGRATIONS).await.expect("inspect empty database");
    assert!(!status.ledger_present);
    assert!(!status.has_problems());
    assert_eq!(status.current, 0);
    assert_eq!(status.pending().len(), MIGRATIONS.len());
    let output = scratch.verify();
    assert!(output.status.success(), "stdout={:?}, stderr={:?}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(db.query("SELECT version FROM schema_migrations", &[]).await.is_err(), "inspection must leave an empty database unchanged");
}
