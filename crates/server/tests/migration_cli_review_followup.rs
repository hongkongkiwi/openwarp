//! CLI previews and integrity exits for interrupted or partially upgraded ledgers.

use openwarp_server::db::{s, Db, Row};
use openwarp_server::migrate::{self, Options, MIGRATIONS};
use serde_json::json;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("openwarp_cli_followup_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_openwarp-migrate"))
            .env_remove("DATABASE_URL").args(["--database-url", &self.url()]).args(args)
            .output().expect("run migration CLI against private fixture")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn diagnostic(output: &Output) -> String {
    format!("exit {:?}, stdout={:?}, stderr={:?}", output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

async fn snapshot(db: &Db) -> Vec<(String, Vec<Row>)> {
    let schema = db.query("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name", &[]).await.unwrap();
    let tables = db.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", &[]).await.unwrap();
    let mut result = vec![("sqlite_master".into(), schema)];
    for table in tables {
        let name = s(&table, "name");
        let sql = format!("SELECT * FROM \"{}\" ORDER BY rowid", name.replace('"', "\"\""));
        result.push((name, db.query(&sql, &[]).await.unwrap()));
    }
    result
}

fn has_number(text: &str, number: i64) -> bool {
    text.split(|c: char| !c.is_ascii_digit()).any(|part| part.parse::<i64>() == Ok(number))
}

async fn interrupted_baseline(scratch: &Scratch, through: i64) -> Db {
    let db = Db::connect(&scratch.url()).await.unwrap();
    migrate::apply(&db, MIGRATIONS, Options { to: Some(17) }).await.unwrap();
    db.exec("DELETE FROM schema_migrations WHERE version>?", &[json!(through)]).await.unwrap();
    let baseline = db.one("SELECT name,checksum FROM schema_migrations WHERE version=1", &[]).await.unwrap().unwrap();
    assert_eq!(s(&baseline, "name"), "baseline");
    assert_eq!(s(&baseline, "checksum"), migrate::checksum(MIGRATIONS[0].sql));
    db
}

#[tokio::test]
async fn interrupted_squash_preview_labels_remaining_prefix_without_mutation() {
    let mut violations = Vec::new();
    for through in [3, 16] {
        let scratch = Scratch::new();
        let db = interrupted_baseline(&scratch, through).await;
        let before = snapshot(&db).await;
        let output = scratch.cli(&["apply", "--dry-run", "--to", "18"]);
        assert_eq!(snapshot(&db).await, before, "preview must preserve all schema, data, ledger and ownership rows");
        assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        for migration in MIGRATIONS.iter().filter(|m| (through + 1..=17).contains(&m.version)) {
            let covered = stdout.lines().any(|line| line.contains("squash") && has_number(line, migration.version))
                || stdout.lines().any(|line| line.contains("squash") && has_number(line, through + 1) && has_number(line, 17));
            let executed = stdout.lines().any(|line| line.contains("would apply") && has_number(line, migration.version));
            if !covered || executed {
                violations.push(format!("prefix through {through}: version {} must be described as squashed, not executed; {}", migration.version, diagnostic(&output)));
            }
        }
        assert!(stdout.lines().any(|line| line.contains("would apply") && has_number(line, 18) && line.contains(MIGRATIONS[17].name)));
        for migration in MIGRATIONS.iter().filter(|m| m.version > 18) { assert!(!stdout.contains(migration.name), "--to 18 must omit later migrations"); }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[tokio::test]
async fn actual_apply_completes_interrupted_squash_prefix_before_version_18() {
    let scratch = Scratch::new();
    let db = interrupted_baseline(&scratch, 3).await;
    let output = scratch.cli(&["apply", "--to", "18"]);
    assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
    let rows = db.query("SELECT version,checksum,success FROM schema_migrations WHERE version BETWEEN 2 AND 17 ORDER BY version", &[]).await.unwrap();
    assert_eq!(rows.len(), 16);
    for row in rows {
        assert_eq!(s(&row, "checksum"), "squashed");
        assert_eq!(openwarp_server::db::n(&row, "success"), 1);
    }
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 18);
    assert!(!status.has_problems());
}

#[tokio::test]
async fn partial_metadata_is_an_integrity_exit_for_verify_and_apply_preflight() {
    let mut violations = Vec::new();
    for success in [1, 0] {
        let scratch = Scratch::new();
        let db = Db::connect(&scratch.url()).await.unwrap();
        db.exec_raw("CREATE TABLE schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL,name TEXT NOT NULL,checksum TEXT NOT NULL,success BIGINT NOT NULL)").await.unwrap();
        db.exec("INSERT INTO schema_migrations VALUES(1,1,'baseline',?,?)", &[json!(migrate::checksum(MIGRATIONS[0].sql)), json!(success)]).await.unwrap();
        db.exec_raw("CREATE TABLE application_data(value TEXT NOT NULL); INSERT INTO application_data VALUES('preserve me')").await.unwrap();
        let before = snapshot(&db).await;
        for args in [&["verify"][..], &["apply"][..], &["apply", "--dry-run"][..]] {
            let output = scratch.cli(args);
            assert_eq!(snapshot(&db).await, before, "partial metadata refusal must not mutate schema, data or ledger");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(!stdout.lines().any(|line| line.starts_with("ok:") || line.contains("already current")), "partial metadata must never be certified clean");
            if output.status.code() != Some(1) {
                violations.push(format!("success={success}, args={args:?}: ledger integrity must exit 1; {}", diagnostic(&output)));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[tokio::test]
async fn genuine_two_column_legacy_ledger_verify_and_preview_remain_read_only() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.unwrap();
    db.exec_raw("CREATE TABLE schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL); INSERT INTO schema_migrations VALUES(1,1)").await.unwrap();
    let before = snapshot(&db).await;
    for args in [&["verify"][..], &["apply", "--dry-run", "--to", "18"][..]] {
        let output = scratch.cli(args);
        assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
        assert_eq!(snapshot(&db).await, before);
    }
}

#[tokio::test]
async fn full_current_ledger_verify_preview_and_apply_remain_successful_noops() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.unwrap();
    migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    let before = snapshot(&db).await;
    for args in [&["verify"][..], &["apply", "--dry-run"][..], &["apply"][..]] {
        let output = scratch.cli(args);
        assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
        assert_eq!(snapshot(&db).await, before);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("would apply"));
    }
}
