//! Offline operator CLI planning and invocation regressions.

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
        let path = std::env::temp_dir().join(format!("openwarp_cli_plan_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("create private fixture directory");
        Self(path)
    }

    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn cli(scratch: &Scratch, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openwarp-migrate"))
        .current_dir(&scratch.0)
        .env_remove("DATABASE_URL")
        .args(["--database-url", &scratch.url()])
        .args(args)
        .output().expect("run migration CLI")
}

fn diagnostic(output: &Output) -> String {
    format!("exit {:?}\nstdout: {}\nstderr: {}", output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

async fn initialized(scratch: &Scratch, to: Option<i64>) -> Db {
    let db = Db::connect(&scratch.url()).await.expect("open private database");
    migrate::apply(&db, MIGRATIONS, Options { to }).await.expect("initialize fixture");
    db
}

// Include schema, application data, ledger and ownership metadata, not file bytes affected by WAL.
async fn snapshot(db: &Db) -> Vec<(String, Vec<Row>)> {
    let schema = db.query("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name", &[]).await.unwrap();
    let tables = db.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", &[]).await.unwrap();
    let mut result = vec![("sqlite_master".to_string(), schema)];
    for table in tables {
        let name = s(&table, "name");
        let sql = format!("SELECT * FROM \"{}\" ORDER BY rowid", name.replace('"', "\"\""));
        result.push((name, db.query(&sql, &[]).await.expect("snapshot fixture table")));
    }
    result
}

fn has_number(text: &str, number: i64) -> bool {
    text.split(|c: char| !c.is_ascii_digit()).any(|part| part.parse::<i64>() == Ok(number))
}

fn assert_planned(stdout: &str, version: i64) {
    let migration = MIGRATIONS.iter().find(|m| m.version == version).unwrap();
    assert!(stdout.lines().any(|line| line.contains(migration.name) && has_number(line, version)),
        "preview must identify migration {} {}\n{}", version, migration.name, stdout);
}

#[tokio::test]
async fn conflicting_repair_actions_are_invocation_errors_without_mutation() {
    let scratch = Scratch::new();
    let db = initialized(&scratch, None).await;
    let latest = MIGRATIONS.last().unwrap().version;
    let version = latest.to_string();
    let actions = ["--set-applied", "--remove", "--accept-checksum"];
    let mut violations = Vec::new();
    for first in actions {
        for second in actions {
            if first == second { continue; }
            // Each action would succeed alone, so a parser accepting the last flag really mutates.
            db.exec("DELETE FROM schema_migrations WHERE version=?", &[json!(latest)]).await.unwrap();
            db.exec("INSERT INTO schema_migrations(version,applied_at,name,checksum,success,execution_ms) VALUES(?,1,?,'fixture-drift',0,0)",
                &[json!(latest), json!(MIGRATIONS.last().unwrap().name)]).await.unwrap();
            let before = snapshot(&db).await;
            let output = cli(&scratch, &["repair", "--version", &version, first, second]);
            if output.status.code() != Some(2) || snapshot(&db).await != before {
                violations.push(format!("{} {} must exit 2 and preserve the database; {}", first, second, diagnostic(&output)));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[tokio::test]
async fn a_single_repair_action_still_performs_the_requested_repair() {
    let scratch = Scratch::new();
    let db = initialized(&scratch, None).await;
    let latest = MIGRATIONS.last().unwrap().version;
    let version = latest.to_string();
    db.exec("UPDATE schema_migrations SET success=0 WHERE version=?", &[json!(latest)]).await.unwrap();
    let output = cli(&scratch, &["repair", "--version", &version, "--set-applied"]);
    assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
    assert!(migrate::status(&db, MIGRATIONS).await.unwrap().problems.is_empty());

    db.exec("UPDATE schema_migrations SET checksum='fixture-drift' WHERE version=?", &[json!(latest)]).await.unwrap();
    let output = cli(&scratch, &["repair", "--version", &version, "--accept-checksum"]);
    assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
    assert!(migrate::status(&db, MIGRATIONS).await.unwrap().problems.is_empty());

    db.exec("UPDATE schema_migrations SET success=0 WHERE version=?", &[json!(latest)]).await.unwrap();
    let earlier = db.query("SELECT * FROM schema_migrations WHERE version<? ORDER BY version", &[json!(latest)]).await.unwrap();
    let output = cli(&scratch, &["repair", "--version", &version, "--remove"]);
    assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
    assert!(db.one("SELECT version FROM schema_migrations WHERE version=?", &[json!(latest)]).await.unwrap().is_none());
    assert_eq!(db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap(), earlier);
}

#[tokio::test]
async fn dry_run_honors_to_without_changing_existing_ledger() {
    let scratch = Scratch::new();
    let db = initialized(&scratch, Some(17)).await;
    let before = snapshot(&db).await;
    let output = cli(&scratch, &["apply", "--dry-run", "--to", "18"]);
    assert_eq!(snapshot(&db).await, before, "preview must preserve schema, data and ledger");
    assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_planned(&stdout, 18);
    for migration in MIGRATIONS.iter().filter(|m| m.version > 18) {
        assert!(!stdout.contains(migration.name), "--to 18 must exclude later migration {} {}\n{}", migration.version, migration.name, stdout);
    }
}

#[tokio::test]
async fn empty_existing_database_preview_distinguishes_baseline_squash_from_execution() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.unwrap();
    let before = snapshot(&db).await;
    assert!(before[0].1.is_empty(), "fixture must be an existing empty database");
    let output = cli(&scratch, &["apply", "--dry-run", "--to", "19"]);
    assert_eq!(snapshot(&db).await, before, "fresh preview must not create schema or ledger");
    assert_eq!(output.status.code(), Some(0), "{}", diagnostic(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for version in [1, 18, 19] { assert_planned(&stdout, version); }
    assert!(stdout.lines().any(|line| line.to_lowercase().contains("squash") && has_number(line, 2) && has_number(line, 17)),
        "preview must identify versions 2 through 17 as squashed, not executed\n{}", stdout);
    for migration in MIGRATIONS.iter().filter(|m| (2..=17).contains(&m.version)) {
        assert!(!stdout.lines().any(|line| line.contains(migration.name) && !line.to_lowercase().contains("squash")),
            "baseline-covered migration {} {} must not be listed for execution\n{}", migration.version, migration.name, stdout);
    }
    for migration in MIGRATIONS.iter().filter(|m| m.version > 19) {
        assert!(!stdout.contains(migration.name), "fresh preview must honor --to 19\n{}", stdout);
    }
}

#[tokio::test]
async fn checksum_drift_is_a_problem_exit_not_an_invocation_error_and_preserves_database() {
    let scratch = Scratch::new();
    let db = initialized(&scratch, Some(18)).await;
    db.exec("UPDATE schema_migrations SET checksum='fixture-drift' WHERE version=18", &[]).await.unwrap();
    let before = snapshot(&db).await;

    let invalid = cli(&scratch, &["apply", "--to", "not-an-integer"]);
    assert_eq!(invalid.status.code(), Some(2), "invalid arguments use the documented invocation exit; {}", diagnostic(&invalid));
    assert_eq!(snapshot(&db).await, before, "invalid invocation must not mutate the database");

    let output = cli(&scratch, &["apply"]);
    assert_eq!(snapshot(&db).await, before, "checksum refusal must not apply later migrations or change ledger/data");
    let message = diagnostic(&output);
    assert!(message.to_lowercase().contains("checksum") && has_number(&message, 18), "refusal must identify the drifted migration; {}", message);
    assert_eq!(output.status.code(), Some(1), "ledger drift uses the documented problem exit, not invocation exit 2; {}", message);
}
