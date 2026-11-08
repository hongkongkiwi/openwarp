//! Completion-write races against real SQLite ledger rows.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Migration, Options, Target, MIGRATIONS, SQUASHED_THROUGH};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("openwarp_completion_marker_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("create private fixture directory");
        Self(path)
    }

    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[derive(Clone, Copy, Debug)]
enum Fault { None, Remove, Name, Checksum }

struct CompletionTarget {
    db: Db,
    fault: Fault,
    intercepted: Cell<bool>,
}

impl CompletionTarget {
    fn completion_fault(&self, sql: &str) -> Option<&'static str> {
        let normalized: String = sql.chars().filter(|c| !c.is_whitespace()).flat_map(char::to_lowercase).collect();
        let assignments = normalized.trim_end_matches(';').strip_prefix("updateschema_migrationsset")?
            .strip_suffix("whereversion=18")?;
        if !assignments.split(',').any(|assignment| assignment == "success=1") { return None; }
        self.intercepted.set(true);
        match self.fault {
            Fault::None => None,
            Fault::Remove => Some("DELETE FROM schema_migrations WHERE version=18"),
            Fault::Name => Some("UPDATE schema_migrations SET name='other_runner' WHERE version=18"),
            Fault::Checksum => Some("UPDATE schema_migrations SET checksum='other_checksum' WHERE version=18"),
        }
    }
}

impl Target for CompletionTarget {
    async fn exec(&self, sql: &str) -> Result<(), String> {
        // Model an operator rewriting history after SQL succeeds but before completion is recorded.
        if let Some(fault) = self.completion_fault(sql) { self.db.exec_raw(fault).await?; }
        self.db.exec_raw(sql).await
    }

    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> { self.db.query(sql, &[]).await }
    async fn script(&self, statements: &[String]) -> Result<(), String> {
        let mut injected = Vec::new();
        for statement in statements {
            if let Some(fault) = self.completion_fault(statement) { injected.push(fault.to_string()); }
            injected.push(statement.clone());
        }
        self.db.exec_script(&injected).await
    }
    fn atomic_ddl(&self) -> bool { self.db.script_is_atomic() }
    async fn has_application_schema(&self) -> Result<bool, String> { self.db.has_application_schema().await }
}

fn migrations(tolerant: bool) -> Vec<Migration> {
    let mut migrations: Vec<_> = MIGRATIONS.iter().take(SQUASHED_THROUGH as usize).map(|m| Migration {
        version: m.version, name: m.name, sql: m.sql, tolerant: m.tolerant,
    }).collect();
    migrations.push(Migration { version: 18, name: "under_test", sql: "INSERT INTO migration_effects(version) VALUES(18);", tolerant });
    migrations.push(Migration { version: 19, name: "later", sql: "INSERT INTO migration_effects(version) VALUES(19);", tolerant: false });
    migrations
}

async fn exercise(fault: Fault, tolerant: bool) {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    let migrations = migrations(tolerant);
    let target = CompletionTarget { db, fault, intercepted: Cell::new(false) };
    // Initialize through the same generic ownership protocol as the fault-injecting run.
    migrate::apply(&target, &migrations[..SQUASHED_THROUGH as usize], Options::default()).await.expect("initialize fixture");
    target.db.exec_raw("CREATE TABLE migration_effects(version INTEGER PRIMARY KEY)").await.unwrap();

    let outcome = migrate::apply(&target, &migrations, Options::default()).await;
    assert!(target.intercepted.get(), "completion fault must reach version 18, fault={:?}, tolerant={}", fault, tolerant);
    let effects = target.db.query("SELECT version FROM migration_effects ORDER BY version", &[]).await.unwrap();
    assert!(effects.iter().any(|row| n(row, "version") == 18), "version 18 SQL must have succeeded before the completion race");
    let row = target.db.one("SELECT name,checksum,success FROM schema_migrations WHERE version=18", &[]).await.unwrap();

    match fault {
        Fault::None => {
            let report = outcome.expect("an unchanged completion marker must succeed");
            assert_eq!(report.applied, vec![18, 19]);
            assert_eq!(effects.iter().map(|row| n(row, "version")).collect::<Vec<_>>(), vec![18, 19]);
            let row = row.expect("successful migration retains its ledger row");
            assert_eq!(s(&row, "name"), migrations[SQUASHED_THROUGH as usize].name);
            assert_eq!(s(&row, "checksum"), migrate::checksum(migrations[SQUASHED_THROUGH as usize].sql));
            assert_eq!(n(&row, "success"), 1);
            let again = migrate::apply(&target, &migrations, Options::default()).await.expect("completed history remains valid");
            assert!(again.applied.is_empty(), "a second apply must not repeat successful SQL");
        }
        _ => {
            match fault {
                Fault::Remove => assert!(row.is_none(), "the completion UPDATE must not recreate the deleted row"),
                Fault::Name => assert_eq!(s(&row.unwrap(), "name"), "other_runner"),
                Fault::Checksum => assert_eq!(s(&row.unwrap(), "checksum"), "other_checksum"),
                Fault::None => unreachable!(),
            }
            let error = outcome.expect_err("missing or mismatched completion history must not be reported as success");
            assert!(error.contains("migration 18") && error.contains("ledger"), "unexpected failure: {}", error);
            assert_eq!(effects.iter().map(|row| n(row, "version")).collect::<Vec<_>>(), vec![18], "later migration SQL must not execute after completion verification fails");
            assert!(target.db.one("SELECT version FROM schema_migrations WHERE version=19", &[]).await.unwrap().is_none(), "later migrations must not be recorded as applied");
        }
    }
}

#[tokio::test]
async fn missing_completion_marker_stops_apply() {
    for tolerant in [false, true] { exercise(Fault::Remove, tolerant).await; }
}

#[tokio::test]
async fn mismatched_completion_marker_stops_apply() {
    for tolerant in [false, true] {
        for fault in [Fault::Name, Fault::Checksum] { exercise(fault, tolerant).await; }
    }
}

#[tokio::test]
async fn unchanged_completion_marker_allows_apply_and_rerun() {
    for tolerant in [false, true] { exercise(Fault::None, tolerant).await; }
}
