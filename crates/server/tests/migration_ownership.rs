//! Migration ownership races with real SQLite writes and a suspended SQL batch.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Migration, Options, Repair, SqlDialect, Target, MIGRATIONS, SQUASHED_THROUGH};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

static SEQ: AtomicU32 = AtomicU32::new(0);
const FIRST_WRITE: &str = "INSERT INTO ownership_effects(id,step) VALUES(1,'started')";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("openwarp_ownership_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("create private fixture directory");
        Self(path)
    }

    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[derive(Default)]
struct Gate { entered: Notify, release: Notify }

struct GenericTarget<'a> { db: Db, gate: Option<&'a Gate> }

impl Target for GenericTarget<'_> {
    async fn exec(&self, sql: &str) -> Result<(), String> {
        self.db.exec_raw(sql).await?;
        if sql.trim().trim_end_matches(';') == FIRST_WRITE {
            if let Some(gate) = self.gate {
                // The first write committed, but the same migration still has SQL to execute.
                gate.entered.notify_one();
                gate.release.notified().await;
            }
        }
        Ok(())
    }

    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> { self.db.query(sql, &[]).await }
    async fn script(&self, statements: &[String]) -> Result<(), String> {
        for statement in statements { self.exec(statement).await?; }
        Ok(())
    }
    fn atomic_ddl(&self) -> bool { false }
    fn sql_dialect(&self) -> SqlDialect { SqlDialect::Sqlite }
    async fn has_application_schema(&self) -> Result<bool, String> { self.db.has_application_schema().await }
}

fn migrations(tolerant: bool) -> Vec<Migration> {
    let mut manifest: Vec<_> = MIGRATIONS.iter().take(SQUASHED_THROUGH as usize).map(|m| Migration {
        version: m.version, name: m.name, sql: m.sql, tolerant: m.tolerant,
    }).collect();
    manifest.push(Migration {
        version: 18, name: "held_sql", tolerant,
        sql: "INSERT INTO ownership_effects(id,step) VALUES(1,'started'); INSERT INTO ownership_effects(id,step) VALUES(2,'finished');",
    });
    manifest.push(Migration {
        version: 19, name: "later_sql", tolerant: false,
        sql: "INSERT INTO ownership_effects(id,step) VALUES(3,'later');",
    });
    manifest
}

async fn fixture(scratch: &Scratch, manifest: &[Migration]) -> Db {
    let target = GenericTarget { db: Db::connect(&scratch.url()).await.expect("connect private database"), gate: None };
    migrate::apply(&target, &manifest[..SQUASHED_THROUGH as usize], Options::default()).await.expect("seed generic-protocol baseline");
    target.db.exec_raw("CREATE TABLE ownership_effects(id INTEGER PRIMARY KEY,step TEXT NOT NULL)").await.unwrap();
    target.db
}

async fn ledger(db: &Db) -> Vec<Row> {
    db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap()
}

async fn locks(db: &Db) -> Vec<Row> {
    db.query("SELECT * FROM schema_migration_lock ORDER BY id", &[]).await.unwrap()
}

async fn effects(db: &Db) -> Vec<String> {
    db.query("SELECT step FROM ownership_effects ORDER BY id", &[]).await.unwrap().iter().map(|row| s(row, "step")).collect()
}

#[derive(Clone, Copy, Debug)]
enum Contender { Apply, Repair(Repair) }

impl Contender {
    async fn run<T: Target>(self, target: &T, manifest: &[Migration]) -> Result<(), String> {
        match self {
            Self::Apply => migrate::apply(target, manifest, Options::default()).await.map(|_| ()),
            Self::Repair(action) => migrate::repair(target, manifest, action).await.map(|_| ()),
        }
    }
}

async fn held_sql(contender: Contender, offset: i64, tolerant: bool) {
    let scratch = Scratch::new();
    let manifest = migrations(tolerant);
    let gate = Gate::default();
    let original = GenericTarget { db: fixture(&scratch, &manifest).await, gate: Some(&gate) };
    let observer = Db::connect_existing(&scratch.url()).await.unwrap();
    let second = GenericTarget { db: Db::connect_existing(&scratch.url()).await.unwrap(), gate: None };

    let original_run = migrate::apply(&original, &manifest, Options::default());
    let compete = async {
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await.expect("original must enter its real SQL batch");
        assert_eq!(effects(&observer).await, vec!["started"]);
        let marker = observer.one("SELECT success FROM schema_migrations WHERE version=18", &[]).await.unwrap().unwrap();
        assert_eq!(n(&marker, "success"), 0, "original SQL is still incomplete");
        assert_eq!(locks(&observer).await.len(), 1, "original must hold ownership before contention");
        // Age the real row while its owner is demonstrably still running, without waiting 15 minutes.
        observer.exec("UPDATE schema_migration_lock SET acquired_at=?", &[json!(openwarp_server::clock::now() + offset)]).await.unwrap();
        let before = (ledger(&observer).await, locks(&observer).await);
        let result = tokio::time::timeout(Duration::from_secs(5), contender.run(&second, &manifest)).await;
        let during = (ledger(&observer).await, locks(&observer).await, effects(&observer).await);
        gate.release.notify_one();
        (before, during, result)
    };
    let (completed, (before, during, result)) = tokio::join!(original_run, compete);

    assert!(before.1 == during.1, "{:?} changed or released another runner's lock while its SQL was held (offset={}, tolerant={})", contender, offset, tolerant);
    assert_eq!(during.0, before.0, "{:?} rewrote migration history while original SQL was held", contender);
    assert_eq!(during.2, vec!["started"], "no remaining or later SQL may run before the original is released");
    assert!(result.expect("contender must refuse promptly, not wait for held SQL").is_err(), "{:?} must refuse a live owner", contender);
    assert_eq!(completed.expect("original must complete after release").applied, vec![18, 19]);
    assert_eq!(effects(&observer).await, vec!["started", "finished", "later"]);
    assert!(locks(&observer).await.is_empty(), "successful owner releases its own lock");
    assert!(migrate::status(&original, &manifest).await.unwrap().problems.is_empty());
    assert!(migrate::apply(&second, &manifest, Options::default()).await.expect("completed history must allow a new runner").applied.is_empty());
    assert_eq!(effects(&observer).await, vec!["started", "finished", "later"], "rerun must not repeat migration SQL");
}

#[tokio::test]
async fn apply_cannot_overtake_aged_owner_during_sql() {
    for tolerant in [false, true] { held_sql(Contender::Apply, -3600, tolerant).await; }
}

#[tokio::test]
async fn repair_set_applied_cannot_overtake_aged_owner_during_sql() {
    for tolerant in [false, true] { held_sql(Contender::Repair(Repair::SetApplied(18)), -3600, tolerant).await; }
}

#[tokio::test]
async fn repair_remove_cannot_overtake_aged_owner_during_sql() {
    for tolerant in [false, true] { held_sql(Contender::Repair(Repair::Remove(18)), -3600, tolerant).await; }
}

#[tokio::test]
async fn repair_accept_checksum_cannot_overtake_aged_owner_during_sql() {
    for tolerant in [false, true] { held_sql(Contender::Repair(Repair::AcceptChecksum(18)), -3600, tolerant).await; }
}

#[tokio::test]
async fn recent_and_future_owners_remain_exclusive_until_sql_finishes() {
    for offset in [0, 3600] {
        for contender in [Contender::Apply, Contender::Repair(Repair::SetApplied(18)), Contender::Repair(Repair::Remove(18)), Contender::Repair(Repair::AcceptChecksum(18))] {
            held_sql(contender, offset, false).await;
        }
    }
}

#[tokio::test]
async fn native_apply_and_repairs_cannot_overtake_a_generic_owner_during_sql() {
    let scratch = Scratch::new();
    let manifest = migrations(false);
    let gate = Gate::default();
    let original = GenericTarget { db: fixture(&scratch, &manifest).await, gate: Some(&gate) };
    let native = Db::connect_existing(&scratch.url()).await.unwrap();
    let compete = async {
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await.expect("generic SQL must be suspended after its first committed write");
        native.exec_raw("UPDATE schema_migration_lock SET acquired_at=0").await.unwrap();
        let before = (ledger(&native).await, locks(&native).await);
        let mut outcomes = Vec::new();
        for contender in [Contender::Apply, Contender::Repair(Repair::SetApplied(18)), Contender::Repair(Repair::Remove(18)), Contender::Repair(Repair::AcceptChecksum(18))] {
            outcomes.push((contender, contender.run(&native, &manifest).await));
        }
        let during = (ledger(&native).await, locks(&native).await, effects(&native).await);
        gate.release.notify_one();
        (before, during, outcomes)
    };
    let (completed, (before, during, outcomes)) = tokio::join!(migrate::apply(&original, &manifest, Options::default()), compete);
    for (contender, outcome) in outcomes {
        let error = outcome.expect_err("native ownership cannot supersede a persistent generic claim");
        assert!(error.contains("migration lock"), "{:?} refused for an unexpected reason: {}", contender, error);
    }
    assert_eq!(during.0, before.0, "native contenders must not backfill or repair generic history");
    assert_eq!(during.1, before.1, "native initialization must not replace the generic owner");
    assert_eq!(during.2, vec!["started"], "remaining SQL must stay with the suspended generic owner");
    assert_eq!(completed.unwrap().applied, vec![18, 19]);
    assert_eq!(effects(&native).await, vec!["started", "finished", "later"]);
    assert!(locks(&native).await.is_empty(), "successful generic owner releases its own claim");
    assert!(migrate::apply(&native, &manifest, Options::default()).await.unwrap().applied.is_empty(), "native protocol can initialize only after the generic owner releases");
    let protocol = locks(&native).await;
    assert_eq!(protocol.len(), 1);
    assert_eq!(s(&protocol[0], "owner"), "native-session-v1");
    assert_eq!(ledger(&native).await.len(), 19);
    let before = ledger(&native).await;
    for contender in [Contender::Apply, Contender::Repair(Repair::SetApplied(19)), Contender::Repair(Repair::Remove(19)), Contender::Repair(Repair::AcceptChecksum(19))] {
        let error = contender.run(&original, &manifest).await.unwrap_err();
        assert!(error.contains("native-session-v1"), "generic protocol cannot resume after native initialization: {}", error);
    }
    assert_eq!(ledger(&native).await, before);
    assert_eq!(locks(&native).await, protocol);
    assert_eq!(effects(&native).await, vec!["started", "finished", "later"]);
}

#[tokio::test]
async fn generic_target_cannot_infer_abandonment_from_old_timestamp_alone() {
    let scratch = Scratch::new();
    let manifest = migrations(false);
    let target = GenericTarget { db: fixture(&scratch, &manifest).await, gate: None };
    target.db.exec("INSERT INTO schema_migration_lock(id,owner,acquired_at) VALUES(1,'unknown-owner',?)", &[json!(openwarp_server::clock::now() - 3600)]).await.unwrap();
    let before = (ledger(&target.db).await, locks(&target.db).await);

    let result = migrate::apply(&target, &manifest, Options::default()).await;
    assert_eq!(effects(&target.db).await, Vec::<String>::new(), "a generic target has no evidence that the old owner stopped executing SQL");
    assert_eq!(ledger(&target.db).await, before.0, "unsafe recovery must leave the ledger for operator reconciliation");
    assert!(locks(&target.db).await == before.1, "unsafe recovery must preserve the unknown owner's lock");
    assert!(result.is_err(), "unknown ownership needs a fail-closed manual fallback");
}

#[tokio::test]
async fn unlocked_generic_target_allows_apply_and_explicit_repairs() {
    let scratch = Scratch::new();
    let manifest = migrations(false);
    let target = GenericTarget { db: fixture(&scratch, &manifest).await, gate: None };
    assert_eq!(migrate::apply(&target, &manifest, Options::default()).await.unwrap().applied, vec![18, 19]);
    assert_eq!(effects(&target.db).await, vec!["started", "finished", "later"]);

    target.db.exec_raw("UPDATE schema_migrations SET success=0 WHERE version=19").await.unwrap();
    migrate::repair(&target, &manifest, Repair::SetApplied(19)).await.expect("unlocked completion repair");
    target.db.exec_raw("UPDATE schema_migrations SET checksum='drift' WHERE version=19").await.unwrap();
    migrate::repair(&target, &manifest, Repair::AcceptChecksum(19)).await.expect("unlocked checksum repair");
    target.db.exec_raw("UPDATE schema_migrations SET success=0 WHERE version=19").await.unwrap();
    migrate::repair(&target, &manifest, Repair::Remove(19)).await.expect("unlocked interrupted-latest removal");
    target.db.exec_raw("DELETE FROM ownership_effects WHERE id=3").await.unwrap();
    assert_eq!(migrate::apply(&target, &manifest, Options::default()).await.unwrap().applied, vec![19]);
    assert_eq!(effects(&target.db).await, vec!["started", "finished", "later"]);
    assert!(migrate::status(&target, &manifest).await.unwrap().problems.is_empty());
    assert!(locks(&target.db).await.is_empty(), "every successful operation releases its own ownership");
}
