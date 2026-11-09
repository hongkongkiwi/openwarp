//! Fresh-baseline squash recovery after a ledger write is interrupted.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, Target, MIGRATIONS, SQUASHED_THROUGH};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);
const INJECTED_ERROR: &str = "injected squash marker write failure";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("openwarp_squash_interruption_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("create private fixture directory");
        Self(path)
    }

    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

struct InterruptedTarget {
    db: Db,
    version: i64,
    intercepted: Cell<bool>,
}

impl Target for InterruptedTarget {
    async fn exec(&self, sql: &str) -> Result<(), String> {
        if !self.intercepted.get() && sql.starts_with("INSERT INTO schema_migrations(")
            && sql.contains(&format!("VALUES({},", self.version)) && sql.contains("'squashed'") {
            self.intercepted.set(true);
            return Err(INJECTED_ERROR.to_string());
        }
        self.db.exec_raw(sql).await
    }

    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> { self.db.query(sql, &[]).await }
    async fn script(&self, statements: &[String]) -> Result<(), String> { self.db.exec_script(statements).await }
    fn atomic_ddl(&self) -> bool { self.db.script_is_atomic() }
    async fn has_application_schema(&self) -> Result<bool, String> { self.db.has_application_schema().await }
}

async fn ledger(db: &Db) -> Vec<Row> {
    db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.expect("read ledger")
}

fn assert_history(rows: &[Row], through: i64) {
    assert_eq!(rows.len(), through as usize, "every covered version must have exactly one ledger row");
    for (row, migration) in rows.iter().zip(MIGRATIONS) {
        assert_eq!(n(row, "version"), migration.version);
        assert_eq!(s(row, "name"), migration.name);
        assert_eq!(n(row, "success"), 1, "migration {} must be complete", migration.version);
        let expected = if (2..=SQUASHED_THROUGH).contains(&migration.version) {
            "squashed".to_string()
        } else {
            migrate::checksum(migration.sql)
        };
        assert_eq!(s(row, "checksum"), expected, "migration {} is covered by the baseline and must not be replayed", migration.version);
    }
}

async fn assert_complete_and_stable(db: &Db) {
    let before = ledger(db).await;
    assert_history(&before, MIGRATIONS.last().unwrap().version);
    let status = migrate::status(db, MIGRATIONS).await.expect("inspect completed history");
    assert_eq!(status.current, MIGRATIONS.last().unwrap().version);
    assert!(status.problems.is_empty(), "{:?}", status.problems);
    assert!(status.pending().is_empty());
    let again = migrate::apply(db, MIGRATIONS, Options::default()).await.expect("completed squash remains restartable");
    assert!(again.applied.is_empty(), "completed migrations must not run twice");
    assert_eq!(ledger(db).await, before, "a second restart must not rewrite completed history");
}

async fn interrupted_squash_resumes(version: i64) {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    let target = InterruptedTarget { db, version, intercepted: Cell::new(false) };

    let error = migrate::apply(&target, MIGRATIONS, Options::default()).await.expect_err("a failed squash marker must not be reported as success");
    assert!(target.intercepted.get(), "the selected squash marker must be attempted");
    assert!(error.contains(INJECTED_ERROR), "unexpected failure: {}", error);
    let prefix = ledger(&target.db).await;
    assert_history(&prefix, version - 1);

    // Seed only after the baseline exists; restart must preserve initialized application data.
    target.db.exec_raw("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('retained-user','squash@example.invalid','fixture-hash','fixture-public','fixture-wrapped',1)").await.unwrap();
    target.db.exec_raw("INSERT INTO meta(k,v) VALUES('squash-fixture','preserve me')").await.unwrap();
    let users_before = target.db.query("SELECT * FROM users ORDER BY id", &[]).await.unwrap();
    let meta_before = target.db.query("SELECT k,v FROM meta WHERE k='squash-fixture'", &[]).await.unwrap();
    drop(target);

    let db = Db::connect_existing(&scratch.url()).await.expect("reopen interrupted database without fault injection");
    let lock_before = db.query("SELECT * FROM schema_migration_lock", &[]).await.unwrap();
    assert_eq!(lock_before.len(), 1, "a generic target cannot infer SQL completion from an error");
    let owner = s(&lock_before[0], "owner");
    assert!(!owner.is_empty());
    let error = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect_err("native restart must respect an uncertain generic owner");
    assert!(error.contains("migration lock"), "{}", error);
    assert_eq!(ledger(&db).await, prefix, "blocked restart must not rewrite the squash prefix");
    assert!(migrate::recover_lock(&db, "wrong-owner").await.is_err());
    assert_eq!(db.query("SELECT * FROM schema_migration_lock", &[]).await.unwrap(), lock_before, "wrong-owner recovery must leave the claim intact");
    // The synchronous fault target has returned and was dropped; no fixture SQL remains in flight.
    migrate::recover_lock(&db, &owner).await.expect("recover only the stopped fixture's exact owner");
    assert!(db.query("SELECT * FROM schema_migration_lock", &[]).await.unwrap().is_empty());
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("restart must finish recording the baseline squash after explicit recovery");
    assert_eq!(db.query("SELECT * FROM users ORDER BY id", &[]).await.unwrap(), users_before, "restart must preserve initialized users");
    assert_eq!(db.query("SELECT k,v FROM meta WHERE k='squash-fixture'", &[]).await.unwrap(), meta_before, "restart must preserve initialized metadata");
    let rows = ledger(&db).await;
    assert_eq!(&rows[..prefix.len()], prefix.as_slice(), "restart must retain already completed ledger entries");
    assert_history(&rows, MIGRATIONS.last().unwrap().version);
    assert_eq!(report.applied, (18i64..=MIGRATIONS.last().unwrap().version).collect::<Vec<_>>(), "restart must run only migrations beyond the consolidated baseline");
    assert_complete_and_stable(&db).await;
}

#[tokio::test]
async fn restart_resumes_squash_before_first_marker() {
    interrupted_squash_resumes(2).await;
}

#[tokio::test]
async fn restart_resumes_squash_after_partial_markers() {
    interrupted_squash_resumes(5).await;
}

#[tokio::test]
async fn fresh_squash_completes_and_restart_is_noop() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("uninterrupted fresh apply");
    assert!(report.squashed);
    assert_eq!(report.applied, [1i64].into_iter().chain(18..=MIGRATIONS.last().unwrap().version).collect::<Vec<_>>());
    assert_complete_and_stable(&db).await;
}
