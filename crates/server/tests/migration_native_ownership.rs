//! Native SQLite ownership, transaction rollback, and process-death recovery.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Migration, Options, Repair, Report, Target, MIGRATIONS, SQUASHED_THROUGH};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        loop {
            let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let sequence = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("openwarp_native_{}_{}_{}", std::process::id(), nonce, sequence));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create private native fixture directory: {}", error),
            }
        }
    }
    fn url(&self) -> String { format!("sqlite://{}", self.0.join("main.db").display()) }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn manifest(tail: Vec<Migration>) -> Vec<Migration> {
    let mut migrations: Vec<_> = MIGRATIONS.iter().take(SQUASHED_THROUGH as usize).map(|m| Migration {
        version: m.version, name: m.name, sql: m.sql, tolerant: m.tolerant,
    }).collect();
    migrations.extend(tail);
    migrations
}

async fn seed(scratch: &Scratch) -> Db {
    let db = Db::connect(&scratch.url()).await.unwrap();
    migrate::apply(&db, &MIGRATIONS[..SQUASHED_THROUGH as usize], Options::default()).await.unwrap();
    db.exec_raw("CREATE TABLE native_effects(id INTEGER PRIMARY KEY); INSERT INTO native_effects VALUES(99)").await.unwrap();
    db
}

async fn ledger(db: &Db) -> Vec<Row> { db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap() }

async fn native_protocol(db: &Db) -> Vec<Row> {
    let rows = db.query("SELECT * FROM schema_migration_lock ORDER BY id", &[]).await.unwrap();
    assert_eq!(rows.len(), 1, "native ownership retains one protocol marker, not a recoverable run claim");
    assert_eq!(n(&rows[0], "id"), 1);
    assert_eq!(s(&rows[0], "owner"), "native-session-v1");
    rows
}

struct DefaultWrapper<'a>(&'a Db);

impl Target for DefaultWrapper<'_> {
    async fn exec(&self, sql: &str) -> Result<(), String> { self.0.exec_raw(sql).await }
    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> { self.0.query(sql, &[]).await }
    async fn script(&self, statements: &[String]) -> Result<(), String> { self.0.exec_script(statements).await }
    fn atomic_ddl(&self) -> bool { self.0.script_is_atomic() }
    async fn has_application_schema(&self) -> Result<bool, String> { self.0.has_application_schema().await }
}

struct ForwardingWrapper<'a>(&'a Db);

impl Target for ForwardingWrapper<'_> {
    async fn apply(&self, migrations: &[Migration], options: Options) -> Result<Report, String> { migrate::apply(self.0, migrations, options).await }
    async fn repair(&self, migrations: &[Migration], action: Repair) -> Result<String, String> { migrate::repair(self.0, migrations, action).await }
    async fn exec(&self, sql: &str) -> Result<(), String> { self.0.exec_raw(sql).await }
    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> { self.0.query(sql, &[]).await }
    async fn script(&self, statements: &[String]) -> Result<(), String> { self.0.exec_script(statements).await }
    fn atomic_ddl(&self) -> bool { self.0.script_is_atomic() }
    async fn has_application_schema(&self) -> Result<bool, String> { self.0.has_application_schema().await }
}

#[tokio::test]
async fn native_protocol_rejects_generic_wrappers_and_recovery_but_allows_explicit_forwarding() {
    let scratch = Scratch::new();
    let db = seed(&scratch).await;
    let migrations = manifest(vec![Migration { version: 18, name: "forwarded_effect", tolerant: false, sql: "INSERT INTO native_effects VALUES(18);" }]);
    db.exec_raw("UPDATE schema_migrations SET checksum='',name='' WHERE version=2; UPDATE schema_migrations SET success=0 WHERE version=17").await.unwrap();
    let before = ledger(&db).await;
    let protocol = native_protocol(&db).await;
    let generic = DefaultWrapper(&db);
    let error = migrate::apply(&generic, &migrations, Options::default()).await.unwrap_err();
    assert!(error.contains("native-session-v1"), "generic apply must reject the protocol before ledger inspection: {}", error);
    for action in [Repair::SetApplied(17), Repair::Remove(17), Repair::AcceptChecksum(16)] {
        let error = migrate::repair(&generic, &migrations, action).await.unwrap_err();
        assert!(error.contains("native-session-v1"), "generic repair must reject the protocol: {}", error);
        assert_eq!(ledger(&db).await, before, "generic repair must not rewrite native history");
    }
    for owner in ["native-session-v1", "wrong-owner"] {
        assert!(migrate::recover_lock(&db, owner).await.is_err());
        assert!(migrate::recover_lock(&generic, owner).await.is_err());
        assert_eq!(native_protocol(&db).await, protocol, "recovery cannot remove the reserved marker");
    }
    assert_eq!(ledger(&db).await, before, "blocked generic apply must not backfill legacy metadata");
    assert_eq!(db.query("SELECT id FROM native_effects", &[]).await.unwrap().len(), 1);

    let forwarded = ForwardingWrapper(&db);
    migrate::repair(&forwarded, &migrations, Repair::SetApplied(17)).await.unwrap();
    assert_eq!(migrate::apply(&forwarded, &migrations, Options::default()).await.unwrap().applied, vec![18]);
    db.exec_raw("UPDATE schema_migrations SET checksum='drift' WHERE version=18").await.unwrap();
    migrate::repair(&forwarded, &migrations, Repair::AcceptChecksum(18)).await.unwrap();
    db.exec_raw("UPDATE schema_migrations SET success=0 WHERE version=18").await.unwrap();
    migrate::repair(&forwarded, &migrations, Repair::Remove(18)).await.unwrap();
    db.exec_raw("DELETE FROM native_effects WHERE id=18").await.unwrap();
    assert_eq!(migrate::apply(&forwarded, &migrations, Options::default()).await.unwrap().applied, vec![18]);
    assert!(migrate::apply(&forwarded, &migrations, Options::default()).await.unwrap().applied.is_empty());
    assert!(migrate::status(&db, &migrations).await.unwrap().problems.is_empty());
    assert_eq!(native_protocol(&db).await, protocol, "forwarded native operations reuse the permanent marker");
}

#[tokio::test]
async fn failed_native_run_rolls_back_earlier_migrations_and_retries_without_repair() {
    for tolerant in [false, true] {
        let scratch = Scratch::new();
        let db = seed(&scratch).await;
        let before = ledger(&db).await;
        let protocol = native_protocol(&db).await;
        let migrations = manifest(vec![
            Migration { version: 18, name: "first_effect", tolerant: false, sql: "INSERT INTO native_effects VALUES(18); CREATE TABLE native_new(id INTEGER PRIMARY KEY);" },
            Migration { version: 19, name: "failing_effect", tolerant, sql: "INSERT INTO native_effects VALUES(19); INSERT INTO native_dependency VALUES(1);" },
        ]);
        let error = migrate::apply(&db, &migrations, Options::default()).await.unwrap_err();
        assert!(error.contains("native_dependency"), "unexpected failure: {}", error);
        assert_eq!(ledger(&db).await, before, "a failed run must roll back even earlier completed migrations");
        let rows = db.query("SELECT id FROM native_effects ORDER BY id", &[]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(n(&rows[0], "id"), 99, "existing data must survive without partial writes");
        assert!(db.query("SELECT id FROM native_new", &[]).await.is_err(), "DDL must roll back with the run");
        assert_eq!(native_protocol(&db).await, protocol, "rollback must preserve the native protocol without a leaked run claim");
        db.exec_raw("CREATE TABLE native_dependency(id INTEGER PRIMARY KEY)").await.unwrap();
        let report = migrate::apply(&db, &migrations, Options::default()).await.expect("confirmed rollback needs no owner recovery or ledger repair");
        assert_eq!(report.applied, vec![18, 19]);
        assert_eq!(db.query("SELECT id FROM native_effects ORDER BY id", &[]).await.unwrap().iter().map(|row| n(row, "id")).collect::<Vec<_>>(), vec![18, 19, 99]);
        assert_eq!(db.query("SELECT id FROM native_dependency", &[]).await.unwrap().len(), 1);
        assert!(migrate::status(&db, &migrations).await.unwrap().problems.is_empty());
        let completed = ledger(&db).await;
        assert!(migrate::apply(&db, &migrations, Options::default()).await.unwrap().applied.is_empty());
        assert_eq!(ledger(&db).await, completed);
        assert_eq!(native_protocol(&db).await, protocol, "retry must reuse the same native protocol marker");
    }
}

fn crash_manifest(root: &std::path::Path) -> Vec<Migration> {
    let sql = format!("INSERT INTO native_effects VALUES(18); CREATE TABLE native_crash_ddl(id INTEGER PRIMARY KEY); ATTACH DATABASE '{}' AS crash_gate; INSERT INTO crash_gate.hold VALUES(1);", root.join("gate.db").display().to_string().replace('\'', "''"));
    manifest(vec![Migration { version: 18, name: "crash_effect", tolerant: false, sql: Box::leak(sql.into_boxed_str()) }])
}

fn signal_busy(_: i32) -> bool {
    std::fs::write(std::env::var_os("OPENWARP_NATIVE_BUSY_SIGNAL").unwrap(), b"SQL reached locked fixture").unwrap();
    std::thread::sleep(Duration::from_millis(10));
    true
}

#[tokio::test]
async fn sqlite_crash_child() {
    let Some(root) = std::env::var_os("OPENWARP_NATIVE_CRASH_ROOT") else { return };
    let root = PathBuf::from(root);
    let db = Db::connect_existing(&format!("sqlite://{}", root.join("main.db").display())).await.unwrap();
    if let Db::Sqlite(conn) = &db { conn.lock().unwrap().busy_handler(Some(signal_busy)).unwrap(); }
    migrate::apply(&db, &crash_manifest(&root), Options::default()).await.unwrap();
    panic!("parent must kill the child before the blocked migration finishes");
}

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

#[tokio::test]
async fn sqlite_process_crash_excludes_apply_and_repair_then_rolls_back_and_retries() {
    let scratch = Scratch::new();
    let observer = seed(&scratch).await;
    let before = ledger(&observer).await;
    let protocol = native_protocol(&observer).await;
    let gate = rusqlite::Connection::open(scratch.0.join("gate.db")).unwrap();
    gate.execute_batch("CREATE TABLE hold(id INTEGER PRIMARY KEY); BEGIN IMMEDIATE;").unwrap();
    let signal = scratch.0.join("busy.signal");
    let mut child = RunningChild(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sqlite_crash_child", "--nocapture"])
        .env("OPENWARP_NATIVE_CRASH_ROOT", &scratch.0)
        .env("OPENWARP_NATIVE_BUSY_SIGNAL", &signal)
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !signal.exists() {
        assert!(child.0.try_wait().unwrap().is_none(), "child exited before reaching blocked SQL");
        assert!(Instant::now() < deadline, "child did not reach locked fixture SQL");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ledger(&observer).await, before, "uncommitted ledger writes must remain invisible");
    observer.exec_raw("PRAGMA busy_timeout=0").await.unwrap();
    let migrations = crash_manifest(&scratch.0);
    let error = migrate::apply(&observer, &migrations, Options::default()).await.unwrap_err();
    assert!(error.contains("locked") || error.contains("busy"), "contending apply must fail on native ownership: {}", error);
    for action in [Repair::SetApplied(18), Repair::Remove(18), Repair::AcceptChecksum(18)] {
        let error = migrate::repair(&observer, &migrations, action).await.unwrap_err();
        assert!(error.contains("locked") || error.contains("busy"), "repair {:?} must fail on native ownership before inspecting history: {}", action, error);
    }
    let generic = DefaultWrapper(&observer);
    let error = migrate::apply(&generic, &migrations, Options::default()).await.unwrap_err();
    assert!(error.contains("locked") || error.contains("busy") || error.contains("native-session-v1"), "generic apply must not cross an active native transaction: {}", error);
    for action in [Repair::SetApplied(18), Repair::Remove(18), Repair::AcceptChecksum(18)] {
        let error = migrate::repair(&generic, &migrations, action).await.unwrap_err();
        assert!(error.contains("locked") || error.contains("busy") || error.contains("native-session-v1"), "generic repair must not cross an active native transaction: {}", error);
    }
    assert_eq!(ledger(&observer).await, before);
    assert_eq!(native_protocol(&observer).await, protocol);
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success(), "fixture must actually die while migration SQL is blocked");
    gate.execute_batch("ROLLBACK").unwrap();
    assert_eq!(ledger(&observer).await, before, "process death must roll back the running ledger entry");
    assert_eq!(observer.query("SELECT id FROM native_effects", &[]).await.unwrap().iter().map(|row| n(row, "id")).collect::<Vec<_>>(), vec![99]);
    assert!(observer.query("SELECT id FROM native_crash_ddl", &[]).await.is_err(), "process death must roll back DDL");
    assert_eq!(native_protocol(&observer).await, protocol, "process death releases execution ownership, not the protocol marker");
    let error = migrate::apply(&generic, &migrations, Options::default()).await.unwrap_err();
    assert!(error.contains("native-session-v1"), "generic takeover must remain blocked after the native transaction ends: {}", error);
    assert_eq!(ledger(&observer).await, before);
    assert_eq!(migrate::apply(&observer, &migrations, Options::default()).await.expect("dead native owner releases automatically").applied, vec![18]);
    assert_eq!(observer.query("SELECT id FROM native_effects ORDER BY id", &[]).await.unwrap().iter().map(|row| n(row, "id")).collect::<Vec<_>>(), vec![18, 99]);
    assert_eq!(gate.query_row("SELECT count(*) FROM hold", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    assert!(migrate::status(&observer, &migrations).await.unwrap().problems.is_empty());
    assert_eq!(native_protocol(&observer).await, protocol);
}
