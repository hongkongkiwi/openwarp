//! Offline migration review regressions against private SQLite databases.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, Repair, MIGRATIONS};
use serde_json::json;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("openwarp_migration_review_{}_{}_{}", std::process::id(), nanos, SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("create private fixture directory");
        Self(path)
    }

    fn url(&self) -> String { format!("sqlite://{}", self.0.join("test.db").display()) }
}

impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

async fn fresh(scratch: &Scratch) -> Db {
    let db = Db::connect(&scratch.url()).await.expect("connect private database");
    migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("initialize fixture");
    db
}

async fn ledger(db: &Db) -> Vec<Row> {
    db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.expect("read ledger snapshot")
}

fn cli(scratch: &Scratch, url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openwarp-migrate"))
        .current_dir(&scratch.0)
        .env_remove("DATABASE_URL")
        .args(["--database-url", url])
        .args(args)
        .output().expect("run migration CLI")
}

#[tokio::test]
async fn unledgered_partial_users_is_not_falsely_squashed() {
    let scratch = Scratch::new();
    let db = Db::connect(&scratch.url()).await.unwrap();
    db.exec("CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL,retained_payload TEXT NOT NULL)", &[]).await.unwrap();
    db.exec("INSERT INTO users(id,email,retained_payload) VALUES('existing','fixture@example.invalid','preserve me')", &[]).await.unwrap();
    let before = db.query("SELECT id,email,retained_payload FROM users ORDER BY id", &[]).await.unwrap();

    let outcome = migrate::apply(&db, MIGRATIONS, Options::default()).await;
    let after = db.query("SELECT id,email,retained_payload FROM users ORDER BY id", &[]).await.expect("existing user data must remain readable");
    assert_eq!(after, before, "migration must not replace or discard existing user data");

    match outcome {
        Ok(report) => {
            let columns = db.query("PRAGMA table_info(users)", &[]).await.unwrap();
            let names: Vec<_> = columns.iter().map(|row| s(row, "name")).collect();
            let missing: Vec<_> = ["id", "email", "pass_hash", "pubkey", "wrapped_privkey", "created_at", "active", "email_verified", "auth_version", "kdf_salt", "kdf_iterations", "kdf_algo", "auth_key_enc"]
                .into_iter().filter(|name| !names.iter().any(|present| present == name)).collect();
            assert!(missing.is_empty(), "apply reported success ({:?}) on an incomplete users schema; missing columns: {:?}", report, missing);
        }
        Err(_) => {
            let rows = db.query("SELECT version FROM schema_migrations WHERE success=1 OR checksum='squashed'", &[]).await.unwrap();
            assert!(rows.is_empty(), "refusing a partial unledgered schema must not certify skipped migrations");
        }
    }
}

#[tokio::test]
async fn cli_repair_remove_dry_run_preserves_entire_ledger() {
    let scratch = Scratch::new();
    let db = fresh(&scratch).await;
    let latest = MIGRATIONS.last().unwrap().version.to_string();
    db.exec("UPDATE schema_migrations SET success=0 WHERE version=?", &[json!(latest.parse::<i64>().unwrap())]).await.unwrap();
    let before = ledger(&db).await;

    let output = cli(&scratch, &scratch.url(), &["repair", "--version", &latest, "--remove", "--dry-run"]);
    assert!(matches!(output.status.code(), Some(0 | 2)), "dry-run must preview or reject the unsupported option");
    assert_eq!(ledger(&db).await, before, "repair --remove --dry-run must not change any ledger row");
}

#[tokio::test]
async fn cli_status_redacts_url_credentials_and_remains_read_only() {
    let scratch = Scratch::new();
    let username = "migration_review_user_canary";
    let password = "migration_review_password_canary";
    let authority = format!("{}:{}@fixture", username, password);
    std::fs::create_dir(scratch.0.join(&authority)).unwrap();
    let path = scratch.0.join(&authority).join("status.db");
    let db = Db::connect(&format!("sqlite://{}", path.display())).await.unwrap();
    migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    let before = ledger(&db).await;

    // The SQLite adapter treats the authority as a relative path, so this reaches status without any network access.
    let output = cli(&scratch, &format!("sqlite://{}/status.db", authority), &["status"]);
    assert!(output.status.success(), "status fixture must reach the successful inspection path");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains(&format!("current: {}", MIGRATIONS.last().unwrap().version)), "status must still report the schema version");
    assert_eq!(ledger(&db).await, before, "status must not mutate the ledger");
    assert!(![username, password].iter().any(|secret| stdout.contains(secret) || stderr.contains(secret)), "status leaked database URL credential canaries");
}

#[test]
fn cli_status_invalid_remote_url_does_not_leak_credentials() {
    let scratch = Scratch::new();
    let username = "migration_review_parse_user_canary";
    let password = "migration_review_parse_password_canary";
    let url = format!("postgres://{}:{}@127.0.0.1:not-a-port/db", username, password);
    let output = cli(&scratch, &url, &["status"]);
    assert_eq!(output.status.code(), Some(2), "invalid port must fail URL parsing before any connection");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.trim().is_empty(), "connection errors must remain visible");
    assert!(![username, password].iter().any(|secret| stdout.contains(secret) || stderr.contains(secret)), "URL parse error leaked database credential canaries");
}

async fn assert_repair_respects_lock(action: Repair) {
    let scratch = Scratch::new();
    let db = fresh(&scratch).await;
    let latest = MIGRATIONS.last().unwrap().version;
    db.exec("UPDATE schema_migrations SET success=0,checksum='review-drift' WHERE version=?", &[json!(latest)]).await.unwrap();
    let now = openwarp_server::clock::now();
    db.exec("INSERT INTO schema_migration_lock(id,owner,acquired_at) VALUES(1,'active-runner',?)", &[json!(now)]).await.unwrap();
    let before = ledger(&db).await;
    let lock_before = db.query("SELECT * FROM schema_migration_lock ORDER BY id", &[]).await.unwrap();
    let second = Db::connect_existing(&scratch.url()).await.unwrap();

    let result = migrate::repair(&second, MIGRATIONS, action).await;
    assert_eq!(ledger(&db).await, before, "repair {:?} changed the ledger while another runner held the migration lock", action);
    assert_eq!(db.query("SELECT * FROM schema_migration_lock ORDER BY id", &[]).await.unwrap(), lock_before, "repair must not release another runner's lock");
    assert!(result.is_err(), "repair {:?} must refuse while another runner holds the migration lock", action);
}

#[tokio::test]
async fn repair_set_applied_respects_active_migration_lock() {
    assert_repair_respects_lock(Repair::SetApplied(MIGRATIONS.last().unwrap().version)).await;
}

#[tokio::test]
async fn repair_remove_respects_active_migration_lock() {
    assert_repair_respects_lock(Repair::Remove(MIGRATIONS.last().unwrap().version)).await;
}

#[tokio::test]
async fn repair_accept_checksum_respects_active_migration_lock() {
    assert_repair_respects_lock(Repair::AcceptChecksum(MIGRATIONS.last().unwrap().version)).await;
}

#[tokio::test]
async fn repair_remove_refuses_to_create_nonlatest_history_gap() {
    let scratch = Scratch::new();
    let db = fresh(&scratch).await;
    let version = MIGRATIONS[MIGRATIONS.len() - 2].version;
    let before = ledger(&db).await;

    let result = migrate::repair(&db, MIGRATIONS, Repair::Remove(version)).await;
    assert_eq!(ledger(&db).await, before, "repair must not remove a migration with later versions recorded");
    assert!(result.is_err(), "removing a nonlatest version must be rejected, not leave a gap that blocks boot");
}

#[tokio::test]
async fn repair_latest_interrupted_migration_can_be_removed_and_reapplied() {
    let scratch = Scratch::new();
    let db = fresh(&scratch).await;
    let latest = MIGRATIONS.last().unwrap().version;
    db.exec("UPDATE schema_migrations SET success=0 WHERE version=?", &[json!(latest)]).await.unwrap();
    let earlier = db.query("SELECT * FROM schema_migrations WHERE version<? ORDER BY version", &[json!(latest)]).await.unwrap();

    migrate::repair(&db, MIGRATIONS, Repair::Remove(latest)).await.expect("latest interrupted migration can be retried");
    assert_eq!(db.query("SELECT * FROM schema_migrations WHERE version<? ORDER BY version", &[json!(latest)]).await.unwrap(), earlier);
    assert!(db.one("SELECT version FROM schema_migrations WHERE version=?", &[json!(latest)]).await.unwrap().is_none());
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("reapply latest migration");
    assert_eq!(report.applied, vec![latest]);
    assert!(migrate::status(&db, MIGRATIONS).await.unwrap().problems.is_empty());
    let row = db.one("SELECT MAX(version) AS n FROM schema_migrations", &[]).await.unwrap().unwrap();
    assert_eq!(n(&row, "n"), latest);
}
