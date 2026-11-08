//! Main18 and engine18 assigned different meanings to the same ledger version.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, State, MIGRATIONS};

fn empty_db() -> Db {
    Db::Sqlite(std::sync::Mutex::new(rusqlite::Connection::open_in_memory().unwrap()))
}

async fn seed_rows(db: &Db) {
    for sql in [
        "INSERT INTO orgs(id,name,created_at) VALUES('main18-org','Historical workspace',11)",
        "INSERT INTO apps(id,org_id,name,created_at) VALUES('main18-app','main18-org','Historical app',12)",
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES('main18-member-env','main18-app','Member environment','dummy-wrapped-key',13)",
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES('main18-open-env','main18-app','Open environment','dummy-open-wrapped-key',14)",
        "INSERT INTO env_members(env_id,user_id) VALUES('main18-member-env','dummy-member')",
        "INSERT INTO secrets(id,env_id,key_enc,key_hash,value_enc,updated_at) VALUES('main18-secret','main18-member-env','dummy-key-ciphertext','dummy-key-hash','dummy-value-ciphertext',15)",
        "INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES('main18-lease','main18-member-env','database','dummy-lease-ciphertext',999,16)",
        "INSERT INTO audit(id,org_id,env_id,actor,action,detail,created_at) VALUES('main18-audit','main18-org','main18-member-env','dummy-actor','fixture.created','preserve audit detail',17)",
    ] { db.exec(sql, &[]).await.unwrap(); }
}

async fn common_data(db: &Db) -> Vec<Vec<Row>> {
    let mut rows = Vec::new();
    for sql in [
        "SELECT id,name,ip_allowlist,created_at,reuse_check FROM orgs ORDER BY id",
        "SELECT id,org_id,name,readme,sse,created_at,reuse_check FROM apps ORDER BY id",
        "SELECT id,app_id,name,env_key_wrapped,created_at,require_approval,mode,runner_id FROM envs ORDER BY id",
        "SELECT * FROM env_members ORDER BY env_id,user_id",
        "SELECT * FROM secrets ORDER BY id",
        "SELECT id,env_id,name,value_enc,expires_at,revoked,created_at,username,config_enc FROM leases ORDER BY id",
        "SELECT id,org_id,app_id,env_id,actor,action,detail,created_at FROM audit ORDER BY id",
    ] { rows.push(db.query(sql, &[]).await.unwrap()); }
    rows
}

async fn main17_data(db: &Db) -> Vec<Vec<Row>> {
    let mut rows = Vec::new();
    for sql in [
        "SELECT id,max_versions FROM envs ORDER BY id",
        "SELECT id,attempted_at FROM leases ORDER BY id",
        "SELECT * FROM audit ORDER BY id",
        "SELECT * FROM audit_heads ORDER BY org_id",
        "SELECT * FROM wrap_tokens ORDER BY token_hash",
    ] { rows.push(db.query(sql, &[]).await.unwrap()); }
    rows
}

async fn legacy_main18(sentinel_present: bool) -> Db {
    let db = empty_db();
    db.exec_script(&migrate::split_sql(include_str!("fixtures/schema_main17.sql"))).await.expect("install shipped main17 schema");
    // Exact migration 18 from main 9082126, not the engine's migration 18.
    for sql in [
        "ALTER TABLE orgs ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE apps ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0",
        "INSERT INTO schema_migrations(version,applied_at) VALUES(18,118)",
    ] { db.exec(sql, &[]).await.unwrap(); }
    let columns = db.query("PRAGMA table_info(schema_migrations)", &[]).await.unwrap();
    assert_eq!(columns.iter().map(|row| s(row, "name")).collect::<Vec<_>>(), vec!["version", "applied_at"]);
    let version = db.one("SELECT MAX(version) AS version FROM schema_migrations", &[]).await.unwrap().unwrap();
    assert_eq!(n(&version, "version"), 18);
    seed_rows(&db).await;
    for sql in [
        "UPDATE orgs SET emergency_locked=1 WHERE id='main18-org'",
        "UPDATE apps SET emergency_locked=1 WHERE id='main18-app'",
        "UPDATE envs SET max_versions=7,require_approval=1 WHERE id='main18-member-env'",
        "UPDATE leases SET attempted_at=123,revoked=1 WHERE id='main18-lease'",
        "UPDATE audit SET seq=42,prev_hash='dummy-previous-hash',hash='dummy-chain-hash' WHERE id='main18-audit'",
        "INSERT INTO audit_heads(org_id,seq,hash) VALUES('main18-org',42,'dummy-chain-hash')",
        "INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_by,created_at,expires_at,used) VALUES('dummy-wrap-hash','main18-member-env','dummy-payload','dummy-actor',18,1000,1)",
    ] { db.exec(sql, &[]).await.unwrap(); }
    if !sentinel_present {
        db.exec("DELETE FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap();
    }
    assert_eq!(db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().is_some(), sentinel_present);
    assert_eq!(restricted(&db, "main18-member-env").await, 0);
    let members = db.one("SELECT COUNT(*) AS n FROM env_members WHERE env_id='main18-member-env'", &[]).await.unwrap().unwrap();
    assert_eq!(n(&members, "n"), 1, "the fixture must exercise an existing environment allowlist");
    db
}

async fn restricted(db: &Db, id: &str) -> i64 {
    let row = db.one("SELECT restricted FROM envs WHERE id=?", &[serde_json::json!(id)]).await.unwrap().unwrap();
    n(&row, "restricted")
}

async fn assert_emergency_schema(db: &Db, expected: i64) {
    for table in ["orgs", "apps"] {
        let columns = db.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap();
        let column = columns.iter().find(|row| s(row, "name") == "emergency_locked")
            .unwrap_or_else(|| panic!("shipped main18 requires {}.emergency_locked", table));
        assert_eq!(n(column, "notnull"), 1, "{}.emergency_locked must reject NULL", table);
        assert_eq!(s(column, "dflt_value"), "0", "{}.emergency_locked defaults to unlocked", table);
        let row = db.one(&format!("SELECT emergency_locked FROM {}", table), &[]).await.unwrap().unwrap();
        assert_eq!(n(&row, "emergency_locked"), expected, "{} lock state must survive migration", table);
    }
}

async fn assert_final22(db: &Db) {
    assert_eq!(db.version().await.unwrap(), 23, "the conflicting main18 history needs an appended reconciliation");
    let status = migrate::status(db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 23);
    assert_eq!(status.latest, 23);
    assert!(status.problems.is_empty(), "{:?}", status.problems);
    assert!(status.pending().is_empty());
    let again = migrate::apply(db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(again.applied.is_empty(), "a second boot must not replay reconciliation");
}

async fn upgrade_legacy_main18(sentinel_present: bool) -> Db {
    let db = legacy_main18(sentinel_present).await;
    let data = common_data(&db).await;
    let main17 = main17_data(&db).await;
    let ledger = db.query("SELECT version,applied_at FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let sentinel = db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap();

    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("upgrade shipped main18 without checksum repair");
    assert!(!report.squashed);
    assert_eq!(common_data(&db).await, data, "ciphertext, membership and ordinary data must survive");
    assert_eq!(main17_data(&db).await, main17, "audit chain, used wrapping tokens and main17 settings must survive");
    assert_eq!(db.query("SELECT version,applied_at FROM schema_migrations WHERE version<=18 ORDER BY version", &[]).await.unwrap(), ledger);
    let old18 = db.one("SELECT checksum FROM schema_migrations WHERE version=18", &[]).await.unwrap().unwrap();
    assert_eq!(s(&old18, "checksum"), "", "main18 is not the engine's env_restricted migration and must remain unverified");
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    assert!(status.entries.iter().any(|entry| entry.version == 18 && entry.state == State::Legacy));
    assert_emergency_schema(&db, 1).await;
    assert_eq!(restricted(&db, "main18-open-env").await, 0, "an environment without members stays open");
    if sentinel_present {
        assert_eq!(db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap(), sentinel, "the historical sentinel must not be overwritten");
    }
    db
}

#[tokio::test]
async fn main18_without_sentinel_backfills_existing_environment_members() {
    let db = upgrade_legacy_main18(false).await;
    assert_eq!(restricted(&db, "main18-member-env").await, 1, "legacy version 18 denotes emergency locks, so it must not suppress the missing allowlist backfill");
    assert!(db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().is_some());
    db.exec("UPDATE envs SET restricted=0 WHERE id='main18-member-env'", &[]).await.unwrap();
    assert_final22(&db).await;
    assert_eq!(restricted(&db, "main18-member-env").await, 0, "a later intentional unlock must survive another boot");
}

#[tokio::test]
async fn main18_with_sentinel_preserves_intentionally_unrestricted_environment() {
    let db = upgrade_legacy_main18(true).await;
    assert_eq!(restricted(&db, "main18-member-env").await, 0, "membership must not override an intentional unrestricted setting after the sentinel");
    let before = common_data(&db).await;
    assert_final22(&db).await;
    assert_eq!(common_data(&db).await, before);
    assert_emergency_schema(&db, 1).await;
}

#[tokio::test]
async fn fresh_engine_database_contains_shipped_main18_emergency_fields() {
    let db = Db::open_memory().await.unwrap();
    seed_rows(&db).await;
    assert_emergency_schema(&db, 0).await;
    db.exec("UPDATE orgs SET emergency_locked=1", &[]).await.unwrap();
    db.exec("UPDATE apps SET emergency_locked=1", &[]).await.unwrap();
    assert_final22(&db).await;
    assert_emergency_schema(&db, 1).await;
}

async fn upgrade_engine_history(version: usize) {
        let db = empty_db();
        migrate::apply(&db, &MIGRATIONS[..version], Options::default()).await.unwrap();
        assert_eq!(db.version().await.unwrap(), version as i64);
        seed_rows(&db).await;
        assert!(db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().is_some());
        let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
        let old18 = db.one("SELECT checksum FROM schema_migrations WHERE version=18", &[]).await.unwrap().unwrap();
        assert_eq!(s(&old18, "checksum"), "353ad58bf282a2e6bbc0e71a728f4349fd9e9268a4b550eac8d353148c09f7f2");
        let before = common_data(&db).await;

        let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("upgrade checksummed engine history without repair");
        assert!(!report.squashed);
        assert_eq!(common_data(&db).await, before, "engine{} seeded data must survive", version);
        assert_eq!(db.query("SELECT * FROM schema_migrations WHERE version<=? ORDER BY version", &[serde_json::json!(version)]).await.unwrap(), ledger, "engine{} ledger rows and checksums are immutable", version);
        assert_eq!(restricted(&db, "main18-member-env").await, 0, "the existing engine sentinel preserves later unrestricted environments");
        assert_emergency_schema(&db, 0).await;
        assert_eq!(report.applied, ((version as i64 + 1)..=23).collect::<Vec<_>>());
        assert_final22(&db).await;
        assert_eq!(common_data(&db).await, before);
}

#[tokio::test]
async fn engine18_upgrade_preserves_data_and_checksummed_history() {
    upgrade_engine_history(18).await;
}

#[tokio::test]
async fn engine19_upgrade_preserves_data_and_checksummed_history() {
    upgrade_engine_history(19).await;
}
