//! The migration-engine merge must retain both independently shipped histories.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, MIGRATIONS};

// SHA-256 of SQL 1-18 at feat/migrations f7447ffc416e6f8843dabbd9457ba269847eaf53.
const BRANCH_CHECKSUMS: [&str; 18] = [
    "a89ebbd90fc2b0af923acf168bfacec1558f14e38d011824e484acccfd2fb3b0",
    "d76522b8f35e8a1366caff017bc1df72c098eb8f527d5768d0857001c8d1fab0",
    "866cfb058f8ce5df39cd3a0a4fee0dd5070feaaea1da1161dd295af064156114",
    "8f4154155e1ecca3da66cc767f9aa7352341d524184c66d188473e7bfc08df84",
    "9bfbf9941a8861b4bd5153cc05c1c886cc40ec681bbf349424d1513a0ab93f03",
    "3527d419847c36cc9153bfac445f64e35129a837d02330d8c391d9b453cb1dd7",
    "f7fb169be6dc67859ea61c40ffcf160066f524659496d85e2d1091d0754a5b3d",
    "7cf708ad070862c425f185d980fd682e5fa3da868170ea76cdbbd71e58b0774f",
    "1dd92d39992933e99ddec47f7b325ee098100037a2fe4da1e6e3f3952bd4439c",
    "82933669878ee929ffe584798205934ff4b4a466bec84c68bc7773081ab2c4a8",
    "36f92524e36e6f3fc7be86b982d1cb41885880865c4c461f1724df5a57d12862",
    "46a0276cccad136fc8d4d62e5cfd34110cd9771f2a6d8ecc7e6736f3c7e2a179",
    "61d521833e6e461aa85c6d1fed0381f85f2d289c5f8df010b1704f7c2784cbc4",
    "e0dd806f3a30be0490e0598ce2ed659eaacbfe0fb8576dca7a872ea738d72119",
    "ee6281adb02649f8f33b06ea61d790c658ce07ddbb66cd287a651c4fe35005a4",
    "771fdc3efdcbd83c06a3be66c866b51c3bb84c9dfbd0cdc14170afdbec520dcd",
    "02ebc4247ca604a0d22563bc7b9b2c60a4912e5c6cafdd31cee5f3734e21309d",
    "353ad58bf282a2e6bbc0e71a728f4349fd9e9268a4b550eac8d353148c09f7f2",
];

fn empty_db() -> Db {
    Db::Sqlite(std::sync::Mutex::new(rusqlite::Connection::open_in_memory().unwrap()))
}

async fn assert_main17_schema(db: &Db) {
    for (table, columns) in [
        ("envs", &["max_versions"][..]),
        ("leases", &["attempted_at"][..]),
        ("audit", &["seq", "prev_hash", "hash"][..]),
        ("audit_heads", &["org_id", "seq", "hash"][..]),
        ("wrap_tokens", &["token_hash", "env_id", "payload_enc", "created_by", "created_at", "expires_at", "used"][..]),
    ] {
        let rows = db.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap();
        for column in columns {
            assert!(rows.iter().any(|row| s(row, "name") == *column), "shipped main migration 17 requires {}.{}", table, column);
        }
    }
    for (table, index, columns) in [
        ("audit", "idx_audit_org_seq", vec!["org_id", "seq"]),
        ("wrap_tokens", "idx_wrap_tokens_expiry", vec!["expires_at"]),
    ] {
        let indexes = db.query(&format!("PRAGMA index_list({})", table), &[]).await.unwrap();
        assert!(indexes.iter().any(|row| s(row, "name") == index), "missing shipped index {} on {}", index, table);
        let info = db.query(&format!("PRAGMA index_info({})", index), &[]).await.unwrap();
        assert_eq!(info.iter().map(|row| s(row, "name")).collect::<Vec<_>>(), columns, "{} must index the shipped columns in order", index);
    }
}

async fn seed_common_rows(db: &Db) {
    for sql in [
        "INSERT INTO orgs(id,name,created_at) VALUES('merge-org','Migration fixture',11)",
        "INSERT INTO apps(id,org_id,name,created_at) VALUES('merge-app','merge-org','App',12)",
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES('merge-env','merge-app','Production','dummy-wrapped-key',13)",
        "INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at) VALUES('merge-lease','merge-env','database','dummy-lease-ciphertext',999,14)",
        "INSERT INTO audit(id,org_id,env_id,actor,action,detail,created_at) VALUES('merge-audit','merge-org','merge-env','dummy-actor','fixture.created','preserve detail',15)",
    ] { db.exec(sql, &[]).await.unwrap(); }
}

async fn assert_main17_defaults(db: &Db) {
    let env = db.one("SELECT max_versions FROM envs WHERE id='merge-env'", &[]).await.unwrap().unwrap();
    assert_eq!(n(&env, "max_versions"), 0);
    let lease = db.one("SELECT attempted_at FROM leases WHERE id='merge-lease'", &[]).await.unwrap().unwrap();
    assert_eq!(n(&lease, "attempted_at"), 0);
    let audit = db.one("SELECT seq,prev_hash,hash FROM audit WHERE id='merge-audit'", &[]).await.unwrap().unwrap();
    assert_eq!(n(&audit, "seq"), 0);
    assert_eq!(s(&audit, "prev_hash"), "");
    assert_eq!(s(&audit, "hash"), "");
    db.exec("INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_at,expires_at) VALUES('dummy-default-wrap-hash','merge-env','dummy-payload',20,1000)", &[]).await.unwrap();
    let wrap = db.one("SELECT created_by,used FROM wrap_tokens WHERE token_hash='dummy-default-wrap-hash'", &[]).await.unwrap().unwrap();
    assert_eq!(s(&wrap, "created_by"), "");
    assert_eq!(n(&wrap, "used"), 0);
}

async fn assert_final22(db: &Db) {
    assert_eq!(db.version().await.unwrap(), 30, "the merge appends reconciliation without renumbering either history");
    for table in ["orgs", "apps"] {
        let rows = db.query(&format!("SELECT emergency_locked FROM {}", table), &[]).await.unwrap();
        assert!(!rows.is_empty(), "{} must contain the seeded row", table);
        for row in rows {
            assert_eq!(row.get("emergency_locked"), Some(&serde_json::json!(0)), "{}.emergency_locked defaults to zero", table);
        }
    }
    let status = migrate::status(db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 30);
    assert_eq!(status.latest, 30);
    assert!(status.problems.is_empty(), "{:?}", status.problems);
    assert!(status.pending().is_empty());
    let again = migrate::apply(db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(again.applied.is_empty(), "a second boot must not replay the reconciliation");
}

#[tokio::test]
async fn fresh_database_contains_shipped_main17_schema() {
    let db = Db::open_memory().await.unwrap();
    assert_main17_schema(&db).await;
    seed_common_rows(&db).await;
    assert_main17_defaults(&db).await;
    assert_final22(&db).await;
}

async fn main_data(db: &Db) -> Vec<Vec<Row>> {
    let mut rows = Vec::new();
    for table in ["orgs", "apps", "envs", "leases", "audit", "audit_heads", "wrap_tokens"] {
        let mut table_rows = db.query(&format!("SELECT * FROM {} ORDER BY 1", table), &[]).await.unwrap();
        if table == "orgs" || table == "apps" {
            for row in &mut table_rows { row.remove("emergency_locked"); }
        }
        rows.push(table_rows);
    }
    rows
}

#[tokio::test]
async fn shipped_main17_legacy_ledger_upgrade_preserves_data() {
    let db = empty_db();
    db.exec_script(&migrate::split_sql(include_str!("fixtures/schema_main17.sql"))).await.expect("install the schema produced by shipped main b7403c9");
    let legacy_version = db.one("SELECT MAX(version) AS version FROM schema_migrations", &[]).await.unwrap().unwrap();
    assert_eq!(n(&legacy_version, "version"), 17);
    let ledger_columns = db.query("PRAGMA table_info(schema_migrations)", &[]).await.unwrap();
    assert_eq!(ledger_columns.iter().map(|row| s(row, "name")).collect::<Vec<_>>(), vec!["version", "applied_at"]);
    assert_main17_schema(&db).await;
    seed_common_rows(&db).await;
    for sql in [
        "UPDATE envs SET max_versions=7,restricted=1,require_approval=1 WHERE id='merge-env'",
        "UPDATE leases SET attempted_at=123,username='dummy-user',config_enc='dummy-config',revoked=1 WHERE id='merge-lease'",
        "UPDATE audit SET seq=42,prev_hash='dummy-previous-hash',hash='dummy-chain-hash' WHERE id='merge-audit'",
        "INSERT INTO audit_heads(org_id,seq,hash) VALUES('merge-org',42,'dummy-chain-hash')",
        "INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_by,created_at,expires_at,used) VALUES('dummy-used-wrap-hash','merge-env','dummy-preserved-payload','dummy-actor',16,999,1)",
        "INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_by,created_at,expires_at,used) VALUES('dummy-unused-wrap-hash','merge-env','dummy-unread-payload','dummy-actor',17,1000,0)",
    ] { db.exec(sql, &[]).await.unwrap(); }
    let before = main_data(&db).await;
    let ledger = db.query("SELECT version,applied_at FROM schema_migrations ORDER BY version", &[]).await.unwrap();

    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("upgrade the real main17 legacy ledger without checksum repair");
    assert!(!report.squashed, "a main17 database must not be replaced by the branch baseline");
    assert_eq!(main_data(&db).await, before, "all shipped main17 data must survive reconciliation");
    assert_main17_schema(&db).await;
    assert_eq!(report.applied, vec![18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]);
    assert_eq!(db.query("SELECT version,applied_at FROM schema_migrations WHERE version<=17 ORDER BY version", &[]).await.unwrap(), ledger);
    assert_final22(&db).await;
    assert_eq!(main_data(&db).await, before, "the second boot must also preserve ciphertext, chain state and used flags");
}

#[tokio::test]
async fn branch18_upgrade_appends19_without_rewriting_checksums() {
    for (migration, expected) in MIGRATIONS[..18].iter().zip(BRANCH_CHECKSUMS) {
        assert_eq!(migrate::checksum(migration.sql), expected, "released branch SQL {} is immutable", migration.version);
    }
    let db = empty_db();
    migrate::apply(&db, &MIGRATIONS[..18], Options::default()).await.unwrap();
    assert_eq!(db.version().await.unwrap(), 18);
    seed_common_rows(&db).await;
    let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let env_before = db.one("SELECT id,app_id,name,env_key_wrapped,created_at FROM envs WHERE id='merge-env'", &[]).await.unwrap();
    let lease_before = db.one("SELECT id,env_id,name,value_enc,expires_at,created_at FROM leases WHERE id='merge-lease'", &[]).await.unwrap();
    let audit_before = db.one("SELECT id,org_id,env_id,actor,action,detail,created_at FROM audit WHERE id='merge-audit'", &[]).await.unwrap();

    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("upgrade a checksum-bearing branch18 ledger without repair");
    assert_main17_schema(&db).await;
    assert_eq!(report.applied, vec![19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]);
    assert!(!report.squashed);
    assert_eq!(db.query("SELECT * FROM schema_migrations WHERE version<=18 ORDER BY version", &[]).await.unwrap(), ledger, "the pre-merge engine ledger must remain unchanged");
    assert_eq!(db.one("SELECT id,app_id,name,env_key_wrapped,created_at FROM envs WHERE id='merge-env'", &[]).await.unwrap(), env_before);
    assert_eq!(db.one("SELECT id,env_id,name,value_enc,expires_at,created_at FROM leases WHERE id='merge-lease'", &[]).await.unwrap(), lease_before);
    assert_eq!(db.one("SELECT id,org_id,env_id,actor,action,detail,created_at FROM audit WHERE id='merge-audit'", &[]).await.unwrap(), audit_before);
    assert_main17_defaults(&db).await;
    assert_final22(&db).await;
}
