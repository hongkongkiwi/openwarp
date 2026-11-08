//! Main21 and the checksummed engine20 history must converge without ledger repair.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, State, MIGRATIONS};

// SHA-256 of the released engine SQL at b2f1ad7, independent of the merge manifest.
const ENGINE_CHECKSUMS: [&str; 20] = [
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
    "0e4d35bb9726c019765f969e2a216a185691bbf59dee0841eae904f89c4cde5c",
    "a7a8496d18fe9e299cd5951e44af1bbb7dcfd65d91d43cda8228f488e31aa248",
];

fn empty_db() -> Db {
    Db::Sqlite(std::sync::Mutex::new(rusqlite::Connection::open_in_memory().unwrap()))
}

async fn legacy_main21() -> Db {
    let db = empty_db();
    db.exec_script(&migrate::split_sql(include_str!("fixtures/schema_main21.sql"))).await.expect("install the schema shipped by main eefa119");
    let columns = db.query("PRAGMA table_info(schema_migrations)", &[]).await.unwrap();
    assert_eq!(columns.iter().map(|row| s(row, "name")).collect::<Vec<_>>(), vec!["version", "applied_at"]);
    let version = db.one("SELECT MAX(version) AS version FROM schema_migrations", &[]).await.unwrap().unwrap();
    assert_eq!(version.get("version"), Some(&serde_json::json!(21)));
    db
}

async fn application_tables(db: &Db) -> Vec<String> {
    db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('schema_migrations','schema_migration_lock') ORDER BY name", &[]).await.unwrap()
        .iter().map(|row| s(row, "name")).collect()
}

async fn assert_main21_schema(db: &Db) {
    let canonical = legacy_main21().await;
    for table in application_tables(&canonical).await {
        let expected = canonical.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap();
        let actual = db.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap();
        assert!(!expected.is_empty(), "canonical table {} must exist", table);
        assert!(!actual.is_empty(), "missing shipped main21 table {}", table);
        for column in &expected {
            let name = s(column, "name");
            let found = actual.iter().find(|row| s(row, "name") == name)
                .unwrap_or_else(|| panic!("missing shipped main21 column {}.{}", table, name));
            for property in ["type", "notnull", "dflt_value", "pk"] {
                assert!(column.contains_key(property), "canonical column metadata must contain {}", property);
                assert_eq!(found.get(property), column.get(property), "{}.{} must preserve {}", table, name, property);
            }
        }
        let indexes = db.query(&format!("PRAGMA index_list({})", table), &[]).await.unwrap();
        for index in canonical.query(&format!("PRAGMA index_list({})", table), &[]).await.unwrap() {
            let name = s(&index, "name");
            let expected_columns = canonical.query(&format!("PRAGMA index_info({})", name), &[]).await.unwrap()
                .iter().map(|row| s(row, "name")).collect::<Vec<_>>();
            assert!(!expected_columns.is_empty(), "canonical index {} must index columns", name);
            let mut matched = false;
            for candidate in &indexes {
                if index.get("unique") != candidate.get("unique") || index.get("partial") != candidate.get("partial") { continue; }
                // SQLite chooses names for primary-key and UNIQUE autoindexes.
                if !name.starts_with("sqlite_autoindex_") && s(candidate, "name") != name { continue; }
                let columns = db.query(&format!("PRAGMA index_info({})", s(candidate, "name")), &[]).await.unwrap()
                    .iter().map(|row| s(row, "name")).collect::<Vec<_>>();
                if columns == expected_columns { matched = true; break; }
            }
            assert!(matched, "missing shipped main21 index {} on {} {:?}", name, table, expected_columns);
        }
    }
}

async fn seed_common(db: &Db) {
    for sql in [
        "INSERT INTO orgs(id,name,created_at,emergency_locked) VALUES('main21-org','Historical workspace',11,1)",
        "INSERT INTO apps(id,org_id,name,created_at,emergency_locked) VALUES('main21-app','main21-org','Historical app',12,1)",
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at,max_versions) VALUES('main21-env','main21-app','Production','dummy-wrapped-env-key',13,7)",
        "INSERT INTO env_members(env_id,user_id) VALUES('main21-env','dummy-member')",
        "INSERT INTO secrets(id,env_id,key_enc,key_hash,value_enc,updated_at) VALUES('main21-secret','main21-env','dummy-key-ciphertext','dummy-key-hash','dummy-value-ciphertext',14)",
        "INSERT INTO leases(id,env_id,name,value_enc,expires_at,created_at,attempted_at,revoked) VALUES('main21-lease','main21-env','database','dummy-lease-ciphertext',999,15,123,1)",
        "INSERT INTO audit(id,org_id,env_id,actor,action,detail,created_at,seq,prev_hash,hash) VALUES('main21-audit','main21-org','main21-env','dummy-actor','fixture.created','preserve detail',16,42,'dummy-prev-hash','dummy-chain-hash')",
        "INSERT INTO audit_heads(org_id,seq,hash) VALUES('main21-org',42,'dummy-chain-hash')",
        "INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_by,created_at,expires_at,used) VALUES('dummy-used-wrap','main21-env','dummy-used-payload','dummy-actor',17,999,1)",
        "INSERT INTO wrap_tokens(token_hash,env_id,payload_enc,created_at,expires_at) VALUES('dummy-unused-wrap','main21-env','dummy-unused-payload',18,1000)",
        "INSERT INTO identities(id,org_id,name,created_at) VALUES('main21-identity','main21-org','Workload',19)",
        "INSERT INTO tokens(id,org_id,env_id,name,token_hash,created_at) VALUES('main21-token','main21-org','main21-env','Workload token','dummy-token-hash',20)",
    ] { db.exec(sql, &[]).await.unwrap(); }
}

async fn seed_product(db: &Db) {
    for sql in [
        "INSERT INTO change_requests(id,org_id,title,author,revision,status,approved_by,created_at) VALUES('main21-request','main21-org','Historical deploy','dummy-author',3,'approved','dummy-approver',21)",
        "INSERT INTO change_request_envs(request_id,env_id,payload_enc) VALUES('main21-request','main21-env','dummy-change-ciphertext')",
        "INSERT INTO workload_trusts(id,org_id,identity_id,env_id,issuer,audience,subject,jwks,scopes,ttl,bound_claims,revoked,created_at) VALUES('main21-trust','main21-org','main21-identity','main21-env','dummy-issuer','dummy-audience','dummy-subject','dummy-jwks','secrets:read',321,'dummy-bound-claims',1,22)",
        "INSERT INTO workload_replay(key,expires_at) VALUES('dummy-replayed-jti',999)",
        "UPDATE tokens SET trust_id='main21-trust',kind='workload' WHERE id='main21-token'",
        "INSERT INTO transit_keys(id,org_id,name,current_version) VALUES('main21-key','main21-org','Historical transit key',2)",
        "INSERT INTO transit_versions(key_id,org_id,version,key_enc) VALUES('main21-key','main21-org',1,'dummy-old-transit-key-ciphertext')",
        "INSERT INTO transit_versions(key_id,org_id,version,key_enc) VALUES('main21-key','main21-org',2,'dummy-current-transit-key-ciphertext')",
    ] { db.exec(sql, &[]).await.unwrap(); }
}

// Retain the original projections so a newly added column does not hide data loss.
async fn snapshot(db: &Db) -> Vec<(String, Vec<Row>)> {
    let mut result = Vec::new();
    for table in application_tables(db).await {
        let columns = db.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap()
            .iter().map(|row| format!("\"{}\"", s(row, "name"))).collect::<Vec<_>>().join(",");
        let sql = format!("SELECT {} FROM {} ORDER BY {}", columns, table, columns);
        let rows = db.query(&sql, &[]).await.unwrap();
        result.push((sql, rows));
    }
    result
}

async fn assert_preserved(db: &Db, before: &[(String, Vec<Row>)]) {
    for (sql, rows) in before {
        assert_eq!(&db.query(sql, &[]).await.unwrap(), rows, "migration must preserve rows for {}", sql);
    }
}

async fn assert_final22_and_second_boot(db: &Db) {
    assert_eq!(db.version().await.unwrap(), 29);
    let status = migrate::status(db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 29);
    assert_eq!(status.latest, 29);
    assert!(status.problems.is_empty(), "{:?}", status.problems);
    assert!(status.pending().is_empty());
    let before = snapshot(db).await;
    let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(report.applied.is_empty(), "a second boot must not replay reconciliation");
    assert!(!report.squashed);
    assert_preserved(db, &before).await;
    assert_eq!(db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap(), ledger);
    assert_main21_schema(db).await;
}

#[test]
fn released_engine_sql_1_through_20_is_immutable() {
    assert!(MIGRATIONS.len() >= ENGINE_CHECKSUMS.len());
    for (i, expected) in ENGINE_CHECKSUMS.iter().enumerate() {
        assert_eq!(MIGRATIONS[i].version, i as i64 + 1);
        assert_eq!(migrate::checksum(MIGRATIONS[i].sql), *expected, "released engine SQL {} is immutable", i + 1);
    }
}

#[tokio::test]
async fn fresh_engine_database_contains_all_shipped_main21_schema() {
    let db = Db::open_memory().await.unwrap();
    assert_main21_schema(&db).await;
    seed_common(&db).await;
    seed_product(&db).await;
    assert_final22_and_second_boot(&db).await;
}

#[tokio::test]
async fn engine20_upgrade_adds_main21_schema_without_rewriting_history_or_data() {
    let db = empty_db();
    migrate::apply(&db, &MIGRATIONS[..20], Options::default()).await.unwrap();
    assert_eq!(db.version().await.unwrap(), 20);
    seed_common(&db).await;
    let before = snapshot(&db).await;
    let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("upgrade engine20 without checksum repair");
    assert!(!report.squashed);
    assert_preserved(&db, &before).await;
    assert_eq!(db.query("SELECT * FROM schema_migrations WHERE version<=20 ORDER BY version", &[]).await.unwrap(), ledger);
    let token = db.one("SELECT trust_id FROM tokens WHERE id='main21-token'", &[]).await.unwrap().expect("old token survives");
    assert_eq!(token.get("trust_id"), Some(&serde_json::json!("")), "old tokens receive a real empty-string trust default, not NULL");
    assert_main21_schema(&db).await;
    assert_eq!(report.applied, vec![21, 22, 23, 24, 25, 26, 27, 28, 29]);
    seed_product(&db).await;
    assert_final22_and_second_boot(&db).await;
}

#[tokio::test]
async fn shipped_main21_legacy_upgrade_preserves_product_data_and_unverified_history() {
    let db = legacy_main21().await;
    seed_common(&db).await;
    seed_product(&db).await;
    let before = snapshot(&db).await;
    let ledger = db.query("SELECT version,applied_at FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("recognise real main21 history without newer-schema rejection or checksum repair");
    assert!(!report.squashed);
    assert_eq!(report.applied, vec![22, 23, 24, 25, 26, 27, 28, 29], "occupied legacy versions must not be replayed as engine SQL");
    assert_preserved(&db, &before).await;
    assert_eq!(db.query("SELECT version,applied_at FROM schema_migrations WHERE version<=21 ORDER BY version", &[]).await.unwrap(), ledger);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    for version in 17..=21 {
        let row = db.one("SELECT checksum FROM schema_migrations WHERE version=?", &[serde_json::json!(version)]).await.unwrap().expect("legacy ledger row survives");
        assert_eq!(row.get("checksum"), Some(&serde_json::json!("")), "legacy main{} must not be falsely certified as engine SQL", version);
        assert!(status.entries.iter().any(|entry| entry.version == version && entry.state == State::Legacy), "main{} remains legacy", version);
    }
    let env = db.one("SELECT restricted FROM envs WHERE id='main21-env'", &[]).await.unwrap().unwrap();
    assert_eq!(n(&env, "restricted"), 0, "a shipped sentinel preserves intentionally unrestricted environments even with members");
    assert_final22_and_second_boot(&db).await;
    assert_preserved(&db, &before).await;
}
