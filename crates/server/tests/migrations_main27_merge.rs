//! Canonical main d39138e (legacy versions 23..27) converges at engine 28.

use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, State, MIGRATIONS};

// Released d64e588 SQL is independent of the appended merge manifest.
const ENGINE_CHECKSUMS: [&str; 23] = [
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
    "6835d580b30c669c3db90d902fa1d70a8b9974a4aa06a4f13df7f10966add015",
    "1ab9582c1e83104678adf3c92c488a134065f664064ec1a9330564a45df6dcf2",
    "b5fc4ecb820f894075c2e25cff75d676a407053e247aeed49c7582115763f65c",
];

fn empty_db() -> Db {
    Db::Sqlite(std::sync::Mutex::new(rusqlite::Connection::open_in_memory().unwrap()))
}

async fn legacy_main(version: i64) -> Db {
    assert!((23..=27).contains(&version));
    let fixture = include_str!("fixtures/schema_main27.sql");
    let sql = if version == 27 { fixture.to_string() } else {
        let marker = format!("-- main migration {}\n", version + 1);
        let prefix = fixture.split_once(&marker).expect("canonical migration boundary").0;
        let bootstrap = fixture.split_once("-- canonical bootstrap meta\n").unwrap().1;
        format!("{}\n{}", prefix, bootstrap)
    };
    let db = empty_db();
    db.exec_script(&migrate::split_sql(&sql)).await.expect("install independently derived canonical main schema");
    assert_eq!(db.version().await.unwrap(), version);
    assert_eq!(db.query("PRAGMA table_info(schema_migrations)", &[]).await.unwrap().iter().map(|row| s(row, "name")).collect::<Vec<_>>(), vec!["version", "applied_at"]);
    db
}

async fn application_tables(db: &Db) -> Vec<String> {
    db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('schema_migrations','schema_migration_lock') ORDER BY name", &[]).await.unwrap()
        .iter().map(|row| s(row, "name")).collect()
}

async fn assert_contains_schema(db: &Db, canonical: &Db) {
    for table in application_tables(canonical).await {
        let expected = canonical.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap();
        let actual = db.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap();
        assert!(!actual.is_empty(), "missing canonical table {}", table);
        for column in expected {
            let name = s(&column, "name");
            let found = actual.iter().find(|row| s(row, "name") == name)
                .unwrap_or_else(|| panic!("missing canonical column {}.{}", table, name));
            for property in ["type", "notnull", "dflt_value", "pk"] {
                assert_eq!(found.get(property), column.get(property), "{}.{} must preserve {}", table, name, property);
            }
        }
        let actual_indexes = db.query(&format!("PRAGMA index_list({})", table), &[]).await.unwrap();
        for index in canonical.query(&format!("PRAGMA index_list({})", table), &[]).await.unwrap() {
            let name = s(&index, "name");
            let expected_columns = canonical.query(&format!("PRAGMA index_info({})", name), &[]).await.unwrap()
                .iter().map(|row| s(row, "name")).collect::<Vec<_>>();
            assert!(!expected_columns.is_empty());
            let mut matched = false;
            for candidate in &actual_indexes {
                if index.get("unique") != candidate.get("unique") || index.get("partial") != candidate.get("partial") { continue; }
                if !name.starts_with("sqlite_autoindex_") && s(candidate, "name") != name { continue; }
                let columns = db.query(&format!("PRAGMA index_info({})", s(candidate, "name")), &[]).await.unwrap()
                    .iter().map(|row| s(row, "name")).collect::<Vec<_>>();
                if columns == expected_columns { matched = true; break; }
            }
            assert!(matched, "missing canonical index {} on {} {:?}", name, table, expected_columns);
        }
    }
}

async fn seed_product_and_ca(db: &Db) {
    for sql in [
        "INSERT INTO orgs(id,name,created_at,emergency_locked) VALUES('merge27-org','Fixture workspace',31,1)",
        "INSERT INTO apps(id,org_id,name,created_at,emergency_locked) VALUES('merge27-app','merge27-org','Fixture app',32,1)",
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at,max_versions) VALUES('merge27-env','merge27-app','Production','dummy-env-ciphertext',33,7)",
        "INSERT INTO env_members(env_id,user_id) VALUES('merge27-env','dummy-member')",
        "INSERT INTO secrets(id,env_id,key_enc,key_hash,value_enc,updated_at) VALUES('merge27-secret','merge27-env','dummy-key-ciphertext','dummy-key-hash','dummy-value-ciphertext',34)",
        "INSERT INTO change_requests(id,org_id,title,author,revision,status,approved_by,created_at) VALUES('merge27-cr','merge27-org','Fixture deploy','dummy-author',3,'approved','dummy-approver',35)",
        "INSERT INTO change_request_envs(request_id,env_id,payload_enc) VALUES('merge27-cr','merge27-env','dummy-change-ciphertext')",
        "INSERT INTO workload_bindings(identity_id,org_id,revision,issuer,jwks_url,audience,subject,max_ttl_secs) VALUES('merge27-identity','merge27-org','rev-7','dummy-issuer','https://dummy-jwks.example','dummy-audience','dummy-subject',600)",
        "INSERT INTO path_policies(env_id,role,rules) VALUES('merge27-env','developer','[{\"effect\":\"deny\",\"path\":\"sys/*\"}]')",
        "INSERT INTO transit_keys(id,org_id,name,current_version) VALUES('merge27-key','merge27-org','Fixture transit',2)",
        "INSERT INTO transit_versions(key_id,org_id,version,key_enc) VALUES('merge27-key','merge27-org',2,'dummy-transit-ciphertext')",
        "INSERT INTO compat_transit_keys(id,org_id,name,wrapping_key,created_at) VALUES('merge27-compat-key','merge27-org','Fixture compat','dummy-wrapping-key',36)",
        "INSERT INTO compat_transit_versions(key_id,version,key_enc,created_at) VALUES('merge27-compat-key',1,'dummy-compat-ciphertext',37)",
        "INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,serial,created_at,kind) VALUES('merge27-ca','merge27-org','Fixture CA','dummy-ca-pem','dummy-ca-key-ciphertext','ca-serial',38,'x509')",
        "INSERT INTO pki_cas(id,org_id,name,cert_pem,key_enc,serial,created_at,kind) VALUES('merge27-ssh-ca','merge27-org','Fixture SSH CA','dummy-ssh-pem','dummy-ssh-key-ciphertext','ssh-serial',39,'ssh')",
        "INSERT INTO pki_certs(id,ca_id,cn,cert_pem,serial,revoked,expires_at,created_at) VALUES('merge27-cert','merge27-ca','fixture.example','dummy-cert-pem','cert-serial',1,900,40)",
    ] { db.exec(sql, &[]).await.unwrap(); }
}

async fn seed_device_history(db: &Db, version: i64) {
    for sql in [
        "INSERT INTO pki_devices(id,org_id,ca_id,app_id,env_id,name,model,hardware_serial,tags,sans,cert_days,active_cert_id,enroll_epoch,deleting,created_at,updated_at) VALUES('merge27-device','merge27-org','merge27-ca','merge27-app','merge27-env','Fixture device','model','hardware','fleet','DNS:fixture.example',45,'merge27-cert',7,1,41,42)",
        "INSERT INTO pki_enrollments(id,device_id,token_hash,expires_at,used_at,created_by,created_at,enroll_epoch) VALUES('merge27-enrollment','merge27-device','dummy-enrollment-hash',901,44,'dummy-creator',43,7)",
        "UPDATE pki_certs SET device_id='merge27-device',revoked_at=44,issued_via='enrollment' WHERE id='merge27-cert'",
    ] { db.exec(sql, &[]).await.unwrap(); }
    if version >= 24 {
        for sql in [
            "INSERT INTO pki_groups(id,org_id,ca_id,name,env_id,sans,cert_days,tags,created_at,updated_at) VALUES('merge27-group','merge27-org','merge27-ca','Fixture group','merge27-env','DNS:group.example',21,'group-tag',45,46)",
            "UPDATE pki_devices SET group_id='merge27-group',attested=1,attestation='dummy-attestation' WHERE id='merge27-device'",
            "UPDATE pki_enrollments SET revoke_previous=1,nonce='dummy-nonce' WHERE id='merge27-enrollment'",
            "UPDATE pki_cas SET parent_id='dummy-parent-ca',ca_kind='intermediate',revoked=1,revoked_at=47,hook_url='https://dummy-hook.example',hook_secret_enc='dummy-hook-ciphertext',attest_issuer='dummy-issuer',attest_key_pem='dummy-attest-pem',attest_alg='ES384',attest_required=1 WHERE id='merge27-ca'",
        ] { db.exec(sql, &[]).await.unwrap(); }
    }
    if version >= 25 {
        for sql in [
            "INSERT INTO pki_renew_challenges(id,device_id,cert_id,csr,challenge,expires_at,used_at) VALUES('merge27-renew','merge27-device','merge27-cert','dummy-csr','dummy-challenge',902,48)",
            "INSERT INTO pki_expiry_deliveries(org_id,user_id,day,status) VALUES('merge27-org','dummy-user',49,'sent')",
            "UPDATE pki_devices SET tpm_ak_public='dummy-tpm-ak',tpm_pcr_digest='dummy-pcr' WHERE id='merge27-device'",
            "UPDATE pki_cas SET attest_mode='tpm' WHERE id='merge27-ca'",
        ] { db.exec(sql, &[]).await.unwrap(); }
    }
}

// Original column projections distinguish preserved values from additive defaults.
// `except` omits tables a test asserts through a narrower contract: the device20
// lineage legitimately gains the canonical bootstrap meta pairs.
async fn snapshot_except(db: &Db, except: &[&str]) -> Vec<(String, Vec<Row>)> {
    let mut result = Vec::new();
    for table in application_tables(db).await {
        if except.contains(&table.as_str()) { continue; }
        let columns = db.query(&format!("PRAGMA table_info({})", table), &[]).await.unwrap()
            .iter().map(|row| format!("\"{}\"", s(row, "name"))).collect::<Vec<_>>().join(",");
        let sql = format!("SELECT {} FROM {} ORDER BY {}", columns, table, columns);
        let rows = db.query(&sql, &[]).await.unwrap();
        result.push((sql, rows));
    }
    result
}

async fn snapshot(db: &Db) -> Vec<(String, Vec<Row>)> { snapshot_except(db, &[]).await }

async fn assert_preserved(db: &Db, before: &[(String, Vec<Row>)>) {
    for (sql, rows) in before {
        assert_eq!(&db.query(sql, &[]).await.unwrap(), rows, "preserve rows for {}", sql);
    }
}

// Canonical bootstrap (d39138e db.rs startup; convergence 0022/0023/0028) seeds
// migration:env_restricted='0' and rotation_lifecycle='' only when absent and
// never overwrites; every preexisting pair and nothing else must remain.
async fn assert_meta_contract(db: &Db, before: &[(String, String)]) {
    let mut expected = before.to_vec();
    for (key, value) in [("migration:env_restricted", "0"), ("rotation_lifecycle", "")] {
        if !expected.iter().any(|(k, _)| k == key) { expected.push((key.to_string(), value.to_string())); }
    }
    expected.sort();
    let actual = db.query("SELECT k,v FROM meta ORDER BY k", &[]).await.unwrap()
        .iter().map(|row| (s(row, "k"), s(row, "v"))).collect::<Vec<_>>();
    assert_eq!(actual, expected, "meta keeps preexisting pairs and only gains the canonical bootstrap keys");
}

async fn assert_final28_and_second_boot(db: &Db) {
    assert_eq!(db.version().await.unwrap(), 28);
    let status = migrate::status(db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, 28);
    assert_eq!(status.latest, 28);
    assert!(status.problems.is_empty(), "{:?}", status.problems);
    assert!(status.pending().is_empty());
    let before = snapshot(db).await;
    let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(report.applied.is_empty(), "second boot must not replay convergence");
    assert!(!report.squashed);
    assert_preserved(db, &before).await;
    assert_eq!(db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap(), ledger);
    assert_contains_schema(db, &legacy_main(27).await).await;
}

#[test]
fn released_engine_sql_1_through_23_is_immutable() {
    assert!(MIGRATIONS.len() >= ENGINE_CHECKSUMS.len());
    for (index, expected) in ENGINE_CHECKSUMS.iter().enumerate() {
        assert_eq!(MIGRATIONS[index].version, index as i64 + 1);
        assert_eq!(migrate::checksum(MIGRATIONS[index].sql), *expected, "released SQL {} is immutable", index + 1);
    }
}

#[tokio::test]
async fn fresh_engine_contains_all_canonical_main27_schema() {
    let db = Db::open_memory().await.unwrap();
    assert_contains_schema(&db, &legacy_main(27).await).await;
    seed_product_and_ca(&db).await;
    seed_device_history(&db, 27).await;
    assert_final28_and_second_boot(&db).await;
}

#[tokio::test]
async fn engine23_upgrade_preserves_checksums_and_product_data() {
    let db = empty_db();
    migrate::apply(&db, &MIGRATIONS[..23], Options::default()).await.unwrap();
    assert_eq!(db.version().await.unwrap(), 23);
    seed_product_and_ca(&db).await;
    let before = snapshot(&db).await;
    let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("append device migrations without checksum repair");
    assert_eq!(report.applied, vec![24, 25, 26, 27, 28]);
    assert!(!report.squashed);
    assert_preserved(&db, &before).await;
    assert_eq!(db.query("SELECT * FROM schema_migrations WHERE version<=23 ORDER BY version", &[]).await.unwrap(), ledger);
    seed_device_history(&db, 27).await;
    assert_final28_and_second_boot(&db).await;
}

// Supersedes the defective empty-meta-stays-empty assertion: canonical bootstrap
// (d39138e startup; SQL 0022/0023/0028) seeds both keys when absent, never overwrites.
#[tokio::test]
async fn historical_device20_restores_skipped_product_schema_and_keeps_ca_kinds() {
    let db = empty_db();
    db.exec_script(&migrate::split_sql(include_str!("fixtures/schema_device20.sql"))).await.unwrap();
    assert_eq!(db.version().await.unwrap(), 20);
    assert!(db.query("SELECT id FROM workload_trusts", &[]).await.is_err(), "fixture represents skipped canonical product history");
    let meta_before = db.query("SELECT k,v FROM meta ORDER BY k", &[]).await.unwrap()
        .iter().map(|row| (s(row, "k"), s(row, "v"))).collect::<Vec<_>>();
    assert!(meta_before.is_empty(), "historical feature20 seed ships an empty meta table");
    let before = snapshot_except(&db, &["meta"]).await;
    let ledger = db.query("SELECT version,applied_at FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("upgrade the historical device20 lineage without ledger repair");
    assert_eq!(report.applied, (21..=28).collect::<Vec<_>>());
    assert!(!report.squashed);
    assert_preserved(&db, &before).await;
    assert_meta_contract(&db, &meta_before).await;
    assert_eq!(db.query("SELECT version,applied_at FROM schema_migrations WHERE version<=20 ORDER BY version", &[]).await.unwrap(), ledger);
    let status = migrate::status(&db, MIGRATIONS).await.unwrap();
    for version in 17..=20 {
        let row = db.one(&format!("SELECT checksum FROM schema_migrations WHERE version={}", version), &[]).await.unwrap().unwrap();
        assert_eq!(s(&row, "checksum"), "");
        assert!(status.entries.iter().any(|entry| entry.version == version && entry.state == State::Legacy));
    }
    let child = db.one("SELECT kind,ca_kind FROM pki_cas WHERE id='child'", &[]).await.unwrap().unwrap();
    assert_eq!(s(&child, "kind"), "x509");
    assert_eq!(s(&child, "ca_kind"), "intermediate");
    assert_eq!(s(&db.one("SELECT kind FROM pki_cas WHERE id='ssh'", &[]).await.unwrap().unwrap(), "kind"), "ssh");
    assert_contains_schema(&db, &Db::open_memory().await.unwrap()).await;
    assert_final28_and_second_boot(&db).await;
    assert_preserved(&db, &before).await;
    assert_meta_contract(&db, &meta_before).await;
    // A lineage already carrying bootstrap meta keeps every preexisting value
    // and only gains the absent key (the no-overwrite clause).
    let guarded = empty_db();
    guarded.exec_script(&migrate::split_sql(include_str!("fixtures/schema_device20.sql"))).await.unwrap();
    for sql in [
        "INSERT INTO meta(k,v) VALUES('migration:env_restricted','device20-sentinel')",
        "INSERT INTO meta(k,v) VALUES('device20:marker','preserve-me')",
    ] { guarded.exec(sql, &[]).await.unwrap(); }
    migrate::apply(&guarded, MIGRATIONS, Options::default()).await.expect("converge a device20 lineage carrying preexisting bootstrap meta");
    assert_eq!(guarded.version().await.unwrap(), 28);
    assert_eq!(n(&guarded.one("SELECT COUNT(*) AS n FROM meta", &[]).await.unwrap().unwrap(), "n"), 3);
    assert_eq!(s(&guarded.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().unwrap(), "v"), "device20-sentinel");
    assert_eq!(s(&guarded.one("SELECT v FROM meta WHERE k='device20:marker'", &[]).await.unwrap().unwrap(), "v"), "preserve-me");
    assert_eq!(s(&guarded.one("SELECT v FROM meta WHERE k='rotation_lifecycle'", &[]).await.unwrap().unwrap(), "v"), "");
}

// Main27 ends with versions 1..27 occupied, so only 28 runs: the guarded
// env_restricted backfill that closed old main's migrations (d39138e db.rs
// trailing bootstrap) must ride with 28 or member envs keep org-wide access.
#[tokio::test]
async fn occupied_main27_convergence_bootstraps_env_restricted() {
    let db = legacy_main(27).await;
    db.exec("DELETE FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap();
    seed_occupied_member_env(&db).await;
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("converge an occupied main27 lineage");
    assert_eq!(report.applied, vec![28]);
    assert_eq!(n(&db.one("SELECT restricted FROM envs WHERE id='occupied-env'", &[]).await.unwrap().unwrap(), "restricted"), 1, "member envs must gain the restricted boundary");
    assert_eq!(s(&db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().unwrap(), "v"), "0");
    // An existing marker suppresses the backfill: no flip, no overwrite.
    let sentinel = legacy_main(27).await;
    seed_occupied_member_env(&sentinel).await;
    migrate::apply(&sentinel, MIGRATIONS, Options::default()).await.unwrap();
    assert_eq!(n(&sentinel.one("SELECT restricted FROM envs WHERE id='occupied-env'", &[]).await.unwrap().unwrap(), "restricted"), 0, "an existing marker must suppress the backfill");
    assert_eq!(s(&sentinel.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().unwrap(), "v"), "127");
}

async fn seed_occupied_member_env(db: &Db) {
    for sql in [
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,restricted,created_at) VALUES('occupied-env','occupied-app','Occupied','occupied-ciphertext',0,200)",
        "INSERT INTO env_members(env_id,user_id) VALUES('occupied-env','occupied-member')",
    ] { db.exec(sql, &[]).await.unwrap(); }
}

#[tokio::test]
async fn canonical_legacy23_through_27_preserve_data_and_unverified_history() {
    let engine = Db::open_memory().await.unwrap();
    for version in 23..=27 {
        let db = legacy_main(version).await;
        seed_product_and_ca(&db).await;
        seed_device_history(&db, version).await;
        let before = snapshot(&db).await;
        let ledger = db.query("SELECT version,applied_at FROM schema_migrations ORDER BY version", &[]).await.unwrap();
        let report = migrate::apply(&db, MIGRATIONS, Options::default()).await
            .unwrap_or_else(|error| panic!("upgrade canonical main{} without ledger repair: {}", version, error));
        assert_eq!(report.applied, ((version + 1)..=28).collect::<Vec<_>>(), "occupied main{} versions must not be replayed as engine SQL", version);
        assert!(!report.squashed);
        assert_preserved(&db, &before).await;
        assert_eq!(db.query(&format!("SELECT version,applied_at FROM schema_migrations WHERE version<={} ORDER BY version", version), &[]).await.unwrap(), ledger);
        let status = migrate::status(&db, MIGRATIONS).await.unwrap();
        for legacy in 17..=version {
            let row = db.one(&format!("SELECT checksum FROM schema_migrations WHERE version={}", legacy), &[]).await.unwrap().unwrap();
            assert_eq!(s(&row, "checksum"), "", "main{} history must not be falsely certified", legacy);
            assert!(status.entries.iter().any(|entry| entry.version == legacy && entry.state == State::Legacy));
        }
        for applied in (version + 1)..=28 {
            let row = db.one(&format!("SELECT checksum,success FROM schema_migrations WHERE version={}", applied), &[]).await.unwrap().unwrap();
            assert_eq!(s(&row, "checksum"), migrate::checksum(MIGRATIONS[(applied - 1) as usize].sql));
            assert_eq!(n(&row, "success"), 1);
        }
        assert_eq!(n(&db.one("SELECT restricted FROM envs WHERE id='merge27-env'", &[]).await.unwrap().unwrap(), "restricted"), 0, "bootstrap sentinel preserves intentional unrestricted access");
        assert_eq!(s(&db.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await.unwrap().unwrap(), "v"), "127");
        assert_eq!(s(&db.one("SELECT v FROM meta WHERE k='rotation_lifecycle'", &[]).await.unwrap().unwrap(), "v"), "");
        assert_contains_schema(&db, &engine).await;
        assert_final28_and_second_boot(&db).await;
        assert_preserved(&db, &before).await;
    }
}
