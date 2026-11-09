//! PR9 AI engine merge: main's migration engine (versions 1..29) carries none
//! of the AI assistant schema that arrived with the feat/ai-assistant branch.
//! These tests pin migration 30 restoring the eight AI tables and their
//! indexes exactly as the AI branch's former inline migration 19 defined them
//! (f59e96b), keep released engine SQL 1..29 immutable, prove an engine-29
//! database upgrades to 30 without data loss or replay, and hold the
//! ai_settings master-rotation rewrap contract through the public
//! rotate-master route (preflight refusal and the no-silent-miss CAS).

use axum::{body::{to_bytes, Body}, http::{Method, Request}};
use openwarp_crypto as oc;
use openwarp_server::db::{n, s, Db, Row};
use openwarp_server::migrate::{self, Options, MIGRATIONS};
use openwarp_server::{app::PeerAddr, clock, new_state, router, S};
use serde_json::{json, Value};
use tower::ServiceExt;

// sha256 of crates/server/migrations/0001..0029 at merge HEAD f001c14.
const ENGINE_CHECKSUMS_1_29: [&str; 29] = [
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
    "51ff75b9f395703b88de4abe0482638e59a47090ba4ad399d21dd2fc256edfbf",
    "730193d05ef0286d19f24230273f99cc8f71e020334cc87bbabda41165c594dd",
    "a822996c268cb3fc42f8f3e3b0a3e64f838ea4eae241b9ca7a2877f1bf27ca8b",
    "f4a6c5372018febff46c175ba6fdb7a7e6a470bcde67bc9948634c0dbb1f5d44",
    "f2f3325b8109b7a01974ddc3787bd337b1941212736bf0c9f6c8c58158af5e97",
    "7daa9f615b9345667b5b403f72e206485fa1a727b8eda14c4caaad78e16fbf49",
];

// The AI branch's former inline migration 19 (git show f59e96b:crates/server/
// src/db.rs), verbatim. Migration 30 must produce exactly this schema.
const FORMER_AI_MIGRATION_19: &str = "\
CREATE TABLE IF NOT EXISTS ai_settings(org_id TEXT PRIMARY KEY,settings TEXT NOT NULL,key_enc TEXT NOT NULL DEFAULT '',updated_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_plans(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,actor TEXT NOT NULL,operations TEXT NOT NULL,status TEXT NOT NULL,expires_at BIGINT NOT NULL,results TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS folders(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,path TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_env_path ON folders(env_id,path);
CREATE TABLE IF NOT EXISTS integration_drafts(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,env_id TEXT NOT NULL,provider_kind TEXT NOT NULL,name TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_finding_states(org_id TEXT NOT NULL,finding_id TEXT NOT NULL,status TEXT NOT NULL,exception_until BIGINT NOT NULL DEFAULT 0,maintenance_note TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,finding_id));
CREATE TABLE IF NOT EXISTS ai_usage(org_id TEXT NOT NULL,day BIGINT NOT NULL,requests BIGINT NOT NULL DEFAULT 0,units BIGINT NOT NULL DEFAULT 0,active_until BIGINT NOT NULL DEFAULT 0,claim TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,day));
CREATE TABLE IF NOT EXISTS ai_activity(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT NOT NULL,env_id TEXT NOT NULL,actor TEXT NOT NULL,credential TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,count BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_finding_history(org_id TEXT NOT NULL,finding_id TEXT NOT NULL,finding TEXT NOT NULL,first_seen BIGINT NOT NULL,last_seen BIGINT NOT NULL,PRIMARY KEY(org_id,finding_id));
CREATE INDEX IF NOT EXISTS idx_ai_activity_org ON ai_activity(org_id,created_at);
CREATE INDEX IF NOT EXISTS idx_ai_plans_expiry ON ai_plans(expires_at);
CREATE INDEX IF NOT EXISTS idx_ai_drafts_org ON integration_drafts(org_id);
";

fn empty_db() -> Db {
    Db::Sqlite(std::sync::Mutex::new(rusqlite::Connection::open_in_memory().unwrap()))
}

async fn ai_canonical_db() -> Db {
    let db = empty_db();
    db.exec_script(&migrate::split_sql(FORMER_AI_MIGRATION_19)).await.expect("install the AI branch's former migration 19 as canonical schema");
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

async fn assert_clean_engine(db: &Db, expected: i64) {
    assert_eq!(db.version().await.unwrap(), expected);
    let status = migrate::status(db, MIGRATIONS).await.unwrap();
    assert_eq!(status.current, expected, "current version");
    assert_eq!(status.latest, expected, "latest version");
    assert!(status.problems.is_empty(), "ledger problems: {:?}", status.problems);
    assert!(status.pending().is_empty(), "pending migrations: {:?}", status.pending().iter().map(|e| e.version).collect::<Vec<_>>());
}

// Original column projections distinguish preserved values from additive defaults.
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
        assert_eq!(&db.query(sql, &[]).await.unwrap(), rows, "preserve rows for {}", sql);
    }
}

async fn assert_ai_tables_exact(db: &Db) {
    let tables = application_tables(db).await;
    assert!(!tables.iter().any(|t| t == "ai_messages"), "the merged AI schema must not carry an ai_messages table");
    let mut ai_tables: Vec<String> = tables.iter().filter(|t| t.starts_with("ai")).cloned().collect();
    ai_tables.sort();
    assert_eq!(ai_tables, Vec::from([
        "ai_activity", "ai_finding_history", "ai_finding_states", "ai_plans", "ai_settings", "ai_usage",
    ]), "ai-prefixed tables must be exactly the AI assistant set");
    assert_contains_schema(db, &ai_canonical_db().await).await;
}

#[test]
fn released_engine_sql_1_through_29_is_immutable() {
    assert!(MIGRATIONS.len() >= 29, "the engine manifest must keep at least versions 1..29");
    for (index, expected) in ENGINE_CHECKSUMS_1_29.iter().enumerate() {
        assert_eq!(MIGRATIONS[index].version, index as i64 + 1);
        assert_eq!(migrate::checksum(MIGRATIONS[index].sql), *expected, "released engine SQL {} is immutable; the AI schema must land as a new migration 30", index + 1);
    }
}

#[tokio::test]
async fn fresh_engine_reaches_30_with_exact_ai_schema() {
    // Migration 30 must exist; the manifest may carry later migrations after it.
    assert!(MIGRATIONS.iter().any(|m| m.version == 30), "the merged engine must carry the AI assistant schema as migration 30");
    let latest = MIGRATIONS.last().expect("manifest").version;
    let db = Db::open_memory().await.unwrap();
    assert_clean_engine(&db, latest).await;
    assert_ai_tables_exact(&db).await;
    let ledger = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(report.applied.is_empty(), "a second boot on a fresh database must not replay anything: {:?}", report.applied);
    assert!(!report.squashed);
    assert_eq!(db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap(), ledger, "an idempotent re-run must leave the ledger untouched");
}

#[tokio::test]
async fn engine29_upgrade_appends_migration_30_and_preserves_data() {
    let db = empty_db();
    migrate::apply(&db, &MIGRATIONS[..29], Options::default()).await.expect("engine 29 applies standalone");
    assert_eq!(db.version().await.unwrap(), 29);
    for sql in [
        "INSERT INTO orgs(id,name,created_at) VALUES('ai29-org','AI merge',31)",
        "INSERT INTO apps(id,org_id,name,created_at) VALUES('ai29-app','ai29-org','Fixture app',32)",
        "INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES('ai29-env','ai29-app','Production','dummy-env-ciphertext',33)",
        "INSERT INTO secrets(id,env_id,key_enc,key_hash,value_enc,updated_at) VALUES('ai29-secret','ai29-env','dummy-key-ciphertext','dummy-key-hash','dummy-value-ciphertext',34)",
    ] { db.exec(sql, &[]).await.unwrap(); }
    let before = snapshot(&db).await;
    let ledger29 = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();

    let report = migrate::apply(&db, MIGRATIONS, Options::default()).await.expect("the merged engine upgrades an engine-29 database");
    let latest = MIGRATIONS.last().expect("manifest").version;
    assert_eq!(report.applied, (30i64..=latest).collect::<Vec<_>>(), "migration 30 and every migration after it must land on an engine-29 database");
    assert!(!report.squashed);
    assert_clean_engine(&db, latest).await;
    assert_preserved(&db, &before).await;
    assert_eq!(db.query("SELECT * FROM schema_migrations WHERE version<=29 ORDER BY version", &[]).await.unwrap(), ledger29, "engine history 1..29 must survive the upgrade untouched");
    let migration30 = MIGRATIONS.iter().find(|m| m.version == 30).expect("migration 30 in the manifest");
    let row = &db.query("SELECT name,checksum,success FROM schema_migrations WHERE version=30", &[]).await.unwrap()[0];
    assert_eq!(s(row, "name"), migration30.name);
    assert_eq!(s(row, "checksum"), migrate::checksum(migration30.sql));
    assert_eq!(n(row, "success"), 1);
    assert_ai_tables_exact(&db).await;

    let ledger30 = db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap();
    let again = migrate::apply(&db, MIGRATIONS, Options::default()).await.unwrap();
    assert!(again.applied.is_empty(), "re-running the upgrade must be a no-op: {:?}", again.applied);
    assert_eq!(db.query("SELECT * FROM schema_migrations ORDER BY version", &[]).await.unwrap(), ledger30);
}

// The AI provider credential lives in ai_settings.key_enc, wrapped with the
// master key and the org-bound AAD ow-ai-key:v1|<org>. Master rotation must
// rewrap it, refuse to rotate when it cannot decrypt it, and report a conflict
// when a row silently misses its update. ai::rewrap itself is pub(crate), so
// the contract is held through the public rotate-master route.
struct Database { url: String, directory: std::path::PathBuf }
impl Database {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("openwarp-ai-engine-{}", oc::random_token("db")));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
        builder.create(&directory).expect("create private dummy-data directory");
        Self { url: format!("sqlite://{}", directory.join("fixture.db").display()), directory }
    }
}
impl Drop for Database { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.directory); } }

const OWNER: &str = "ow_fake_ai_engine_owner";
const CREDENTIAL: &[u8] = b"fake-ai-engine-provider-credential";
const OLD: [u8; 32] = [41; 32];
const NEW_A: [u8; 32] = [42; 32];
const NEW_B: [u8; 32] = [43; 32];
const NEW_C: [u8; 32] = [44; 32];
const NEW_D: [u8; 32] = [45; 32];

struct Fixture { state: S, app: axum::Router }
impl Fixture {
    async fn open(database: &Database, master: [u8; 32]) -> Self {
        let db = Db::open(&database.url).await.expect("open and migrate private SQLite database");
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, database.url.clone(), "ai-engine-merge".into(), "https://openwarp.test.invalid".into(), master, live,
            #[cfg(feature = "redis-cache")] None);
        Self { app: router(state.clone()), state }
    }
    async fn sql(&self, sql: &str, params: &[Value]) { self.state.db().exec(sql, params).await.expect("fixture SQL"); }
    async fn text(&self, sql: &str) -> String {
        json!(self.state.db().query(sql, &[]).await.expect("inspect private fixture").iter().map(openwarp_server::db::obj).collect::<Vec<_>>()).to_string()
    }
    async fn expect(&self, method: Method, path: &str, body: Option<Value>, status: u16) -> Value {
        let request_line = format!("{} {}", method, path);
        let mut builder = Request::builder().method(method).uri(path).header("host", "openwarp.test.invalid")
            .header("authorization", format!("Bearer {}", OWNER));
        let body = if let Some(v) = body { builder = builder.header("content-type", "application/json"); Body::from(v.to_string()) } else { Body::empty() };
        let mut request = builder.body(body).unwrap();
        request.extensions_mut().insert(PeerAddr("192.0.2.40".parse().unwrap()));
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), self.app.clone().oneshot(request)).await.expect("bounded router request").expect("router response");
        let actual = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024).await.expect("bounded response body");
        let body: Value = serde_json::from_slice(&bytes).expect("JSON API response");
        assert_eq!(actual, status, "{}: error={}", request_line, body["error"]);
        body
    }
    async fn rotate(&self, key: &[u8; 32], status: u16) {
        self.expect(Method::POST, "/api/instance/rotate-master", Some(json!({"new_key": oc::b64(key)})), status).await;
    }
    async fn ai_key_enc(&self, org: &str) -> String {
        s(&self.state.db().query("SELECT key_enc FROM ai_settings WHERE org_id=?", &[json!(org)]).await.expect("read ai_settings")[0], "key_enc")
    }
}

fn aad(org: &str) -> Vec<u8> { format!("ow-ai-key:v1|{}", org).into_bytes() }

async fn seed_instance(f: &Fixture) {
    f.sql("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES('owner','ai-engine@test.invalid','unused','','',?,1,1)", &[json!(clock::now())]).await;
    f.sql("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token(OWNER)), json!(clock::now())]).await;
    f.sql("INSERT INTO orgs(id,name,created_at) VALUES('org','ai-engine',?)", &[json!(clock::now())]).await;
    f.sql("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await;
    f.sql("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await;
    f.sql("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&OLD))]).await;
    // Boot installs the master verifier before any request can rotate the key,
    // and the rotation batch updates that row by name with a required count,
    // so the fixture must carry it or every rotation answers 409.
    f.sql("INSERT INTO meta(k,v) VALUES('master_key_check',?)", &[json!(oc::encrypt_symmetric(&OLD, b"openwarp-master-key-v1"))]).await;
}

#[tokio::test]
async fn rotate_master_rewraps_ai_settings_after_engine_merge() {
    let database = Database::new();
    let f = Fixture::open(&database, OLD).await;
    seed_instance(&f).await;
    f.expect(Method::GET, "/api/me", None, 200).await;
    f.rotate(&NEW_A, 200).await;

    f.sql("INSERT INTO ai_settings(org_id,settings,key_enc,updated_at) VALUES('org','{}',?,?)", &[json!(oc::encrypt_symmetric_aad(&NEW_A, &aad("org"), CREDENTIAL)), json!(clock::now())]).await;
    f.sql("INSERT INTO ai_settings(org_id,settings,key_enc,updated_at) VALUES('empty-org','{}','',?)", &[json!(clock::now())]).await;
    let wrapped_a = f.ai_key_enc("org").await;

    f.rotate(&NEW_B, 200).await;
    let wrapped_b = f.ai_key_enc("org").await;
    assert_ne!(wrapped_b, wrapped_a, "rotation must rewrite the AI credential wrapping");
    assert_eq!(oc::decrypt_symmetric_aad(&NEW_B, &aad("org"), &wrapped_b).unwrap(), CREDENTIAL, "the rewrapped credential must decrypt under the new master");
    assert!(oc::decrypt_symmetric_aad(&NEW_A, &aad("org"), &wrapped_b).is_err(), "the old master must no longer read the credential");
    assert_eq!(f.ai_key_enc("empty-org").await, "", "rows without a credential must stay untouched");

    // A fresh boot on the rotated database must read the credential.
    let fresh = Fixture::open(&database, NEW_B).await;
    fresh.expect(Method::GET, "/api/me", None, 200).await;
    assert_eq!(oc::decrypt_symmetric_aad(&NEW_B, &aad("org"), &fresh.ai_key_enc("org").await).unwrap(), CREDENTIAL);

    // Undecryptable wrapping must refuse rotation without partial updates.
    f.sql("UPDATE ai_settings SET key_enc='invalid-fixture-ciphertext' WHERE org_id='org'", &[]).await;
    let before = f.text("SELECT org_id,settings,key_enc FROM ai_settings ORDER BY org_id").await;
    let master_before = f.text("SELECT k,v FROM meta WHERE k='master'").await;
    f.rotate(&NEW_C, 400).await;
    assert_eq!(f.text("SELECT org_id,settings,key_enc FROM ai_settings ORDER BY org_id").await, before, "a refused rotation must not touch ai_settings");
    assert_eq!(f.text("SELECT k,v FROM meta WHERE k='master'").await, master_before, "a refused rotation must not publish a new master");
    f.sql("UPDATE ai_settings SET key_enc=? WHERE org_id='org'", &[json!(oc::encrypt_symmetric_aad(&NEW_B, &aad("org"), CREDENTIAL))]).await;
    let restored = f.text("SELECT org_id,settings,key_enc FROM ai_settings ORDER BY org_id").await;

    // A silently missed ai_settings update (SQLite RAISE(IGNORE)) is a
    // conflict, never a reported success with a stale credential.
    f.sql("CREATE TRIGGER ignore_ai_rotation BEFORE UPDATE ON ai_settings BEGIN SELECT RAISE(IGNORE); END", &[]).await;
    f.rotate(&NEW_D, 409).await;
    f.sql("DROP TRIGGER ignore_ai_rotation", &[]).await;
    assert_eq!(f.text("SELECT org_id,settings,key_enc FROM ai_settings ORDER BY org_id").await, restored, "a conflicted rotation must leave the restored wrapping in place");
    f.rotate(&NEW_D, 200).await;
    assert_eq!(oc::decrypt_symmetric_aad(&NEW_D, &aad("org"), &f.ai_key_enc("org").await).unwrap(), CREDENTIAL);
}
