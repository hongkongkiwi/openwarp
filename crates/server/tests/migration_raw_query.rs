//! Migration Target queries must preserve SQL question marks without parameter translation.

use openwarp_server::db::{s, Db};
use openwarp_server::migrate::Target;

#[tokio::test]
async fn sqlite_target_query_preserves_literal_identifier_and_comment_question_marks() {
    let db = Db::connect("sqlite://:memory:").await.expect("open private in-memory database");
    for sql in [
        "SELECT '?' AS value",
        "SELECT \"?\" AS value FROM (SELECT '?' AS \"?\")",
        "SELECT '?' AS value /* ? is a comment */",
        "SELECT '?' AS value -- ? is a comment\n",
    ] {
        let rows = Target::query(&db, sql).await.expect("raw SQLite query must execute");
        assert_eq!(rows.len(), 1);
        assert_eq!(s(&rows[0], "value"), "?", "raw SQL: {sql}");
    }
}

struct PgDatabase {
    admin: tokio_postgres::Config,
    name: String,
}

impl Drop for PgDatabase {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() { Ok(runtime) => runtime, Err(_) => return };
            runtime.block_on(async move {
                if let Ok((client, connection)) = admin.connect(tokio_postgres::NoTls).await {
                    let driver = tokio::spawn(async move { let _ = connection.await; });
                    let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", name)).await;
                    driver.abort();
                }
            });
        }).join();
    }
}

#[tokio::test]
async fn postgres_target_query_preserves_literals_json_operator_identifiers_and_comments() {
    let Some(admin_url) = std::env::var("OPENWARP_TEST_POSTGRES_URL").ok().filter(|url| !url.trim().is_empty()) else {
        eprintln!("PostgreSQL raw-query coverage not executed: OPENWARP_TEST_POSTGRES_URL is not configured");
        return;
    };
    let admin_config: tokio_postgres::Config = admin_url.parse().expect("parse configured PostgreSQL admin URL");
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let name = format!("openwarp_raw_query_{}_{}", std::process::id(), nanos);
    let (admin, connection) = admin_config.connect(tokio_postgres::NoTls).await.expect("connect configured PostgreSQL admin");
    let driver = tokio::spawn(async move { let _ = connection.await; });
    admin.batch_execute(&format!("CREATE DATABASE {}", name)).await.expect("create disposable PostgreSQL database");
    let guard = PgDatabase { admin: admin_config, name: name.clone() };
    let (base, options) = admin_url.split_once('?').map(|(base, options)| (base, format!("?{options}"))).unwrap_or((&admin_url, String::new()));
    let prefix = base.rsplit_once('/').expect("configured PostgreSQL URL must include its admin database").0;
    let db = Db::connect(&format!("{prefix}/{name}{options}")).await.expect("open disposable PostgreSQL database");

    let mut failures = Vec::new();
    for (sql, expected) in [
        ("SELECT '?'::text AS value", "?"),
        (r#"SELECT ('{"key":1}'::jsonb ? 'key')::text AS value"#, "true"),
        ("SELECT \"?\" AS value FROM (SELECT '?'::text AS \"?\") AS sample", "?"),
        ("SELECT $raw$?$raw$::text AS value", "?"),
        ("SELECT '?'::text AS value /* ? is a comment */", "?"),
        ("SELECT '?'::text AS value -- ? is a comment\n", "?"),
        ("SELECT 'ok'::text AS value", "ok"),
    ] {
        match Target::query(&db, sql).await {
            Ok(rows) if rows.len() == 1 && s(&rows[0], "value") == expected => {},
            Ok(rows) => failures.push(format!("raw SQL {sql:?}: expected one row with value {expected:?}, got {rows:?}")),
            Err(error) => failures.push(format!("raw SQL {sql:?}: must execute unchanged, got error {error}")),
        }
    }
    drop(db);
    drop(guard);
    driver.abort();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
