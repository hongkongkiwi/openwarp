//! SQLite scripts must roll back both statement failures and deferred commit failures.

use openwarp_server::db::{n, Db};

async fn database() -> Db {
    let db = Db::connect("sqlite://:memory:").await.expect("connect private in-memory database");
    db.exec_raw("PRAGMA foreign_keys=ON").await.unwrap();
    let enabled = db.one("PRAGMA foreign_keys", &[]).await.unwrap().unwrap();
    assert_eq!(n(&enabled, "foreign_keys"), 1);
    db.exec_raw("CREATE TABLE parents(id INTEGER PRIMARY KEY)").await.unwrap();
    db.exec_raw("CREATE TABLE children(id INTEGER PRIMARY KEY,parent_id INTEGER NOT NULL REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED)").await.unwrap();
    db
}

async fn counts(db: &Db) -> (i64, i64) {
    let parents = db.one("SELECT COUNT(*) AS n FROM parents", &[]).await.unwrap().unwrap();
    let children = db.one("SELECT COUNT(*) AS n FROM children", &[]).await.unwrap().unwrap();
    (n(&parents, "n"), n(&children, "n"))
}

async fn valid_script(db: &Db) {
    db.exec_script(&[
        "INSERT INTO children(id,parent_id) VALUES(1,1)".into(),
        "INSERT INTO parents(id) VALUES(1)".into(),
    ]).await.expect("a valid deferred-constraint script must commit on the same connection");
    assert_eq!(counts(db).await, (1, 1));
}

#[tokio::test]
async fn sqlite_failed_deferred_commit_rolls_back_and_connection_accepts_next_script() {
    let db = database().await;
    let error = db.exec_script(&[
        "INSERT INTO parents(id) VALUES(1)".into(),
        "INSERT INTO children(id,parent_id) VALUES(1,2)".into(),
    ]).await.expect_err("an orphan with a deferred foreign key must fail at COMMIT");
    assert!(error.to_ascii_lowercase().contains("foreign key constraint failed"), "unexpected failure: {error}");
    assert_eq!(counts(&db).await, (0, 0), "failed COMMIT must roll back the entire script, including the orphan");
    valid_script(&db).await;
}

#[tokio::test]
async fn sqlite_valid_deferred_script_commits_and_connection_accepts_next_script() {
    let db = database().await;
    valid_script(&db).await;
    db.exec_script(&[
        "INSERT INTO children(id,parent_id) VALUES(2,2)".into(),
        "INSERT INTO parents(id) VALUES(2)".into(),
    ]).await.expect("a committed script must leave the connection ready for another transaction");
    assert_eq!(counts(&db).await, (2, 2));
}

#[tokio::test]
async fn sqlite_statement_failure_rolls_back_and_connection_accepts_next_script() {
    let db = database().await;
    let error = db.exec_script(&[
        "INSERT INTO children(id,parent_id) VALUES(1,1)".into(),
        "INSERT INTO parents(id) VALUES(1)".into(),
        "INSERT INTO parents(id) VALUES(1)".into(),
    ]).await.expect_err("a duplicate primary key must fail before COMMIT");
    assert!(error.to_ascii_lowercase().contains("unique constraint failed"), "unexpected failure: {error}");
    assert_eq!(counts(&db).await, (0, 0), "a statement failure must roll back all earlier script statements");
    valid_script(&db).await;
}
