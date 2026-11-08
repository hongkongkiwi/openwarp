//! SQLite trigger modifiers must not expose body semicolons as statement boundaries.

use openwarp_server::migrate::{split_sql_with_dialect, SqlDialect};
use rusqlite::Connection;

fn stored_values(db: &Connection) -> Vec<i64> {
    db.prepare("SELECT value FROM effects ORDER BY rowid").unwrap()
        .query_map([], |row| row.get(0)).unwrap()
        .collect::<Result<Vec<_>, _>>().unwrap()
}

fn exercise(prefix: &str) {
    let trigger = format!("{prefix} record_insert AFTER INSERT ON samples BEGIN INSERT INTO effects VALUES(NEW.value); INSERT INTO effects VALUES(NEW.value + 1); END");
    let insert = "INSERT INTO samples VALUES(7)";
    let sql = format!("{trigger}; {insert};");
    let schema = "CREATE TABLE samples(value INTEGER); CREATE TABLE effects(value INTEGER);";

    let unsplit = Connection::open_in_memory().unwrap();
    unsplit.execute_batch(schema).unwrap();
    unsplit.execute_batch(&sql).expect("the complete fixture must be valid SQLite SQL");
    assert_eq!(stored_values(&unsplit), vec![7, 8]);

    let statements = split_sql_with_dialect(&sql, SqlDialect::Sqlite);
    assert_eq!(statements, vec![trigger.as_str(), insert], "{prefix} must retain all body statements through END");
    let split = Connection::open_in_memory().unwrap();
    split.execute_batch(schema).unwrap();
    for statement in &statements {
        split.execute_batch(statement).expect("each split statement must be independently executable");
    }
    assert_eq!(stored_values(&split), vec![7, 8], "splitting must preserve both trigger effects");
}

#[test]
fn sqlite_create_temp_trigger_preserves_body_and_following_statement() {
    exercise("CREATE TEMP TRIGGER");
}

#[test]
fn sqlite_create_temporary_trigger_preserves_body_and_following_statement() {
    exercise("CREATE TEMPORARY TRIGGER");
}

#[test]
fn sqlite_create_trigger_preserves_body_and_following_statement() {
    exercise("CREATE TRIGGER");
}
