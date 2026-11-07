//! Trigger statement boundaries in the public migration SQL splitter.

use openwarp_server::migrate::{split_sql, split_sql_with_dialect, SqlDialect};
use rusqlite::Connection;

fn audit_values(db: &Connection) -> Vec<i64> {
    db.prepare("SELECT value FROM audit ORDER BY rowid").unwrap()
        .query_map([], |row| row.get(0)).unwrap()
        .collect::<Result<Vec<_>, _>>().unwrap()
}

fn assert_sqlite_trigger(trigger: &str, expected: &[i64]) {
    let schema = "CREATE TABLE events(value INTEGER, backend INTEGER); CREATE TABLE audit(value INTEGER);";
    let insert = "INSERT INTO events(value,backend) VALUES(5,9)";
    let sql = format!("{};\n{};", trigger, insert);

    let unsplit = Connection::open_in_memory().unwrap();
    unsplit.execute_batch(schema).unwrap();
    unsplit.execute_batch(&sql).expect("the complete fixture must be valid SQLite SQL");
    assert_eq!(audit_values(&unsplit), expected, "the fixture must fire both trigger actions");

    let statements = split_sql_with_dialect(&sql, SqlDialect::Sqlite);
    assert_eq!(statements, vec![trigger, insert], "only the trigger's closing END terminates its statement");
    let split = Connection::open_in_memory().unwrap();
    split.execute_batch(schema).unwrap();
    for statement in &statements {
        split.execute_batch(statement).expect("each split statement must be independently executable");
    }
    assert_eq!(audit_values(&split), expected, "split SQL must preserve trigger effects");
}

#[test]
fn sqlite_trigger_case_end_does_not_terminate_the_trigger() {
    let trigger = "CREATE TRIGGER record_event AFTER INSERT ON events BEGIN
    INSERT INTO audit(value) SELECT CASE WHEN NEW.value > 0 THEN CASE WHEN NEW.backend = 9 THEN 10 ELSE 20 END ELSE 30 END;
    INSERT INTO audit(value) VALUES(NEW.backend);
END";
    assert_sqlite_trigger(trigger, &[10, 9]);
}

#[test]
fn sqlite_trigger_identifier_ending_in_end_does_not_terminate_the_trigger() {
    let trigger = "CREATE TRIGGER record_event AFTER INSERT ON events BEGIN
    INSERT INTO audit(value) SELECT NEW.backend;
    INSERT INTO audit(value) VALUES(NEW.value);
END";
    assert_sqlite_trigger(trigger, &[9, 5]);
}

#[test]
fn sqlite_trigger_keeps_body_semicolons_and_ignores_quoted_and_commented_keywords() {
    let trigger = "CREATE TRIGGER record_event AFTER INSERT ON events BEGIN
    SELECT 'CASE BEGIN END;';
    /* CASE BEGIN END; */ INSERT INTO audit(value) VALUES(NEW.value);
    INSERT INTO audit(value) VALUES(NEW.backend);
END";
    assert_sqlite_trigger(trigger, &[5, 9]);
}

#[test]
fn postgres_execute_function_trigger_does_not_absorb_the_following_statement() {
    let trigger = "CREATE TRIGGER record_event AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION record_event()";
    let following = "SELECT 1";
    let statements = split_sql_with_dialect(&format!("{};\n{};", trigger, following), SqlDialect::Postgres);
    assert_eq!(statements, vec![trigger, following], "a PostgreSQL function trigger has no inline BEGIN/END body");
}

#[test]
fn sqlite_trigger_bracket_quoted_end_does_not_terminate_the_trigger() {
    let schema = "CREATE TABLE events(value INTEGER, backend INTEGER); CREATE TABLE audit([end] INTEGER);";
    let trigger = "CREATE TRIGGER record_event AFTER INSERT ON events BEGIN
    INSERT INTO audit([end]) VALUES(NEW.value);
    INSERT INTO audit([end]) VALUES(NEW.backend);
END";
    let insert = "INSERT INTO events(value,backend) VALUES(5,9)";
    let sql = format!("{};\n{};", trigger, insert);
    let values = |db: &Connection| {
        db.prepare("SELECT [end] FROM audit ORDER BY rowid").unwrap()
            .query_map([], |row| row.get::<_, i64>(0)).unwrap()
            .collect::<Result<Vec<_>, _>>().unwrap()
    };

    let unsplit = Connection::open_in_memory().unwrap();
    unsplit.execute_batch(schema).unwrap();
    unsplit.execute_batch(&sql).expect("the bracket-quoted fixture must be valid SQLite SQL");
    assert_eq!(values(&unsplit), vec![5, 9], "the fixture must fire both trigger actions");

    let statements = split_sql_with_dialect(&sql, SqlDialect::Sqlite);
    assert_eq!(statements, vec![trigger, insert], "a bracket-quoted END identifier must not close the trigger body");
    let split = Connection::open_in_memory().unwrap();
    split.execute_batch(schema).unwrap();
    for statement in &statements {
        split.execute_batch(statement).expect("each split statement must be independently executable");
    }
    assert_eq!(values(&split), vec![5, 9], "split SQL must preserve both bracket-quoted trigger actions");
}

#[test]
fn postgres_array_quoted_bracket_and_semicolon_preserve_statement_boundaries() {
    let statements = split_sql_with_dialect("SELECT ARRAY[']',';']; SELECT 1;", SqlDialect::Postgres);
    assert_eq!(statements, vec!["SELECT ARRAY[']',';']", "SELECT 1"], "array string elements must not change statement boundaries");
}

#[test]
fn legacy_split_sql_keeps_sqlite_bracket_quoted_trigger_support() {
    let trigger = "CREATE TRIGGER record_event AFTER INSERT ON events BEGIN
    INSERT INTO audit([end]) SELECT CASE WHEN NEW.value > 0 THEN NEW.value ELSE 0 END;
    INSERT INTO audit([end]) VALUES(NEW.backend);
END";
    let insert = "INSERT INTO events(value,backend) VALUES(5,9)";
    let statements = split_sql(&format!("{};\n{};", trigger, insert));
    assert_eq!(statements, vec![trigger, insert], "the legacy wrapper must retain SQLite trigger and bracket-identifier behavior");

    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE events(value INTEGER, backend INTEGER); CREATE TABLE audit([end] INTEGER);").unwrap();
    for statement in &statements {
        db.execute_batch(statement).expect("legacy-wrapper statements must remain executable SQLite SQL");
    }
    let values = db.prepare("SELECT [end] FROM audit ORDER BY rowid").unwrap()
        .query_map([], |row| row.get::<_, i64>(0)).unwrap()
        .collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(values, vec![5, 9], "the legacy wrapper must preserve both trigger actions");
}
