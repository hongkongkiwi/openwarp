//! Dialect-specific string and comment boundaries in migration SQL.

use openwarp_server::migrate::{split_sql_with_dialect, SqlDialect};
use rusqlite::Connection;

fn stored_values(db: &Connection) -> Vec<String> {
    db.prepare("SELECT value FROM samples ORDER BY rowid").unwrap()
        .query_map([], |row| row.get(0)).unwrap()
        .collect::<Result<Vec<_>, _>>().unwrap()
}

#[test]
fn sqlite_trailing_backslash_closes_literal_and_preserves_following_statement() {
    let first = r"INSERT INTO samples(value) VALUES('value\')";
    let second = "INSERT INTO samples(value) VALUES('it''s; still data')";
    let sql = format!("{}; {};", first, second);
    let schema = "CREATE TABLE samples(value TEXT NOT NULL)";
    let expected = vec!["value\\", "it's; still data"];

    let unsplit = Connection::open_in_memory().unwrap();
    unsplit.execute_batch(schema).unwrap();
    unsplit.execute_batch(&sql).expect("the complete fixture must be valid SQLite SQL");
    assert_eq!(stored_values(&unsplit), expected, "SQLite treats the backslash as literal data");

    let statements = split_sql_with_dialect(&sql, SqlDialect::Sqlite);
    assert_eq!(statements, vec![first, second], "a backslash must not escape a SQLite closing quote");
    let split = Connection::open_in_memory().unwrap();
    split.execute_batch(schema).unwrap();
    for statement in &statements {
        split.execute_batch(statement).expect("each split statement must be independently executable");
    }
    assert_eq!(stored_values(&split), expected, "splitting must preserve both stored values");
}

#[test]
fn postgres_standard_literal_backslash_does_not_escape_closing_quote() {
    // Ordinary strings use standard_conforming_strings=on; E-strings are tested separately.
    let first = r"SELECT 'value\'";
    let second = "SELECT 'it''s; still data'";
    assert_eq!(
        split_sql_with_dialect(&format!("{}; {};", first, second), SqlDialect::Postgres),
        vec![first, second],
        "standard PostgreSQL strings must not absorb the following statement",
    );
}

#[test]
fn postgres_json_path_operators_do_not_start_hash_comments() {
    let text_path = r#"SELECT '{"a":{"b":7}}'::jsonb #>> '{a,b}'"#;
    let json_path = r#"SELECT '{"a":7}'::jsonb #> '{a}'"#;
    assert_eq!(
        split_sql_with_dialect(&format!("{}; {}; SELECT 2;", text_path, json_path), SqlDialect::Postgres),
        vec![text_path, json_path, "SELECT 2"],
        "both PostgreSQL JSON path operators must preserve same-line statement boundaries",
    );
}

#[test]
fn mysql_backslash_escapes_keep_literal_semicolons_and_hashes() {
    let escaped_quote = r"SELECT 'it\'s; # data'";
    let escaped_backslash = r"SELECT '\\'";
    assert_eq!(
        split_sql_with_dialect(&format!("{}; {}; SELECT 2;", escaped_quote, escaped_backslash), SqlDialect::Mysql),
        vec![escaped_quote, escaped_backslash, "SELECT 2"],
        "MySQL backslash escapes must protect quotes without hiding the final closing quote",
    );
}

#[test]
fn mysql_hash_comments_hide_semicolons_and_unmatched_quotes() {
    let sql = "# leading ; '\nSELECT 1; SELECT 2 # inline ; '\n; # trailing ; '";
    assert_eq!(
        split_sql_with_dialect(sql, SqlDialect::Mysql),
        vec!["SELECT 1", "SELECT 2 # inline ; '"],
        "MySQL hash comments must end at newline and comment-only chunks must not execute",
    );
}

#[test]
fn postgres_explicit_escape_strings_keep_backslash_escapes() {
    let escaped_quote = r"SELECT E'it\'s; # data'";
    let escaped_backslash = r"SELECT e'\\'";
    assert_eq!(
        split_sql_with_dialect(&format!("{}; {}; SELECT 2;", escaped_quote, escaped_backslash), SqlDialect::Postgres),
        vec![escaped_quote, escaped_backslash, "SELECT 2"],
        "both E and e prefixes must retain explicit PostgreSQL backslash escapes",
    );
}

#[test]
fn postgres_escape_string_continuation_retains_escapes_without_repeated_prefix() {
    let continued = r"SELECT E'one'
 'two\'three;four'";
    assert_eq!(
        split_sql_with_dialect(&format!("{}; SELECT 2;", continued), SqlDialect::Postgres),
        vec![continued, "SELECT 2"],
        "a newline-separated E-string continuation must retain escapes without another E prefix",
    );
}

#[test]
fn postgres_standard_string_continuation_keeps_backslash_literal_after_escape_statement() {
    let continued = r"SELECT 'one'
 'two\'";
    assert_eq!(
        split_sql_with_dialect(&format!("SELECT E'earlier'; {}; SELECT 2;", continued), SqlDialect::Postgres),
        vec!["SELECT E'earlier'", continued, "SELECT 2"],
        "ordinary continued strings must not inherit escape semantics from an earlier statement",
    );
}
