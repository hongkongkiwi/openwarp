//! Carriage-return boundaries in migration line comments.

use openwarp_server::migrate::{split_sql, split_sql_with_dialect, SqlDialect};

#[test]
fn postgres_cr_terminated_leading_comments_preserve_following_statements() {
    let sql = "-- leading ; '\rSELECT 1; -- next ; '\rSELECT 2;";
    assert_eq!(
        split_sql_with_dialect(sql, SqlDialect::Postgres),
        vec!["SELECT 1", "SELECT 2"],
        "a PostgreSQL leading comment ends at CR without discarding the SQL after it",
    );
}

#[test]
fn postgres_lf_and_crlf_leading_comments_preserve_following_statements() {
    for newline in ["\n", "\r\n"] {
        let sql = format!("-- leading ; '{newline}SELECT 1; -- next ; '{newline}SELECT 2;");
        assert_eq!(
            split_sql_with_dialect(&sql, SqlDialect::Postgres),
            vec!["SELECT 1", "SELECT 2"],
            "leading comments with newline {newline:?}",
        );
    }
}

#[test]
fn postgres_repeated_leading_comments_preserve_sql() {
    for newline in ["\r", "\n", "\r\n"] {
        let sql = format!(" \t-- first ; '{newline} /* block ; */ -- second ; '{newline}\tSELECT 1;");
        assert_eq!(
            split_sql_with_dialect(&sql, SqlDialect::Postgres),
            vec!["SELECT 1"],
            "repeated leading comments with newline {newline:?}",
        );
    }
}

#[test]
fn postgres_trailing_comment_only_chunks_do_not_become_statements() {
    for newline in ["\r", "\n", "\r\n"] {
        let comments = format!("-- first ; '{newline} /* block ; */ -- last ; '");
        assert!(split_sql_with_dialect(&comments, SqlDialect::Postgres).is_empty());
        assert_eq!(
            split_sql_with_dialect(&format!("SELECT 1; {comments}"), SqlDialect::Postgres),
            vec!["SELECT 1"],
            "comment-only tail with newline {newline:?}",
        );
    }
}

#[test]
fn postgres_inline_comments_preserve_text_and_resume_sql_at_each_newline() {
    for newline in ["\r", "\n", "\r\n"] {
        let first = format!("SELECT 1 -- inline ; '{newline} + 2");
        let sql = format!("{first}; SELECT 3;");
        assert_eq!(
            split_sql_with_dialect(&sql, SqlDialect::Postgres),
            vec![first.as_str(), "SELECT 3"],
            "inline comments must remain intact and end at newline {newline:?}",
        );
    }
}

#[test]
fn non_postgres_line_comments_keep_lf_only_termination() {
    for dialect in [SqlDialect::Legacy, SqlDialect::Mysql, SqlDialect::Sqlite] {
        let cr_only = "-- leading\rSELECT 1;";
        let cr_then_lf = "-- leading\rSELECT 1;\nSELECT 2;";
        assert!(split_sql_with_dialect(cr_only, dialect).is_empty(), "{dialect:?}");
        assert_eq!(split_sql_with_dialect(cr_then_lf, dialect), vec!["SELECT 2"], "{dialect:?}");
        for newline in ["\n", "\r\n"] {
            let sql = format!("-- leading{newline}SELECT 1; -- trailing");
            assert_eq!(split_sql_with_dialect(&sql, dialect), vec!["SELECT 1"], "{dialect:?}, {newline:?}");
        }
        let inline = "SELECT 1 -- inline ; '\rSELECT 9;\n; SELECT 2;";
        assert_eq!(
            split_sql_with_dialect(inline, dialect),
            vec!["SELECT 1 -- inline ; '\rSELECT 9;", "SELECT 2"],
            "CR must remain inside a non-PostgreSQL line comment for {dialect:?}",
        );
    }
    assert!(split_sql("-- leading\rSELECT 1;").is_empty());
    assert_eq!(split_sql("-- leading\rSELECT 1;\nSELECT 2;"), vec!["SELECT 2"]);
}
