use serde_json::{json, Map, Value};
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use mysql_async::prelude::Queryable;

pub type Row = HashMap<String, Value>;
#[path = "db_webhooks.rs"]
mod webhooks;
pub use webhooks::WebhookTx;

#[path = "migration_session.rs"]
mod migration_session;

/// Storage backend. Native builds use SQLite or a PostgreSQL pool; the Workers
/// build uses the synchronous SQLite handle of a Durable Object, which is
/// wrapped in async methods so call sites stay identical on both targets.
pub enum Db {
    #[cfg(not(target_arch = "wasm32"))]
    Sqlite(std::sync::Mutex<rusqlite::Connection>),
    #[cfg(not(target_arch = "wasm32"))]
    Postgres(deadpool_postgres::Pool),
    #[cfg(target_arch = "wasm32")]
    DoSqlite(std::rc::Rc<worker::SqlStorage>, std::rc::Rc<worker::Storage>),
    #[cfg(not(target_arch = "wasm32"))]
    Mysql(mysql_async::Pool),
}

// A Workers isolate has no threads and the Durable Object serialises event
// delivery, so the JS-backed SQL handle is never used from two threads. axum's
// state bound still requires Send+Sync, hence these two impls.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for Db {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for Db {}

/// The dialect a query needs when one statement cannot be written portably.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, PartialEq)]
pub enum Backend { Sqlite, Postgres, Mysql }

/// How an operator command opens SQLite. PostgreSQL and MySQL ignore it because
/// opening a connection does not create a database.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, PartialEq)]
enum OpenMode { Create, Existing, ReadOnly }

#[cfg(not(target_arch = "wasm32"))]
fn pg_sql(sql: &str) -> String {
    let mut out = String::new(); let mut n = 0;
    for c in sql.chars() { if c == '?' { n += 1; out.push_str(&format!("${}", n)); } else { out.push(c); } }
    out.replace("OW_NOW()", "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
}
#[cfg(not(target_arch = "wasm32"))]
fn pg_err(error: tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => db.message().to_string(),
        None => error.to_string(),
    }
}

fn sqlite_sql(sql: &str) -> String { sql.replace("OW_NOW()", "CAST(strftime('%s','now') AS INTEGER)") }
#[cfg(not(target_arch = "wasm32"))]
fn pg_row(r: &tokio_postgres::Row) -> Row {
    let mut m = Row::new();
    for (i, col) in r.columns().iter().enumerate() {
        let v = if let Ok(v) = r.try_get::<_, Option<String>>(i) { v.map(Value::String).unwrap_or(Value::Null) }
            else if let Ok(v) = r.try_get::<_, Option<i64>>(i) { v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null) }
            else if let Ok(v) = r.try_get::<_, Option<bool>>(i) { v.map(Value::Bool).unwrap_or(Value::Null) }
            else if let Ok(v) = r.try_get::<_, Option<Value>>(i) { v.unwrap_or(Value::Null) } else { Value::Null };
        m.insert(col.name().to_string(), v);
    } m
}
#[cfg(not(target_arch = "wasm32"))]
fn mysql_row(r: &mysql_async::Row) -> Row { let mut m = Row::new(); for (i, col) in r.columns_ref().iter().enumerate() { m.insert(col.name_str().to_string(), mysql_value(r.as_ref(i))); } m }

impl Db {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn backend(&self) -> Backend { match self { Db::Sqlite(_) => Backend::Sqlite, Db::Postgres(_) => Backend::Postgres, Db::Mysql(_) => Backend::Mysql } }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open(url: &str) -> Result<Self, String> {
        let db = Db::connect(url).await?;
        db.migrate().await?;
        Ok(db)
    }
    /// Open without migrating. The operator CLI uses this to apply or repair.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(url: &str) -> Result<Self, String> { Db::open_mode(url, OpenMode::Create).await }
    /// Open an existing database without creating it. A mistyped SQLite path
    /// fails instead of leaving an empty file behind.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_existing(url: &str) -> Result<Self, String> { Db::open_mode(url, OpenMode::Existing).await }
    /// Open for inspection. SQLite rejects writes on this connection, so status
    /// and verify cannot change a ledger or create a database by accident.
    /// PostgreSQL and MySQL are not enforced read-only; those commands only
    /// issue SELECTs.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_read_only(url: &str) -> Result<Self, String> { Db::open_mode(url, OpenMode::ReadOnly).await }
    #[cfg(not(target_arch = "wasm32"))]
    async fn open_mode(url: &str, mode: OpenMode) -> Result<Self, String> {
        // A scheme is case-insensitive in a URL; the drivers are not, so the
        // normalized form is what gets parsed.
        let (scheme, rest) = match url.split_once("://") { Some((s, r)) => (s.to_ascii_lowercase(), r), None => (String::new(), "") };
        if scheme == "postgres" || scheme == "postgresql" {
            let url = format!("{}://{}", scheme, rest);
            let config: tokio_postgres::Config = url.parse().map_err(|e| format!("invalid DATABASE_URL: {}", e))?;
            let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
            let size = std::env::var("OPENWARP_PG_POOL_SIZE").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(8).clamp(1, 64);
            let pool = deadpool_postgres::Pool::builder(manager).max_size(size).build().map_err(|e| format!("postgres pool: {}", e))?;
            Ok(Db::Postgres(pool))
        } else if scheme == "mysql" || scheme == "mariadb" {
            let url = format!("mysql://{}", rest);
            let opts = mysql_async::Opts::from_url(&url).map_err(|e| format!("invalid DATABASE_URL: {}", e))?;
            let size = std::env::var("OPENWARP_MYSQL_POOL_SIZE").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(8).clamp(1, 64);
            let constraints = mysql_async::PoolConstraints::new(1, size).ok_or("invalid mysql pool size")?;
            // Match PostgreSQL/SQLite affected-row semantics: callers compare the
            // count from UPDATE (leader election, rotation claims), and MySQL
            // otherwise reports changed rows only.
            let opts = mysql_async::OptsBuilder::from_opts(opts).client_found_rows(true).pool_opts(mysql_async::PoolOpts::default().with_constraints(constraints));
            Ok(Db::Mysql(mysql_async::Pool::new(opts)))
        } else {
            let path = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")).unwrap_or(url);
            let flags = if mode == OpenMode::Create {
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            } else {
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            };
            let conn = rusqlite::Connection::open_with_flags(path, flags).map_err(|e| e.to_string())?;
            // A second instance booting at the same time waits for the writer
            // instead of failing the migration with SQLITE_BUSY.
            conn.busy_timeout(std::time::Duration::from_secs(30)).map_err(|e| e.to_string())?;
            if mode == OpenMode::ReadOnly {
                conn.execute_batch("PRAGMA query_only=ON;").map_err(|e| e.to_string())?;
            } else {
                conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;").map_err(|e| e.to_string())?;
            }
            Ok(Db::Sqlite(std::sync::Mutex::new(conn)))
        }
    }
    /// Wrap the Durable Object SQLite handle used by the Workers deployment.
    #[cfg(target_arch = "wasm32")]
    pub async fn from_do_sql(storage: worker::Storage) -> Result<Self, String> {
        let db = Db::DoSqlite(std::rc::Rc::new(storage.sql()), std::rc::Rc::new(storage)); db.migrate().await?; Ok(db)
    }
    /// Cheap clone of the Durable Object SQL handle for deferred work.
    #[cfg(target_arch = "wasm32")]
    pub fn clone_handle(&self) -> Db { match self { Db::DoSqlite(s, storage) => Db::DoSqlite(s.clone(), storage.clone()) } }
    #[allow(dead_code)]
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        let db = Db::Sqlite(std::sync::Mutex::new(conn)); db.migrate().await?; Ok(db)
    }
    pub async fn exec(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => { let conn = c.lock().unwrap(); exec_sqlite(&conn, sql, params) }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                client.execute(sql2.as_str(), &refs[..]).await.map_err(pg_err)
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(s, _) => {
                let cursor = s.exec(&sqlite_sql(sql), do_binds(params)).map_err(|e| e.to_string())?;
                Ok(cursor.rows_written() as u64)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
                let sql2 = mysql_sql(sql);
                // Schema statements go over the text protocol; the binary
                // protocol prepares them, which DDL does not uniformly support.
                if sql2.starts_with("CREATE ") || sql2.starts_with("ALTER ") || sql2.starts_with("DROP ") {
                    client.query_drop(sql2.as_str()).await.map_err(|e| e.to_string())?;
                    return Ok(0); }
                let mut result = client.exec_iter(sql2.as_str(), mysql_params(params)).await.map_err(|e| e.to_string())?;
                // Reading the result set populates the OK packet behind affected_rows().
                let _rows: Vec<mysql_async::Row> = result.collect().await.map_err(|e| e.to_string())?;
                Ok(result.affected_rows())
            }
        }
    }
    /// Execute one statement without placeholder translation. Migrations use
    /// this so a literal `?` in SQL text is never rewritten as `$1`.
    pub async fn exec_raw(&self, sql: &str) -> Result<(), String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => { let conn = c.lock().unwrap(); conn.execute_batch(sql).map_err(|e| e.to_string()) }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                client.batch_execute(sql).await.map_err(pg_err)
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(s, _) => { s.exec(sql, do_binds(&[])).map_err(|e| e.to_string())?; Ok(()) }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
                client.query_drop(mysql_sql(sql)).await.map_err(|e| e.to_string())
            }
        }
    }
    /// Apply a migration in one transaction where the backend supports it.
    /// MySQL commits DDL implicitly, so `script_is_atomic` is false there.
    pub async fn exec_script(&self, statements: &[String]) -> Result<(), String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => {
                let conn = c.lock().unwrap();
                conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| e.to_string())?;
                for statement in statements {
                    if let Err(e) = conn.execute_batch(statement) { let _ = conn.execute_batch("ROLLBACK"); return Err(e.to_string()); }
                }
                if let Err(error) = conn.execute_batch("COMMIT") { let _ = conn.execute_batch("ROLLBACK"); return Err(error.to_string()); }
                Ok(())
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let mut client = pool.get().await.map_err(|e| e.to_string())?;
                let tx = client.transaction().await.map_err(pg_err)?;
                for statement in statements { tx.batch_execute(statement).await.map_err(pg_err)?; }
                tx.commit().await.map_err(pg_err)
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(s, _) => {
                // The object serialises events and the handle is synchronous, so
                // a sequential script cannot interleave with another request.
                for statement in statements { s.exec(statement, do_binds(&[])).map_err(|e| e.to_string())?; }
                Ok(())
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
                client.query_drop("START TRANSACTION").await.map_err(|e| e.to_string())?;
                for statement in statements {
                    if let Err(e) = client.query_drop(mysql_sql(statement)).await {
                        let _ = client.query_drop("ROLLBACK").await;
                        return Err(e.to_string());
                    }
                }
                client.query_drop("COMMIT").await.map_err(|e| e.to_string())
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn script_is_atomic(&self) -> bool { matches!(self.backend(), Backend::Sqlite | Backend::Postgres) }
    #[cfg(target_arch = "wasm32")]
    pub fn script_is_atomic(&self) -> bool { false }
    pub async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        self.query_inner(sql, params, true).await
    }
    pub(crate) async fn query_raw(&self, sql: &str) -> Result<Vec<Row>, String> {
        self.query_inner(sql, &[], false).await
    }
    async fn query_inner(&self, sql: &str, params: &[Value], translate: bool) -> Result<Vec<Row>, String> {
        #[cfg(target_arch = "wasm32")]
        let _ = translate;
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => { let conn = c.lock().unwrap(); query_sqlite(&conn, sql, params) }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                let sql2 = if translate { pg_sql(sql) } else { sql.to_string() }; let pg = PgParams::new(params); let refs = pg.refs();
                let rows = client.query(sql2.as_str(), &refs[..]).await.map_err(pg_err)?;
                let mut out = Vec::new();
                for r in &rows {
                    let mut m = Row::new();
                    for (i, col) in r.columns().iter().enumerate() {
                        let v: Value = if let Ok(v) = r.try_get::<_, Option<String>>(i) { v.map(Value::String).unwrap_or(Value::Null) }
                            else if let Ok(v) = r.try_get::<_, Option<i64>>(i) { v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null) }
                            else if let Ok(v) = r.try_get::<_, Option<bool>>(i) { v.map(Value::Bool).unwrap_or(Value::Null) }
                            else if let Ok(v) = r.try_get::<_, Option<Value>>(i) { v.unwrap_or(Value::Null) }
                            else { Value::Null };
                        m.insert(col.name().to_string(), v);
                    }
                    out.push(m);
                }
                Ok(out)
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(s, _) => {
                let cursor = s.exec(&sqlite_sql(sql), do_binds(params)).map_err(|e| e.to_string())?;
                let cols = cursor.column_names();
                let mut out = Vec::new();
                for row in cursor.raw() {
                    let values = row.map_err(|e| e.to_string())?;
                    let mut m = Row::new();
                    for (i, v) in values.into_iter().enumerate() {
                        if let Some(name) = cols.get(i) { m.insert(name.clone(), do_value(v)); }
                    }
                    out.push(m);
                }
                Ok(out)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
                let sql2 = mysql_sql(sql);
                let rows = client.exec::<mysql_async::Row, _, _>(sql2.as_str(), mysql_params(params)).await.map_err(|e| e.to_string())?;
                let mut out = Vec::new();
                for r in &rows {
                    let mut m = Row::new();
                    for (i, col) in r.columns_ref().iter().enumerate() { m.insert(col.name_str().to_string(), mysql_value(r.as_ref(i))); }
                    out.push(m);
                }
                Ok(out)
            }
        }
    }
    pub async fn one(&self, sql: &str, params: &[Value]) -> Result<Option<Row>, String> { Ok(self.query(sql, params).await?.into_iter().next()) }
    pub async fn tx(&self, statements: &[(&str, Vec<Value>)]) -> Result<Vec<u64>, String> { self.tx_checked(statements, &[]).await }
    pub async fn tx_checked(&self, statements: &[(&str, Vec<Value>)], expect: &[(usize, u64)]) -> Result<Vec<u64>, String> {
        self.tx_locked("SELECT 1 AS guard", &[], |_| true, statements, expect).await
    }
    /// The row predicate and writes share one transaction; cancellation drops the native transaction guards.
    pub async fn tx_locked<F>(&self, lock_sql: &str, lock_params: &[Value], ok: F, statements: &[(&str, Vec<Value>)], expect: &[(usize, u64)]) -> Result<Vec<u64>, String>
    where F: Fn(&Row) -> bool + Send + Sync {
        let verify = |index: usize, count: u64| match expect.iter().find(|(i, _)| *i == index) {
            Some((_, want)) if count != *want => Err(format!("statement {} affected {} rows, expected {}", index, count, want)), _ => Ok(()) };
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => {
                let mut conn = c.lock().unwrap();
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
                let rows = query_sqlite(&tx, lock_sql, lock_params)?;
                if !rows.first().map(&ok).unwrap_or(false) { return Err("lock condition failed".into()); }
                let mut counts = Vec::with_capacity(statements.len());
                for (index, (sql, params)) in statements.iter().enumerate() { let count = exec_sqlite(&tx, sql, params)?; verify(index, count)?; counts.push(count); }
                tx.commit().map_err(|e| e.to_string())?; Ok(counts)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let mut client = pool.get().await.map_err(|e| e.to_string())?;
                let tx = client.transaction().await.map_err(pg_err)?;
                let sql = pg_sql(&format!("{} FOR UPDATE", lock_sql)); let params = PgParams::new(lock_params); let refs = params.refs();
                let rows = tx.query(sql.as_str(), &refs).await.map_err(pg_err)?;
                if !rows.first().map(pg_row).as_ref().map(&ok).unwrap_or(false) { return Err("lock condition failed".into()); }
                let mut counts = Vec::with_capacity(statements.len());
                for (index, (sql, params)) in statements.iter().enumerate() {
                    let sql = pg_sql(sql); let params = PgParams::new(params); let refs = params.refs();
                    let count = tx.execute(sql.as_str(), &refs).await.map_err(pg_err)?; verify(index, count)?; counts.push(count); }
                tx.commit().await.map_err(pg_err)?; Ok(counts)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
                let mut opts = mysql_async::TxOpts::default(); opts.with_isolation_level(mysql_async::IsolationLevel::ReadCommitted);
                let mut tx = client.start_transaction(opts).await.map_err(|e| e.to_string())?;
                let result = async {
                    let sql = mysql_sql(&format!("{} FOR UPDATE", lock_sql));
                    let rows: Vec<mysql_async::Row> = tx.exec(sql.as_str(), mysql_params(lock_params)).await.map_err(|e| e.to_string())?;
                    if !rows.first().map(mysql_row).as_ref().map(&ok).unwrap_or(false) { return Err("lock condition failed".into()); }
                    let mut counts = Vec::with_capacity(statements.len());
                    for (index, (sql, params)) in statements.iter().enumerate() {
                        tx.exec_drop(mysql_sql(sql), mysql_params(params)).await.map_err(|e| e.to_string())?;
                        let count = tx.affected_rows(); verify(index, count)?; counts.push(count); }
                    Ok(counts)
                }.await;
                match result { Ok(counts) => { tx.commit().await.map_err(|e| e.to_string())?; Ok(counts) }, Err(e) => { let _ = tx.rollback().await; Err(e) } }
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(sql, storage) => {
                use worker::wasm_bindgen::{closure::ScopedClosure, JsCast, JsValue};
                let raw: &JsValue = storage.as_raw().as_ref();
                let transaction = js_sys::Reflect::get(raw, &JsValue::from_str("transactionSync")).map_err(|e| worker::Error::from(e).to_string())?
                    .dyn_into::<js_sys::Function>().map_err(|_| "Durable Object transactionSync is unavailable".to_string())?;
                let mut counts = Vec::with_capacity(statements.len());
                let mut run = || -> Result<JsValue, JsValue> {
                    let convert = |e: String| JsValue::from_str(&e);
                    let cursor = sql.exec(&sqlite_sql(lock_sql), do_binds(lock_params)).map_err(|e| convert(e.to_string()))?;
                    let cols = cursor.column_names(); let mut rows = Vec::new();
                    for row in cursor.raw() { let mut r = Row::new(); for (i, v) in row.map_err(|e| convert(e.to_string()))?.into_iter().enumerate() { if let Some(name) = cols.get(i) { r.insert(name.clone(), do_value(v)); } } rows.push(r); }
                    if !rows.first().map(&ok).unwrap_or(false) { return Err(convert("lock condition failed".into())); }
                    for (index, (statement, params)) in statements.iter().enumerate() {
                        let cursor = sql.exec(&sqlite_sql(statement), do_binds(params)).map_err(|e| convert(e.to_string()))?;
                        for row in cursor.raw() { row.map_err(|e| convert(e.to_string()))?; }
                        let changes: Value = sql.exec("SELECT changes() AS affected", None).map_err(|e| convert(e.to_string()))?.one().map_err(|e| convert(e.to_string()))?;
                        let count = changes["affected"].as_u64().ok_or_else(|| convert("missing affected row count".into()))?;
                        verify(index, count).map_err(convert)?; counts.push(count);
                    }
                    Ok(JsValue::UNDEFINED)
                };
                let callback = ScopedClosure::borrow_mut_aborting(&mut run);
                transaction.call1(raw, callback.as_ref()).map_err(|e| worker::Error::from(e).to_string())?;
                drop(callback); Ok(counts)
            }
        }
    }
    /// Insert a meta row unless the key exists; true when this call created it.
    /// MySQL has no ON CONFLICT, so a duplicate key there is the expected losing
    /// branch while every other driver error still fails the caller.
    pub async fn insert_if_absent(&self, k: &str, v: &str) -> Result<bool, String> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Db::Mysql(pool) = self {
            let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
            return match client.exec_drop("INSERT INTO meta(k,v) VALUES(?,?)", mysql_params(&[json!(k), json!(v)])).await {
                Ok(()) => Ok(true),
                Err(mysql_async::Error::Server(e)) if e.code == 1062 => Ok(false),
                Err(e) => Err(e.to_string()),
            };
        }
        #[cfg(target_arch = "wasm32")]
        {
            let Db::DoSqlite(s, _) = self;
            s.exec("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO NOTHING", do_binds(&[json!(k), json!(v)])).map_err(|e| e.to_string())?;
            let changes: Value = s.exec("SELECT changes() AS n", None).map_err(|e| e.to_string())?.one().map_err(|e| e.to_string())?;
            Ok(changes["n"].as_u64() == Some(1))
        }
        #[cfg(not(target_arch = "wasm32"))]
        { Ok(self.exec("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO NOTHING", &[json!(k), json!(v)]).await? == 1) }    }
    pub async fn rate_increment(&self, key: &str, current: i64, window: i64) -> Result<i64, String> {
        let cutoff = current - window;
        #[cfg(not(target_arch = "wasm32"))]
        if let Db::Mysql(pool) = self {
            let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
            let mut tx = client.start_transaction(mysql_async::TxOpts::default()).await.map_err(|e| e.to_string())?;
            let result = async {
                tx.exec_drop("INSERT INTO rate_limits(`key`,window_start,count) VALUES(?,?,1) ON DUPLICATE KEY UPDATE count=IF(window_start<=?,1,count+1),window_start=IF(window_start<=?,?,window_start)", mysql_params(&[serde_json::json!(key),serde_json::json!(current),serde_json::json!(cutoff),serde_json::json!(cutoff),serde_json::json!(current)])).await.map_err(|e| e.to_string())?;
                // Keep the upsert's row lock until its count has been read.
                let count: Option<i64> = tx.exec_first("SELECT count FROM rate_limits WHERE `key`=?", (key,)).await.map_err(|e| e.to_string())?;
                count.ok_or_else(|| "rate counter unavailable".to_string())
            }.await;
            return match result {
                Ok(count) => { tx.commit().await.map_err(|e| e.to_string())?; Ok(count) },
                Err(e) => { let _ = tx.rollback().await; Err(e) },
            };
        }
        let row = self.one("INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN rate_limits.window_start<=? THEN 1 ELSE rate_limits.count+1 END,window_start=CASE WHEN rate_limits.window_start<=? THEN ? ELSE rate_limits.window_start END RETURNING count", &[serde_json::json!(key),serde_json::json!(current),serde_json::json!(cutoff),serde_json::json!(cutoff),serde_json::json!(current)]).await?.ok_or("rate counter unavailable")?;
        row.get("count").and_then(Value::as_i64).ok_or_else(|| "invalid rate counter".to_string())
    }
    /// Execute several statements atomically, optionally requiring one affected row.
    pub async fn batch(&self, statements: &[(String, Vec<Value>)]) -> Result<(), String> {
        self.batch_checked(statements, &[]).await
    }
    pub async fn batch_checked(&self, statements: &[(String, Vec<Value>)], require_one: &[usize]) -> Result<(), String> {
        let expected: Vec<Option<u64>> = (0..statements.len()).map(|index| require_one.contains(&index).then_some(1)).collect();
        self.batch_expected(statements, &expected, false).await
    }
    async fn batch_expected(&self, statements: &[(String, Vec<Value>)], expected: &[Option<u64>], lock_secrets: bool) -> Result<(), String> {
        #[cfg(not(target_arch = "wasm32"))]
        let checked = |index: usize, rows: u64| {
            if expected[index].is_some_and(|n| n != rows) { Err("version conflict: concurrent secret change".to_string()) } else { Ok(()) }
        };
        #[cfg(target_arch = "wasm32")]
        let _ = lock_secrets;
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => {
                let mut conn = c.lock().unwrap();
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
                for (index, (sql, params)) in statements.iter().enumerate() {
                    checked(index, exec_sqlite(&tx, sql, params)?)?;
                }
                // rusqlite rolls back on drop, including a failed commit.
                tx.commit().map_err(|e| e.to_string())
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let mut client = pool.get().await.map_err(|e| e.to_string())?;
                let result = async {
                    let tx = client.transaction().await.map_err(|e| e.to_string())?;
                    if lock_secrets { tx.batch_execute("LOCK TABLE secrets IN SHARE ROW EXCLUSIVE MODE").await.map_err(pg_err)?; }
                    for (index, (sql, params)) in statements.iter().enumerate() {
                        let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                        checked(index, tx.execute(sql2.as_str(), &refs[..]).await.map_err(pg_err)?)?;
                    }
                    tx.commit().await.map_err(pg_err)
                }.await;
                if result.is_err() { let _ = client.batch_execute("ROLLBACK").await; }
                result
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
                let mut opts = mysql_async::TxOpts::default();
                if lock_secrets { opts.with_isolation_level(mysql_async::IsolationLevel::RepeatableRead); }
                let mut tx = client.start_transaction(opts).await.map_err(|e| e.to_string())?;
                if lock_secrets {
                    // InnoDB next-key locks cover existing rows and insertion gaps without an implicit DDL commit.
                    if let Err(e) = tx.query::<mysql_async::Row, _>("SELECT id FROM secrets FOR UPDATE").await {
                        let _ = tx.rollback().await; return Err(e.to_string());
                    }
                }
                for (index, (sql, params)) in statements.iter().enumerate() {
                    let sql2 = mysql_sql(sql);
                    let result = async {
                        tx.exec_drop(sql2.as_str(), mysql_params(params)).await.map_err(|e| e.to_string())?;
                        checked(index, tx.affected_rows())
                    }.await;
                    if let Err(e) = result { let _ = tx.rollback().await; return Err(e); }
                }
                let result = tx.commit().await.map_err(|e| e.to_string());
                if result.is_err() { let _ = client.query_drop("ROLLBACK").await; }
                result
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(s, storage) => {
                use worker::wasm_bindgen::{closure::Closure, JsCast, JsValue};
                let raw: &JsValue = storage.as_raw().as_ref();
                let transaction = js_sys::Reflect::get(raw, &JsValue::from_str("transactionSync"))
                    .map_err(|e| worker::Error::from(e).to_string())?
                    .dyn_into::<js_sys::Function>().map_err(|_| "Durable Object transactionSync is unavailable".to_string())?;
                let sql = s.clone(); let statements = statements.to_vec(); let expected = expected.to_vec();
                // Returning Err throws into transactionSync so the runtime rolls back SQL writes.
                let callback = Closure::wrap(Box::new(move || -> Result<JsValue, JsValue> {
                    for (index, (statement, params)) in statements.iter().enumerate() {
                        let cursor = sql.exec(&sqlite_sql(statement), do_binds(params)).map_err(|e| JsValue::from_str(&e.to_string()))?;
                        for row in cursor.raw() { row.map_err(|e| JsValue::from_str(&e.to_string()))?; }
                        if let Some(count) = expected[index] {
                            // rowsWritten includes index writes; changes() counts affected table rows.
                            let changes: Value = sql.exec("SELECT changes() AS affected", None).map_err(|e| JsValue::from_str(&e.to_string()))?
                                .one().map_err(|e| JsValue::from_str(&e.to_string()))?;
                            if changes["affected"].as_u64() != Some(count) {
                                return Err(JsValue::from_str("version conflict: concurrent secret change"));
                            }
                        }
                    }
                    Ok(JsValue::UNDEFINED)
                }) as Box<dyn FnMut() -> Result<JsValue, JsValue>>);
                transaction.call1(raw, callback.as_ref()).map(|_| ()).map_err(|e| worker::Error::from(e).to_string())
            }
        }
    }
    // Serialize rotation claims and destructive cleanup on the same database row.
    pub async fn rotation_batch(&self, blocked: &str, params: &[Value], statements: &[(String,Vec<Value>)]) -> Result<bool,String> {
        self.rotation_batch_checked(blocked, params, statements, &[]).await
    }
    pub async fn rotation_batch_checked(&self, blocked: &str, params: &[Value], statements: &[(String,Vec<Value>)], require_one: &[usize]) -> Result<bool,String> {
        #[cfg(not(target_arch = "wasm32"))]
        let checked = |index: usize, rows: u64| {
            if require_one.contains(&index) && rows != 1 { Err("version conflict: concurrent lifecycle change".to_string()) } else { Ok(()) }
        };
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => {
                let mut conn=c.lock().unwrap(); let tx=conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
                if !query_sqlite(&tx,blocked,params)?.is_empty() { return Ok(false); }
                for (index,(sql,p)) in statements.iter().enumerate() { checked(index,exec_sqlite(&tx,sql,p)?)?; }
                tx.commit().map_err(|e| e.to_string())?; Ok(true)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let mut client=pool.get().await.map_err(|e| e.to_string())?; let tx=client.transaction().await.map_err(pg_err)?;
                tx.query_one("SELECT v FROM meta WHERE k='rotation_lifecycle' FOR UPDATE",&[]).await.map_err(pg_err)?;
                let pg=PgParams::new(params); let refs=pg.refs();
                if !tx.query(pg_sql(blocked).as_str(),&refs).await.map_err(pg_err)?.is_empty() { return Ok(false); }
                for (index,(sql,p)) in statements.iter().enumerate() { let pg=PgParams::new(p); let refs=pg.refs(); checked(index,tx.execute(pg_sql(sql).as_str(),&refs).await.map_err(pg_err)?)?; }
                tx.commit().await.map_err(pg_err)?; Ok(true)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let mut client=pool.get_conn().await.map_err(|e| e.to_string())?;
                let mut tx=client.start_transaction(mysql_async::TxOpts::default()).await.map_err(|e| e.to_string())?;
                let result = async {
                    let _: Option<String> = tx.query_first("SELECT v FROM meta WHERE k='rotation_lifecycle' FOR UPDATE").await.map_err(|e| e.to_string())?;
                    let rows: Vec<mysql_async::Row> = tx.exec(mysql_sql(blocked),mysql_params(params)).await.map_err(|e| e.to_string())?;
                    if !rows.is_empty() { return Ok(false); }
                    for (index,(sql,p)) in statements.iter().enumerate() {
                        tx.exec_drop(mysql_sql(sql),mysql_params(p)).await.map_err(|e| e.to_string())?;
                        checked(index,tx.affected_rows())?;
                    }
                    Ok(true)
                }.await;
                match result { Ok(true) => { tx.commit().await.map_err(|e| e.to_string())?; Ok(true) }, other => { let _ = tx.rollback().await; other } }
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(_, _) => {
                if !self.query(blocked,params).await?.is_empty() { return Ok(false); }
                self.batch_checked(statements,require_one).await?; Ok(true)
            }
        }
    }
    /// Checked mutations roll back together; secret snapshot guards additionally lock out normal writers.
    pub async fn checked_batch(&self, statements: &[(String, Vec<Value>, Option<u64>)], lock_secrets: bool) -> Result<(), String> {
        let expected: Vec<Option<u64>> = statements.iter().map(|(_, _, count)| *count).collect();
        let statements: Vec<(String, Vec<Value>)> = statements.iter().map(|(sql, params, _)| (sql.clone(), params.clone())).collect();
        self.batch_expected(&statements, &expected, lock_secrets).await
            .map_err(|e| if e.contains("version conflict") { "checked transaction conflict".into() } else { e })
    }
    /// True when the database holds tables outside the migration ledger and
    /// its lock. A pre-engine database has application tables but no ledger,
    /// so the migration runner must refuse to squash its baseline. System,
    /// extension bookkeeping and D1 internal tables are not application schema.
    pub async fn has_application_schema(&self) -> Result<bool, String> {
        // SQLite, the Durable Object handle and D1 all answer from sqlite_master.
        #[cfg(target_arch = "wasm32")]
        let sql = "SELECT name FROM sqlite_master WHERE type='table' \
                   AND substr(name,1,7)<>'sqlite_' AND substr(name,1,4)<>'_cf_' AND substr(name,1,3)<>'d1_' \
                   AND name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1";        #[cfg(not(target_arch = "wasm32"))]
        let sql = match self {
            Db::Sqlite(_) => "SELECT name FROM sqlite_master WHERE type='table' \
                              AND substr(name,1,7)<>'sqlite_' \
                              AND name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
            Db::Postgres(_) => "SELECT table_name AS name FROM information_schema.tables \
                                WHERE table_schema=current_schema() \
                                AND table_type='BASE TABLE' \
                                AND table_name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
            Db::Mysql(_) => "SELECT table_name AS name FROM information_schema.tables \
                             WHERE table_schema=DATABASE() AND table_type='BASE TABLE' \
                             AND table_name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
        };
        Ok(!self.query(sql, &[]).await?.is_empty())
    }
    pub async fn version(&self) -> Result<i64, String> {
        // A ledger written before the engine has no success column and every
        // row in it applied; the engine's own ledger marks interrupted rows.
        match self.one("SELECT COALESCE(MAX(version),0) AS version FROM schema_migrations WHERE success=1", &[]).await {
            Ok(row) => Ok(row.map(|r| n(&r, "version")).unwrap_or(0)),
            Err(_) => Ok(self.one("SELECT COALESCE(MAX(version),0) AS version FROM schema_migrations", &[]).await?.map(|r| n(&r, "version")).unwrap_or(0)),
        } }
    async fn migrate(&self) -> Result<(), String> { crate::migrate::run(self).await }
}

#[cfg(target_arch = "wasm32")]
impl Db {
    /// Constructor for the Durable Object. Migrations run synchronously because
    /// the object constructor cannot await, and every storage call in that path
    /// resolves without yielding.
    pub fn from_do_sql_now(storage: worker::Storage) -> Result<Self, String> {
        let db = Db::DoSqlite(std::rc::Rc::new(storage.sql()), std::rc::Rc::new(storage));
        crate::migrate::wait(db.migrate())?;
        Ok(db)
    }
    /// Workers entrypoint variant of from_do_sql_now; both apply the numbered
    /// migrations synchronously through the shared engine.
    pub fn from_do_storage_now(storage: worker::Storage) -> Result<Self, String> {
        let db = Db::DoSqlite(std::rc::Rc::new(storage.sql()), std::rc::Rc::new(storage));
        crate::migrate::wait(db.migrate())?;
        Ok(db)
    }
    /// Synchronous exec for callers that cannot hold a future across a borrow,
    /// such as the risaml replay cache. Mirrors the async DoSqlite exec arm.
    pub(crate) fn exec_sync(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        let Db::DoSqlite(s, _) = self;
        let cursor = s.exec(&sqlite_sql(sql), do_binds(params)).map_err(|e| e.to_string())?;
        Ok(cursor.rows_written() as u64)
    }
}

#[cfg(target_arch = "wasm32")]
fn do_binds(params: &[Value]) -> Option<Vec<worker::SqlStorageValue>> {
    if params.is_empty() { return None; }
    Some(params.iter().map(|v| match v {
        Value::Null => worker::SqlStorageValue::Null,
        Value::Bool(b) => worker::SqlStorageValue::Integer(if *b { 1 } else { 0 }),
        Value::Number(n) => match n.as_i64() { Some(i) => worker::SqlStorageValue::Integer(i), None => worker::SqlStorageValue::Float(n.as_f64().unwrap_or(0.0)) },
        Value::String(s) => worker::SqlStorageValue::String(s.clone()),
        other => worker::SqlStorageValue::String(other.to_string()),
    }).collect())
}

#[cfg(target_arch = "wasm32")]
fn do_value(v: worker::SqlStorageValue) -> Value {
    match v {
        worker::SqlStorageValue::Null => Value::Null,
        worker::SqlStorageValue::Boolean(b) => Value::Bool(b),
        worker::SqlStorageValue::Integer(i) => Value::Number(i.into()),
        worker::SqlStorageValue::Float(f) => serde_json::json!(f),
        worker::SqlStorageValue::String(s) => Value::String(s),
        worker::SqlStorageValue::Blob(b) => Value::String(openwarp_crypto::b64(&b)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
enum PgOwned { S(String), I(i64), B(bool), N(Option<String>) }
#[cfg(not(target_arch = "wasm32"))]
struct PgParams { owned: Vec<PgOwned> }
#[cfg(not(target_arch = "wasm32"))]
impl PgParams {
    fn new(params: &[Value]) -> Self { Self { owned: params.iter().map(|v| match v { Value::String(s) => PgOwned::S(s.clone()), Value::Number(n) => PgOwned::I(n.as_i64().unwrap_or(0)), Value::Bool(b) => PgOwned::B(*b), _ => PgOwned::N(None) }).collect() } }
    fn refs(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> { self.owned.iter().map(|o| -> &(dyn tokio_postgres::types::ToSql + Sync) { match o { PgOwned::S(s) => s, PgOwned::I(n) => n, PgOwned::B(b) => b, PgOwned::N(n) => n } }).collect() }
}
#[cfg(not(target_arch = "wasm32"))]
fn sqlite_val(v: &rusqlite::types::Value) -> Value {
    use rusqlite::types::Value as V;
    match v { V::Null => Value::Null, V::Integer(n) => Value::Number((*n).into()), V::Real(f) => serde_json::json!(*f), V::Text(s) => Value::String(s.clone()), V::Blob(b) => Value::String(openwarp_crypto::b64(b)) }
}
#[cfg(not(target_arch = "wasm32"))]
fn exec_sqlite(conn: &rusqlite::Connection, sql: &str, params: &[Value]) -> Result<u64, String> {
    let sql = sqlite_sql(sql);
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let n = stmt.execute(rusqlite::params_from_iter(params.iter().map(sqlite_param))).map_err(|e| e.to_string())?;
    Ok(n as u64)
}
#[cfg(not(target_arch = "wasm32"))]
fn query_sqlite(conn: &rusqlite::Connection, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
    let sql = sqlite_sql(sql);
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter().map(sqlite_param))).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let mut m = Row::new();
        for (i, c) in cols.iter().enumerate() { let v: rusqlite::types::Value = r.get(i).map_err(|e| e.to_string())?; m.insert(c.clone(), sqlite_val(&v)); }
        out.push(m);
    }
    Ok(out)
}
#[cfg(not(target_arch = "wasm32"))]
fn sqlite_param(v: &Value) -> SqliteParam { SqliteParam(v.clone()) }
#[cfg(not(target_arch = "wasm32"))]
struct SqliteParam(Value);
#[cfg(not(target_arch = "wasm32"))]
impl rusqlite::ToSql for SqliteParam {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, Value as V};
        Ok(match &self.0 { Value::Null => ToSqlOutput::Owned(V::Null), Value::String(s) => ToSqlOutput::Owned(V::Text(s.clone())), Value::Number(n) => ToSqlOutput::Owned(V::Integer(n.as_i64().unwrap_or(0))), Value::Bool(b) => ToSqlOutput::Owned(V::Integer(if *b {1} else {0})), other => ToSqlOutput::Owned(V::Text(other.to_string())) })
    }
}
// --- MySQL/MariaDB dialect (native only) ---
// The canonical DDL is SQLite/PostgreSQL shaped. MySQL cannot key or index a
// TEXT column without a prefix length, rejects literal defaults on TEXT before
// 8.0.13, and compares text case-insensitively by default, so only this backend
// rewrites the statements. A Workers build stores in the Durable Object instead.
#[cfg(not(target_arch = "wasm32"))]
fn mysql_sql(sql: &str) -> String {
    if sql.starts_with("CREATE TABLE") { return mysql_create_table(sql) }
    if sql.starts_with("CREATE INDEX") || sql.starts_with("CREATE UNIQUE INDEX") { return sql.replacen("IF NOT EXISTS ", "", 1) }
    if sql.starts_with("ALTER TABLE") { return mysql_alter_table(sql) }
    // `key` is reserved in MySQL. Quote only the column positions the schema
    // uses, so a future `key_enc` or a joined alias is not rewritten.
    if sql.contains("rate_limits") || sql.contains("saml_replay") || sql.contains("workload_replay") {
        return sql.replace("(key,", "(`key`,").replace("WHERE key=", "WHERE `key`=").replace("SELECT key,", "SELECT `key`,") }
    sql.replace("OW_NOW()", "UNIX_TIMESTAMP()") }
#[cfg(not(target_arch = "wasm32"))]
fn split_sql_list(s: &str) -> Vec<&str> {
    let mut out = Vec::new(); let mut depth = 0i32; let mut quoted = false; let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => { out.push(&s[start..i]); start = i + 1; }
            _ => {} } }
    out.push(&s[start..]); out }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_index_target(sql: &str) -> Option<(String, Vec<String>)> {
    if !(sql.starts_with("CREATE INDEX") || sql.starts_with("CREATE UNIQUE INDEX")) { return None }
    let rest = &sql[sql.rfind(" ON ")? + 4..];
    let (table, cols) = rest.split_once('(')?;
    Some((table.trim().to_string(), cols.trim_end_matches(')').split(',').map(|c| c.trim().to_string()).filter(|c| c != "*").collect())) }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_indexed_columns() -> HashMap<String, Vec<String>> {
    // Indexed TEXT columns become VARCHAR on MySQL, so the rewriter needs the
    // column list from every CREATE INDEX and PRIMARY KEY in the manifest.
    static CACHE: std::sync::OnceLock<HashMap<String, Vec<String>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for sql in crate::migrate::all_statements() {
            if let Some((table, cols)) = mysql_index_target(&sql) { out.entry(table).or_default().extend(cols); }
        }
        out
    }).clone() }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_column_def(seg: &str, keyed: &[String]) -> String {
    let t = seg.trim();
    let upper = t.to_ascii_uppercase();
    if upper.starts_with("PRIMARY KEY") || upper.starts_with("UNIQUE") || upper.starts_with("FOREIGN KEY") || upper.starts_with("CHECK") || upper.starts_with("CONSTRAINT") { return t.to_string() }
    // A table-level `KEY name (cols)` carries a column list; a column named
    // `key` does not, so the parenthesis keeps the two apart.
    if (upper.starts_with("KEY ") || upper.starts_with("INDEX ")) && t.contains('(') { return t.to_string() }
    let Some((name, rest)) = t.split_once(char::is_whitespace) else { return t.to_string() };
    let rest = rest.trim();
    if !rest.to_ascii_uppercase().starts_with("TEXT") { return format!("`{}` {}", name, rest) }
    let after = &rest[4..]; let after_upper = after.to_ascii_uppercase();
    if keyed.iter().any(|k| k == name) || after_upper.contains("PRIMARY KEY") || after_upper.contains("UNIQUE") { return format!("`{}` VARCHAR(255){}", name, after) }
    match after.split_once("DEFAULT ") {
        Some((pre, value)) => format!("`{}` TEXT{} DEFAULT ({})", name, pre.trim_end(), value.trim()),
        None => format!("`{}` TEXT{}", name, after) } }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_create_table(sql: &str) -> String {
    let Some(open) = sql.find('(') else { return sql.to_string() };
    let head = sql[..open].trim_end().to_string();
    let inner = sql[open + 1..].trim_end();
    let body = inner.strip_suffix(')').unwrap_or(inner);
    let table = head.rsplit(' ').next().unwrap_or("").to_string();
    let mut keyed = mysql_indexed_columns().remove(&table).unwrap_or_default();
    for seg in split_sql_list(body) {
        let t = seg.trim();
        if t.to_ascii_uppercase().starts_with("PRIMARY KEY") || t.to_ascii_uppercase().starts_with("UNIQUE") {
            if let (Some(a), Some(b)) = (t.find('('), t.rfind(')')) { for c in t[a + 1..b].split(',') { keyed.push(c.trim().to_string()); } } } }
    let cols: Vec<String> = split_sql_list(body).iter().map(|seg| mysql_column_def(seg, &keyed)).collect();
    format!("{}({}) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin", head, cols.join(",")) }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_alter_table(sql: &str) -> String {
    let Some((table, tail)) = sql.strip_prefix("ALTER TABLE ").and_then(|rest| rest.split_once(' ')) else { return sql.to_string() };
    let Some(definition) = tail.trim_start().strip_prefix("ADD COLUMN ") else { return sql.to_string() };
    let keyed = mysql_indexed_columns().remove(table).unwrap_or_default();
    format!("ALTER TABLE {} ADD COLUMN {}", table, mysql_column_def(definition, &keyed)) }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_value(v: Option<&mysql_async::Value>) -> Value {
    use mysql_async::Value as V;
    match v {
        None | Some(V::NULL) => Value::Null,
        Some(V::Bytes(b)) => Value::String(String::from_utf8_lossy(b).into_owned()),
        Some(V::Int(n)) => Value::Number((*n).into()),
        Some(V::UInt(n)) => Value::Number((*n).into()),
        Some(V::Float(f)) => serde_json::json!(*f as f64),
        Some(V::Double(f)) => serde_json::json!(*f),
        Some(V::Date(y, mo, d, h, mi, s, _)) => Value::String(format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)),
        Some(V::Time(neg, d, h, mi, s, _)) => Value::String(format!("{}{} {:02}:{:02}:{:02}", if *neg { "-" } else { "" }, d, h, mi, s)) } }
#[cfg(not(target_arch = "wasm32"))]
fn mysql_params(params: &[Value]) -> mysql_async::Params {
    use mysql_async::Value as V;
    mysql_async::Params::Positional(params.iter().map(|p| match p {
        Value::Null => V::NULL,
        Value::String(s) => V::Bytes(s.as_bytes().to_vec()),
        Value::Bool(b) => V::Int(if *b { 1 } else { 0 }),
        Value::Number(n) => match n.as_i64() { Some(i) => V::Int(i), None => V::Double(n.as_f64().unwrap_or(0.0)) },
        other => V::Bytes(other.to_string().into_bytes()) }).collect()) }
pub fn s(row: &Row, k: &str) -> String { row.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string() }
pub fn n(row: &Row, k: &str) -> i64 { row.get(k).and_then(|v| v.as_i64()).unwrap_or(0) }
pub fn obj(row: &Row) -> Value { let mut m = Map::new(); for (k, v) in row { m.insert(k.clone(), v.clone()); } Value::Object(m) }

#[cfg(test)]
mod tests {
    use super::*; use serde_json::json;
    #[tokio::test] async fn sqlite_migrate_and_crud() {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("o1"), json!("Acme"), json!(1)]).await.unwrap();
        let rows = db.query("SELECT name FROM orgs WHERE id=?", &[json!("o1")]).await.unwrap();
        assert_eq!(s(&rows[0], "name"), "Acme");
        // placeholder translation used by Postgres backend
        assert_eq!(pg_sql("SELECT * FROM t WHERE a=? AND b=?"), "SELECT * FROM t WHERE a=$1 AND b=$2");
    }
    #[tokio::test] async fn migrations_are_recorded_once() {
        let db = Db::open_memory().await.unwrap();
        assert_eq!(db.version().await.unwrap(), crate::migrate::MIGRATIONS.last().map(|m| m.version).unwrap_or(0), "a fresh database lands on the current version");
        db.migrate().await.unwrap();
        let row = db.one("SELECT COUNT(*) AS n FROM schema_migrations", &[]).await.unwrap().unwrap();
        assert_eq!(n(&row, "n"), 34, "each migration must be recorded exactly once");
        let squashed = db.one("SELECT COUNT(*) AS n FROM schema_migrations WHERE checksum='squashed'", &[]).await.unwrap().unwrap();
        assert_eq!(n(&squashed, "n"), 16, "the baseline replaces versions 2 through 17");
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test] fn mysql_ddl_rewrites_only_what_mysql_rejects() {
        let users = mysql_sql("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,pass_hash TEXT NOT NULL)");
        assert!(users.contains("`id` VARCHAR(255) PRIMARY KEY"), "{}", users);
        assert!(users.contains("`email` VARCHAR(255) UNIQUE NOT NULL"), "{}", users);
        assert!(users.contains("`pass_hash` TEXT NOT NULL"), "{}", users);
        assert!(users.ends_with("DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"), "{}", users);
        let secrets = mysql_sql("CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,path TEXT DEFAULT '/',value_enc TEXT NOT NULL)");
        assert!(secrets.contains("`env_id` VARCHAR(255) NOT NULL"), "an indexed column must be indexable: {}", secrets);
        assert!(secrets.contains("`path` TEXT DEFAULT ('/')"), "a TEXT default needs the expression form: {}", secrets);
        assert!(secrets.contains("`value_enc` TEXT NOT NULL"), "a value column must stay unbounded: {}", secrets);
        let rate = mysql_sql("CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY,count BIGINT NOT NULL)");
        assert!(rate.contains("`key` VARCHAR(255) PRIMARY KEY"), "a reserved word must be quoted: {}", rate);
        assert_eq!(mysql_sql("ALTER TABLE secrets ADD COLUMN value_fp TEXT DEFAULT ''"), "ALTER TABLE secrets ADD COLUMN `value_fp` VARCHAR(255) DEFAULT ''");
        assert_eq!(mysql_sql("ALTER TABLE envs ADD COLUMN mode TEXT DEFAULT 'sse'"), "ALTER TABLE envs ADD COLUMN `mode` TEXT DEFAULT ('sse')");
        assert_eq!(mysql_sql("CREATE INDEX IF NOT EXISTS idx_x ON secrets(env_id)"), "CREATE INDEX idx_x ON secrets(env_id)");
        assert_eq!(mysql_sql("INSERT INTO saml_replay(key,expires_at) VALUES(?,?)"), "INSERT INTO saml_replay(`key`,expires_at) VALUES(?,?)");
        assert_eq!(mysql_sql("SELECT count FROM rate_limits WHERE key=?"), "SELECT count FROM rate_limits WHERE `key`=?");
        assert_eq!(mysql_sql("INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,1) ON DUPLICATE KEY UPDATE count = IF(window_start <= ?, 1, count + 1)"), "INSERT INTO rate_limits(`key`,window_start,count) VALUES(?,?,1) ON DUPLICATE KEY UPDATE count = IF(window_start <= ?, 1, count + 1)");
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test] fn mysql_ddl_promotes_inline_unique_columns() {
        // The shipped receipt DDL, read from the migration files so the test
        // drifts with the shipped schema instead of a hand-written copy.
        let receipt = crate::migrate::MIGRATIONS.iter()
            .find(|m| m.sql.contains("CREATE TABLE IF NOT EXISTS webhook_receipts("))
            .map(|m| m.sql.split(';').map(str::trim).find(|s| s.starts_with("CREATE TABLE IF NOT EXISTS webhook_receipts(")).expect("the webhook migration defines webhook_receipts"))
            .expect("the webhook migration defines webhook_receipts");
        let ddl = mysql_sql(receipt);
        assert!(ddl.contains("`message_id` VARCHAR(255) NOT NULL"), "an inline UNIQUE column must be promoted to an indexable type: {}", ddl);
        assert!(ddl.contains("`webhook_id` VARCHAR(255) NOT NULL"), "{}", ddl);
        assert!(ddl.contains("UNIQUE(webhook_id,message_id)"), "the receipt uniqueness constraint must survive the rewrite: {}", ddl);
        // A generic table-level UNIQUE(a,b) promotes both TEXT columns, while an
        // unrelated payload column stays unbounded TEXT.
        let generic = mysql_sql("CREATE TABLE IF NOT EXISTS pair_dedup(id TEXT PRIMARY KEY,a TEXT NOT NULL,b TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(a,b))");
        assert!(generic.contains("`a` VARCHAR(255) NOT NULL"), "first inline UNIQUE column must be promoted: {}", generic);
        assert!(generic.contains("`b` VARCHAR(255) NOT NULL"), "second inline UNIQUE column must be promoted: {}", generic);
        assert!(generic.contains("`payload` TEXT NOT NULL"), "unbounded columns must stay TEXT: {}", generic);
        assert!(generic.contains("UNIQUE(a,b)"), "the uniqueness constraint must be preserved: {}", generic);
    }
}
