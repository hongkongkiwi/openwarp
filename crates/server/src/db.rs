use serde_json::{Map, Value};
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use mysql_async::prelude::Queryable;

pub type Row = HashMap<String, Value>;

/// Storage backend. Native builds use SQLite or a PostgreSQL pool; the Workers
/// build uses the synchronous SQLite handle of a Durable Object, which is
/// wrapped in async methods so call sites stay identical on both targets.
pub enum Db {
    #[cfg(not(target_arch = "wasm32"))]
    Sqlite(std::sync::Mutex<rusqlite::Connection>),
    #[cfg(not(target_arch = "wasm32"))]
    Postgres(deadpool_postgres::Pool),
    #[cfg(target_arch = "wasm32")]
    DoSqlite(std::rc::Rc<DoSqlite>),
    #[cfg(not(target_arch = "wasm32"))]
    Mysql(mysql_async::Pool),
}

#[cfg(target_arch = "wasm32")]
pub struct DoSqlite { sql: worker::SqlStorage, storage: Option<worker::Storage> }
#[cfg(target_arch = "wasm32")]
impl std::ops::Deref for DoSqlite {
    type Target = worker::SqlStorage;
    fn deref(&self) -> &Self::Target { &self.sql }
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

#[cfg(not(target_arch = "wasm32"))]
fn pg_sql(sql: &str) -> String {
    let mut out = String::new(); let mut n = 0;
    for c in sql.chars() { if c == '?' { n += 1; out.push_str(&format!("${}", n)); } else { out.push(c); } }
    out
}
#[cfg(not(target_arch = "wasm32"))]
fn pg_err(error: tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => db.message().to_string(),
        None => error.to_string(),
    }
}

impl Db {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn backend(&self) -> Backend { match self { Db::Sqlite(_) => Backend::Sqlite, Db::Postgres(_) => Backend::Postgres, Db::Mysql(_) => Backend::Mysql } }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open(url: &str) -> Result<Self, String> {
        // A scheme is case-insensitive in a URL; the drivers are not, so the
        // normalized form is what gets parsed.
        let (scheme, rest) = match url.split_once("://") { Some((s, r)) => (s.to_ascii_lowercase(), r), None => (String::new(), "") };
        if scheme == "postgres" || scheme == "postgresql" {
            let url = format!("{}://{}", scheme, rest);
            let config: tokio_postgres::Config = url.parse().map_err(|e| format!("invalid DATABASE_URL: {}", e))?;
            let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
            let size = std::env::var("OPENWARP_PG_POOL_SIZE").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(8).clamp(1, 64);
            let pool = deadpool_postgres::Pool::builder(manager).max_size(size).build().map_err(|e| format!("postgres pool: {}", e))?;
            let db = Db::Postgres(pool); db.migrate().await?; Ok(db)
        } else if scheme == "mysql" || scheme == "mariadb" {
            let url = format!("mysql://{}", rest);
            let opts = mysql_async::Opts::from_url(&url).map_err(|e| format!("invalid DATABASE_URL: {}", e))?;
            let size = std::env::var("OPENWARP_MYSQL_POOL_SIZE").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(8).clamp(1, 64);
            let constraints = mysql_async::PoolConstraints::new(1, size).ok_or("invalid mysql pool size")?;
            // Match PostgreSQL/SQLite affected-row semantics: callers compare the
            // count from UPDATE (leader election, rotation claims), and MySQL
            // otherwise reports changed rows only.
            let opts = mysql_async::OptsBuilder::from_opts(opts).client_found_rows(true).pool_opts(mysql_async::PoolOpts::default().with_constraints(constraints));
            let db = Db::Mysql(mysql_async::Pool::new(opts)); db.migrate().await?; Ok(db)
        } else {
            let path = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")).unwrap_or(url);
            let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;").map_err(|e| e.to_string())?;
            let db = Db::Sqlite(std::sync::Mutex::new(conn)); db.migrate().await?; Ok(db)
        }
    }
    /// Wrap the Durable Object SQLite handle used by the Workers deployment.
    #[cfg(target_arch = "wasm32")]
    pub async fn from_do_sql(storage: worker::SqlStorage) -> Result<Self, String> {
        let db = Db::DoSqlite(std::rc::Rc::new(DoSqlite { sql: storage, storage: None })); db.migrate().await?; Ok(db)
    }
    /// Cheap clone of the Durable Object SQL handle for deferred work.
    #[cfg(target_arch = "wasm32")]
    pub fn clone_handle(&self) -> Db { match self { Db::DoSqlite(s) => Db::DoSqlite(s.clone()) } }
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
            Db::DoSqlite(s) => {
                let cursor = s.exec(sql, do_binds(params)).map_err(|e| e.to_string())?;
                for row in cursor.raw() { row.map_err(|e| e.to_string())?; }
                let changes: Value = s.exec("SELECT changes() AS affected", None).map_err(|e| e.to_string())?.one().map_err(|e| e.to_string())?;
                Ok(changes["affected"].as_u64().unwrap_or(0))
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
    pub async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => { let conn = c.lock().unwrap(); query_sqlite(&conn, sql, params) }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
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
            Db::DoSqlite(s) => {
                let cursor = s.exec(sql, do_binds(params)).map_err(|e| e.to_string())?;
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
    /// Execute several statements atomically, optionally requiring one affected row.
    pub async fn batch(&self, statements: &[(String, Vec<Value>)]) -> Result<(), String> {
        self.batch_checked(statements, &[]).await
    }
    pub async fn batch_checked(&self, statements: &[(String, Vec<Value>)], require_one: &[usize]) -> Result<(), String> {
        #[cfg(not(target_arch = "wasm32"))]
        let checked = |index: usize, rows: u64| {
            if require_one.contains(&index) && rows != 1 { Err("version conflict: concurrent secret change".to_string()) } else { Ok(()) }
        };
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
                let mut tx = client.start_transaction(mysql_async::TxOpts::default()).await.map_err(|e| e.to_string())?;
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
            Db::DoSqlite(s) => { s.transaction_sync(statements, require_one) }
        }
    }
    pub fn master_rotation_supported(&self) -> bool {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(_) | Db::Mysql(_) => false,
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(_) => true,
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(s) => s.storage.is_some(),
        }
    }
    pub async fn version(&self) -> Result<i64, String> {
        Ok(self.one("SELECT COALESCE(MAX(version),0) AS version FROM schema_migrations", &[]).await?.map(|r| n(&r, "version")).unwrap_or(0)) }
    async fn migrate(&self) -> Result<(), String> {
        for stmt in SCHEMA { self.exec(stmt, &[]).await?; }
        for alter in [
            "ALTER TABLE envs ADD COLUMN mode TEXT DEFAULT 'sse'",
            "ALTER TABLE envs ADD COLUMN restricted BIGINT DEFAULT 0",
            "ALTER TABLE envs ADD COLUMN require_approval BIGINT DEFAULT 0",
            "ALTER TABLE secrets ADD COLUMN e2e BIGINT DEFAULT 0",
            "ALTER TABLE secrets ADD COLUMN deleted_at BIGINT DEFAULT 0",
            "ALTER TABLE users ADD COLUMN active BIGINT DEFAULT 1",
            "ALTER TABLE tokens ADD COLUMN kind TEXT DEFAULT 'human'",
            "ALTER TABLE tokens ADD COLUMN expires_at BIGINT DEFAULT 0",
            "ALTER TABLE leases ADD COLUMN username TEXT DEFAULT ''",
            "ALTER TABLE leases ADD COLUMN config_enc TEXT DEFAULT ''",
            "ALTER TABLE oidc_states ADD COLUMN nonce TEXT DEFAULT ''",
            "ALTER TABLE pki_cas ADD COLUMN serial TEXT DEFAULT ''",
            "ALTER TABLE rotation_schedules ADD COLUMN path TEXT DEFAULT '/'",
            "ALTER TABLE rotation_schedules ADD COLUMN config_enc TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN email_verified BIGINT DEFAULT 1",
        ] { let _ = self.exec(alter, &[]).await; }
        for idx in INDEXES { let _ = self.exec(idx, &[]).await; }
        // Record the baseline once, then apply numbered additive migrations.
        if self.one("SELECT version FROM schema_migrations WHERE version=1", &[]).await?.is_none() {
            let _ = self.exec("INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)", &[serde_json::json!(crate::clock::now())]).await;
        }
        for (version, statements) in MIGRATIONS {
            if self.one("SELECT version FROM schema_migrations WHERE version=?", &[serde_json::json!(version)]).await?.is_some() { continue; }
            for stmt in *statements {
                if let Err(e) = self.exec(stmt, &[]).await {
                    let message = e.to_ascii_lowercase();
                    let duplicate = message.contains("duplicate column") || message.contains("already exists") || message.contains("duplicate key name");
                    if !duplicate { return Err(format!("migration {} failed: {}", version, e)); }
                }
            }
            self.exec("INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", &[serde_json::json!(version), serde_json::json!(crate::clock::now())]).await?;
        }
        // One-time backfill: environments that already had an allowlist keep it.
        if self.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await?.is_none() {
            let _ = self.exec("UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)", &[]).await;
            let _ = self.exec("INSERT INTO meta(k,v) VALUES('migration:env_restricted',?)", &[serde_json::json!(crate::clock::now())]).await;
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
impl DoSqlite {
    fn transaction_sync(&self, statements: &[(String, Vec<Value>)], require_one: &[usize]) -> Result<(), String> {
        use worker::wasm_bindgen::{JsCast, JsValue};
        let storage = self.storage.as_ref().ok_or("atomic batches require Durable Object storage")?;
        let raw: &JsValue = storage.as_raw().as_ref();
        let transaction = js_sys::Reflect::get(raw, &JsValue::from_str("transactionSync"))
            .map_err(|e| worker::Error::from(e).to_string())?
            .dyn_into::<js_sys::Function>().map_err(|_| "transactionSync is not a function")?;
        let statements = statements.to_vec(); let require_one = require_one.to_vec();
        let sql = self.sql.clone();
        let callback = worker::wasm_bindgen::closure::Closure::wrap(Box::new(move || -> Result<(), JsValue> {
            for (index, (statement, params)) in statements.iter().enumerate() {
                let cursor = sql.exec(statement, do_binds(params)).map_err(|e| JsValue::from_str(&e.to_string()))?;
                for row in cursor.raw() { row.map_err(|e| JsValue::from_str(&e.to_string()))?; }
                if require_one.contains(&index) {
                    // rowsWritten includes index writes; changes() counts affected table rows.
                    let changes: Value = sql.exec("SELECT changes() AS affected", None).map_err(|e| JsValue::from_str(&e.to_string()))?
                        .one().map_err(|e| JsValue::from_str(&e.to_string()))?;
                    if changes["affected"].as_u64() != Some(1) {
                        return Err(JsValue::from_str("version conflict: concurrent secret change"));
                    }
                }
            }
            Ok(())
        }) as Box<dyn FnMut() -> Result<(), JsValue>>);
        // The runtime rolls back the whole batch when the callback throws.
        transaction.call1(raw, callback.as_ref()).map_err(|e| worker::Error::from(e).to_string())?;
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
impl Db {
    pub fn from_do_storage_now(storage: worker::Storage) -> Result<Self, String> {
        let sql = storage.sql();
        let db = Db::DoSqlite(std::rc::Rc::new(DoSqlite { sql, storage: Some(storage) }));
        db.migrate_now()?;
        Ok(db)
    }
    /// Constructor for the Durable Object. Migrations run synchronously because
    /// the object constructor cannot await, and the SQL handle never yields.
    pub fn from_do_sql_now(storage: worker::SqlStorage) -> Result<Self, String> {
        let db = Db::DoSqlite(std::rc::Rc::new(DoSqlite { sql: storage, storage: None }));
        db.migrate_now()?;
        Ok(db)
    }
    pub(crate) fn exec_sync(&self, sql: &str, params: &[Value]) -> Result<u64, String> { self.exec_now(sql, params) }
    fn exec_now(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        match self {
            Db::DoSqlite(s) => {
                let cursor = s.exec(sql, do_binds(params)).map_err(|e| e.to_string())?;
                for row in cursor.raw() { row.map_err(|e| e.to_string())?; }
                let changes: Value = s.exec("SELECT changes() AS affected", None).map_err(|e| e.to_string())?.one().map_err(|e| e.to_string())?;
                Ok(changes["affected"].as_u64().unwrap_or(0))
            }
        }
    }
    fn query_now(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        match self {
            Db::DoSqlite(s) => {
                let cursor = s.exec(sql, do_binds(params)).map_err(|e| e.to_string())?;
                let cols = cursor.column_names();
                let mut out = Vec::new();
                for row in cursor.raw() {
                    let values = row.map_err(|e| e.to_string())?;
                    let mut m = Row::new();
                    for (i, v) in values.into_iter().enumerate() { if let Some(name) = cols.get(i) { m.insert(name.clone(), do_value(v)); } }
                    out.push(m);
                }
                Ok(out)
            }
        }
    }
    fn one_now(&self, sql: &str, params: &[Value]) -> Result<Option<Row>, String> { Ok(self.query_now(sql, params)?.into_iter().next()) }
    fn migrate_now(&self) -> Result<(), String> {
        for stmt in SCHEMA { self.exec_now(stmt, &[])?; }
        for alter in [
            "ALTER TABLE envs ADD COLUMN mode TEXT DEFAULT 'sse'",
            "ALTER TABLE envs ADD COLUMN restricted BIGINT DEFAULT 0",
            "ALTER TABLE envs ADD COLUMN require_approval BIGINT DEFAULT 0",
            "ALTER TABLE secrets ADD COLUMN e2e BIGINT DEFAULT 0",
            "ALTER TABLE secrets ADD COLUMN deleted_at BIGINT DEFAULT 0",
            "ALTER TABLE users ADD COLUMN active BIGINT DEFAULT 1",
            "ALTER TABLE tokens ADD COLUMN kind TEXT DEFAULT 'human'",
            "ALTER TABLE tokens ADD COLUMN expires_at BIGINT DEFAULT 0",
            "ALTER TABLE leases ADD COLUMN username TEXT DEFAULT ''",
            "ALTER TABLE leases ADD COLUMN config_enc TEXT DEFAULT ''",
            "ALTER TABLE oidc_states ADD COLUMN nonce TEXT DEFAULT ''",
            "ALTER TABLE pki_cas ADD COLUMN serial TEXT DEFAULT ''",
            "ALTER TABLE rotation_schedules ADD COLUMN path TEXT DEFAULT '/'",
            "ALTER TABLE rotation_schedules ADD COLUMN config_enc TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN email_verified BIGINT DEFAULT 1",
        ] { let _ = self.exec_now(alter, &[]); }
        for idx in INDEXES { let _ = self.exec_now(idx, &[]); }
        if self.one_now("SELECT version FROM schema_migrations WHERE version=1", &[])?.is_none() {
            let _ = self.exec_now("INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)", &[serde_json::json!(crate::clock::now())]);
        }
        for (version, statements) in MIGRATIONS {
            if self.one_now("SELECT version FROM schema_migrations WHERE version=?", &[serde_json::json!(version)])?.is_some() { continue; }
            for stmt in *statements {
                if let Err(e) = self.exec_now(stmt, &[]) {
                    let duplicate = e.contains("duplicate column") || e.contains("already exists");
                    if !duplicate { return Err(format!("migration {} failed: {}", version, e)); }
                }
            }
            self.exec_now("INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", &[serde_json::json!(version), serde_json::json!(crate::clock::now())])?;
        }
        if self.one_now("SELECT v FROM meta WHERE k='migration:env_restricted'", &[])?.is_none() {
            let _ = self.exec_now("UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)", &[]);
            let _ = self.exec_now("INSERT INTO meta(k,v) VALUES('migration:env_restricted',?)", &[serde_json::json!(crate::clock::now())]);
        }
        Ok(())
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
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let n = stmt.execute(rusqlite::params_from_iter(params.iter().map(sqlite_param))).map_err(|e| e.to_string())?;
    Ok(n as u64)
}
#[cfg(not(target_arch = "wasm32"))]
fn query_sqlite(conn: &rusqlite::Connection, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
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
    if sql.starts_with("INSERT INTO meta(") {
        if let Some(insert) = sql.strip_suffix(" ON CONFLICT(k) DO NOTHING") { return format!("{} ON DUPLICATE KEY UPDATE k=k", insert); }
    }
    if sql.starts_with("CREATE TABLE") { return mysql_create_table(sql) }
    if sql.starts_with("CREATE INDEX") || sql.starts_with("CREATE UNIQUE INDEX") { return sql.replacen("IF NOT EXISTS ", "", 1) }
    if sql.starts_with("ALTER TABLE") { return mysql_alter_table(sql) }
    // `key` is reserved in MySQL. Quote only the column positions the schema
    // uses, so a future `key_enc` or a joined alias is not rewritten.
    if sql.contains("rate_limits") || sql.contains("saml_replay") {
        return sql.replace("(key,", "(`key`,").replace("WHERE key=", "WHERE `key`=").replace("SELECT key,", "SELECT `key`,") }
    sql.to_string() }
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
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut statements: Vec<&str> = INDEXES.to_vec();
    for (_, list) in MIGRATIONS { statements.extend(list.iter().copied()); }
    for sql in statements { if let Some((table, cols)) = mysql_index_target(sql) { out.entry(table).or_default().extend(cols); } }
    out }
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
        if t.to_ascii_uppercase().starts_with("PRIMARY KEY") {
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

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,pass_hash TEXT NOT NULL,pubkey TEXT NOT NULL,wrapped_privkey TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS oidc_subjects(issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(issuer,subject))",
    "CREATE TABLE IF NOT EXISTS orgs(id TEXT PRIMARY KEY,name TEXT NOT NULL,ip_allowlist TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS org_members(org_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(org_id,user_id))",
    "CREATE TABLE IF NOT EXISTS teams(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS team_members(team_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(team_id,user_id))",
    "CREATE TABLE IF NOT EXISTS apps(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,readme TEXT DEFAULT '',sse BIGINT DEFAULT 1,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS app_members(app_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(app_id,user_id))",
    "CREATE TABLE IF NOT EXISTS envs(id TEXT PRIMARY KEY,app_id TEXT NOT NULL,name TEXT NOT NULL,env_key_wrapped TEXT NOT NULL,restricted BIGINT DEFAULT 0,require_approval BIGINT DEFAULT 0,max_versions BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS env_members(env_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(env_id,user_id))",
    "CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,path TEXT DEFAULT '/',key_enc TEXT NOT NULL,key_hash TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',tags TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',version BIGINT DEFAULT 1,deleted BIGINT DEFAULT 0,deleted_at BIGINT DEFAULT 0,updated_at BIGINT NOT NULL,updated_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS secret_versions(id TEXT PRIMARY KEY,secret_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',path TEXT DEFAULT '/',tags TEXT DEFAULT '',created_at BIGINT NOT NULL,created_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS overrides(secret_id TEXT NOT NULL,user_id TEXT NOT NULL,value_enc TEXT NOT NULL,PRIMARY KEY(secret_id,user_id))",
    "CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,org_id TEXT DEFAULT '',app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',actor TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL,seq BIGINT DEFAULT 0,prev_hash TEXT DEFAULT '',hash TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,org_id TEXT DEFAULT '',app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,token_hash TEXT NOT NULL,role TEXT DEFAULT 'developer',expires_at BIGINT DEFAULT 0,scopes TEXT DEFAULT '',last_used_at BIGINT DEFAULT 0,created_at BIGINT NOT NULL,created_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS integrations(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,config_enc TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS lockbox(id TEXT PRIMARY KEY,value_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,max_views BIGINT DEFAULT 1,views BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,name TEXT NOT NULL,value_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,revoked BIGINT DEFAULT 0,attempted_at BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS env_keys(env_id TEXT NOT NULL,user_id TEXT NOT NULL,wrapped_key TEXT NOT NULL,PRIMARY KEY(env_id,user_id))",
    "CREATE TABLE IF NOT EXISTS oidc_states(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,nonce TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,role TEXT DEFAULT 'developer',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS identity_credentials(id TEXT PRIMARY KEY,identity_id TEXT NOT NULL,client_id TEXT UNIQUE NOT NULL,secret_hash TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,author TEXT NOT NULL,status TEXT DEFAULT 'pending',payload_enc TEXT NOT NULL,created_at BIGINT NOT NULL,decided_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS access_requests(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,user_id TEXT NOT NULL,reason TEXT DEFAULT '',status TEXT DEFAULT 'pending',created_at BIGINT NOT NULL,decided_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS pki_cas(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,cert_pem TEXT NOT NULL,key_enc TEXT NOT NULL,serial TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS integration_sync_state(integration_id TEXT NOT NULL,remote_name TEXT NOT NULL,value_hash TEXT NOT NULL,PRIMARY KEY(integration_id,remote_name))",
    "CREATE TABLE IF NOT EXISTS oauth_clients(client_id TEXT PRIMARY KEY,client_secret_hash TEXT DEFAULT '',name TEXT DEFAULT '',redirect_uris TEXT DEFAULT '[]',scopes TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS oauth_codes(code_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,user_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,code_challenge TEXT NOT NULL,scope TEXT DEFAULT '',resource TEXT DEFAULT '',expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS oauth_tokens(token_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,user_id TEXT NOT NULL,scope TEXT DEFAULT '',resource TEXT DEFAULT '',kind TEXT DEFAULT 'access',pair_id TEXT DEFAULT '',expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS roles(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,permissions TEXT DEFAULT '[]')",
    "CREATE TABLE IF NOT EXISTS log_streams(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,secret TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS log_deliveries(id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,event TEXT NOT NULL,payload TEXT DEFAULT '',status TEXT DEFAULT 'pending',attempts BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS rotation_schedules(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,key_name TEXT NOT NULL,path TEXT DEFAULT '/',interval_secs BIGINT NOT NULL,next_run BIGINT NOT NULL,enabled BIGINT DEFAULT 1,config_enc TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS mfa_challenges(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS pki_certs(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,cn TEXT NOT NULL,cert_pem TEXT NOT NULL,serial TEXT NOT NULL,revoked BIGINT DEFAULT 0,expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY,window_start BIGINT NOT NULL,count BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS social_states(state TEXT PRIMARY KEY,provider TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS social_subjects(provider TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(provider,subject))",
    "CREATE TABLE IF NOT EXISTS invites(token_hash TEXT PRIMARY KEY,email TEXT NOT NULL,org_id TEXT NOT NULL,role TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,accepted BIGINT DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS auth_tokens(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,kind TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS team_env_grants(team_id TEXT NOT NULL,env_id TEXT NOT NULL,PRIMARY KEY(team_id,env_id))",
    "CREATE TABLE IF NOT EXISTS instance_leases(name TEXT PRIMARY KEY,owner TEXT NOT NULL,expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS saml_configs(org_id TEXT PRIMARY KEY,idp_entity_id TEXT NOT NULL,idp_metadata_xml TEXT NOT NULL,sp_key_enc TEXT NOT NULL,sp_cert_pem TEXT NOT NULL,allow_unsigned_metadata BIGINT DEFAULT 0,metadata_trusted_cert TEXT DEFAULT '',auto_provision BIGINT DEFAULT 0,allowed_domains TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS saml_pending(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,snapshot TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS saml_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS saml_subjects(org_id TEXT NOT NULL,idp_entity_id TEXT NOT NULL,name_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(org_id,idp_entity_id,name_id))",
    "CREATE TABLE IF NOT EXISTS rotation_hooks(org_id TEXT PRIMARY KEY,url TEXT NOT NULL,secret_enc TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS live_events(id BIGINT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL)",
];

// Additive migrations applied after the baseline schema. A statement may fail
// because a fresh database already created the column or table; those errors
// are recognised and ignored, anything else aborts the boot.
const MIGRATIONS: &[(i64, &[&str])] = &[
    (2, &[
        "ALTER TABLE tokens ADD COLUMN scopes TEXT DEFAULT ''",
        "ALTER TABLE tokens ADD COLUMN last_used_at BIGINT DEFAULT 0",
    ]),
    (3, &[
        "CREATE TABLE IF NOT EXISTS team_env_grants(team_id TEXT NOT NULL,env_id TEXT NOT NULL,PRIMARY KEY(team_id,env_id))",
    ]),
    (4, &[
        "CREATE TABLE IF NOT EXISTS instance_leases(name TEXT PRIMARY KEY,owner TEXT NOT NULL,expires_at BIGINT NOT NULL)",
    ]),
    (5, &[
        "CREATE TABLE IF NOT EXISTS saml_configs(org_id TEXT PRIMARY KEY,idp_entity_id TEXT NOT NULL,idp_metadata_xml TEXT NOT NULL,sp_key_enc TEXT NOT NULL,sp_cert_pem TEXT NOT NULL,allow_unsigned_metadata BIGINT DEFAULT 0,metadata_trusted_cert TEXT DEFAULT '',auto_provision BIGINT DEFAULT 0,allowed_domains TEXT DEFAULT '',created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS saml_pending(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,snapshot TEXT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS saml_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS saml_subjects(org_id TEXT NOT NULL,idp_entity_id TEXT NOT NULL,name_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(org_id,idp_entity_id,name_id))",
    ]),
    (6, &[
        "CREATE TABLE IF NOT EXISTS rotation_hooks(org_id TEXT PRIMARY KEY,url TEXT NOT NULL,secret_enc TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    ]),
    (7, &[
        "ALTER TABLE social_states ADD COLUMN nonce TEXT DEFAULT ''",
        "ALTER TABLE social_states ADD COLUMN code_verifier TEXT DEFAULT ''",
    ]),
    (8, &[
        "CREATE TABLE IF NOT EXISTS live_events(id BIGINT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    ]),
    (9, &[
        "ALTER TABLE social_states ADD COLUMN link_user TEXT DEFAULT ''",
        "ALTER TABLE oidc_states ADD COLUMN link_user TEXT DEFAULT ''",
        "CREATE TABLE IF NOT EXISTS identity_bindings(issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,provider TEXT DEFAULT '',created_at BIGINT NOT NULL,PRIMARY KEY(issuer,subject))",
        "CREATE TABLE IF NOT EXISTS logout_replay(jti TEXT PRIMARY KEY,expires_at BIGINT NOT NULL)",
    ]),
    (10, &[
        "CREATE TABLE IF NOT EXISTS ldap_configs(org_id TEXT PRIMARY KEY,url TEXT NOT NULL DEFAULT '',bind_dn TEXT NOT NULL DEFAULT '',bind_password_enc TEXT NOT NULL DEFAULT '',base_dn TEXT NOT NULL DEFAULT '',user_filter TEXT NOT NULL DEFAULT '(uid={username})',email_attr TEXT NOT NULL DEFAULT 'mail',name_attr TEXT NOT NULL DEFAULT 'displayName',group_attr TEXT NOT NULL DEFAULT 'memberOf',group_roles TEXT NOT NULL DEFAULT '',default_role TEXT NOT NULL DEFAULT 'developer',auto_provision BIGINT NOT NULL DEFAULT 0,allowed_domains TEXT NOT NULL DEFAULT '',ca_cert_pem TEXT NOT NULL DEFAULT '',updated_at BIGINT NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS ldap_subjects(org_id TEXT NOT NULL,dn TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,role TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,dn))",
    ]),
    (11, &[
        "ALTER TABLE rotation_schedules ADD COLUMN config_enc TEXT DEFAULT ''",
    ]),
    (12, &[
        "ALTER TABLE orgs ADD COLUMN reuse_check BIGINT DEFAULT 1",
        "ALTER TABLE apps ADD COLUMN reuse_check BIGINT DEFAULT 1",
        "ALTER TABLE secrets ADD COLUMN value_fp TEXT DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_secrets_fp ON secrets(value_fp)",
    ]),
    (13, &[
        "ALTER TABLE secret_versions ADD COLUMN path TEXT DEFAULT '/'",
        "ALTER TABLE secret_versions ADD COLUMN tags TEXT DEFAULT ''",
    ]),
    // SSH certificate authorities reuse pki_cas so the sealed CA key and the
    // master-key rotation that re-wraps it stay in one place.
    (14, &[
        "ALTER TABLE pki_cas ADD COLUMN kind TEXT DEFAULT 'x509'",
        "ALTER TABLE pki_cas ADD COLUMN allow_forwarding BIGINT DEFAULT 0",
        "CREATE TABLE IF NOT EXISTS ssh_principal_grants(ca_id TEXT NOT NULL,role TEXT NOT NULL,principals TEXT NOT NULL,max_ttl BIGINT DEFAULT 900,PRIMARY KEY(ca_id,role))",
        "CREATE TABLE IF NOT EXISTS ssh_certs(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,key_id TEXT NOT NULL,principal TEXT NOT NULL,public_key TEXT NOT NULL,cert TEXT NOT NULL,serial BIGINT NOT NULL,actor TEXT NOT NULL,revoked BIGINT DEFAULT 0,valid_after BIGINT NOT NULL,valid_before BIGINT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_ssh_certs_ca ON ssh_certs(ca_id,created_at)",
        "CREATE INDEX IF NOT EXISTS idx_ssh_grants_ca ON ssh_principal_grants(ca_id)",
    ]),
    // Host certificates are issued only for a hostname and key an admin
    // registered, so the registry is the authorisation for host issuance.
    (15, &[
        "ALTER TABLE ssh_certs ADD COLUMN cert_type TEXT DEFAULT 'user'",
        "CREATE TABLE IF NOT EXISTS ssh_hosts(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,hostname TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_hosts_key ON ssh_hosts(ca_id,hostname,fingerprint)",
        "CREATE TABLE IF NOT EXISTS step_up_challenges(challenge_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,risk TEXT NOT NULL,need_totp BIGINT DEFAULT 0,need_email BIGINT DEFAULT 0,email_code_hash TEXT DEFAULT '',attempts BIGINT DEFAULT 0,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS step_up_grants(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,risk TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0)",
    ]),
    // Delegated environments, client-derived auth and second factors.
    (16, &[
        "ALTER TABLE envs ADD COLUMN runner_id TEXT DEFAULT ''",
        "ALTER TABLE secrets ADD COLUMN path_enc TEXT DEFAULT ''",
        "ALTER TABLE secrets ADD COLUMN tags_enc TEXT DEFAULT ''",
        "ALTER TABLE secrets ADD COLUMN key_index TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN auth_version BIGINT DEFAULT 1",
        "ALTER TABLE users ADD COLUMN kdf_salt TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN kdf_iterations BIGINT DEFAULT 0",
        "ALTER TABLE users ADD COLUMN kdf_algo TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN auth_key_enc TEXT DEFAULT ''",
        "CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT DEFAULT '',credential_id TEXT NOT NULL,credential_json TEXT NOT NULL,sign_count BIGINT DEFAULT 0,created_at BIGINT NOT NULL,last_used_at BIGINT DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS passkey_registrations(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,state_json TEXT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS mfa_passkey_states(mfa_token TEXT PRIMARY KEY,user_id TEXT NOT NULL,state_json TEXT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS email_codes(user_id TEXT NOT NULL,purpose TEXT NOT NULL,code_hash TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,attempts BIGINT DEFAULT 0,PRIMARY KEY(user_id,purpose))",
        "CREATE TABLE IF NOT EXISTS runners(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,pubkey TEXT NOT NULL,token_hash TEXT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS runner_env_keys(runner_id TEXT NOT NULL,env_id TEXT NOT NULL,wrapped_key TEXT NOT NULL,PRIMARY KEY(runner_id,env_id))",
        "CREATE TABLE IF NOT EXISTS sync_jobs(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,integration_id TEXT NOT NULL,runner_id TEXT NOT NULL,kind TEXT DEFAULT 'sync',status TEXT DEFAULT 'pending',detail TEXT DEFAULT '',created_at BIGINT NOT NULL,claimed_at BIGINT DEFAULT 0,claim_id TEXT DEFAULT '')",
        "CREATE TABLE IF NOT EXISTS auth_challenges(id_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,challenge TEXT NOT NULL,created_at BIGINT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_secrets_key_index ON secrets(env_id,key_index)",
        "CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_passkeys_credential ON passkeys(credential_id)",
        "CREATE INDEX IF NOT EXISTS idx_runners_token ON runners(token_hash)",
        "CREATE INDEX IF NOT EXISTS idx_sync_jobs_pending ON sync_jobs(status,created_at)",
        "CREATE INDEX IF NOT EXISTS idx_sync_jobs_integration ON sync_jobs(integration_id,status)",
        "CREATE INDEX IF NOT EXISTS idx_auth_challenges_user ON auth_challenges(user_id)",
    ]),
    (17, &[
        "ALTER TABLE envs ADD COLUMN max_versions BIGINT DEFAULT 0",
        "ALTER TABLE leases ADD COLUMN attempted_at BIGINT DEFAULT 0",
        "ALTER TABLE audit ADD COLUMN seq BIGINT DEFAULT 0",
        "ALTER TABLE audit ADD COLUMN prev_hash TEXT DEFAULT ''",
        "ALTER TABLE audit ADD COLUMN hash TEXT DEFAULT ''",
        "CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0)",
        "CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq)",
        "CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at)",
    ]),
];

const INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(env_id)",
    "CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_org ON audit(org_id,created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq)",
    "CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_env_members_user ON env_members(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_leases_env ON leases(env_id)",
    "CREATE INDEX IF NOT EXISTS idx_sync_state_integration ON integration_sync_state(integration_id)",
    "CREATE INDEX IF NOT EXISTS idx_team_env_grants_env ON team_env_grants(env_id)",
    "CREATE INDEX IF NOT EXISTS idx_instance_leases_expiry ON instance_leases(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_rotations_due ON rotation_schedules(enabled,next_run)",
    "CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email)",
    "CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_live_events_id ON live_events(id)",
];

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
        assert_eq!(db.version().await.unwrap(), 17, "a fresh database lands on the current version");
        db.migrate().await.unwrap();
        let row = db.one("SELECT COUNT(*) AS n FROM schema_migrations", &[]).await.unwrap().unwrap();
        assert_eq!(n(&row, "n"), 17, "each migration must be recorded exactly once");
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test] fn mysql_master_verifier_insert_preserves_existing_value() {
        assert_eq!(mysql_sql("INSERT INTO meta(k,v) VALUES('master_key_check',?) ON CONFLICT(k) DO NOTHING"),
            "INSERT INTO meta(k,v) VALUES('master_key_check',?) ON DUPLICATE KEY UPDATE k=k");
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
}
