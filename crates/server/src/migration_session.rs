use super::*;
use crate::migrate::{self, Migration, Options, Repair, Report};
#[cfg(not(target_arch = "wasm32"))]
use crate::migrate::{SqlDialect, Target};

#[cfg(not(target_arch = "wasm32"))]
fn ready<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    struct NoWake;
    impl std::task::Wake for NoWake { fn wake(self: std::sync::Arc<Self>) {} }
    let waker = std::task::Waker::from(std::sync::Arc::new(NoWake));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => Ok(value),
        std::task::Poll::Pending => Err("SQLite migration unexpectedly yielded; rolling back".to_string()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
enum Session<'a> {
    Sqlite(&'a rusqlite::Connection),
    Postgres(deadpool_postgres::ClientWrapper),
    Mysql(tokio::sync::Mutex<mysql_async::Conn>),
}

#[cfg(not(target_arch = "wasm32"))]
impl Target for Session<'_> {
    async fn exec(&self, sql: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(conn) => conn.execute_batch(sql).map_err(|e| e.to_string()),
            Self::Postgres(client) => client.batch_execute(sql).await.map_err(pg_err),
            Self::Mysql(client) => client.lock().await.query_drop(mysql_sql(sql)).await.map_err(|e| e.to_string()),
        }
    }
    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> {
        match self {
            Self::Sqlite(conn) => query_sqlite(conn, sql, &[]),
            Self::Postgres(client) => {
                let rows = client.query(sql, &[]).await.map_err(pg_err)?;
                Ok(rows.iter().map(|row| row.columns().iter().enumerate().map(|(i, col)| {
                    let value = if let Ok(value) = row.try_get::<_, Option<String>>(i) { value.map(Value::String).unwrap_or(Value::Null) }
                        else if let Ok(value) = row.try_get::<_, Option<i64>>(i) { value.map(|n| Value::Number(n.into())).unwrap_or(Value::Null) }
                        else { Value::Null };
                    (col.name().to_string(), value)
                }).collect()).collect())
            }
            Self::Mysql(client) => {
                let rows: Vec<mysql_async::Row> = client.lock().await.exec(mysql_sql(sql), mysql_async::Params::Empty).await.map_err(|e| e.to_string())?;
                Ok(rows.iter().map(|row| row.columns_ref().iter().enumerate().map(|(i, col)| (col.name_str().to_string(), mysql_value(row.as_ref(i)))).collect()).collect())
            }
        }
    }
    async fn script(&self, statements: &[String]) -> Result<(), String> {
        if matches!(self, Self::Postgres(_)) {
            self.exec("BEGIN").await?;
            for statement in statements {
                if let Err(error) = self.exec(statement).await { let _ = self.exec("ROLLBACK").await; return Err(error); }
            }
            // A failed COMMIT is ambiguous. Never delete evidence or claim rollback.
            self.exec("COMMIT").await
        } else {
            for statement in statements { self.exec(statement).await?; }
            Ok(())
        }
    }
    fn atomic_ddl(&self) -> bool { !matches!(self, Self::Mysql(_)) }
    fn sql_dialect(&self) -> SqlDialect { match self { Self::Sqlite(_) => SqlDialect::Sqlite, Self::Postgres(_) => SqlDialect::Postgres, Self::Mysql(_) => SqlDialect::Mysql } }
    async fn has_application_schema(&self) -> Result<bool, String> {
        let sql = match self {
            Self::Sqlite(_) => "SELECT name FROM sqlite_master WHERE type='table' AND substr(name,1,7)<>'sqlite_' AND name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
            Self::Postgres(_) => "SELECT table_name AS name FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE' AND table_name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
            Self::Mysql(_) => "SELECT table_name AS name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE' AND table_name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
        };
        Ok(!self.query(sql).await?.is_empty())
    }
}

impl Db {
    pub(crate) async fn migration_apply(&self, migrations: &[Migration], options: Options) -> Result<Report, String> {
        self.migration_operation(migrations, Some(options), None).await.map(|(report, _)| report)
    }
    pub(crate) async fn migration_repair(&self, migrations: &[Migration], action: Repair) -> Result<String, String> {
        self.migration_operation(migrations, None, Some(action)).await.map(|(_, message)| message)
    }
    #[cfg(not(target_arch = "wasm32"))]
    async fn migration_operation(&self, migrations: &[Migration], options: Option<Options>, repair: Option<Repair>) -> Result<(Report, String), String> {
        async fn run(target: &Session<'_>, migrations: &[Migration], options: Option<Options>, repair: Option<Repair>) -> Result<(Report, String), String> {
            if let Some(options) = options { migrate::apply_owned(target, migrations, options).await.map(|report| (report, String::new())) }
            else { migrate::repair_owned(target, migrations, repair.expect("repair operation")).await.map(|message| (Report::default(), message)) }
        }
        match self {
            Self::Sqlite(conn) => {
                let mut conn = conn.lock().unwrap();
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
                let result = ready(run(&Session::Sqlite(&tx), migrations, options, repair))??;
                tx.commit().map_err(|e| e.to_string())?;
                Ok(result)
            }
            Self::Postgres(pool) => {
                // Detach before submitting the lock: cancellation must close this
                // session, never recycle it into a pool with ownership attached.
                let client = deadpool_postgres::Client::take(pool.get().await.map_err(|e| e.to_string())?);
                let held: bool = client.query_one("SELECT pg_try_advisory_lock(1869636978, 1835624306)", &[]).await.map_err(pg_err)?.get(0);
                if !held { return Err("another instance is applying migrations (PostgreSQL session lock)".to_string()); }
                run(&Session::Postgres(client), migrations, options, repair).await
            }
            Self::Mysql(pool) => {
                let opts = { let conn = pool.get_conn().await.map_err(|e| e.to_string())?; conn.opts().clone() };
                // Conn::new has no pool binding. Drop disconnects rather than
                // returning an advisory-lock-bearing connection to the pool.
                let mut client = mysql_async::Conn::new(opts).await.map_err(|e| e.to_string())?;
                let held: Option<i64> = client.query_first("SELECT GET_LOCK(CONCAT('openwarp:migrate:', LEFT(SHA2(DATABASE(),256),40)),0)").await.map_err(|e| e.to_string())?;
                if held != Some(1) { return Err("another instance is applying migrations (MySQL session lock)".to_string()); }
                let session = Session::Mysql(tokio::sync::Mutex::new(client));
                let result = run(&session, migrations, options, repair).await;
                if result.is_ok() {
                    if let Session::Mysql(client) = session { client.into_inner().disconnect().await.map_err(|e| e.to_string())?; }
                }
                result
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    async fn migration_operation(&self, migrations: &[Migration], options: Option<Options>, repair: Option<Repair>) -> Result<(Report, String), String> {
        use worker::wasm_bindgen::{closure::Closure, JsCast, JsValue};
        let Self::DoSqlite(_, storage) = self;
        let raw: &JsValue = storage.as_raw().as_ref();
        let transaction = js_sys::Reflect::get(raw, &JsValue::from_str("transactionSync"))
            .map_err(|e| worker::Error::from(e).to_string())?
            .dyn_into::<js_sys::Function>().map_err(|_| "Durable Object transactionSync is unavailable".to_string())?;
        let mut output = None;
        let mut callback = || -> Result<JsValue, JsValue> {
            let result = migrate::wait(async {
                if let Some(options) = options { migrate::apply_owned(self, migrations, options).await.map(|report| (report, String::new())) }
                else { migrate::repair_owned(self, migrations, repair.expect("repair operation")).await.map(|message| (Report::default(), message)) }
            });
            match result {
                Ok(value) => { output = Some(value); Ok(JsValue::UNDEFINED) }
                Err(error) => Err(JsValue::from_str(&error)),
            }
        };
        let callback = Closure::borrow_mut_assert_unwind_safe(&mut callback);
        transaction.call1(raw, callback.as_ref()).map_err(|e| worker::Error::from(e).to_string())?;
        drop(callback);
        output.ok_or_else(|| "Durable Object transaction callback did not run".to_string())
    }
}
