use super::*;

pub struct WebhookTx<'a> {
    #[cfg(not(target_arch = "wasm32"))] sqlite: Option<&'a rusqlite::Connection>,
    #[cfg(not(target_arch = "wasm32"))] postgres: Option<(&'a tokio_postgres::Client, &'a tokio::runtime::Handle)>,
    #[cfg(target_arch = "wasm32")] storage: &'a worker::SqlStorage,
}
impl WebhookTx<'_> {
    pub fn exec(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        #[cfg(not(target_arch = "wasm32"))] {
            if let Some(c) = self.sqlite { return exec_sqlite(c, sql, params); }
            let (c, rt) = self.postgres.expect("transaction backend"); let pg = PgParams::new(params); let refs = pg.refs();
            rt.block_on(c.execute(pg_sql(sql).as_str(), &refs)).map_err(pg_err)
        }
        #[cfg(target_arch = "wasm32")] { self.storage.exec(sql, do_binds(params)).map(|v| v.rows_written() as u64).map_err(|e| e.to_string()) }
    }
    pub fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        #[cfg(not(target_arch = "wasm32"))] {
            if let Some(c) = self.sqlite { return query_sqlite(c, sql, params); }
            let (c, rt) = self.postgres.expect("transaction backend"); let pg = PgParams::new(params); let refs = pg.refs();
            let rows = rt.block_on(c.query(pg_sql(sql).as_str(), &refs)).map_err(pg_err)?;
            Ok(rows.into_iter().map(|r| { let mut m=Row::new(); for (i,col) in r.columns().iter().enumerate() {
                let v=if let Ok(v)=r.try_get::<_,Option<String>>(i) {v.map(Value::String).unwrap_or(Value::Null)} else if let Ok(v)=r.try_get::<_,Option<i64>>(i) {v.map(|v|Value::Number(v.into())).unwrap_or(Value::Null)} else {Value::Null}; m.insert(col.name().to_string(),v);
            } m }).collect())
        }
        #[cfg(target_arch = "wasm32")] {
            let cursor=self.storage.exec(sql,do_binds(params)).map_err(|e|e.to_string())?; let cols=cursor.column_names(); let mut out=Vec::new();
            for row in cursor.raw() { let values=row.map_err(|e|e.to_string())?; let mut m=Row::new(); for (i,v) in values.into_iter().enumerate() { if let Some(k)=cols.get(i) {m.insert(k.clone(),do_value(v));} } out.push(m); } Ok(out)
        }
    }
    pub fn one(&self, sql: &str, params: &[Value]) -> Result<Option<Row>, String> { Ok(self.query(sql,params)?.into_iter().next()) }
}
impl Db {
    pub async fn webhook_atomic<T: Send + 'static>(&self, operation: impl FnOnce(&WebhookTx<'_>) -> Result<T,String> + Send + 'static) -> Result<T,String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(c) => {
                let conn=c.lock().unwrap(); conn.execute_batch("BEGIN IMMEDIATE").map_err(|e|e.to_string())?;
                let result=operation(&WebhookTx {sqlite:Some(&conn),postgres:None});
                match result { Ok(v)=>{ if let Err(e)=conn.execute_batch("COMMIT") {let _=conn.execute_batch("ROLLBACK");return Err(e.to_string());} Ok(v)}, Err(e)=>{let _=conn.execute_batch("ROLLBACK"); Err(e)} }
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let pool=pool.clone(); let rt=tokio::runtime::Handle::current(); tokio::task::spawn_blocking(move || {
                    let client=rt.block_on(pool.get()).map_err(|e|e.to_string())?;
                    rt.block_on(client.batch_execute("BEGIN")).map_err(pg_err)?;
                    struct Rollback<'a>(&'a tokio_postgres::Client,&'a tokio::runtime::Handle,bool);
                    impl Drop for Rollback<'_> {fn drop(&mut self) {if self.2 {let _=self.1.block_on(self.0.batch_execute("ROLLBACK"));}}}
                    let mut rollback=Rollback(&client,&rt,true);
                    rt.block_on(client.batch_execute("SET LOCAL lock_timeout='5s'; SELECT id FROM webhook_serialization WHERE id=1 FOR UPDATE")).map_err(pg_err)?;
                    let value=operation(&WebhookTx {sqlite:None,postgres:Some((&client,&rt))})?;
                    rt.block_on(client.batch_execute("COMMIT")).map_err(pg_err)?; rollback.2=false; Ok(value)
                }).await.map_err(|e|e.to_string())?
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(storage) => { operation(&WebhookTx {storage}) }
        }
    }
}
