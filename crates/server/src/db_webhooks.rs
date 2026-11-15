use super::*;

pub struct WebhookTx<'a> {
    #[cfg(not(target_arch = "wasm32"))] sqlite: Option<&'a rusqlite::Connection>,
    #[cfg(not(target_arch = "wasm32"))] postgres: Option<(&'a tokio_postgres::Client, &'a tokio::runtime::Handle)>,
    #[cfg(not(target_arch = "wasm32"))] mysql: Option<(&'a std::sync::Mutex<mysql_async::Conn>, &'a tokio::runtime::Handle)>,
    #[cfg(target_arch = "wasm32")] storage: &'a worker::SqlStorage,
}
impl WebhookTx<'_> {
    pub fn exec(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        #[cfg(not(target_arch = "wasm32"))] {
            if let Some(c) = self.sqlite { return exec_sqlite(c, sql, params); }
            if let Some((c, rt)) = self.mysql { let mut c=c.lock().unwrap(); return rt.block_on(async { c.exec_drop(mysql_sql(sql),mysql_params(params)).await.map_err(|e|e.to_string())?; Ok(c.affected_rows()) }); }
            let (c, rt) = self.postgres.expect("transaction backend"); let pg = PgParams::new(params); let refs = pg.refs();
            rt.block_on(c.execute(pg_sql(sql).as_str(), &refs)).map_err(pg_err)
        }
        #[cfg(target_arch = "wasm32")] {
            let cursor=self.storage.exec(&sqlite_sql(sql), do_binds(params)).map_err(|e| e.to_string())?;
            for row in cursor.raw() { row.map_err(|e|e.to_string())?; }
            let changed: Value=self.storage.exec("SELECT changes() AS affected",None).map_err(|e|e.to_string())?.one().map_err(|e|e.to_string())?;
            changed["affected"].as_u64().ok_or_else(||"missing affected row count".into())
        }
    }
    pub fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        #[cfg(not(target_arch = "wasm32"))] {
            if let Some(c) = self.sqlite { return query_sqlite(c, sql, params); }
            if let Some((c,rt))=self.mysql { let mut c=c.lock().unwrap(); let rows=rt.block_on(c.exec::<mysql_async::Row,_,_>(mysql_sql(sql),mysql_params(params))).map_err(|e|e.to_string())?;
                return Ok(rows.iter().map(|r| { let mut m=Row::new(); for (i,col) in r.columns_ref().iter().enumerate() {m.insert(col.name_str().to_string(),mysql_value(r.as_ref(i)));} m }).collect()); }
            let (c, rt) = self.postgres.expect("transaction backend"); let pg = PgParams::new(params); let refs = pg.refs();
            let rows = rt.block_on(c.query(pg_sql(sql).as_str(), &refs)).map_err(pg_err)?;
            Ok(rows.into_iter().map(|r| { let mut m=Row::new(); for (i,col) in r.columns().iter().enumerate() {
                let v=if let Ok(v)=r.try_get::<_,Option<String>>(i) {v.map(Value::String).unwrap_or(Value::Null)} else if let Ok(v)=r.try_get::<_,Option<i64>>(i) {v.map(|v|Value::Number(v.into())).unwrap_or(Value::Null)} else {Value::Null}; m.insert(col.name().to_string(),v);
            } m }).collect())
        }
        #[cfg(target_arch = "wasm32")] {
            let cursor=self.storage.exec(&sqlite_sql(sql),do_binds(params)).map_err(|e|e.to_string())?; let cols=cursor.column_names(); let mut out=Vec::new();
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
                let mut conn=c.lock().unwrap(); let tx=conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e|e.to_string())?;
                let value=operation(&WebhookTx {sqlite:Some(&tx),postgres:None,mysql:None})?;
                tx.commit().map_err(|e|e.to_string())?; Ok(value)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(pool) => {
                let pool=pool.clone(); let rt=tokio::runtime::Handle::current(); tokio::task::spawn_blocking(move || {
                    let client=rt.block_on(pool.get()).map_err(|e|e.to_string())?;
                    rt.block_on(client.batch_execute("BEGIN")).map_err(pg_err)?;
                    struct Rollback<'a>(&'a tokio_postgres::Client,&'a tokio::runtime::Handle,bool);
                    impl Drop for Rollback<'_> {fn drop(&mut self) {if self.2 {let _=self.1.block_on(self.0.batch_execute("ROLLBACK"));}}}
                    let mut rollback=Rollback(&client,&rt,true);
                    rt.block_on(client.batch_execute("SET LOCAL lock_timeout='5s'")).map_err(pg_err)?;
                    if (WebhookTx {sqlite:None,postgres:Some((&client,&rt)),mysql:None}).one("SELECT id FROM webhook_serialization WHERE id=1 FOR UPDATE",&[])?.is_none() {return Err("missing webhook serialization row".into());}
                    let value=operation(&WebhookTx {sqlite:None,postgres:Some((&client,&rt)),mysql:None})?;
                    rt.block_on(client.batch_execute("COMMIT")).map_err(pg_err)?; rollback.2=false; Ok(value)
                }).await.map_err(|e|e.to_string())?
            }
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(pool) => {
                let pool=pool.clone(); let rt=tokio::runtime::Handle::current(); tokio::task::spawn_blocking(move || {
                    let client=std::sync::Mutex::new(rt.block_on(pool.get_conn()).map_err(|e|e.to_string())?);
                    rt.block_on(client.lock().unwrap().query_drop("START TRANSACTION")).map_err(|e|e.to_string())?;
                    struct Rollback<'a>(&'a std::sync::Mutex<mysql_async::Conn>,&'a tokio::runtime::Handle,bool);
                    impl Drop for Rollback<'_> {fn drop(&mut self) {if self.2 {let _=self.1.block_on(self.0.lock().unwrap().query_drop("ROLLBACK"));}}}
                    let mut rollback=Rollback(&client,&rt,true);
                    if (WebhookTx {sqlite:None,postgres:None,mysql:Some((&client,&rt))}).one("SELECT id FROM webhook_serialization WHERE id=1 FOR UPDATE",&[])?.is_none() {return Err("missing webhook serialization row".into());}
                    let value=operation(&WebhookTx {sqlite:None,postgres:None,mysql:Some((&client,&rt))})?;
                    rt.block_on(client.lock().unwrap().query_drop("COMMIT")).map_err(|e|e.to_string())?; rollback.2=false; Ok(value)
                }).await.map_err(|e|e.to_string())?
            }
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(sql, storage) => {
                use worker::wasm_bindgen::{closure::Closure, JsCast, JsValue};
                let raw: &JsValue=storage.as_raw().as_ref();
                let transaction=js_sys::Reflect::get(raw,&JsValue::from_str("transactionSync")).map_err(|e|worker::Error::from(e).to_string())?
                    .dyn_into::<js_sys::Function>().map_err(|_|"Durable Object transactionSync is unavailable".to_string())?;
                let sql=sql.clone(); let mut operation=Some(operation); let result=std::rc::Rc::new(std::cell::RefCell::new(None)); let output=result.clone();
                let callback=Closure::wrap(Box::new(move || -> Result<JsValue,JsValue> {
                    let value=operation.take().ok_or_else(||JsValue::from_str("transaction callback repeated"))?(&WebhookTx {storage:&sql}).map_err(|e|JsValue::from_str(&e))?;
                    *output.borrow_mut()=Some(value); Ok(JsValue::UNDEFINED)
                }) as Box<dyn FnMut()->Result<JsValue,JsValue>>);
                transaction.call1(raw,callback.as_ref()).map_err(|e|worker::Error::from(e).to_string())?;
                let value=result.borrow_mut().take().ok_or_else(||"transaction returned no result".to_string()); value
            }
        }
    }
}
