use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub type Row = HashMap<String, Value>;
pub enum Db {
    Sqlite(Mutex<rusqlite::Connection>),
    Postgres(deadpool_postgres::Pool),
}
fn pg_sql(sql: &str) -> String {
    let mut out = String::new(); let mut n = 0;
    for c in sql.chars() { if c == '?' { n += 1; out.push_str(&format!("${}", n)); } else { out.push(c); } }
    out
}
fn pg_err(error: tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => db.message().to_string(),
        None => error.to_string(),
    }
}
fn pg_row(r: &tokio_postgres::Row) -> Row {
    let mut m = Row::new();
    for (i, col) in r.columns().iter().enumerate() {
        let v: Value = if let Ok(v) = r.try_get::<_, Option<String>>(i) { v.map(Value::String).unwrap_or(Value::Null) }
            else if let Ok(v) = r.try_get::<_, Option<i64>>(i) { v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null) }
            else if let Ok(v) = r.try_get::<_, Option<bool>>(i) { v.map(Value::Bool).unwrap_or(Value::Null) }
            else if let Ok(v) = r.try_get::<_, Option<Value>>(i) { v.unwrap_or(Value::Null) }
            else { Value::Null };
        m.insert(col.name().to_string(), v);
    }
    m
}
impl Db {
    pub async fn open(url: &str) -> Result<Self, String> {
        if url.starts_with("postgres") {
            let config: tokio_postgres::Config = url.parse().map_err(|e| format!("invalid DATABASE_URL: {}", e))?;
            let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
            let size = std::env::var("OPENWARP_PG_POOL_SIZE").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(8).clamp(1, 64);
            let pool = deadpool_postgres::Pool::builder(manager).max_size(size).build().map_err(|e| format!("postgres pool: {}", e))?;
            let db = Db::Postgres(pool); db.migrate().await?; Ok(db)
        } else {
            let path = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")).unwrap_or(url);
            let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;").map_err(|e| e.to_string())?;
            let db = Db::Sqlite(Mutex::new(conn)); db.migrate().await?; Ok(db)
        }
    }
    #[allow(dead_code)]
    pub async fn open_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        let db = Db::Sqlite(Mutex::new(conn)); db.migrate().await?; Ok(db)
    }
    pub async fn exec(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        match self {
            Db::Sqlite(c) => {
                let result = { let conn = c.lock().unwrap(); exec_sqlite(&conn, sql, params) };
                result
            }
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                client.execute(sql2.as_str(), &refs[..]).await.map_err(pg_err)
            }
        }
    }
    // Multi-statement atomicity for the flows where a partial apply would leave
    // a delivered certificate live or a device half-deleted.
    pub async fn tx(&self, statements: &[(&str, Vec<Value>)]) -> Result<Vec<u64>, String> {
        self.tx_checked(statements, &[]).await
    }
    // tx_checked rolls back when a named statement affects a different number of
    // rows than expected, so a lost race cannot commit a partial certificate.
    pub async fn tx_checked(&self, statements: &[(&str, Vec<Value>)], expect: &[(usize, u64)]) -> Result<Vec<u64>, String> {
        fn verify(index: usize, n: u64, expect: &[(usize, u64)]) -> Result<(), String> {
            match expect.iter().find(|(i, _)| *i == index) { Some((_, want)) if n != *want => Err(format!("statement {} affected {} rows, expected {}", index, n, want)), _ => Ok(()) } }
        match self {
            Db::Sqlite(c) => {
                let conn = c.lock().unwrap();
                conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| e.to_string())?;
                let mut counts = Vec::with_capacity(statements.len());
                for (sql, params) in statements {
                    let index = counts.len();
                    match exec_sqlite(&conn, sql, params) {
                        Ok(n) => { counts.push(n); if let Err(e) = verify(index, n, expect) { let _ = conn.execute_batch("ROLLBACK"); return Err(e); } }
                        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); return Err(e); } } }
                if let Err(e) = conn.execute_batch("COMMIT") { let _ = conn.execute_batch("ROLLBACK"); return Err(e.to_string()); }
                Ok(counts)
            }
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                client.batch_execute("BEGIN").await.map_err(pg_err)?;
                let mut counts = Vec::with_capacity(statements.len());
                for (sql, params) in statements {
                    let index = counts.len();
                    let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                    match client.execute(sql2.as_str(), &refs[..]).await {
                        Ok(n) => { counts.push(n); if let Err(e) = verify(index, n, expect) { let _ = client.batch_execute("ROLLBACK").await; return Err(e); } }
                        Err(e) => { let _ = client.batch_execute("ROLLBACK").await; return Err(pg_err(e)); } } }
                if let Err(e) = client.batch_execute("COMMIT").await { let _ = client.batch_execute("ROLLBACK").await; return Err(pg_err(e)); }
                Ok(counts)
            }
        }
    }
    // Lock one row, verify it with `ok`, then run statements in the same
    // transaction. PostgreSQL uses FOR UPDATE; SQLite serializes writers with
    // BEGIN IMMEDIATE, so the row read and the writes cannot interleave.
    pub async fn tx_locked<F>(&self, lock_sql: &str, lock_params: &[Value], ok: F, statements: &[(&str, Vec<Value>)], expect: &[(usize, u64)]) -> Result<Vec<u64>, String>
    where F: Fn(&Row) -> bool {
        fn verify(index: usize, n: u64, expect: &[(usize, u64)]) -> Result<(), String> {
            match expect.iter().find(|(i, _)| *i == index) { Some((_, want)) if n != *want => Err(format!("statement {} affected {} rows, expected {}", index, n, want)), _ => Ok(()) } }
        match self {
            Db::Sqlite(c) => {
                let conn = c.lock().unwrap();
                conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| e.to_string())?;
                let rows = match query_sqlite(&conn, lock_sql, lock_params) { Ok(r) => r, Err(e) => { let _ = conn.execute_batch("ROLLBACK"); return Err(e); } };
                if !rows.first().map(ok).unwrap_or(false) { let _ = conn.execute_batch("ROLLBACK"); return Err("lock condition failed".into()); }
                let mut counts = Vec::with_capacity(statements.len());
                for (sql, params) in statements {
                    let index = counts.len();
                    match exec_sqlite(&conn, sql, params) {
                        Ok(n) => { counts.push(n); if let Err(e) = verify(index, n, expect) { let _ = conn.execute_batch("ROLLBACK"); return Err(e); } }
                        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); return Err(e); } } }
                if let Err(e) = conn.execute_batch("COMMIT") { let _ = conn.execute_batch("ROLLBACK"); return Err(e.to_string()); }
                Ok(counts)
            }
            Db::Postgres(pool) => {
                let client = pool.get().await.map_err(|e| e.to_string())?;
                client.batch_execute("BEGIN").await.map_err(pg_err)?;
                let locked_sql = format!("{} FOR UPDATE", lock_sql); let sql2 = pg_sql(&locked_sql);
                let pg = PgParams::new(lock_params); let refs = pg.refs();
                let rows = match client.query(sql2.as_str(), &refs[..]).await { Ok(r) => r, Err(e) => { let _ = client.batch_execute("ROLLBACK").await; return Err(pg_err(e)); } };
                let first = rows.first().map(pg_row);
                if !first.as_ref().map(ok).unwrap_or(false) { let _ = client.batch_execute("ROLLBACK").await; return Err("lock condition failed".into()); }
                let mut counts = Vec::with_capacity(statements.len());
                for (sql, params) in statements {
                    let index = counts.len();
                    let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                    match client.execute(sql2.as_str(), &refs[..]).await {
                        Ok(n) => { counts.push(n); if let Err(e) = verify(index, n, expect) { let _ = client.batch_execute("ROLLBACK").await; return Err(e); } }
                        Err(e) => { let _ = client.batch_execute("ROLLBACK").await; return Err(pg_err(e)); } } }
                if let Err(e) = client.batch_execute("COMMIT").await { let _ = client.batch_execute("ROLLBACK").await; return Err(pg_err(e)); }
                Ok(counts)
            }
        }
    }
    pub async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        match self {
            Db::Sqlite(c) => {
                let result = { let conn = c.lock().unwrap(); query_sqlite(&conn, sql, params) };
                result
            }
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
        }
    }
    pub async fn one(&self, sql: &str, params: &[Value]) -> Result<Option<Row>, String> { Ok(self.query(sql, params).await?.into_iter().next()) }
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
            let _ = self.exec("INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)", &[serde_json::json!(now_secs())]).await;
        }
        for (version, statements) in MIGRATIONS {
            if self.one("SELECT version FROM schema_migrations WHERE version=?", &[serde_json::json!(version)]).await?.is_some() { continue; }
            for stmt in *statements {
                if let Err(e) = self.exec(stmt, &[]).await {
                    let duplicate = e.contains("duplicate column") || e.contains("already exists");
                    if !duplicate { return Err(format!("migration {} failed: {}", version, e)); }
                }
            }
            self.exec("INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", &[serde_json::json!(version), serde_json::json!(now_secs())]).await?;
        }
        // One-time backfill: environments that already had an allowlist keep it.
        if self.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[]).await?.is_none() {
            let _ = self.exec("UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)", &[]).await;
            let _ = self.exec("INSERT INTO meta(k,v) VALUES('migration:env_restricted',?)", &[serde_json::json!(now_secs())]).await;
        }
        Ok(())
    }
}
enum PgOwned { S(String), I(i64), B(bool), N(Option<String>) }
struct PgParams { owned: Vec<PgOwned> }
impl PgParams {
    fn new(params: &[Value]) -> Self { Self { owned: params.iter().map(|v| match v { Value::String(s) => PgOwned::S(s.clone()), Value::Number(n) => PgOwned::I(n.as_i64().unwrap_or(0)), Value::Bool(b) => PgOwned::B(*b), _ => PgOwned::N(None) }).collect() } }
    fn refs(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> { self.owned.iter().map(|o| -> &(dyn tokio_postgres::types::ToSql + Sync) { match o { PgOwned::S(s) => s, PgOwned::I(n) => n, PgOwned::B(b) => b, PgOwned::N(n) => n } }).collect() }
}
fn sqlite_val(v: &rusqlite::types::Value) -> Value {
    use rusqlite::types::Value as V;
    match v { V::Null => Value::Null, V::Integer(n) => Value::Number((*n).into()), V::Real(f) => serde_json::json!(*f), V::Text(s) => Value::String(s.clone()), V::Blob(b) => Value::String(openwarp_crypto::b64(b)) }
}
fn exec_sqlite(conn: &rusqlite::Connection, sql: &str, params: &[Value]) -> Result<u64, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let n = stmt.execute(rusqlite::params_from_iter(params.iter().map(sqlite_param))).map_err(|e| e.to_string())?;
    Ok(n as u64)
}
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
fn sqlite_param(v: &Value) -> SqliteParam { SqliteParam(v.clone()) }
struct SqliteParam(Value);
impl rusqlite::ToSql for SqliteParam {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, Value as V};
        Ok(match &self.0 { Value::Null => ToSqlOutput::Owned(V::Null), Value::String(s) => ToSqlOutput::Owned(V::Text(s.clone())), Value::Number(n) => ToSqlOutput::Owned(V::Integer(n.as_i64().unwrap_or(0))), Value::Bool(b) => ToSqlOutput::Owned(V::Integer(if *b {1} else {0})), other => ToSqlOutput::Owned(V::Text(other.to_string())) })
    }
}
pub fn s(row: &Row, k: &str) -> String { row.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string() }
pub fn n(row: &Row, k: &str) -> i64 { row.get(k).and_then(|v| v.as_i64()).unwrap_or(0) }
pub fn obj(row: &Row) -> Value { let mut m = Map::new(); for (k, v) in row { m.insert(k.clone(), v.clone()); } Value::Object(m) }
fn now_secs() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }

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
    "CREATE TABLE IF NOT EXISTS envs(id TEXT PRIMARY KEY,app_id TEXT NOT NULL,name TEXT NOT NULL,env_key_wrapped TEXT NOT NULL,restricted BIGINT DEFAULT 0,require_approval BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS env_members(env_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(env_id,user_id))",
    "CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,path TEXT DEFAULT '/',key_enc TEXT NOT NULL,key_hash TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',tags TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',version BIGINT DEFAULT 1,deleted BIGINT DEFAULT 0,deleted_at BIGINT DEFAULT 0,updated_at BIGINT NOT NULL,updated_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS secret_versions(id TEXT PRIMARY KEY,secret_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',path TEXT DEFAULT '/',tags TEXT DEFAULT '',created_at BIGINT NOT NULL,created_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS overrides(secret_id TEXT NOT NULL,user_id TEXT NOT NULL,value_enc TEXT NOT NULL,PRIMARY KEY(secret_id,user_id))",
    "CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,org_id TEXT DEFAULT '',app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',actor TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,org_id TEXT DEFAULT '',app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,token_hash TEXT NOT NULL,role TEXT DEFAULT 'developer',expires_at BIGINT DEFAULT 0,scopes TEXT DEFAULT '',last_used_at BIGINT DEFAULT 0,created_at BIGINT NOT NULL,created_by TEXT DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS integrations(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,config_enc TEXT NOT NULL,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS lockbox(id TEXT PRIMARY KEY,value_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,max_views BIGINT DEFAULT 1,views BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,name TEXT NOT NULL,value_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,revoked BIGINT DEFAULT 0,created_at BIGINT NOT NULL)",
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
    (14, &[
        "CREATE TABLE IF NOT EXISTS pki_devices(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,model TEXT DEFAULT '',hardware_serial TEXT DEFAULT '',tags TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,active_cert_id TEXT DEFAULT '',enroll_epoch BIGINT DEFAULT 0,deleting BIGINT DEFAULT 0,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_devices_ca_name ON pki_devices(ca_id,name)",
        "CREATE INDEX IF NOT EXISTS idx_pki_devices_org ON pki_devices(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_pki_devices_env ON pki_devices(env_id)",
        "CREATE TABLE IF NOT EXISTS pki_enrollments(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,token_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,enroll_epoch BIGINT DEFAULT 0)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_enrollments_hash ON pki_enrollments(token_hash)",
        "CREATE INDEX IF NOT EXISTS idx_pki_enrollments_device ON pki_enrollments(device_id)",
        "ALTER TABLE pki_certs ADD COLUMN device_id TEXT DEFAULT ''",
        "ALTER TABLE pki_certs ADD COLUMN revoked_at BIGINT DEFAULT 0",
        "ALTER TABLE pki_certs ADD COLUMN issued_via TEXT DEFAULT ''",
    ]),
    (15, &[
        "ALTER TABLE pki_cas ADD COLUMN parent_id TEXT DEFAULT ''",
        "ALTER TABLE pki_cas ADD COLUMN kind TEXT DEFAULT 'root'",
        "ALTER TABLE pki_cas ADD COLUMN revoked BIGINT DEFAULT 0",
        "ALTER TABLE pki_cas ADD COLUMN revoked_at BIGINT DEFAULT 0",
        "ALTER TABLE pki_cas ADD COLUMN hook_url TEXT DEFAULT ''",
        "ALTER TABLE pki_cas ADD COLUMN hook_secret_enc TEXT DEFAULT ''",
        "ALTER TABLE pki_cas ADD COLUMN attest_issuer TEXT DEFAULT ''",
        "ALTER TABLE pki_cas ADD COLUMN attest_key_pem TEXT DEFAULT ''",
        "ALTER TABLE pki_cas ADD COLUMN attest_alg TEXT DEFAULT 'ES256'",
        "ALTER TABLE pki_cas ADD COLUMN attest_required BIGINT DEFAULT 0",
        "CREATE TABLE IF NOT EXISTS pki_groups(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,name TEXT NOT NULL,env_id TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,tags TEXT DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_groups_ca_name ON pki_groups(ca_id,name)",
        "CREATE INDEX IF NOT EXISTS idx_pki_groups_org ON pki_groups(org_id)",
        "ALTER TABLE pki_devices ADD COLUMN group_id TEXT DEFAULT ''",
        "ALTER TABLE pki_devices ADD COLUMN attested BIGINT DEFAULT 0",
        "ALTER TABLE pki_devices ADD COLUMN attestation TEXT DEFAULT ''",
        "ALTER TABLE pki_enrollments ADD COLUMN revoke_previous BIGINT DEFAULT 0",
        "ALTER TABLE pki_enrollments ADD COLUMN nonce TEXT DEFAULT ''",
    ]),
];

const INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(env_id)",
    "CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_org ON audit(org_id,created_at)",
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
        assert_eq!(db.version().await.unwrap(), 15, "a fresh database lands on the current version");
        db.migrate().await.unwrap();
        let row = db.one("SELECT COUNT(*) AS n FROM schema_migrations", &[]).await.unwrap().unwrap();
        assert_eq!(n(&row, "n"), 15, "each migration must be recorded exactly once");
    }
    #[tokio::test]
    async fn checked_transaction_rolls_back_on_a_lost_race() {
        let db = Db::open_memory().await.unwrap();
        let result = db.tx_checked(&[("UPDATE orgs SET name='x' WHERE id=?", vec![json!("missing")])], &[(0, 1)]).await;
        assert!(result.is_err(), "a statement with the wrong affected-row count must abort");
    }
    #[tokio::test]
    async fn transaction_rolls_back_on_error() {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("o1"), json!("Acme"), json!(1)]).await.unwrap();
        let result = db.tx(&[
            ("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", vec![json!("o2"), json!("Two"), json!(2)]),
            ("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", vec![json!("o1"), json!("Duplicate"), json!(3)]),
        ]).await;
        assert!(result.is_err(), "a failing statement must abort the transaction");
        let rows = db.query("SELECT id FROM orgs", &[]).await.unwrap();
        assert_eq!(rows.len(), 1, "the first insert must be rolled back");
    }
}
