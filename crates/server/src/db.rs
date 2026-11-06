use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub type Row = HashMap<String, Value>;
pub enum Db {
    Sqlite(Mutex<rusqlite::Connection>),
    Postgres(r2d2::Pool<r2d2_postgres::PostgresConnectionManager<postgres::NoTls>>),
}
fn pg_sql(sql: &str) -> String {
    let mut out = String::new(); let mut n = 0;
    for c in sql.chars() { if c == '?' { n += 1; out.push_str(&format!("${}", n)); } else { out.push(c); } }
    out
}
impl Db {
    pub fn open(url: &str) -> Result<Self, String> {
        if url.starts_with("postgres") {
            // `postgres` sync client drives its own runtime; it cannot run inside tokio.
            let url = url.to_string();
            std::thread::spawn(move || {
                let config: postgres::Config = url.parse().map_err(|e| format!("invalid DATABASE_URL: {}", e))?;
                let manager = r2d2_postgres::PostgresConnectionManager::new(config, postgres::NoTls);
                let size = std::env::var("OPENWARP_PG_POOL_SIZE").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(8).clamp(1, 64);
                let pool = r2d2::Pool::builder().max_size(size).build(manager).map_err(|e| format!("postgres pool: {}", e))?;
                let db = Db::Postgres(pool); db.migrate()?; Ok(db)
            }).join().map_err(|_| "postgres connect thread panicked".to_string())?
        } else {
            let path = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")).unwrap_or(url);
            let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;").map_err(|e| e.to_string())?;
            let db = Db::Sqlite(Mutex::new(conn)); db.migrate()?; Ok(db)
        }
    }
    #[allow(dead_code)]
    pub fn open_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        let db = Db::Sqlite(Mutex::new(conn)); db.migrate()?; Ok(db)
    }
    pub fn exec(&self, sql: &str, params: &[Value]) -> Result<u64, String> {
        match self {
            Db::Sqlite(c) => { let conn = c.lock().unwrap(); exec_sqlite(&conn, sql, params) }
            Db::Postgres(pool) => {
                let mut client = pool.get().map_err(|e| e.to_string())?;
                let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                client.execute(sql2.as_str(), &refs[..]).map_err(|e| e.to_string())
            }
        }
    }
    pub fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        match self {
            Db::Sqlite(c) => { let conn = c.lock().unwrap(); query_sqlite(&conn, sql, params) }
            Db::Postgres(pool) => {
                let mut client = pool.get().map_err(|e| e.to_string())?;
                let sql2 = pg_sql(sql); let pg = PgParams::new(params); let refs = pg.refs();
                let rows = client.query(sql2.as_str(), &refs[..]).map_err(|e| e.to_string())?;
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
    pub fn one(&self, sql: &str, params: &[Value]) -> Result<Option<Row>, String> { Ok(self.query(sql, params)?.into_iter().next()) }
    fn migrate(&self) -> Result<(), String> {
        for stmt in SCHEMA { self.exec(stmt, &[])?; }
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
            "ALTER TABLE users ADD COLUMN email_verified BIGINT DEFAULT 1",
        ] { let _ = self.exec(alter, &[]); }
        for idx in INDEXES { let _ = self.exec(idx, &[]); }
        // Record the baseline once, then apply numbered additive migrations.
        if self.one("SELECT version FROM schema_migrations WHERE version=1", &[])?.is_none() {
            let _ = self.exec("INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)", &[serde_json::json!(now_secs())]);
        }
        for (version, statements) in MIGRATIONS {
            if self.one("SELECT version FROM schema_migrations WHERE version=?", &[serde_json::json!(version)])?.is_some() { continue; }
            for stmt in *statements {
                if let Err(e) = self.exec(stmt, &[]) {
                    let duplicate = e.contains("duplicate column") || e.contains("already exists");
                    if !duplicate { return Err(format!("migration {} failed: {}", version, e)); }
                }
            }
            self.exec("INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", &[serde_json::json!(version), serde_json::json!(now_secs())])?;
        }
        // One-time backfill: environments that already had an allowlist keep it.
        if self.one("SELECT v FROM meta WHERE k='migration:env_restricted'", &[])?.is_none() {
            let _ = self.exec("UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)", &[]);
            let _ = self.exec("INSERT INTO meta(k,v) VALUES('migration:env_restricted',?)", &[serde_json::json!(now_secs())]);
        }
        Ok(())
    }
}
enum PgOwned { S(String), I(i64), B(bool), N(Option<String>) }
struct PgParams { owned: Vec<PgOwned> }
impl PgParams {
    fn new(params: &[Value]) -> Self { Self { owned: params.iter().map(|v| match v { Value::String(s) => PgOwned::S(s.clone()), Value::Number(n) => PgOwned::I(n.as_i64().unwrap_or(0)), Value::Bool(b) => PgOwned::B(*b), _ => PgOwned::N(None) }).collect() } }
    fn refs(&self) -> Vec<&(dyn postgres::types::ToSql + Sync)> { self.owned.iter().map(|o| -> &(dyn postgres::types::ToSql + Sync) { match o { PgOwned::S(s) => s, PgOwned::I(n) => n, PgOwned::B(b) => b, PgOwned::N(n) => n } }).collect() }
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
    "CREATE TABLE IF NOT EXISTS secret_versions(id TEXT PRIMARY KEY,secret_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',created_at BIGINT NOT NULL,created_by TEXT DEFAULT '')",
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
    "CREATE TABLE IF NOT EXISTS rotation_schedules(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,key_name TEXT NOT NULL,path TEXT DEFAULT '/',interval_secs BIGINT NOT NULL,next_run BIGINT NOT NULL,enabled BIGINT DEFAULT 1,created_at BIGINT NOT NULL)",
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
    #[test] fn sqlite_migrate_and_crud() {
        let db = Db::open_memory().unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("o1"), json!("Acme"), json!(1)]).unwrap();
        let rows = db.query("SELECT name FROM orgs WHERE id=?", &[json!("o1")]).unwrap();
        assert_eq!(s(&rows[0], "name"), "Acme");
        // placeholder translation used by Postgres backend
        assert_eq!(pg_sql("SELECT * FROM t WHERE a=? AND b=?"), "SELECT * FROM t WHERE a=$1 AND b=$2");
    }
}
