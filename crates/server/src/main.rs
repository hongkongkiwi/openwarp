use openwarp_crypto as oc;
use openwarp_server::{backfill_value_fingerprints, install_kms, kms, new_state, process_maintenance, production, router, try_leader, validate_auth_env};
use openwarp_server::db::{self, Db};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://openwarp.db".into());
    let db = Db::open(&db_url).await.expect("open database (sqlite://file.db or postgres://...)");
    // Migration-only entry point for deploy jobs: no master key or listener.
    if std::env::args().any(|a| a == "--migrate") {
        match db.version().await { Ok(v) => println!("schema version {}", v), Err(e) => { eprintln!("{}", e); std::process::exit(1); } }
        return;
    }
    // A configured KMS must fail closed: an unreachable or invalid bridge is
    // not a reason to fall back to a locally generated root key.
    let kms = match kms::Kms::from_env() { Ok(k) => k, Err(e) => { eprintln!("{}", e); std::process::exit(1); } };
    let master = load_master(&db, kms.as_ref()).await.unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    if let Err(e) = validate_auth_env() { eprintln!("{}", e); std::process::exit(1); }
    if !openwarp_server::mailer::MailConfig::from_env().enabled() {
        if production() {
            eprintln!("no email provider is configured: password signup is disabled until one is set; configured SSO sign-in still works");
        } else {
            eprintln!("no email provider is configured: verification and reset links are written to this log");
        }
    }
    #[cfg(feature = "redis-cache")]
    let redis_conn = std::env::var("REDIS_URL").ok().and_then(|u| redis::Client::open(u).ok()).and_then(|c| c.get_connection().ok());
    let pub_url = std::env::var("OPENWARP_PUBLIC_URL").unwrap_or_default();
    let (live, _) = broadcast::channel(256);
    let state = new_state(db, db_url.clone(), oc::random_token("inst"), pub_url, master, live, #[cfg(feature = "redis-cache")] redis_conn);
    install_kms(&state, kms);
    { let st2 = state.clone(); tokio::spawn(async move { backfill_value_fingerprints(&st2).await; }); }
    { let st2 = state.clone(); tokio::spawn(async move { loop { tokio::time::sleep(std::time::Duration::from_secs(30)).await; if try_leader(&st2, "background", st2.instance_id(), 60).await { process_maintenance(&st2).await; } } }); }
    // One poll for the whole process. With no sockets subscribed it only reads
    // the current high-water mark, so the next connection starts from now.
    { let st2 = state.clone(); tokio::spawn(async move {
        let mut cursor = st2.db().one("SELECT MAX(id) AS id FROM live_events", &[]).await.ok().flatten().map(|r| db::n(&r, "id")).unwrap_or(0);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if st2.live().receiver_count() == 0 {
                if let Some(r) = st2.db().one("SELECT MAX(id) AS id FROM live_events", &[]).await.ok().flatten() { cursor = db::n(&r, "id"); }
                continue; }
            let rows = st2.db().query("SELECT id,org_id,app_id,env_id,action,detail,created_at FROM live_events WHERE id>? ORDER BY id LIMIT 200", &[json!(cursor)]).await.unwrap_or_default();
            for r in &rows {
                cursor = cursor.max(db::n(r, "id"));
                let ev = json!({"id":db::n(r,"id"),"org":db::s(r,"org_id"),"app":db::s(r,"app_id"),"env":db::s(r,"env_id"),"action":db::s(r,"action"),"detail":db::s(r,"detail"),"ts":db::n(r,"created_at")}).to_string();
                let _ = st2.live().send(Arc::from(ev));
            }
        }
    }); }

    let app = router(state.clone());
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    println!("openwarp listening on {} db={}", addr, db_url);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal()).await.unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async { let _ = tokio::signal::ctrl_c().await; };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) { s.recv().await; } };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    eprintln!("shutdown signal received; draining connections"); }

async fn load_master(db: &Db, kms: Option<&kms::Kms>) -> Result<[u8;32], String> {
    if let Ok(v) = std::env::var("OPENWARP_MASTER_KEY") {
        let bytes = oc::unb64(&v).map_err(|_| "OPENWARP_MASTER_KEY is not valid base64".to_string())?;
        return bytes.try_into().map_err(|_| "OPENWARP_MASTER_KEY must decode to exactly 32 bytes".to_string());
    }
    if let Some(kms) = kms {
        // A present-but-unreadable master row must stop the boot. Minting a new
        // root here would make every record under the old key undecryptable and
        // delete the only copy of the old root.
        let local: Option<[u8; 32]> = if let Some(r) = db.one("SELECT v FROM meta WHERE k='master'", &[]).await.map_err(|e| e.to_string())? {
            let raw = oc::unb64(&db::s(&r, "v")).map_err(|_| "the stored master root is not valid base64; refusing to generate a replacement".to_string())?;
            Some(raw.try_into().map_err(|_| "the stored master root is not 32 bytes; refusing to generate a replacement".to_string())?)
        } else { None };
        let stored = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.map_err(|e| e.to_string())?;
        let master = if let Some(r) = stored {
            let raw = kms.unwrap(&db::s(&r, "v"), "master").map_err(|e| format!("KMS could not unwrap the master root: {}", e))?;
            raw.try_into().map_err(|_| "KMS master root is not 32 bytes".to_string())?
        } else {
            let k = local.unwrap_or_else(oc::random_key);
            let wrapped = kms.wrap(&k, "master")?;
            // The insert is atomic and portable across SQLite, PostgreSQL and
            // MySQL. A losing concurrent first boot adopts the stored winner
            // before writing anything encrypted by this process.
            if db.insert_if_absent("kms_root", &wrapped).await.map_err(|e| e.to_string())? { k } else {
                let row = db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.map_err(|e| e.to_string())?.ok_or("the concurrent KMS root is missing")?;
                let raw = kms.unwrap(&db::s(&row, "v"), "master").map_err(|e| format!("KMS could not unwrap the master root: {}", e))?;
                raw.try_into().map_err(|_| "KMS master root is not 32 bytes".to_string())?
            }
        };
        // A plaintext master that differs from the effective wrapped root is a
        // mixed-root database. Deleting either copy would lose key material, so
        // startup stops and both rows stay for operator recovery.
        if let Some(local) = local { if local != master { return Err("meta.master and meta.kms_root hold different roots; refusing to delete either. Restore the matching root or database backup.".into()); } }
        db.exec("DELETE FROM meta WHERE k='master'", &[]).await.map_err(|e| e.to_string())?;
        return Ok(master);
    }
    if std::env::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) {
        return Err("OPENWARP_MASTER_KEY or OPENWARP_KMS_URL is required in production. Preserve the original root for an existing database; a generated development key must be supplied externally or adopted by a KMS.".into());
    }
    if let Some(r) = db.one("SELECT v FROM meta WHERE k='master'", &[]).await.map_err(|e| e.to_string())? {
        let raw = oc::unb64(&db::s(&r, "v")).map_err(|_| "the stored master root is not valid base64; refusing to generate a replacement".to_string())?;
        return raw.try_into().map_err(|_| "the stored master root is not 32 bytes; refusing to generate a replacement".to_string());
    }
    // A database booted with a KMS has no plaintext master row: the root lives
    // in meta.kms_root. Generating one here would silently make every owkms:
    // environment key and every account key unreadable.
    if db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.map_err(|e| e.to_string())?.is_some() {
        return Err("this database's master root is wrapped by a KMS, but OPENWARP_KMS_URL is not configured. Restore the KMS bridge, or set OPENWARP_MASTER_KEY to the original root.".into());
    }
    let k = oc::random_key(); let _ = db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&k))]).await;
    eprintln!("warning: OPENWARP_MASTER_KEY is not set; a generated key was stored in the database. Set OPENWARP_MASTER_KEY before production use.");
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Neither test may inherit a supplied root, or they would take the
    // OPENWARP_MASTER_KEY branch and prove nothing.
    fn clear_key_env() { std::env::remove_var("OPENWARP_MASTER_KEY"); std::env::remove_var("OPENWARP_ENV"); }

    #[tokio::test]
    async fn refuses_to_generate_a_root_over_a_kms_wrapped_database() {
        clear_key_env();
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('kms_root','owkms:test:blob')", &[]).await.unwrap();
        let err = load_master(&db, None).await.expect_err("must not mint a replacement root");
        assert!(err.contains("wrapped by a KMS"), "{}", err);
    }

    #[tokio::test]
    async fn refuses_to_replace_an_unreadable_master_row() {
        clear_key_env();
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('master','not-base64!')", &[]).await.unwrap();
        let err = load_master(&db, None).await.expect_err("must not replace an unreadable root");
        assert!(err.contains("refusing to generate"), "{}", err);
    }
}

