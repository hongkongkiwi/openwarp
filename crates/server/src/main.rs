use openwarp_crypto as oc;
use openwarp_server::{backfill_value_fingerprints, install_kms, kms, load_master, new_state, process_maintenance, production, router, try_leader, validate_auth_env};
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

