//! Dynamic PostgreSQL lease roles.
//!
//! A lease creates a login role with a random password in the operator's own
//! database and drops it on revocation. Native connects with tokio-postgres
//! over rustls; Workers connects through a Cloudflare socket that terminates
//! TLS with a PostgreSQL SSLRequest (StartTls), so no TLS library is linked
//! into the wasm build.

/// Host and port from a postgres URL, used for the Workers socket.
pub fn host_port(conn: &str) -> Result<(String, u16), String> {
    let (scheme, rest) = conn.split_once("://").ok_or("connection string must be a postgres:// URL")?;
    if !scheme.eq_ignore_ascii_case("postgres") && !scheme.eq_ignore_ascii_case("postgresql") {
        return Err("connection string must be a postgres:// URL".into());
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.contains(',') { return Err("multi-host connection strings are not allowed".into()); }
    let hostport = authority.rsplit('@').next().unwrap_or("");
    if hostport.is_empty() { return Err("connection string has no host".into()); }
    if let Some(inner) = hostport.strip_prefix('[') {
        let (host, tail) = inner.split_once(']').ok_or("invalid IPv6 host")?;
        let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(5432);
        return Ok((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((host.to_string(), port.parse::<u16>().unwrap_or(5432))),
        _ => Ok((hostport.to_string(), 5432)),
    }
}

pub fn validate_static(conn: &str, username: &str) -> Result<(), String> {
    if username.is_empty() || username.len()>63 || username.chars().any(char::is_control) { return Err("postgres-static requires an existing login username (1-63 bytes)".into()); }
    if !(conn.starts_with("postgres://") || conn.starts_with("postgresql://")) { return Err("postgres-static requires a PostgreSQL URL".into()); }
    let config: tokio_postgres::Config = conn.parse().map_err(|_| "invalid PostgreSQL connection URL".to_string())?;
    if config.get_hosts().len()!=1 || !config.get_hostaddrs().is_empty() || config.get_ports().len()>1 || config.get_user().is_none_or(str::is_empty) || config.get_password().is_none_or(|p| p.is_empty()) { return Err("postgres-static requires one TCP host and explicit admin credentials; hostaddr is not allowed".into()); }
    let host = match &config.get_hosts()[0] { tokio_postgres::config::Host::Tcp(h) => h, #[cfg(unix)] _ => return Err("Unix sockets are not allowed".into()) };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    // Prefer is the driver default and silently retries without TLS. Require is
    // the only accepted mode, except an explicit Disable to a literal loopback
    // address outside production for local development. Hostnames such as
    // localhost are not loopback proof, and query parameters cannot fake mode.
    match config.get_ssl_mode() {
        tokio_postgres::config::SslMode::Require => {}
        tokio_postgres::config::SslMode::Disable if matches!(host.as_str(), "127.0.0.1" | "::1") && !crate::production() => {}
        _ => return Err("postgres-static requires sslmode=require; sslmode=disable is allowed only for a literal loopback host outside production".into()),
    }
    let allow=crate::envcfg::var("OPENWARP_ALLOWED_DB_HOSTS").unwrap_or_default();
    if !allow.split(',').map(str::trim).filter(|s| !s.is_empty()).any(|entry| entry.eq_ignore_ascii_case(host) || entry.eq_ignore_ascii_case(&format!("{}:{}",host,port)) || entry.eq_ignore_ascii_case(&format!("[{}]:{}",host,port))) { return Err("PostgreSQL driver host is not in OPENWARP_ALLOWED_DB_HOSTS".into()); }
    Ok(())
}
pub fn static_target(conn: &str, username: &str) -> Result<String,String> {
    validate_static(conn,username)?;
    let config: tokio_postgres::Config=conn.parse().map_err(|_| "invalid PostgreSQL connection URL".to_string())?;
    let host=match &config.get_hosts()[0] { tokio_postgres::config::Host::Tcp(h)=>h.to_ascii_lowercase(), #[cfg(unix)] _=>return Err("TCP host required".into()) };
    Ok(openwarp_crypto::hash_token(&serde_json::json!(["postgres-static",host,config.get_ports().first().copied().unwrap_or(5432),username]).to_string()))
}
#[cfg(not(target_arch = "wasm32"))]
pub async fn rotate_static(conn: &str, username: &str, password: &str) -> Result<(), String> {
    validate_static(conn,username)?;
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let client=client(conn).await.map_err(|_| "PostgreSQL connection failed".to_string())?;
        let sql=format!("ALTER ROLE {} PASSWORD {}",ident(username),literal(password));
        client.execute(&sql,&[]).await.map_err(|_| "static rotation outcome uncertain".to_string())?;
        Ok(())
    }).await.map_err(|_| "static rotation outcome uncertain".to_string())?
}
#[cfg(target_arch = "wasm32")]
pub async fn rotate_static(_conn: &str, _username: &str, _password: &str) -> Result<(), String> { Err("static PostgreSQL rotation requires the native server".into()) }
/// Every target the driver would dial. The driver parses the URL, so a query
/// parameter cannot point the connection somewhere the authority did not name.
#[cfg(not(target_arch = "wasm32"))]
pub fn targets(conn: &str) -> Result<Vec<(String, u16)>, String> {
    let config: tokio_postgres::Config = conn.parse().map_err(|e| format!("invalid postgres connection string: {}", e))?;
    let hosts = config.get_hosts(); let ports = config.get_ports();
    if hosts.len() > 1 || ports.len() > 1 { return Err("multi-host connection strings are not allowed".into()); }
    if !config.get_hostaddrs().is_empty() { return Err("hostaddr connections are not allowed".into()); }
    let Some(first) = hosts.first() else { return Err("connection string has no host".into()) };
    let host = match first {
        tokio_postgres::config::Host::Tcp(host) => host.clone(),
        tokio_postgres::config::Host::Unix(_) => return Err("unix-socket connections are not allowed".into()) };
    Ok(vec![(host, ports.first().copied().unwrap_or(5432))]) }

#[cfg(target_arch = "wasm32")]
pub fn targets(conn: &str) -> Result<Vec<(String, u16)>, String> { Ok(vec![host_port(conn)?]) }

fn ident(name: &str) -> String { format!("\"{}\"", name.replace('"', "\"\"")) }

/// Postgres timestamp literal in UTC, without a date library.
fn timestamp(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = crate::clock::utc_parts(unix);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}+00", y, mo, d, h, mi, s)
}
fn literal(value: &str) -> String { format!("'{}'", value.replace('\'', "''")) }

/// Create a login role. The statements match what the native server always ran:
/// one role, one password, no grants.
pub async fn create_role(conn: &str, username: &str, password: &str, expires_at: i64) -> Result<(), String> {
    let client = client(conn).await?;
    // Postgres refuses logins after VALID UNTIL even if nobody revokes the lease.
    let sql = format!("CREATE ROLE {} LOGIN PASSWORD {} VALID UNTIL {}", ident(username), literal(password), literal(&timestamp(expires_at)));
    client.execute(&sql, &[]).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn drop_role(conn: &str, username: &str) -> Result<(), String> {
    let client = client(conn).await?;
    let sql = format!("DROP ROLE IF EXISTS {}", ident(username));
    client.execute(&sql, &[]).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
async fn client(conn: &str) -> Result<tokio_postgres::Client, String> {
    // Decide transport from the parsed mode, never a substring of the URL.
    let mut config = conn.parse::<tokio_postgres::Config>().map_err(|e| e.to_string())?;
    if config.get_ssl_mode() == tokio_postgres::config::SslMode::Disable {
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move { let _ = connection.await; });
        return Ok(client);
    }
    // A default or explicit Prefer would let the driver fall back to plaintext.
    config.ssl_mode(tokio_postgres::config::SslMode::Require);
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let (client, connection) = config.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls)).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move { let _ = connection.await; });
    Ok(client)
}

#[cfg(target_arch = "wasm32")]
async fn client(conn: &str) -> Result<tokio_postgres::Client, String> {
    let (host, port) = host_port(conn)?;
    let config = conn.parse::<tokio_postgres::Config>().map_err(|e| e.to_string())?;
    // StartTls covers the normal case (Hyperdrive or a TLS-enabled database).
    // A local database with TLS off needs the explicit opt-out, same as native.
    let transport = if config.get_ssl_mode() == tokio_postgres::config::SslMode::Disable {
        worker::SecureTransport::Off
    } else {
        worker::SecureTransport::StartTls
    };
    let socket = worker::Socket::builder()
        .secure_transport(transport)
        .connect(host, port)
        .map_err(|e| e.to_string())?;
    // TLS is already inside the socket, so the Postgres client passes through.
    let (client, connection) = config.connect_raw(socket, worker::postgres_tls::PassthroughTls).await.map_err(|e| e.to_string())?;
    wasm_bindgen_futures::spawn_local(async move { let _ = connection.await; });
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_postgres_hosts() {
        assert_eq!(host_port("postgres://u:p@db.example.com:5433/app").unwrap(), ("db.example.com".into(), 5433));
        assert_eq!(host_port("postgres://u@localhost/app").unwrap(), ("localhost".into(), 5432));
        assert_eq!(host_port("postgresql://u@[::1]:6543/app").unwrap(), ("::1".into(), 6543));
        assert!(host_port("postgres://u@a,b/app").is_err());
        assert!(host_port("mysql://u@host/app").is_err());
    }

    #[test]
    fn formats_postgres_timestamps() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00+00");
        assert_eq!(timestamp(1_767_225_600), "2026-01-01 00:00:00+00");
    }

    #[test]
    fn quotes_identifiers_and_literals() {
        assert_eq!(ident("dyn_abc"), "\"dyn_abc\"");
        assert_eq!(ident("we\"ird"), "\"we\"\"ird\"");
        assert_eq!(literal("p'a"), "'p''a'");
    }
}
