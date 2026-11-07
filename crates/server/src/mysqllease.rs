//! Dynamic MySQL/MariaDB lease accounts.
//!
//! A lease creates an account with a random password and the privileges the
//! caller named, and revokes it by dropping the account. Native builds connect
//! with `mysql_async`. The Workers build speaks the small part of the MySQL
//! protocol needed for CREATE USER, GRANT and DROP USER over a Cloudflare
//! socket, because `mysql_async` needs tokio's network stack.

#[cfg(any(target_arch = "wasm32", test))]
use sha1::{Digest, Sha1};
#[cfg(any(target_arch = "wasm32", test))]
use sha2::Sha256;

#[derive(Clone, Debug, PartialEq)]
pub struct MySqlUrl {
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    /// TLS is off unless the URL asks for it, matching the native driver.
    pub require_ssl: bool,
}

fn scheme_ok(scheme: &str) -> bool { scheme.eq_ignore_ascii_case("mysql") || scheme.eq_ignore_ascii_case("mariadb") }

fn decode(value: &str) -> String {
    let bytes = value.as_bytes(); let mut out = Vec::with_capacity(bytes.len()); let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) { out.push(byte); i += 3; continue; } }
        out.push(bytes[i]); i += 1; }
    String::from_utf8_lossy(&out).into_owned() }

fn host_port_of(hostport: &str) -> Result<(String, u16), String> {
    if hostport.is_empty() { return Err("connection string has no host".into()); }
    if let Some(inner) = hostport.strip_prefix('[') {
        let (host, tail) = inner.split_once(']').ok_or("invalid IPv6 host")?;
        let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(3306);
        return Ok((host.to_string(), port)); }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((host.to_string(), port.parse::<u16>().unwrap_or(3306))),
        _ => Ok((hostport.to_string(), 3306)) } }

pub fn parse_url(conn: &str) -> Result<MySqlUrl, String> {
    let (scheme, rest) = conn.split_once("://").ok_or("connection string must be a mysql:// or mariadb:// URL")?;
    if !scheme_ok(scheme) { return Err("connection string must be a mysql:// or mariadb:// URL".into()); }
    let (authority, tail) = match rest.find(['/', '?']) { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "") };
    if authority.contains(',') { return Err("multi-host connection strings are not allowed".into()); }
    let (userinfo, hostport) = match authority.rsplit_once('@') { Some((u, h)) => (Some(u), h), None => (None, authority) };
    let (user, password) = match userinfo {
        Some(u) => match u.split_once(':') { Some((user, pass)) => (decode(user), decode(pass)), None => (decode(u), String::new()) },
        None => (String::new(), String::new()) };
    let (host, port) = host_port_of(hostport)?;
    let (database, query) = if let Some(rest) = tail.strip_prefix('/') {
        match rest.split_once('?') { Some((db, q)) => (decode(db), q), None => (decode(rest), "") }
    } else { (String::new(), tail.strip_prefix('?').unwrap_or("")) };
    let mut require_ssl = false;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key.to_ascii_lowercase().as_str() {
            "require_ssl" | "ssl_mode" | "ssl-mode" => match value.to_ascii_lowercase().as_str() {
                "true" | "1" | "required" | "verify_ca" | "verify_identity" => require_ssl = true,
                _ => require_ssl = false },
            _ => {} } }
    Ok(MySqlUrl { user, password, host, port, database, require_ssl }) }

/// Host and port for the allowlist and the Workers socket.
pub fn host_port(conn: &str) -> Result<(String, u16), String> { let url = parse_url(conn)?; Ok((url.host, url.port)) }

#[cfg(not(target_arch = "wasm32"))]
fn driver_url(conn: &str) -> String { format!("mysql://{}", conn.split_once("://").map(|x| x.1).unwrap_or(conn)) }

/// Every target the driver would dial. The driver parses the URL, so a query
/// parameter cannot point the connection somewhere the authority did not name.
#[cfg(not(target_arch = "wasm32"))]
pub fn targets(conn: &str) -> Result<Vec<(String, u16)>, String> {
    let url = driver_url(conn);
    let opts = mysql_async::Opts::from_url(&url).map_err(|e| format!("invalid mysql connection string: {}", e))?;
    if opts.socket().is_some() { return Err("unix-socket connections are not allowed".into()); }
    Ok(vec![(opts.ip_or_hostname().to_string(), opts.tcp_port())]) }

#[cfg(target_arch = "wasm32")]
pub fn targets(conn: &str) -> Result<Vec<(String, u16)>, String> { Ok(vec![host_port(conn)?]) }

#[cfg(any(target_arch = "wasm32", test))]
fn native_scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() { return Vec::new(); }
    let mut hash = Sha1::new();
    hash.update(password.as_bytes()); let stage1 = hash.finalize_reset();
    hash.update(stage1); let stage2 = hash.finalize_reset();
    hash.update(nonce); hash.update(stage2); let mix = hash.finalize();
    stage1.iter().zip(mix.iter()).map(|(a, b)| a ^ b).collect() }

#[cfg(any(target_arch = "wasm32", test))]
fn sha2_scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() { return Vec::new(); }
    let mut hash = Sha256::new();
    hash.update(password.as_bytes()); let stage1 = hash.finalize_reset();
    hash.update(stage1); let stage2 = hash.finalize_reset();
    hash.update(stage2); hash.update(nonce); let mix = hash.finalize();
    stage1.iter().zip(mix.iter()).map(|(a, b)| a ^ b).collect() }

#[cfg(any(target_arch = "wasm32", test))]
fn scramble(plugin: &str, password: &str, nonce: &[u8]) -> Result<Vec<u8>, String> {
    match plugin {
        "mysql_native_password" | "" => Ok(native_scramble(password, nonce)),
        "caching_sha2_password" => Ok(sha2_scramble(password, nonce)),
        other => Err(format!("unsupported MySQL auth plugin {}", other)) } }

fn ident_ok(name: &str) -> bool { !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') }

const GRANT_PRIVS: &[&str] = &["SELECT","INSERT","UPDATE","DELETE","CREATE","DROP","ALTER","INDEX","REFERENCES","EXECUTE","CREATE VIEW","SHOW VIEW","CREATE ROUTINE","ALTER ROUTINE","EVENT","TRIGGER","CREATE TEMPORARY TABLES","LOCK TABLES"];

/// Turn one `privileges ON database[.table]` entry into a GRANT statement. The
/// lease account gets only what the caller spelled out, never a wildcard schema.
pub fn grant_sql(grant: &str, user: &str) -> Result<String, String> {
    if !ident_ok(user) { return Err("invalid lease account name".into()); }
    let lower = grant.to_ascii_lowercase();
    let at = lower.find(" on ").ok_or("each grant must read \"PRIV1, PRIV2 ON database[.table]\"")?;
    let mut privs: Vec<String> = Vec::new();
    for p in grant[..at].split(',') {
        let p = p.trim().to_ascii_uppercase();
        if !GRANT_PRIVS.contains(&p.as_str()) { return Err(format!("grant privilege is not allowed: {}", p)); }
        if !privs.contains(&p) { privs.push(p); } }
    if privs.is_empty() { return Err("a grant needs at least one privilege".into()); }
    let target = grant[at + 4..].trim();
    let (db, table) = target.split_once('.').ok_or("grant target must be database.table or database.*")?;
    if db == "*" { return Err("a wildcard database is not allowed; name the database the lease may use".into()); }
    if !ident_ok(db) || !(table == "*" || ident_ok(table)) { return Err("grant target must use plain identifiers".into()); }
    let table = if table == "*" { "*".to_string() } else { format!("`{}`", table) };
    Ok(format!("GRANT {} ON `{}`.{} TO '{}'@'%'", privs.join(", "), db, table, user)) }

pub async fn create_account(conn: &str, username: &str, password: &str, grants: &[String]) -> Result<(), String> {
    if !ident_ok(username) { return Err("invalid lease account name".into()); }
    if username.len() > 32 { return Err("lease account names are limited to 32 characters".into()); }
    let mut statements = vec![format!("CREATE USER '{}'@'%' IDENTIFIED BY '{}'", username, password.replace('\'', "''"))];
    for grant in grants { statements.push(grant_sql(grant, username)?); }
    run(conn, &statements).await }

pub async fn drop_account(conn: &str, username: &str) -> Result<(), String> {
    if !ident_ok(username) { return Err("invalid lease account name".into()); }
    run(conn, &[format!("DROP USER IF EXISTS '{}'@'%'", username)]).await }

// --- native driver ---
#[cfg(not(target_arch = "wasm32"))]
async fn run(conn: &str, statements: &[String]) -> Result<(), String> {
    use mysql_async::prelude::Queryable;
    let url = driver_url(conn);
    let opts = mysql_async::Opts::from_url(&url).map_err(|e| e.to_string())?;
    let pool = mysql_async::Pool::new(opts);
    let work = async {
        let mut client = pool.get_conn().await.map_err(|e| e.to_string())?;
        for statement in statements { client.query_drop(statement.as_str()).await.map_err(|e| e.to_string())?; }
        Ok(()) };
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), work).await
        .map_err(|_| "database lease target did not answer within 10s".to_string())?;
    pool.disconnect().await.ok();
    result }

// --- Workers protocol client ---
#[cfg(target_arch = "wasm32")]
async fn run(conn: &str, statements: &[String]) -> Result<(), String> {
    let url = parse_url(conn)?;
    let mut client = wire::Client::connect(&url).await?;
    for statement in statements { client.query(statement).await?; }
    client.close().await;
    Ok(()) }

#[cfg(target_arch = "wasm32")]
mod wire {
    use super::{scramble, MySqlUrl};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use worker::Socket;

    const CLIENT_LONG_PASSWORD: u32 = 0x1;
    const CLIENT_CONNECT_WITH_DB: u32 = 0x8;
    const CLIENT_PROTOCOL_41: u32 = 0x200;
    const CLIENT_SSL: u32 = 0x800;
    const CLIENT_TRANSACTIONS: u32 = 0x2000;
    const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
    const CLIENT_PLUGIN_AUTH: u32 = 0x80000;
    const CHARSET_UTF8MB4: u8 = 45;

    fn caps(with_db: bool, tls: bool) -> u32 {
        CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
            | if with_db { CLIENT_CONNECT_WITH_DB } else { 0 }
            | if tls { CLIENT_SSL } else { 0 } }

    struct Handshake { plugin: String, nonce: Vec<u8> }

    impl Handshake {
        fn parse(packet: &[u8]) -> Result<Self, String> {
            let mut i = 0usize;
            let version = *packet.first().ok_or("empty handshake")?; i += 1;
            if version != 10 { return Err(format!("unsupported MySQL protocol version {}", version)); }
            let end = packet[i..].iter().position(|b| *b == 0).ok_or("short handshake")? + i;
            i = end + 1; i += 4; // server version, connection id
            let part1 = packet.get(i..i + 8).ok_or("short handshake")?; i += 8 + 1;
            let cap_low = read_u16(packet, i)? as u32; i += 2 + 1 + 2;
            let cap_high = read_u16(packet, i)? as u32; i += 2;
            let capabilities = cap_low | (cap_high << 16);
            let auth_len = *packet.get(i).ok_or("short handshake")? as usize; i += 1 + 10;
            let second_len = auth_len.saturating_sub(8).max(13);
            let part2 = packet.get(i..i + second_len).ok_or("short handshake")?;
            i += second_len;
            let mut nonce = part1.to_vec();
            nonce.extend(part2.iter().copied().take(auth_len.saturating_sub(9)));
            let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
                let tail = packet.get(i..).unwrap_or(&[]);
                let name = tail.iter().position(|b| *b == 0).map(|n| &tail[..n]).unwrap_or(tail);
                String::from_utf8_lossy(name).into_owned()
            } else { "mysql_native_password".to_string() };
            Ok(Handshake { plugin, nonce }) } }

    fn read_u16(packet: &[u8], at: usize) -> Result<u16, String> {
        let bytes = packet.get(at..at + 2).ok_or("short handshake")?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]])) }

    fn err_message(packet: &[u8]) -> String {
        let text = if packet.len() > 9 && packet[3] == b'#' { &packet[9..] } else { &packet[3.min(packet.len())..] };
        format!("MySQL error: {}", String::from_utf8_lossy(text)) }

    async fn read_packet(socket: &mut Socket, seq: &mut u8) -> Result<Vec<u8>, String> {
        let mut header = [0u8; 4];
        socket.read_exact(&mut header).await.map_err(|e| e.to_string())?;
        let len = header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
        *seq = header[3].wrapping_add(1);
        let mut payload = vec![0u8; len];
        socket.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
        Ok(payload) }

    async fn write_packet(socket: &mut Socket, seq: &mut u8, payload: &[u8]) -> Result<(), String> {
        let len = payload.len();
        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&[len as u8, (len >> 8) as u8, (len >> 16) as u8, *seq]);
        frame.extend_from_slice(payload);
        *seq = seq.wrapping_add(1);
        socket.write_all(&frame).await.map_err(|e| e.to_string())?;
        socket.flush().await.map_err(|e| e.to_string()) }

    pub struct Client { socket: Socket, seq: u8 }

    impl Client {
        pub async fn connect(url: &MySqlUrl) -> Result<Self, String> {
            let transport = if url.require_ssl { worker::SecureTransport::StartTls } else { worker::SecureTransport::Off };
            let mut socket = worker::Socket::builder().secure_transport(transport).connect(url.host.clone(), url.port).map_err(|e| e.to_string())?;
            let mut seq = 0u8;
            let handshake = Handshake::parse(&read_packet(&mut socket, &mut seq).await?)?;
            let with_db = !url.database.is_empty();
            let capabilities = caps(with_db, url.require_ssl);
            if url.require_ssl {
                // SSLRequest, then the socket upgrades and the handshake response
                // continues encrypted on the next sequence number.
                let mut request = Vec::with_capacity(32);
                request.extend_from_slice(&capabilities.to_le_bytes());
                request.extend_from_slice(&16_777_215u32.to_le_bytes());
                request.push(CHARSET_UTF8MB4);
                request.extend_from_slice(&[0u8; 23]);
                write_packet(&mut socket, &mut seq, &request).await?;
                socket = socket.start_tls();
            }
            let auth = scramble(&handshake.plugin, &url.password, &handshake.nonce)?;
            let mut response = Vec::new();
            response.extend_from_slice(&capabilities.to_le_bytes());
            response.extend_from_slice(&16_777_215u32.to_le_bytes());
            response.push(CHARSET_UTF8MB4);
            response.extend_from_slice(&[0u8; 23]);
            response.extend_from_slice(url.user.as_bytes()); response.push(0);
            response.push(auth.len() as u8); response.extend_from_slice(&auth);
            if with_db { response.extend_from_slice(url.database.as_bytes()); response.push(0); }
            response.extend_from_slice(handshake.plugin.as_bytes()); response.push(0);
            write_packet(&mut socket, &mut seq, &response).await?;
            let mut plugin: String;
            let mut nonce: Vec<u8>;
            loop {
                let packet = read_packet(&mut socket, &mut seq).await?;
                match packet.first().copied() {
                    Some(0x00) => break,
                    Some(0xff) => return Err(err_message(&packet)),
                    Some(0xfe) if packet.len() > 1 => {
                        // Auth switch: plugin name NUL, then a new nonce.
                        let body = &packet[1..];
                        let end = body.iter().position(|b| *b == 0).ok_or("short auth switch")?;
                        plugin = String::from_utf8_lossy(&body[..end]).into_owned();
                        nonce = body[end + 1..].iter().copied().filter(|b| *b != 0).collect();
                        let auth = scramble(&plugin, &url.password, &nonce)?;
                        write_packet(&mut socket, &mut seq, &auth).await?;
                    }
                    Some(0x01) => match packet.get(1).copied() {
                        Some(0x03) => continue, // fast auth succeeded; the OK follows
                        Some(0x04) if url.require_ssl => {
                            let mut clear = url.password.as_bytes().to_vec(); clear.push(0);
                            write_packet(&mut socket, &mut seq, &clear).await?;
                        }
                        Some(0x04) => return Err("this account needs full authentication; set require_ssl=true on the lease connection".into()),
                        _ => return Err("unexpected MySQL auth response".into()),
                    },
                    _ => return Err("unexpected MySQL auth packet".into()) } }
            Ok(Client { socket, seq: 0 }) }

        pub async fn query(&mut self, sql: &str) -> Result<(), String> {
            self.seq = 0;
            let mut payload = Vec::with_capacity(1 + sql.len());
            payload.push(0x03);
            payload.extend_from_slice(sql.as_bytes());
            write_packet(&mut self.socket, &mut self.seq, &payload).await?;
            let packet = read_packet(&mut self.socket, &mut self.seq).await?;
            match packet.first().copied() {
                Some(0x00) => Ok(()),
                Some(0xff) => Err(err_message(&packet)),
                _ => Err("unexpected result for a lease statement".into()) } }

        pub async fn close(mut self) {
            let _ = write_packet(&mut self.socket, &mut self.seq, &[0x01]).await; } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mysql_urls() {
        let url = parse_url("mysql://admin:p%40ss@db.example.com:3307/app?require_ssl=true").unwrap();
        assert_eq!(url.host, "db.example.com");
        assert_eq!(url.port, 3307);
        assert_eq!(url.user, "admin");
        assert_eq!(url.password, "p@ss");
        assert_eq!(url.database, "app");
        assert!(url.require_ssl);
        let defaults = parse_url("mariadb://u@db.internal/app").unwrap();
        assert_eq!(defaults.port, 3306);
        assert!(!defaults.require_ssl);
        assert!(parse_url("postgres://u@h/db").is_err());
        assert!(parse_url("mysql://u@a,b/db").is_err());
        let v6 = parse_url("mysql://u@[::1]:3308/db").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 3308);
    }

    #[test]
    fn auth_scrambles_match_independent_vectors() {
        let nonce = b"12345678901234567890";
        assert_eq!(hex(&native_scramble("secret", nonce)), "0f8b9033e0897c0a8338ebe3dea9010dda47ab56");
        assert_eq!(hex(&sha2_scramble("secret", nonce)), "51ecd6dedbd34d5445c0a190d4f51acf0d23b94db66c91f3f789faa9193751cd");
        assert!(native_scramble("", nonce).is_empty());
        assert_ne!(native_scramble("secret", b"different-nonce!"), native_scramble("secret", nonce));
        assert!(scramble("auth_gssapi_client", "secret", nonce).is_err());
    }

    #[test]
    fn grants_stay_least_privilege() {
        assert_eq!(grant_sql("select on app.users", "dyn_x").unwrap(), "GRANT SELECT ON `app`.`users` TO 'dyn_x'@'%'");
        for bad in ["ALL ON app.*", "GRANT OPTION ON app.*", "SELECT ON *.*", "SELECT ON app.*; DROP USER x", "SELECT ON app", "SELECT ON app.users.x", "SELECT"] {
            assert!(grant_sql(bad, "dyn_x").is_err(), "accepted {:?}", bad); }
        assert!(grant_sql("SELECT ON app.*", "bad'name").is_err());
    }

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }
}
