#![cfg(feature = "ldap")]
// LDAP suite: the real server binary against a private database and an
// in-process LDAPS directory. The stub speaks just enough BER for bind and
// search, and records the filters and bind attempts the server sends.

use hmac::Mac;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static ISSUED_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

// ---------- stub directory ----------

#[derive(Clone)]
struct DirectoryUser {
    username: String,
    dn: String,
    email: String,
    name: String,
    groups: Vec<String>,
    password: String,
}

struct Stub {
    port: u16,
    ca_pem: String,
    filters: Arc<Mutex<Vec<String>>>,
    binds: Arc<Mutex<Vec<(String, String)>>>,
    users: Arc<Mutex<Vec<DirectoryUser>>>,
}

impl Stub {
    fn set_groups(&self, username: &str, groups: Vec<String>) {
        if let Some(user) = self.users.lock().unwrap().iter_mut().find(|u| u.username == username) {
            user.groups = groups;
        }
    }
}

fn start_directory(users: Vec<DirectoryUser>) -> Stub {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "OpenWarp test CA");
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("leaf params");
    leaf_params.distinguished_name.push(DnType::CommonName, "127.0.0.1");
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).expect("leaf cert");

    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("tls config");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().expect("stub addr").port();
    let filters = Arc::new(Mutex::new(Vec::new()));
    let binds = Arc::new(Mutex::new(Vec::new()));
    let users = Arc::new(Mutex::new(users));
    let seen_filters = filters.clone();
    let seen_binds = binds.clone();
    let live_users = users.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let config = config.clone();
            let users = live_users.clone();
            let filters = seen_filters.clone();
            let binds = seen_binds.clone();
            std::thread::spawn(move || {
                if let Ok(conn) = ServerConnection::new(config) {
                    let mut tls = StreamOwned::new(conn, stream);
                    serve(&mut tls, &users, &filters, &binds);
                }
            });
        }
    });

    Stub { port, ca_pem: ca.pem(), filters, binds, users }
}

const SERVICE_DN: &str = "cn=openwarp,ou=services,dc=example,dc=com";
const SERVICE_PASSWORD: &str = "service-secret";

fn serve(mut tls: impl Read + Write, users: &Mutex<Vec<DirectoryUser>>, filters: &Mutex<Vec<String>>, binds: &Mutex<Vec<(String, String)>>) {
    let mut service_bound = false;
    while let Some(frame) = read_frame(&mut tls) {
        let Some((msgid, op, content)) = ldap_message(&frame) else { return };
        match op {
            // UnbindRequest
            0x42 => return,
            // BindRequest
            0x60 => {
                let Some((name, password)) = bind_request(&content) else { return };
                binds.lock().unwrap().push((name.clone(), password.clone()));
                let ok = !password.is_empty()
                    && ((name == SERVICE_DN && password == SERVICE_PASSWORD)
                        || users.lock().unwrap().iter().any(|u| u.dn == name && u.password == password));
                service_bound = ok && name == SERVICE_DN;
                if write_all(&mut tls, &bind_response(msgid, if ok { 0 } else { 49 })).is_err() {
                    return;
                }
            }
            // SearchRequest
            0x63 => {
                let Some((filter, _attrs)) = search_request(&content) else { return };
                let mut values = Vec::new();
                collect_equalities(&filter, b"uid", &mut values);
                if let Some(v) = values.first() {
                    filters.lock().unwrap().push(v.clone());
                }
                let matched = if service_bound && values.len() == 1 {
                    users.lock().unwrap().iter().find(|u| u.username == values[0]).cloned()
                } else {
                    None
                };
                if let Some(u) = &matched {
                    if write_all(&mut tls, &search_entry(msgid, u)).is_err() {
                        return;
                    }
                }
                if write_all(&mut tls, &search_done(msgid, 0)).is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

fn read_frame(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let mut frame = head.to_vec();
    let len = if head[1] & 0x80 == 0 {
        head[1] as usize
    } else {
        let n = (head[1] & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut raw = vec![0u8; n];
        stream.read_exact(&mut raw).ok()?;
        frame.extend_from_slice(&raw);
        raw.iter().fold(0usize, |a, b| (a << 8) | *b as usize)
    };
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).ok()?;
    frame.extend_from_slice(&body);
    Some(frame)
}

fn ldap_message(frame: &[u8]) -> Option<(u32, u8, Vec<u8>)> {
    let (tag, content, _) = parse_tlv(frame)?;
    if tag != 0x30 {
        return None;
    }
    let (t1, id, used) = parse_tlv(content)?;
    if t1 != 0x02 {
        return None;
    }
    let msgid = id.iter().fold(0u32, |a, b| (a << 8) | *b as u32);
    let (op, body, _) = parse_tlv(&content[used..])?;
    Some((msgid, op, body.to_vec()))
}

fn bind_request(op: &[u8]) -> Option<(String, String)> {
    let (t1, _version, u1) = parse_tlv(op)?;
    if t1 != 0x02 {
        return None;
    }
    let (t2, name, u2) = parse_tlv(&op[u1..])?;
    if t2 != 0x04 {
        return None;
    }
    let (t3, password, _) = parse_tlv(&op[u1 + u2..])?;
    if t3 != 0x80 {
        return None;
    }
    Some((String::from_utf8_lossy(name).into_owned(), String::from_utf8_lossy(password).into_owned()))
}

fn search_request(op: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let mut rest = op;
    let (t, _base, used) = parse_tlv(rest)?;
    if t != 0x04 {
        return None;
    }
    rest = &rest[used..];
    // scope, derefAliases, sizeLimit, timeLimit, typesOnly
    for _ in 0..5 {
        let (_, _, used) = parse_tlv(rest)?;
        rest = &rest[used..];
    }
    let (ftag, fcontent, used) = parse_tlv(rest)?;
    let filter = tlv_bytes(ftag, fcontent);
    rest = &rest[used..];
    let (_, attrs, _) = parse_tlv(rest)?;
    let mut names = Vec::new();
    let mut cursor = attrs;
    while let Some((_, value, used)) = parse_tlv(cursor) {
        names.push(String::from_utf8_lossy(value).into_owned());
        cursor = &cursor[used..];
    }
    Some((filter, names))
}

// Equality, and/or/not recursion. Only equality assertions are collected; a
// filter that failed to escape an injected `*` shows up as extra structure and
// therefore a different number of assertions.
fn collect_equalities(filter: &[u8], attr: &[u8], out: &mut Vec<String>) {
    let Some((tag, content, _)) = parse_tlv(filter) else { return };
    match tag {
        0xA0 | 0xA1 => {
            let mut rest = content;
            while let Some((t, c, used)) = parse_tlv(rest) {
                collect_equalities(&tlv_bytes(t, c), attr, out);
                rest = &rest[used..];
            }
        }
        0xA2 => {
            if let Some((t, c, _)) = parse_tlv(content) {
                collect_equalities(&tlv_bytes(t, c), attr, out);
            }
        }
        0xA3 => {
            let Some((t1, a, u1)) = parse_tlv(content) else { return };
            let Some((t2, v, _)) = parse_tlv(&content[u1..]) else { return };
            if t1 == 0x04 && t2 == 0x04 && a.eq_ignore_ascii_case(attr) {
                out.push(String::from_utf8_lossy(v).into_owned());
            }
        }
        _ => {}
    }
}

fn bind_response(msgid: u32, code: u8) -> Vec<u8> {
    let mut body = enumerated(&[code]); body.extend(octet(b"")); body.extend(octet(b""));
    ldap_reply(msgid, 0x61, &body)
}

fn search_done(msgid: u32, code: u8) -> Vec<u8> {
    let mut body = enumerated(&[code]); body.extend(octet(b"")); body.extend(octet(b""));
    ldap_reply(msgid, 0x65, &body)
}

fn search_entry(msgid: u32, user: &DirectoryUser) -> Vec<u8> {
    let mut attrs = Vec::new();
    for (name, values) in [
        ("mail", vec![user.email.clone()]),
        ("displayName", vec![user.name.clone()]),
        ("memberOf", user.groups.clone()),
    ] {
        let mut set = Vec::new();
        for value in values {
            set.extend(octet(value.as_bytes()));
        }
        let mut partial = octet(name.as_bytes());
        partial.extend(tlv(0x31, &set));
        attrs.extend(tlv(0x30, &partial));
    }
    let mut content = octet(user.dn.as_bytes());
    content.extend(tlv(0x30, &attrs));
    ldap_reply(msgid, 0x64, &content)
}

fn ldap_reply(msgid: u32, tag: u8, content: &[u8]) -> Vec<u8> {
    let mut body = int(&[msgid as u8]);
    body.extend(tlv(tag, content));
    tlv(0x30, &body)
}

fn write_all(stream: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes)?;
    stream.flush()
}

fn tlv_bytes(tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(tag, content)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(content);
    out
}

fn int(value: &[u8]) -> Vec<u8> {
    tlv(0x02, value)
}

fn enumerated(value: &[u8]) -> Vec<u8> {
    tlv(0x0a, value)
}

fn octet(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

fn parse_tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let (len, header) = if buf[1] & 0x80 == 0 {
        (buf[1] as usize, 2)
    } else {
        let n = (buf[1] & 0x7f) as usize;
        if n == 0 || buf.len() < 2 + n {
            return None;
        }
        let len = buf[2..2 + n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, 2 + n)
    };
    if buf.len() < header + len {
        return None;
    }
    Some((tag, &buf[header..header + len], header + len))
}

// ---------- server under test ----------

struct Server {
    child: Child,
    base: String,
    dir: std::path::PathBuf,
    client: reqwest::Client,
    inbox: Arc<Mutex<Vec<Value>>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    // Two server processes must never share a port: the loser would take over
    // the winner's traffic. Ephemeral allocation plus a per-process record
    // closes the reuse window that a PID-derived range leaves open.
    let mut issued = ISSUED_PORTS.lock().unwrap();
    loop {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if !issued.contains(&port) {
            issued.push(port);
            return port;
        }
    }
}

impl Server {
    async fn start() -> Server {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("openwarp-ldap-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let port = free_port();
        let base = format!("http://127.0.0.1:{}", port);
        let (inbox_url, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_EMAIL_WEBHOOK", &inbox_url)
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY")
            .env_remove("REDIS_URL")
            .env_remove("OPENWARP_ENV")
            .env_remove("OPENWARP_SIGNUPS")
            .env_remove("OPENWARP_REQUIRE_EMAIL_VERIFICATION")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openwarp-server");
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15)).build().expect("http client");
        let server = Server { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            if let Ok(r) = server.client.get(server.url("/health")).send().await {
                if r.status().is_success() {
                    return server;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy at {}", server.base);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn call(&self, method: reqwest::Method, path: &str, token: Option<&str>, body: Option<Value>) -> Reply {
        let mut req = self.client.request(method, self.url(path));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        finish(req.send().await).await
    }

    async fn register(&self, email: &str, password: &str) -> (String, String) {
        let r = self.call(reqwest::Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": password}))).await;
        assert_eq!(r.status, 200, "register {} failed: {}", email, r.text);
        let org = r.body["org_id"].as_str().expect("org").to_string();
        // Password signup now needs the verification link, so finish the flow the
        // way an operator with a mail relay would before signing in.
        if r.body["verification_required"] == json!(true) {
            let text = wait_for_mail(&self.inbox, "/api/auth/verify?token=").await;
            let link = extract_link(&text, "/api/auth/verify?token=");
            let path = link.strip_prefix(&self.base).unwrap_or(&link).to_string();
            let verified = self.call(reqwest::Method::GET, &path, None, None).await;
            assert_eq!(verified.status, 200, "verification failed for {}: {}", email, verified.text);
            let login = self.call(reqwest::Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await;
            assert_eq!(login.status, 200, "verified sign-in failed for {}: {}", email, login.text);
            return (login.body["token"].as_str().expect("token").to_string(), org);
        }
        (r.body["token"].as_str().expect("token").to_string(), org)
    }

    async fn put_ldap(&self, token: &str, org: &str, dir: &Stub, extra: Value) -> Reply {
        let mut body = json!({
            "url": format!("ldaps://127.0.0.1:{}", dir.port),
            "bind_dn": SERVICE_DN,
            "bind_password": SERVICE_PASSWORD,
            "base_dn": "ou=people,dc=example,dc=com",
            "user_filter": "(&(objectClass=person)(uid={username}))",
            "email_attr": "mail",
            "name_attr": "displayName",
            "group_attr": "memberOf",
            "ca_cert_pem": dir.ca_pem,
        });
        if let Some(overrides) = extra.as_object() {
            for (k, v) in overrides {
                body[k] = v.clone();
            }
        }
        self.call(reqwest::Method::PUT, &format!("/api/orgs/{}/ldap", org), Some(token), Some(body)).await
    }

    async fn ldap_login(&self, org: &str, username: &str, password: &str) -> Reply {
        self.call(reqwest::Method::POST, "/api/auth/ldap", None,
            Some(json!({"org_id": org, "username": username, "password": password}))).await
    }
}

struct Reply {
    status: u16,
    text: String,
    body: Value,
}

async fn finish(result: Result<reqwest::Response, reqwest::Error>) -> Reply {
    let response = result.expect("http request");
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Reply { status, text, body }
}

/// Minimal email relay: records each JSON body and answers 200.
fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("inbox bind");
    let addr = listener.local_addr().expect("inbox addr");
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming { Ok(s) => s, Err(_) => continue };
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = match stream.read(&mut chunk) { Ok(0) => break, Ok(n) => n, Err(_) => break };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
            let body = String::from_utf8_lossy(&buf[end.min(buf.len())..]).to_string();
            if let Ok(v) = serde_json::from_str::<Value>(&body) { sink.lock().unwrap().push(v); }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", addr), inbox)
}

async fn wait_for_mail(inbox: &Arc<Mutex<Vec<Value>>>, needle: &str) -> String {
    for _ in 0..60 {
        { let guard = inbox.lock().unwrap();
          if let Some(m) = guard.iter().rev().find(|m| m["text"].as_str().unwrap_or("").contains(needle)) {
              return m["text"].as_str().unwrap_or("").to_string(); } }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no email containing {:?} arrived", needle);
}

fn extract_link(text: &str, needle: &str) -> String {
    for word in text.split_whitespace() {
        if let Some(i) = word.find(needle) { return word[i..].to_string(); }
    }
    panic!("no link containing {:?} in {:?}", needle, text);
}

fn user(username: &str, email: &str) -> DirectoryUser {
    DirectoryUser {
        username: username.to_string(),
        dn: format!("uid={},ou=people,dc=example,dc=com", username),
        email: email.to_string(),
        name: username.to_string(),
        groups: vec![],
        password: "user-secret".to_string(),
    }
}

fn totp(secret_b32: &str) -> String {
    let mut out = Vec::new();
    let (mut val, mut bits) = (0u32, 0u32);
    for c in secret_b32.chars() {
        let d = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;
        val = (val << 5) | d;
        bits += 5;
        if bits >= 8 {
            out.push(((val >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    let counter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&out).expect("hmac");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let off = (hash[19] & 0x0f) as usize;
    let code = (((hash[off] as u32 & 0x7f) << 24)
        | ((hash[off + 1] as u32) << 16)
        | ((hash[off + 2] as u32) << 8)
        | hash[off + 3] as u32)
        % 1_000_000;
    format!("{:06}", code)
}

// ---------- tests ----------

#[tokio::test]
async fn ldap_config_is_admin_only_and_requires_tls_and_a_placeholder() {
    let s = Server::start().await;
    let dir = start_directory(vec![]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    let (other, other_org) = s.register("other@example.com", "password123").await;

    let before = s.call(reqwest::Method::GET, &format!("/api/orgs/{}/ldap", org), Some(&owner), None).await;
    assert_eq!(before.status, 200);
    assert_eq!(before.body["configured"], json!(false));

    let denied = s.put_ldap(&other, &org, &dir, json!({})).await;
    assert_eq!(denied.status, 403, "non-admin configured LDAP: {}", denied.text);

    let plaintext = s.put_ldap(&owner, &org, &dir, json!({"url": format!("ldap://127.0.0.1:{}", dir.port)})).await;
    assert_eq!(plaintext.status, 400, "ldap:// must be refused: {}", plaintext.text);

    let no_placeholder = s.put_ldap(&owner, &org, &dir, json!({"user_filter": "(uid=admin)"})).await;
    assert_eq!(no_placeholder.status, 400, "filter without {{username}} accepted: {}", no_placeholder.text);

    let no_password = s.put_ldap(&owner, &org, &dir, json!({"bind_password": ""})).await;
    assert_eq!(no_password.status, 400, "empty bind password accepted: {}", no_password.text);

    let ok = s.put_ldap(&owner, &org, &dir, json!({})).await;
    assert_eq!(ok.status, 200, "valid config rejected: {}", ok.text);
    let after = s.call(reqwest::Method::GET, &format!("/api/orgs/{}/ldap", org), Some(&owner), None).await;
    assert_eq!(after.body["configured"], json!(true));
    assert_eq!(after.body["bind_password_set"], json!(true));
    assert!(!after.text.contains(SERVICE_PASSWORD), "the service password leaked in the config response: {}", after.text);

    let _ = other_org;
}

#[tokio::test]
async fn ldap_login_provisions_the_user_and_applies_group_roles() {
    let s = Server::start().await;
    let mut bob = user("bob", "bob@example.com");
    bob.groups = vec!["CN=Admins,OU=Groups,DC=example,DC=com".to_string()];
    let dir = start_directory(vec![bob]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    let saved = s.put_ldap(&owner, &org, &dir, json!({"group_roles": "Admins=admin", "auto_provision": true, "allowed_domains": "example.com"})).await;
    assert_eq!(saved.status, 200, "config failed: {}", saved.text);

    let r = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(r.status, 200, "ldap login failed: {}", r.text);
    let token = r.body["token"].as_str().expect("token").to_string();
    let uid = r.body["user_id"].as_str().expect("user id").to_string();

    let me = s.call(reqwest::Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(me.status, 200);
    assert_eq!(me.body["email"], json!("bob@example.com"));

    let orgs = s.call(reqwest::Method::GET, "/api/orgs", Some(&token), None).await;
    let role = orgs.body.as_array().and_then(|a| a.iter().find(|o| o["id"] == json!(org))).and_then(|o| o["role"].as_str()).unwrap_or("");
    assert_eq!(role, "admin", "group mapping did not set the role: {}", orgs.text);

    // The directory DN, not the email, is the subject key.
    let again = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(again.status, 200);
    assert_eq!(again.body["user_id"], json!(uid));

    let audit = s.call(reqwest::Method::GET, &format!("/api/orgs/{}/audit", org), Some(&owner), None).await;
    assert!(audit.text.contains("auth.ldap_provision"), "provision audit missing: {}", audit.text);
    assert!(audit.text.contains("auth.ldap_login"), "login audit missing: {}", audit.text);
}

#[tokio::test]
async fn ldap_login_denies_wrong_unknown_and_empty_credentials() {
    let s = Server::start().await;
    let dir = start_directory(vec![user("bob", "bob@example.com")]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true})).await.status, 200);

    let wrong = s.ldap_login(&org, "bob", "not-the-password").await;
    assert_eq!(wrong.status, 401, "wrong password accepted: {}", wrong.text);

    let unknown = s.ldap_login(&org, "mallory", "whatever").await;
    assert_eq!(unknown.status, 401, "unknown user accepted: {}", unknown.text);

    let empty = s.ldap_login(&org, "bob", "").await;
    assert_eq!(empty.status, 401, "empty password accepted: {}", empty.text);
    let binds = dir.binds.lock().unwrap().clone();
    assert!(binds.iter().all(|(_, pw)| !pw.is_empty()), "an empty password reached the directory: {:?}", binds);
}

#[tokio::test]
async fn ldap_filter_injection_is_escaped() {
    let s = Server::start().await;
    let dir = start_directory(vec![user("bob", "bob@example.com")]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true})).await.status, 200);

    let hostile = "*)(uid=*";
    let r = s.ldap_login(&org, hostile, "user-secret").await;
    assert_eq!(r.status, 401, "injected username authenticated: {}", r.text);

    let filters = dir.filters.lock().unwrap().clone();
    assert_eq!(filters, vec![hostile.to_string()],
        "the directory saw a different filter (escaping broken): {:?}", filters);
}

#[tokio::test]
async fn ldap_provisioning_respects_invites_and_allowed_domains() {
    let s = Server::start().await;
    let dir = start_directory(vec![user("bob", "bob@example.com"), user("carol", "carol@elsewhere.test")]);
    let (owner, org) = s.register("owner@example.com", "password123").await;

    // Auto-provisioning off and no invite: refused.
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": false})).await.status, 200);
    let refused = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(refused.status, 403, "uninvited user provisioned: {}", refused.text);

    // An invitation admits the user with the invited role.
    let invite = s.call(reqwest::Method::POST, &format!("/api/orgs/{}/members", org), Some(&owner),
        Some(json!({"email": "bob@example.com", "role": "developer"}))).await;
    assert_eq!(invite.status, 200, "invite failed: {}", invite.text);
    let r = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(r.status, 200, "invited user refused: {}", r.text);
    let token = r.body["token"].as_str().expect("token").to_string();
    let orgs = s.call(reqwest::Method::GET, "/api/orgs", Some(&token), None).await;
    let role = orgs.body.as_array().and_then(|a| a.iter().find(|o| o["id"] == json!(org))).and_then(|o| o["role"].as_str()).unwrap_or("");
    assert_eq!(role, "developer", "invite role not applied: {}", orgs.text);

    // Auto-provisioning on, but the address is outside the allowed domains.
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true, "allowed_domains": "example.com"})).await.status, 200);
    let off_domain = s.ldap_login(&org, "carol", "user-secret").await;
    assert_eq!(off_domain.status, 403, "off-domain user provisioned: {}", off_domain.text);
}

#[tokio::test]
async fn ldap_login_requires_the_second_factor_when_enrolled() {
    let s = Server::start().await;
    let dir = start_directory(vec![user("bob", "bob@example.com")]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true})).await.status, 200);

    let first = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(first.status, 200, "provisioning login failed: {}", first.text);
    let token = first.body["token"].as_str().expect("token").to_string();

    let setup = s.call(reqwest::Method::POST, "/api/me/totp/setup", Some(&token), Some(json!({}))).await;
    assert_eq!(setup.status, 200, "totp setup failed: {}", setup.text);
    let secret = setup.body["secret"].as_str().expect("secret").to_string();
    let verified = s.call(reqwest::Method::POST, "/api/me/totp/verify", Some(&token), Some(json!({"code": totp(&secret)}))).await;
    assert_eq!(verified.status, 200, "totp verify failed: {}", verified.text);

    let challenged = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(challenged.status, 200);
    assert_eq!(challenged.body["mfa_required"], json!(true), "directory login skipped MFA: {}", challenged.text);
    assert!(challenged.body["token"].is_null(), "a session was issued before the second factor");
    let mfa_token = challenged.body["mfa_token"].as_str().expect("mfa token").to_string();

    let done = s.call(reqwest::Method::POST, "/api/auth/mfa", None,
        Some(json!({"mfa_token": mfa_token, "code": totp(&secret)}))).await;
    assert_eq!(done.status, 200, "MFA step failed: {}", done.text);
    let session = done.body["token"].as_str().expect("session").to_string();
    assert_eq!(s.call(reqwest::Method::GET, "/api/me", Some(&session), None).await.status, 200);
}

#[tokio::test]
async fn ldap_sign_in_stops_after_the_configuration_is_removed() {
    let s = Server::start().await;
    let dir = start_directory(vec![user("bob", "bob@example.com")]);
    let (owner, org) = s.register("owner@example.com", "password123").await;

    let unconfigured = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(unconfigured.status, 400, "login without config: {}", unconfigured.text);

    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true})).await.status, 200);
    assert_eq!(s.ldap_login(&org, "bob", "user-secret").await.status, 200);

    let removed = s.call(reqwest::Method::DELETE, &format!("/api/orgs/{}/ldap", org), Some(&owner), None).await;
    assert_eq!(removed.status, 200, "delete failed: {}", removed.text);
    let after = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(after.status, 400, "login still worked after removal: {}", after.text);
}

#[tokio::test]
async fn changing_the_directory_url_invalidates_existing_bindings() {
    let first_dir = start_directory(vec![user("bob", "bob@example.com")]);
    let s = Server::start().await;
    let (owner, org) = s.register("owner@example.com", "password123").await;
    assert_eq!(s.put_ldap(&owner, &org, &first_dir, json!({"auto_provision": true})).await.status, 200);
    assert_eq!(s.ldap_login(&org, "bob", "user-secret").await.status, 200);

    // A second directory that accepts anything for the same DN must not inherit
    // the binding created against the first one.
    let second_dir = start_directory(vec![user("bob", "bob@example.com")]);
    assert_eq!(s.put_ldap(&owner, &org, &second_dir, json!({"auto_provision": true})).await.status, 200);
    let after = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(after.status, 409, "a binding survived a directory URL change: {}", after.text);
}

#[tokio::test]
async fn leaving_a_mapped_group_revokes_the_mapped_role() {
    let mut bob = user("bob", "bob@example.com");
    bob.groups = vec!["CN=Admins,OU=Groups,DC=example,DC=com".to_string()];
    let dir = start_directory(vec![bob]);
    let s = Server::start().await;
    let (owner, org) = s.register("owner@example.com", "password123").await;
    let saved = s.put_ldap(&owner, &org, &dir,
        json!({"group_roles": "Admins=admin", "auto_provision": true, "default_role": "developer"})).await;
    assert_eq!(saved.status, 200, "config failed: {}", saved.text);

    let first = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(first.status, 200, "provisioning login failed: {}", first.text);
    let admin_token = first.body["token"].as_str().expect("token").to_string();
    assert_eq!(org_role(&s, &admin_token, &org).await, "admin");

    dir.set_groups("bob", vec![]);
    let second = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(second.status, 200, "login failed after the group change: {}", second.text);
    let token = second.body["token"].as_str().expect("token").to_string();
    assert_eq!(org_role(&s, &token, &org).await, "developer",
        "leaving the mapped group kept the mapped role");
}

#[tokio::test]
async fn failed_attempts_are_counted_before_the_directory_answers() {
    let dir = start_directory(vec![user("bob", "bob@example.com")]);
    let s = Server::start().await;
    let (owner, org) = s.register("owner@example.com", "password123").await;
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true})).await.status, 200);

    for attempt in 0..5 {
        let r = s.ldap_login(&org, "bob", "wrong-password").await;
        assert_eq!(r.status, 401, "attempt {}: {}", attempt, r.text);
    }
    let blocked = s.ldap_login(&org, "bob", "wrong-password").await;
    assert_eq!(blocked.status, 429, "the account budget was not enforced: {}", blocked.text);
}

async fn org_role(s: &Server, token: &str, org: &str) -> String {
    let r = s.call(reqwest::Method::GET, "/api/orgs", Some(token), None).await;
    r.body.as_array()
        .and_then(|orgs| orgs.iter().find(|o| o["id"] == json!(org)))
        .and_then(|o| o["role"].as_str())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn ldap_providers_are_advertised_to_the_console() {
    let s = Server::start().await;
    let r = s.call(reqwest::Method::GET, "/api/auth/providers", None, None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["ldap"], json!(true), "native build should advertise LDAP");
}

// The LDAP client parses responses with lber, which is recursive. A hostile
// directory must not be able to exhaust the process stack with deep nesting.
#[test]
fn deeply_nested_ber_is_rejected_before_it_reaches_the_stack() {
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 128 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap();
            out.push(0x80 | (bytes.len() - start) as u8);
            out.extend_from_slice(&bytes[start..]);
        }
        out.extend_from_slice(content);
        out
    }
    let mut wire = vec![0x0a, 0x01, 0x00];
    for _ in 0..100 {
        wire = tlv(0x30, &wire);
    }
    assert!(lber::parse::parse_tag(&wire).is_err(), "deep nesting must be refused, not parsed");
}

#[tokio::test]
async fn only_an_owner_can_map_the_owner_or_admin_role() {
    let s = Server::start().await;
    let dir = start_directory(vec![]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    let (admin_token, _) = s.register("admin@example.com", "password123").await;
    let promoted = s.call(reqwest::Method::POST, &format!("/api/orgs/{}/members", org), Some(&owner),
        Some(json!({"email": "admin@example.com", "role": "admin"}))).await;
    assert_eq!(promoted.status, 200, "promotion failed: {}", promoted.text);
    let accepted = s.call(reqwest::Method::POST, "/api/auth/accept-invite", Some(&admin_token), Some(json!({"token": promoted.body["invite_token"]}))).await;
    assert_eq!(accepted.status, 200, "accept admin invitation failed: {}", accepted.text);

    let owner_mapping = s.put_ldap(&admin_token, &org, &dir, json!({"group_roles": "Admins=owner"})).await;
    assert_eq!(owner_mapping.status, 403, "an admin mapped owner through LDAP: {}", owner_mapping.text);

    let unknown = s.put_ldap(&admin_token, &org, &dir, json!({"group_roles": "Admins=not_a_role"})).await;
    assert_eq!(unknown.status, 400, "a mapping to a nonexistent role was accepted: {}", unknown.text);

    let owner_default = s.put_ldap(&admin_token, &org, &dir, json!({"default_role": "admin"})).await;
    assert_eq!(owner_default.status, 403, "an admin set default_role admin through LDAP: {}", owner_default.text);

    // A custom role with admin permissions is the same escalation by another
    // name, so it is checked by effective permissions rather than the name.
    let wide = s.call(reqwest::Method::POST, &format!("/api/orgs/{}/roles", org), Some(&admin_token),
        Some(json!({"name": "ops", "permissions": ["*"]}))).await;
    assert_eq!(wide.status, 200, "custom role creation failed: {}", wide.text);
    let wide_mapping = s.put_ldap(&admin_token, &org, &dir, json!({"group_roles": "Admins=ops"})).await;
    assert_eq!(wide_mapping.status, 403, "an admin mapped an all-powerful custom role: {}", wide_mapping.text);

    let narrow = s.call(reqwest::Method::POST, &format!("/api/orgs/{}/roles", org), Some(&admin_token),
        Some(json!({"name": "reader", "permissions": ["secrets:read"]}))).await;
    assert_eq!(narrow.status, 200, "narrow role creation failed: {}", narrow.text);
    let narrow_mapping = s.put_ldap(&admin_token, &org, &dir, json!({"group_roles": "Admins=reader"})).await;
    assert_eq!(narrow_mapping.status, 200, "a read-only custom role was refused: {}", narrow_mapping.text);

    let by_owner = s.put_ldap(&owner, &org, &dir, json!({"group_roles": "Admins=admin"})).await;
    assert_eq!(by_owner.status, 200, "the owner was refused: {}", by_owner.text);
}

#[tokio::test]
async fn a_removed_member_cannot_sign_back_in_without_a_new_invite() {
    let s = Server::start().await;
    let dir = start_directory(vec![user("bob", "bob@example.com")]);
    let (owner, org) = s.register("owner@example.com", "password123").await;
    assert_eq!(s.put_ldap(&owner, &org, &dir, json!({"auto_provision": true})).await.status, 200);

    let first = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(first.status, 200, "provisioning login failed: {}", first.text);
    let uid = first.body["user_id"].as_str().expect("user id").to_string();

    let removed = s.call(reqwest::Method::DELETE, &format!("/api/orgs/{}/members/{}", org, uid), Some(&owner), None).await;
    assert_eq!(removed.status, 200, "removal failed: {}", removed.text);
    let back = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(back.status, 403, "a removed member signed back in: {}", back.text);

    let invite = s.call(reqwest::Method::POST, &format!("/api/orgs/{}/members", org), Some(&owner),
        Some(json!({"email": "bob@example.com", "role": "developer"}))).await;
    assert_eq!(invite.status, 200, "re-invite failed: {}", invite.text);
    let again = s.ldap_login(&org, "bob", "user-secret").await;
    assert_eq!(again.status, 200, "re-invited member refused: {}", again.text);
}
