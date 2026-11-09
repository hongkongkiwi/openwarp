use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
fn relay() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || { for incoming in listener.incoming() {
        let mut stream = incoming.unwrap(); stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
        loop {
            let n = stream.read(&mut chunk).expect("read verification mail"); assert_ne!(n, 0); buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]);
                let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                if buf.len() >= end + 4 + len { sink.lock().unwrap().push(serde_json::from_slice(&buf[end+4..end+4+len]).expect("mail JSON")); break; }
            }
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    } });
    (format!("http://{}/mail", addr), inbox)
}
impl Server {
    async fn start() -> Self {
        let _guard = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-group-security-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (mail, inbox) = relay();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", mail).env("TOKIO_WORKER_THREADS", "1")
            .env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1").env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ENV").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let s = Self { child, base, dir, client: Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().unwrap(), inbox };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            assert!(Instant::now() < deadline, "server did not become healthy"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn call(&self, method: Method, path: &str, session: Option<&str>, body: Option<Value>) -> Resp {
        let mut r = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(t) = session { r = r.bearer_auth(t); }
        if let Some(b) = body { r = r.json(&b); }
        let r = r.send().await.expect("HTTP request"); let status = r.status().as_u16();
        let text = r.text().await.unwrap(); Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }
    async fn ok(&self, method: Method, path: &str, session: &str, body: Option<Value>) -> Value {
        let r = self.call(method.clone(), path, Some(session), body).await;
        assert_eq!(r.status, 200, "{} {} must succeed", method, path); r.body
    }
}
struct Fixture { owner: String, member: String, ca: String, env: String, group: String, device: String }
async fn setup(s: &Server) -> Fixture {
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email": "group-owner@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "register owner"); let org = r.body["org_id"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = loop {
        let text = s.inbox.lock().unwrap().iter().find_map(|m| m["text"].as_str().map(str::to_string));
        if let Some(text) = text { if let Some(path) = text.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string())) { break path; } }
        assert!(Instant::now() < deadline, "verification mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(s.call(Method::GET, &path, None, None).await.status, 200, "verify owner");
    let r = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email": "group-owner@test.invalid", "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "owner session"); let owner = r.body["token"].as_str().unwrap().to_string();
    s.ok(Method::PUT, "/api/instance/features", &owner, Some(json!({"org": org, "features": ["pki"]}))).await;
    s.ok(Method::POST, &format!("/api/orgs/{}/roles", org), &owner, Some(json!({"name": "pki-operator", "permissions": ["pki:read", "pki:write"]}))).await;
    let invite = s.ok(Method::POST, &format!("/api/orgs/{}/members", org), &owner, Some(json!({"email": "group-member@test.invalid", "role": "pki-operator"}))).await;
    let r = s.call(Method::POST, "/api/auth/accept-invite", None, Some(json!({"token": invite["invite_token"].as_str().expect("new account invite"), "password": "correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "accept invite with an account session");
    assert_eq!(r.body["org_id"], org); assert_eq!(r.body["role"], "pki-operator");
    let member = r.body["token"].as_str().unwrap().to_string();
    let app = s.ok(Method::POST, &format!("/api/orgs/{}/apps", org), &owner, Some(json!({"name": "restricted-fleet"}))).await;
    let envs = s.ok(Method::GET, &format!("/api/apps/{}/envs", app["id"].as_str().unwrap()), &owner, None).await;
    let env = envs.as_array().unwrap()[0]["id"].as_str().unwrap().to_string();
    s.ok(Method::PUT, &format!("/api/envs/{}/policy", env), &owner, Some(json!({"restricted": true}))).await;
    let ca = s.ok(Method::POST, &format!("/api/orgs/{}/pki/cas", org), &owner, Some(json!({"name": "group-root"}))).await;
    let ca = ca["id"].as_str().unwrap().to_string();
    let group = s.ok(Method::POST, &format!("/api/pki/cas/{}/groups", ca), &owner, Some(json!({"name": "unscoped-fleet"}))).await;
    assert_eq!(group["env_id"], ""); let group = group["id"].as_str().unwrap().to_string();
    let device = s.ok(Method::POST, &format!("/api/pki/cas/{}/devices", ca), &owner, Some(json!({"name": "restricted-sensor", "group_id": group, "env_id": env, "sans": ["restricted-sensor.local"]}))).await;
    let device = device["id"].as_str().unwrap().to_string();
    let key = rcgen::KeyPair::generate().unwrap(); let code = code(s, &owner, &device).await;
    assert_eq!(redeem(s, &code, &key).await.status, 200, "initial certificate");
    let r = s.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(&member), None).await;
    assert!([403, 404].contains(&r.status), "PKI permissions alone must not open the restricted device");
    let visible = s.ok(Method::GET, &format!("/api/pki/cas/{}/devices", ca), &member, None).await;
    assert!(visible.as_array().unwrap().is_empty(), "restricted device must be filtered from inventory");
    Fixture { owner, member, ca, env, group, device }
}
async fn code(s: &Server, owner: &str, device: &str) -> String {
    let r = s.ok(Method::POST, &format!("/api/pki/devices/{}/enrollment", device), owner, Some(json!({}))).await;
    r["code"].as_str().unwrap().to_string()
}
async fn redeem(s: &Server, code: &str, key: &rcgen::KeyPair) -> Resp {
    let csr = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(key).unwrap().pem().unwrap();
    s.call(Method::POST, "/api/pki/enroll", None, Some(json!({"code": code, "csr": csr}))).await
}
async fn grant(s: &Server, f: &Fixture) {
    let r = s.ok(Method::POST, &format!("/api/envs/{}/access-requests", f.env), &f.member, Some(json!({"reason": "operate the restricted fleet"}))).await;
    s.ok(Method::POST, &format!("/api/access-requests/{}/approve", r["id"].as_str().unwrap()), &f.owner, Some(json!({}))).await;
    s.ok(Method::GET, &format!("/api/pki/devices/{}", f.device), &f.member, None).await;
}
fn denial_or_filter(r: &Resp) {
    assert!([200, 403, 404].contains(&r.status), "group action must deny access or filter inaccessible members, got {}", r.status);
}
fn denied(r: &Resp) { assert!([403, 404].contains(&r.status), "restricted group must be denied, got {}", r.status); }

#[tokio::test]
async fn group_security_revoke_preserves_inaccessible_device_certificates_and_codes() {
    let s = Server::start().await; let f = setup(&s).await;
    let path = format!("/api/pki/devices/{}", f.device);
    let before = s.ok(Method::GET, &path, &f.owner, None).await;
    let pending = code(&s, &f.owner, &f.device).await;
    let r = s.call(Method::POST, &format!("/api/pki/groups/{}/revoke", f.group), Some(&f.member), Some(json!({}))).await;
    denial_or_filter(&r);
    assert_eq!(s.ok(Method::GET, &path, &f.owner, None).await, before, "group revoke must not alter an inaccessible device or its certificates");
    let key = rcgen::KeyPair::generate().unwrap();
    assert_eq!(redeem(&s, &pending, &key).await.status, 200, "unauthorized group revoke must preserve an outstanding enrollment code");
    grant(&s, &f).await;
    let pending = code(&s, &f.owner, &f.device).await;
    let r = s.ok(Method::POST, &format!("/api/pki/groups/{}/revoke", f.group), &f.member, Some(json!({}))).await;
    assert_eq!(r["devices"], 1); assert_eq!(r["revoked"], 2);
    let after = s.ok(Method::GET, &path, &f.owner, None).await;
    assert!(after["active_cert"].is_null(), "granted group revoke clears the active certificate");
    let certs = after["certs"].as_array().unwrap(); assert_eq!(certs.len(), 2);
    assert!(certs.iter().all(|c| c["revoked"] == 1), "granted group revoke revokes every issued certificate");
    assert_eq!(redeem(&s, &pending, &key).await.status, 401, "granted group revoke invalidates outstanding enrollment codes");
}

#[tokio::test]
async fn group_security_delete_preserves_inaccessible_membership_and_codes() {
    let s = Server::start().await; let f = setup(&s).await;
    let path = format!("/api/pki/devices/{}", f.device);
    let before = s.ok(Method::GET, &path, &f.owner, None).await;
    let pending = code(&s, &f.owner, &f.device).await;
    let r = s.call(Method::DELETE, &format!("/api/pki/groups/{}", f.group), Some(&f.member), None).await;
    denial_or_filter(&r);
    assert_eq!(s.ok(Method::GET, &path, &f.owner, None).await, before, "group deletion must not detach or alter an inaccessible device or its certificates");
    let key = rcgen::KeyPair::generate().unwrap();
    assert_eq!(redeem(&s, &pending, &key).await.status, 200, "unauthorized group deletion must preserve an outstanding enrollment code");
    grant(&s, &f).await;
    let before = s.ok(Method::GET, &path, &f.owner, None).await;
    let pending = code(&s, &f.owner, &f.device).await;
    let r = s.ok(Method::DELETE, &format!("/api/pki/groups/{}", f.group), &f.member, None).await;
    assert_eq!(r["deleted"], true); assert_eq!(r["detached"], 1);
    let after = s.ok(Method::GET, &path, &f.owner, None).await;
    assert_eq!(after["group_id"], ""); assert_eq!(after["env_id"], f.env);
    assert_eq!(after["active_cert"], before["active_cert"], "authorized group deletion does not revoke device certificates");
    assert_eq!(after["certs"], before["certs"]);
    assert_eq!(redeem(&s, &pending, &key).await.status, 200, "authorized group deletion only detaches devices and keeps their enrollment codes usable");
    let groups = s.ok(Method::GET, &format!("/api/pki/cas/{}/groups", f.ca), &f.owner, None).await;
    assert!(groups.as_array().unwrap().iter().all(|g| g["id"] != f.group), "authorized deletion removes the group");
}

#[tokio::test]
async fn group_security_counts_do_not_disclose_inaccessible_devices() {
    let s = Server::start().await; let f = setup(&s).await;
    let path = format!("/api/pki/cas/{}/groups", f.ca);
    let groups = s.ok(Method::GET, &path, &f.owner, None).await;
    assert_eq!(groups.as_array().unwrap().iter().find(|g| g["id"] == f.group).unwrap()["device_count"], 1);
    let r = s.call(Method::GET, &path, Some(&f.member), None).await;
    denial_or_filter(&r);
    if r.status == 200 {
        if let Some(group) = r.body.as_array().unwrap().iter().find(|g| g["id"] == f.group) {
            assert_eq!(group["device_count"], 0, "unscoped group counts must not reveal devices hidden by environment policy");
        }
    }
    grant(&s, &f).await;
    let groups = s.ok(Method::GET, &path, &f.member, None).await;
    assert_eq!(groups.as_array().unwrap().iter().find(|g| g["id"] == f.group).unwrap()["device_count"], 1, "environment access reveals the authorized member count");
}

#[tokio::test]
async fn group_security_scoped_group_metadata_requires_environment_access() {
    let s = Server::start().await; let f = setup(&s).await;
    let path = format!("/api/pki/cas/{}/groups", f.ca);
    let scoped = s.ok(Method::POST, &path, &f.owner, Some(json!({"name": "restricted-metadata", "env_id": f.env, "tags": "private-site"}))).await;
    let id = scoped["id"].as_str().unwrap(); let item = format!("/api/pki/groups/{}", id);
    let groups = s.ok(Method::GET, &path, &f.member, None).await;
    assert!(groups.as_array().unwrap().iter().all(|g| g["id"] != id), "restricted group metadata must be filtered");
    denied(&s.call(Method::POST, &path, Some(&f.member), Some(json!({"name": "unauthorized-group", "env_id": f.env}))).await);
    denied(&s.call(Method::PATCH, &item, Some(&f.member), Some(json!({"tags": "overwritten"}))).await);
    denied(&s.call(Method::DELETE, &item, Some(&f.member), None).await);
    denied(&s.call(Method::POST, &format!("{}/revoke", item), Some(&f.member), Some(json!({}))).await);
    let groups = s.ok(Method::GET, &path, &f.owner, None).await;
    assert_eq!(groups.as_array().unwrap().len(), 2, "denied group creation must not persist metadata");
    assert_eq!(groups.as_array().unwrap().iter().find(|g| g["id"] == id).unwrap(), &scoped, "denied mutations must leave restricted group metadata intact");
    grant(&s, &f).await;
    let groups = s.ok(Method::GET, &path, &f.member, None).await;
    assert!(groups.as_array().unwrap().iter().any(|g| g["id"] == id), "granted environment access reveals scoped group metadata");
    let updated = s.ok(Method::PATCH, &item, &f.member, Some(json!({"tags": "authorized-edit"}))).await;
    assert_eq!(updated["tags"], "authorized-edit");
    s.ok(Method::POST, &path, &f.member, Some(json!({"name": "authorized-group", "env_id": f.env}))).await;
}
