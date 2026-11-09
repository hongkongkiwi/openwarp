use base64ct::{Base64, Encoding};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

#[derive(Clone, Copy)]
enum Auth<'a> { None, Bearer(&'a str), Cookie(&'a str) }

fn read_body(stream: &mut std::net::TcpStream) -> Value {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).expect("read relay request");
        assert_ne!(n, 0, "relay request ended before body"); buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]);
            let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
            if buf.len() >= end + 4 + len { return serde_json::from_slice(&buf[end+4..end+4+len]).expect("relay JSON"); }
        }
    }
}
fn relay() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || { for incoming in listener.incoming() {
        let mut stream = incoming.unwrap(); sink.lock().unwrap().push(read_body(&mut stream));
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    } });
    (format!("http://{}/mail", addr), inbox)
}

impl Server {
    async fn start() -> Self {
        let _guard = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-lockdown-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr); let (mail, inbox) = relay();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", mail).env("TOKIO_WORKER_THREADS", "1")
            .env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1").env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ENV").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let s = Self { child, base, dir, client: Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap(), inbox };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            assert!(Instant::now() < deadline, "server did not become healthy"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn call(&self, method: Method, path: &str, auth: Auth<'_>, body: Option<Value>) -> Resp {
        let mut r = self.client.request(method, format!("{}{}", self.base, path));
        match auth {
            Auth::Bearer(t) => { r = r.bearer_auth(t); }
            Auth::Cookie(t) => { r = r.header("cookie", format!("ow_session={}", t)).header("origin", self.base.as_str()); }
            Auth::None => {}
        }
        if let Some(b) = body { r = r.json(&b); }
        let r = r.send().await.expect("HTTP request"); let status = r.status().as_u16();
        let text = r.text().await.unwrap(); Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }
    async fn post(&self, path: &str, auth: Auth<'_>, body: Value) -> Resp { self.call(Method::POST, path, auth, Some(body)).await }
    async fn get_device(&self, device: &str, token: &str) -> Value {
        let r = self.call(Method::GET, &format!("/api/pki/devices/{}", device), Auth::Bearer(token), None).await;
        assert_eq!(r.status, 200, "device inventory"); r.body
    }
}

fn csr(key: &rcgen::KeyPair) -> String {
    let mut p = rcgen::CertificateParams::new(vec!["untrusted-csr.local".to_string()]).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, "not-the-device-name"); p.serialize_request(key).unwrap().pem().unwrap()
}
fn sign(key: &rcgen::KeyPair, text: &str) -> String {
    let bytes = keystore_pki::sign(keystore_pki::SignatureAlgorithm::Sha256WithEcdsa, &key.serialize_der(), text.as_bytes()).expect("P256 SHA256 DER signature");
    Base64::encode_string(&bytes)
}

async fn setup(s: &Server) -> (String, String, String) {
    let r = s.post("/api/auth/register", Auth::None, json!({"email": "lockdown@test.invalid", "password": "correct-horse-battery"})).await;
    assert_eq!(r.status, 200, "register"); let org = r.body["org_id"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = loop {
        let text = s.inbox.lock().unwrap().iter().find_map(|m| m["text"].as_str().map(str::to_string));
        if let Some(text) = text { if let Some(path) = text.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string())) { break path; } }
        assert!(Instant::now() < deadline, "verification mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(s.call(Method::GET, &path, Auth::None, None).await.status, 200, "verify");
    let r = s.post("/api/auth/login", Auth::None, json!({"email": "lockdown@test.invalid", "password": "correct-horse-battery"})).await;
    assert_eq!(r.status, 200, "login"); let token = r.body["token"].as_str().unwrap().to_string();
    assert_eq!(s.call(Method::PUT, "/api/instance/features", Auth::Bearer(&token), Some(json!({"org": org, "features": ["pki"]}))).await.status, 200, "pki grant");
    let r = s.post(&format!("/api/orgs/{}/pki/cas", org), Auth::Bearer(&token), json!({"name": "lockdown-root"})).await;
    assert_eq!(r.status, 200, "CA"); (token, org, r.body["id"].as_str().unwrap().to_string())
}
async fn device(s: &Server, token: &str, ca: &str) -> String {
    let name = format!("sensor-{}", SEQ.fetch_add(1, Ordering::SeqCst));
    let r = s.post(&format!("/api/pki/cas/{}/devices", ca), Auth::Bearer(token), json!({"name": name, "sans": ["sensor.local"]})).await;
    assert_eq!(r.status, 200, "device"); r.body["id"].as_str().unwrap().to_string()
}
async fn enroll(s: &Server, token: &str, device: &str, key: &rcgen::KeyPair) -> Value {
    let r = s.post(&format!("/api/pki/devices/{}/enrollment", device), Auth::Bearer(token), json!({})).await;
    assert_eq!(r.status, 200, "enrollment code");
    let r = s.post("/api/pki/enroll", Auth::None, json!({"code": r.body["code"], "csr": csr(key)})).await;
    assert_eq!(r.status, 200, "initial enrollment"); r.body
}
async fn challenge(s: &Server, device: &str, csr_pem: &str) -> Value {
    let r = s.post("/api/pki/renew/challenge", Auth::None, json!({"device_id": device, "csr": csr_pem})).await;
    assert_eq!(r.status, 200, "public renewal challenge route must accept a device with an active certificate");
    assert!(!r.body["challenge_id"].as_str().unwrap_or("").is_empty(), "challenge id");
    assert!(!r.body["challenge"].as_str().unwrap_or("").is_empty(), "challenge text"); r.body
}
async fn finish(s: &Server, c: &Value, key: &rcgen::KeyPair) -> Resp {
    s.post("/api/pki/renew", Auth::None, json!({"challenge_id": c["challenge_id"], "signature": sign(key, c["challenge"].as_str().unwrap())})).await
}
fn unchanged(inventory: &Value, old: &Value) {
    assert_eq!(inventory["active_cert"]["serial"], old["serial"], "old certificate remains active on failure");
    let certs = inventory["certs"].as_array().unwrap(); assert_eq!(certs.len(), 1, "failure must not issue a certificate");
    assert_eq!(certs[0]["revoked"], 0, "failure must not revoke old certificate");
}
async fn lock(s: &Server, org: &str, token: &str) {
    assert_eq!(s.call(Method::PUT, &format!("/api/orgs/{}/emergency", org), Auth::Cookie(token), Some(json!({"locked": true}))).await.status, 200, "owner cookie activates lockdown");
}
async fn unlock(s: &Server, org: &str, token: &str) {
    assert_eq!(s.call(Method::PUT, &format!("/api/orgs/{}/emergency", org), Auth::Cookie(token), Some(json!({"locked": false}))).await.status, 200, "owner cookie restores access");
}
async fn lock_app(s: &Server, app: &str, token: &str) {
    assert_eq!(s.call(Method::PUT, &format!("/api/apps/{}/emergency", app), Auth::Cookie(token), Some(json!({"locked": true}))).await.status, 200, "owner cookie activates app lockdown");
}
async fn unlock_app(s: &Server, app: &str, token: &str) {
    assert_eq!(s.call(Method::PUT, &format!("/api/apps/{}/emergency", app), Auth::Cookie(token), Some(json!({"locked": false}))).await.status, 200, "owner cookie restores app access");
}
fn gate_hook() -> (String, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = mpsc::channel(); let (release_tx, release_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_body(&mut stream);
        seen_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(60)).unwrap();
        let payload = "{\"allow\":true}";
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload);
    });
    (url, seen_rx, release_tx)
}

#[tokio::test]
async fn workspace_lockdown_blocks_enroll_after_code_minted() {
    let s = Server::start().await; let (token, org, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    let key = rcgen::KeyPair::generate().unwrap();
    let r = s.post(&format!("/api/pki/devices/{}/enrollment", d), Auth::Bearer(&token), json!({})).await;
    assert_eq!(r.status, 200, "code minted before lockdown"); let code = r.body["code"].as_str().unwrap().to_string();
    lock(&s, &org, &token).await;
    let r = s.post("/api/pki/enroll", Auth::None, json!({"code": code.clone(), "csr": csr(&key)})).await;
    assert_eq!(r.status, 403, "lockdown must forbid public enrollment, not weaken to 401");
    unlock(&s, &org, &token).await;
    let inv = s.get_device(&d, &token).await;
    assert!(inv["active_cert"].is_null(), "blocked enrollment must not attach a certificate");
    assert_eq!(inv["certs"].as_array().unwrap().len(), 0, "blocked enrollment must not issue a certificate");
    let r = s.post("/api/pki/enroll", Auth::None, json!({"code": code, "csr": csr(&key)})).await;
    assert_eq!(r.status, 200, "the same code succeeds after restore, proving it was valid");
}

#[tokio::test]
async fn workspace_lockdown_blocks_renewal_after_challenge_minted() {
    let s = Server::start().await; let (token, org, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    let old_key = rcgen::KeyPair::generate().unwrap(); let old = enroll(&s, &token, &d, &old_key).await;
    let new_key = rcgen::KeyPair::generate().unwrap(); let request = csr(&new_key);
    let c = challenge(&s, &d, &request).await;
    lock(&s, &org, &token).await;
    let r = s.post("/api/pki/renew/challenge", Auth::None, json!({"device_id": d.clone(), "csr": request})).await;
    assert_eq!(r.status, 403, "lockdown must block minting a new renewal challenge");
    let r = finish(&s, &c, &old_key).await;
    assert_eq!(r.status, 403, "lockdown must block renewal commit, not weaken to 401");
    unlock(&s, &org, &token).await;
    let inv = s.get_device(&d, &token).await;
    unchanged(&inv, &old);
    let r = finish(&s, &c, &old_key).await;
    assert_eq!(r.status, 200, "the same challenge succeeds after restore, proving it was valid");
}

#[tokio::test]
async fn workspace_lockdown_blocks_admin_device_writes() {
    let s = Server::start().await; let (token, org, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    lock(&s, &org, &token).await;
    let writes = [
        (Method::POST, format!("/api/pki/cas/{}/devices", ca), json!({"name": "blocked-device"})),
        (Method::PATCH, format!("/api/pki/devices/{}", d), json!({"name": "renamed"})),
        (Method::POST, format!("/api/pki/devices/{}/enrollment", d), json!({})),
        (Method::POST, format!("/api/pki/devices/{}/renew", d), json!({})),
        (Method::POST, format!("/api/pki/devices/{}/revoke", d), json!({})),
        (Method::DELETE, format!("/api/pki/devices/{}", d), json!({})),
    ];
    for (method, path, body) in writes {
        let r = s.call(method.clone(), &path, Auth::Bearer(&token), Some(body)).await;
        assert_eq!(r.status, 403, "lockdown must block admin device write {} {}", method, path);
    }
    unlock(&s, &org, &token).await;
    let inv = s.get_device(&d, &token).await;
    assert_eq!(inv["id"].as_str(), Some(d.as_str()), "blocked writes must leave the device intact");
    let r = s.post(&format!("/api/pki/cas/{}/devices", ca), Auth::Bearer(&token), json!({"name": "after-restore"})).await;
    assert_eq!(r.status, 200, "admin write succeeds after restore, proving the token was valid");
}

#[tokio::test]
async fn app_lockdown_blocks_device_operations() {
    let s = Server::start().await; let (token, org, ca) = setup(&s).await;
    let r = s.post(&format!("/api/orgs/{}/apps", org), Auth::Bearer(&token), json!({"name": "device-app"})).await;
    assert_eq!(r.status, 200, "app"); let app = r.body["id"].as_str().unwrap().to_string();
    let name = format!("sensor-{}", SEQ.fetch_add(1, Ordering::SeqCst));
    let r = s.post(&format!("/api/pki/cas/{}/devices", ca), Auth::Bearer(&token), json!({"name": name, "app_id": app, "sans": ["sensor.local"]})).await;
    assert_eq!(r.status, 200, "device scoped to app"); let d = r.body["id"].as_str().unwrap().to_string();
    let key = rcgen::KeyPair::generate().unwrap(); let old = enroll(&s, &token, &d, &key).await;
    let r = s.post(&format!("/api/pki/devices/{}/enrollment", d), Auth::Bearer(&token), json!({})).await;
    assert_eq!(r.status, 200, "code minted before app lockdown"); let code = r.body["code"].as_str().unwrap().to_string();
    lock_app(&s, &app, &token).await;
    let r = s.post("/api/pki/enroll", Auth::None, json!({"code": code.clone(), "csr": csr(&key)})).await;
    assert_eq!(r.status, 403, "app lockdown must block public enrollment");
    let r = s.call(Method::PATCH, &format!("/api/pki/devices/{}", d), Auth::Bearer(&token), Some(json!({"name": "renamed"}))).await;
    assert_eq!(r.status, 403, "app lockdown must block admin device writes");
    unlock_app(&s, &app, &token).await;
    let inv = s.get_device(&d, &token).await;
    assert_eq!(inv["active_cert"]["serial"], old["serial"], "blocked enrollment must not replace the active certificate");
    assert_eq!(inv["certs"].as_array().unwrap().len(), 1, "blocked enrollment must not issue a certificate");
    let r = s.post("/api/pki/enroll", Auth::None, json!({"code": code, "csr": csr(&key)})).await;
    assert_eq!(r.status, 200, "the same code succeeds after app restore, proving it was valid");
}

#[tokio::test]
async fn hook_delayed_issuance_denies_commit_when_lock_toggles() {
    let s = Server::start().await; let (token, org, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    let old_key = rcgen::KeyPair::generate().unwrap(); let old = enroll(&s, &token, &d, &old_key).await;
    let new_key = rcgen::KeyPair::generate().unwrap(); let request = csr(&new_key);
    let c = challenge(&s, &d, &request).await;
    let (url, seen_rx, release_tx) = gate_hook();
    assert_eq!(s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Auth::Bearer(&token), Some(json!({"url": url}))).await.status, 200, "policy hook configured");
    let (r, _) = tokio::join!(
        finish(&s, &c, &old_key),
        async {
            tokio::task::spawn_blocking(move || seen_rx.recv_timeout(Duration::from_secs(30)))
                .await.expect("blocking join").expect("renewal must reach the policy hook before commit");
            lock(&s, &org, &token).await;
            release_tx.send(()).unwrap();
        }
    );
    assert!(matches!(r.status, 400 | 403 | 409 | 410), "delayed commit must be denied by lockdown, got {}", r.status);
    unlock(&s, &org, &token).await;
    assert_eq!(s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Auth::Bearer(&token), Some(json!({"url": ""}))).await.status, 200);
    let inv = s.get_device(&d, &token).await;
    unchanged(&inv, &old);
    let r = finish(&s, &c, &old_key).await;
    assert_eq!(r.status, 200, "the denied commit must not consume the challenge; retry after restore succeeds");
}
