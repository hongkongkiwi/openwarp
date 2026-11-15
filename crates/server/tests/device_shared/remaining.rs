use base64ct::{Base64, Encoding};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::Digest;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Resp { status: u16, body: Value }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
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
        let dir = std::env::temp_dir().join(format!("openwarp-renew-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
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
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { drop(_guard); return Box::pin(Server::start()).await; }
            assert!(Instant::now() < deadline, "server did not become healthy"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut r = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(t) = token { r = r.bearer_auth(t); }
        if let Some(b) = body { r = r.json(&b); }
        let r = r.send().await.expect("HTTP request"); let status = r.status().as_u16();
        let text = r.text().await.unwrap(); Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }
    async fn create_root_ca(&self, org: &str, token: &str) -> Resp {
        let before = self.inbox.lock().unwrap().len();
        let start = self.post("/api/auth/step-up/start", Some(token), json!({"risk": "very_risky"})).await;
        assert_eq!(start.status, 200, "start email proof: {}", start.body);
        assert_eq!(start.body["methods"], json!(["email"]));
        let deadline = Instant::now() + Duration::from_secs(5);
        let text = loop {
            let text = self.inbox.lock().unwrap().iter().skip(before).find_map(|m| {
                if m["subject"] == "Your OpenWarp verification code" { m["text"].as_str().map(str::to_string) } else { None }
            });
            if let Some(text) = text { break text; }
            assert!(Instant::now() < deadline, "fresh step-up email missing");
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let code = text.split(|c: char| !c.is_ascii_digit()).find(|v| v.len() == 6).expect("emailed verification code");
        let verified = self.post("/api/auth/step-up/verify", Some(token), json!({"challenge": start.body["challenge"], "email_code": code})).await;
        assert_eq!(verified.status, 200, "verify email proof: {}", verified.body);
        let grant = verified.body["token"].as_str().expect("step-up grant");
        let r = self.client.post(format!("{}/api/orgs/{}/pki/cas", self.base, org)).bearer_auth(token)
            .header("x-openwarp-step-up", grant).json(&json!({"name": "renew-root"})).send().await.expect("create root CA");
        let status = r.status().as_u16(); let text = r.text().await.unwrap();
        Resp { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }
    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> Resp { self.call(Method::POST, path, token, Some(body)).await }
    async fn get(&self, device: &str, token: &str) -> Value {
        let r = self.call(Method::GET, &format!("/api/pki/devices/{}", device), Some(token), None).await;
        assert_eq!(r.status, 200, "device inventory"); r.body
    }
    fn fixture_sql(&self, sql: &str, id: &str) {
        let db = rusqlite::Connection::open(self.dir.join("test.db")).unwrap(); db.busy_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(db.execute(sql, [id]).unwrap(), 1, "fixture must affect exactly one owned row");
    }
}
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn hash(csr: &str) -> String { format!("{:x}", sha2::Sha256::digest(csr.as_bytes())) }
fn csr(key: &rcgen::KeyPair) -> String {
    let mut p = rcgen::CertificateParams::new(vec!["untrusted-csr.local".to_string()]).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, "not-the-device-name"); p.serialize_request(key).unwrap().pem().unwrap()
}
fn sign(key: &rcgen::KeyPair, text: &str) -> String {
    let bytes = keystore_pki::sign(keystore_pki::SignatureAlgorithm::Sha256WithEcdsa, &key.serialize_der(), text.as_bytes()).expect("P256 SHA256 DER signature");
    Base64::encode_string(&bytes)
}
fn spki(pem: &str) -> Vec<u8> {
    keystore_pki::parse_certificate(&keystore_ocsp::pem::decode("CERTIFICATE", pem).unwrap()).unwrap().spki
}
async fn setup(s: &Server) -> (String, String, String) {
    let r = s.post("/api/auth/register", None, json!({"email": "renew@test.invalid", "password": "correct-horse-battery"})).await;
    assert_eq!(r.status, 200, "register"); let org = r.body["org_id"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = loop {
        let text = s.inbox.lock().unwrap().iter().find_map(|m| m["text"].as_str().map(str::to_string));
        if let Some(text) = text { if let Some(path) = text.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string())) { break path; } }
        assert!(Instant::now() < deadline, "verification mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(s.call(Method::GET, &path, None, None).await.status, 200, "verify");
    let r = s.post("/api/auth/login", None, json!({"email": "renew@test.invalid", "password": "correct-horse-battery"})).await;
    assert_eq!(r.status, 200, "login"); let token = r.body["token"].as_str().unwrap().to_string();
    let g = s.call(Method::PUT, "/api/instance/features", Some(&token), Some(json!({"org": org, "features": ["pki"]}))).await;
    assert_eq!(g.status, 200, "grant pki: {:?}", g.body);
    let r = s.create_root_ca(&org, &token).await;
    assert_eq!(r.status, 200, "CA"); (token, org, r.body["id"].as_str().unwrap().to_string())
}
async fn device(s: &Server, token: &str, ca: &str) -> String {
    let name = format!("sensor-{}", SEQ.fetch_add(1, Ordering::SeqCst));
    let r = s.post(&format!("/api/pki/cas/{}/devices", ca), Some(token), json!({"name": name, "sans": ["sensor.local"]})).await;
    assert_eq!(r.status, 200, "device"); r.body["id"].as_str().unwrap().to_string()
}
async fn enroll(s: &Server, token: &str, device: &str, key: &rcgen::KeyPair) -> Value {
    let r = s.post(&format!("/api/pki/devices/{}/enrollment", device), Some(token), json!({})).await;
    assert_eq!(r.status, 200, "enrollment code");
    let r = s.post("/api/pki/enroll", None, json!({"code": r.body["code"], "csr": csr(key)})).await;
    assert_eq!(r.status, 200, "initial enrollment"); r.body
}
async fn challenge(s: &Server, device: &str, csr: &str) -> Value {
    let before = now(); let r = s.post("/api/pki/renew/challenge", None, json!({"device_id": device, "csr": csr})).await;
    assert_eq!(r.status, 200, "public renewal challenge route must accept a device with an active certificate");
    assert!(!r.body["challenge_id"].as_str().unwrap_or("").is_empty(), "challenge id");
    assert!(!r.body["challenge"].as_str().unwrap_or("").is_empty(), "challenge text");
    let expiry = r.body["expires_at"].as_i64().expect("expiry seconds");
    assert!(expiry >= before + 300 && expiry <= now() + 300, "challenge TTL must be five minutes"); r.body
}
async fn finish(s: &Server, c: &Value, key: &rcgen::KeyPair, attestation: Option<String>) -> Resp {
    let mut body = json!({"challenge_id": c["challenge_id"], "signature": sign(key, c["challenge"].as_str().unwrap())});
    if let Some(jwt) = attestation { body["attestation"] = json!(jwt); }
    s.post("/api/pki/renew", None, body).await
}
fn denied(r: &Resp) { assert!([400, 401, 403, 409, 410].contains(&r.status), "renewal must fail closed, got {}", r.status); }
fn unchanged(inventory: &Value, old: &Value) {
    assert_eq!(inventory["active_cert"]["serial"], old["serial"], "old certificate remains active on failure");
    let certs = inventory["certs"].as_array().unwrap(); assert_eq!(certs.len(), 1, "failure must not issue a certificate");
    assert_eq!(certs[0]["revoked"], 0, "failure must not revoke old certificate");
}

#[tokio::test]
async fn public_renewal_proves_old_key_rotates_to_csr_key_and_is_single_use() {
    let s = Server::start().await; let (token, _, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    let old_key = rcgen::KeyPair::generate().unwrap(); let old = enroll(&s, &token, &d, &old_key).await;
    let other = device(&s, &token, &ca).await; let other_key = rcgen::KeyPair::generate().unwrap(); enroll(&s, &token, &other, &other_key).await;
    let new_key = rcgen::KeyPair::generate().unwrap(); let request = csr(&new_key); let c = challenge(&s, &d, &request).await;
    let competing = challenge(&s, &d, &request).await;
    assert_ne!(c["challenge"], competing["challenge"], "identical CSR requests need fresh unpredictable challenges");
    denied(&finish(&s, &c, &other_key, None).await); unchanged(&s.get(&d, &token).await, &old);
    denied(&finish(&s, &c, &new_key, None).await); unchanged(&s.get(&d, &token).await, &old);
    let tampered = s.post("/api/pki/renew", None, json!({"challenge_id": c["challenge_id"], "signature": sign(&old_key, &(c["challenge"].as_str().unwrap().to_string() + "\n"))})).await;
    denied(&tampered); unchanged(&s.get(&d, &token).await, &old);
    let r = finish(&s, &c, &old_key, None).await;
    assert_eq!(r.status, 200, "a failed signature must not consume the challenge");
    assert!(r.body.get("private_key").is_none(), "renewal must never return a private key");
    assert_eq!(spki(r.body["certificate"].as_str().unwrap()), new_key.public_key_der(), "stored CSR key must be used");
    let inventory = s.get(&d, &token).await;
    assert_ne!(inventory["active_cert"]["serial"], old["serial"]);
    let certs = inventory["certs"].as_array().unwrap(); assert_eq!(certs.len(), 2);
    assert!(certs.iter().any(|c| c["serial"] == old["serial"] && c["revoked"] == 1), "successful renewal revokes old cert");
    assert_eq!(inventory["active_cert"]["revoked"], false);
    denied(&finish(&s, &c, &old_key, None).await);
    denied(&finish(&s, &competing, &old_key, None).await);
    assert_eq!(s.get(&d, &token).await["certs"].as_array().unwrap().len(), 2, "replayed and stale snapshots cannot issue");
}

#[tokio::test]
async fn renewal_rejects_expired_challenge_and_replaced_active_snapshot() {
    let s = Server::start().await; let (token, _, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    let old_key = rcgen::KeyPair::generate().unwrap(); let old = enroll(&s, &token, &d, &old_key).await;
    let new_key = rcgen::KeyPair::generate().unwrap(); let c = challenge(&s, &d, &csr(&new_key)).await;
    s.fixture_sql("UPDATE pki_renew_challenges SET expires_at=1 WHERE id=?", c["challenge_id"].as_str().unwrap());
    denied(&finish(&s, &c, &old_key, None).await); unchanged(&s.get(&d, &token).await, &old);
    let c = challenge(&s, &d, &csr(&new_key)).await;
    let replacement_key = rcgen::KeyPair::generate().unwrap(); let replacement = enroll(&s, &token, &d, &replacement_key).await;
    denied(&finish(&s, &c, &old_key, None).await);
    assert_eq!(s.get(&d, &token).await["active_cert"]["serial"], replacement["serial"], "stale challenge cannot replace current cert");
}

#[tokio::test]
async fn renewal_requires_live_leaf_and_live_issuing_and_root_cas() {
    let s = Server::start().await; let (token, org, root) = setup(&s).await;
    let r = s.post(&format!("/api/orgs/{}/pki/cas", org), Some(&token), json!({"name": "intermediate", "parent_id": root})).await;
    assert_eq!(r.status, 200); let ca = r.body["id"].as_str().unwrap();
    let key = rcgen::KeyPair::generate().unwrap(); let new_key = rcgen::KeyPair::generate().unwrap();
    let empty = device(&s, &token, ca).await;
    denied(&s.post("/api/pki/renew/challenge", None, json!({"device_id": empty, "csr": csr(&new_key)})).await);
    for state in ["expired", "revoked-leaf", "revoked-issuer", "revoked-root"] {
        let d = device(&s, &token, ca).await; enroll(&s, &token, &d, &key).await;
        let c = challenge(&s, &d, &csr(&new_key)).await;
        let cert = s.get(&d, &token).await["active_cert"]["id"].as_str().unwrap().to_string();
        match state {
            "expired" => s.fixture_sql("UPDATE pki_certs SET expires_at=1 WHERE id=?", &cert),
            "revoked-leaf" => s.fixture_sql("UPDATE pki_certs SET revoked=1 WHERE id=?", &cert),
            "revoked-issuer" => s.fixture_sql("UPDATE pki_cas SET revoked=1 WHERE id=?", ca),
            _ => s.fixture_sql("UPDATE pki_cas SET revoked=1 WHERE id=?", &root),
        }
        denied(&finish(&s, &c, &key, None).await);
        denied(&s.post("/api/pki/renew/challenge", None, json!({"device_id": d, "csr": csr(&new_key)})).await);
        assert_eq!(s.get(&d, &token).await["certs"].as_array().unwrap().len(), 1, "{} cannot issue", state);
        if state == "revoked-issuer" { s.fixture_sql("UPDATE pki_cas SET revoked=0 WHERE id=?", ca); }
    }
}

#[tokio::test]
async fn renewal_policy_denial_preserves_old_cert_and_retry_and_requires_bound_attestation() {
    let s = Server::start().await; let (token, _, ca) = setup(&s).await; let d = device(&s, &token, &ca).await;
    let old_key = rcgen::KeyPair::generate().unwrap(); let old = enroll(&s, &token, &d, &old_key).await;
    let new_key = rcgen::KeyPair::generate().unwrap(); let request = csr(&new_key); let c = challenge(&s, &d, &request).await;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap(); seen_tx.send(read_body(&mut stream)).unwrap();
        let payload = "{\"allow\":false}"; let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload);
    });
    let r = s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Some(&token), Some(json!({"url": url}))).await; assert_eq!(r.status, 200);
    assert_eq!(finish(&s, &c, &old_key, None).await.status, 403, "renewal must enforce hook denial");
    let seen = seen_rx.recv_timeout(Duration::from_secs(2)).expect("renewal must actually call policy hook");
    assert_eq!(seen["device"]["id"], d); assert_eq!(seen["csr_sha256"], hash(&request));
    unchanged(&s.get(&d, &token).await, &old);
    assert_eq!(s.call(Method::PUT, &format!("/api/pki/cas/{}/hook", ca), Some(&token), Some(json!({"url": ""}))).await.status, 200);
    let attest_key = rcgen::KeyPair::generate().unwrap();
    assert_eq!(s.call(Method::PUT, &format!("/api/pki/cas/{}/attestation", ca), Some(&token), Some(json!({"issuer": "renew-attest.test", "public_key_pem": attest_key.public_key_pem(), "algorithm": "ES256", "required": true}))).await.status, 200);
    assert_eq!(finish(&s, &c, &old_key, None).await.status, 403, "mandatory attestation also applies to renewal");
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(attest_key.serialize_pem().as_bytes()).unwrap();
    let jwt = |nonce: &str, csr_hash: String| jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256), &json!({"iss": "renew-attest.test", "aud": "openwarp-pki", "sub": d, "exp": now()+300, "iat": now(), "nonce": nonce, "csr_sha256": csr_hash, "hardware_backed": true}), &enc).unwrap();
    let id = c["challenge_id"].as_str().unwrap();
    assert_eq!(finish(&s, &c, &old_key, Some(jwt("another-challenge", hash(&request)))).await.status, 403);
    assert_eq!(finish(&s, &c, &old_key, Some(jwt(id, hash("another CSR")))).await.status, 403);
    unchanged(&s.get(&d, &token).await, &old);
    assert_eq!(finish(&s, &c, &old_key, Some(jwt(id, hash(&request)))).await.status, 200, "policy failures must not consume challenge");
    let inventory = s.get(&d, &token).await; assert_eq!(inventory["attested"], true);
    assert!(inventory["certs"].as_array().unwrap().iter().any(|c| c["serial"] == old["serial"] && c["revoked"] == 1));
}
