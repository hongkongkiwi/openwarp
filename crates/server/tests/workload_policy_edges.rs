use axum::{routing::{get, post}, Json, Router};
use openwarp_crypto as oc;
use openwarp_server::db::Db;
use reqwest::Client;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
struct Database { dir: PathBuf, db: Db }
impl Drop for Database { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }
impl Database {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-policy-edges-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&format!("sqlite://{}", dir.join("test.db").display())).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','owner@test.invalid','unused','unused','unused',?,1)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token("owner")), json!(now())]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await.unwrap();
        for iid in ["machine", "duplicate"] {
            db.exec("INSERT INTO identities(id,org_id,name,role,created_at) VALUES(?,'org',?,'developer',?)", &[json!(iid), json!(iid), json!(now())]).await.unwrap();
        }
        Self { dir, db }
    }
}
struct Server { child: Child, base: String, log: PathBuf, client: Client, mail: Arc<Mutex<Vec<Value>>>, _mail_server: Mock }
impl Drop for Server { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }
impl Server {
    fn start(data: &Database, kms: Option<&str>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let mail_url = format!("http://{}/mail", listener.local_addr().unwrap());
        let mail = Arc::new(Mutex::new(Vec::new())); let sink = mail.clone();
        let app = Router::new().route("/mail", post(move |Json(body): Json<Value>| { let sink = sink.clone(); async move { sink.lock().unwrap().push(body); Json(json!({})) } }));
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let mail_server = Mock { url: mail_url, task };
        let log = data.dir.join(format!("server-{}.log", addr.port()));
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        command.env("DATABASE_URL", format!("sqlite://{}", data.dir.join("test.db").display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", &mail_server.url)
            .env("OPENWARP_ENV", if kms.is_some() { "production" } else { "test" })
            .env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1").env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL")
            .env_remove("OPENWARP_KMS_TOKEN").env("OPENWARP_KMS_KEY_ID", "test")
            .stdout(Stdio::null()).stderr(Stdio::from(std::fs::File::create(&log).unwrap()));
        if let Some(url) = kms { command.env("OPENWARP_KMS_URL", url); } else { command.env_remove("OPENWARP_KMS_URL"); }
        let child = command.spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(20)).build().unwrap();
        Self { child, base, log, client, mail, _mail_server: mail_server }
    }
    async fn healthy(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() { panic!("server exited {}: {}", status, std::fs::read_to_string(&self.log).unwrap()); }
            if let Ok(r) = self.client.get(format!("{}/health", self.base)).send().await { if r.status().is_success() { return; } }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server failed health check: {}", std::fs::read_to_string(&self.log).unwrap());
    }
    async fn call(&self, method: &str, path: &str, token: &str, input: Value) -> (u16, Value) {
        let mut request = self.client.request(method.parse().unwrap(), format!("{}{}", self.base, path));
        if !token.is_empty() { request = request.bearer_auth(token); }
        if !input.is_null() { request = request.json(&input); }
        let r = request.send().await.unwrap(); let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw":text}));
        (status, body)
    }
    async fn rotate_master(&self, next: &str) {
        let before = self.mail.lock().unwrap().len();
        let start = self.ok("POST", "/api/auth/step-up/start", json!({"risk":"very_risky"})).await;
        assert_eq!(start["email_sent"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        let code = loop {
            let code = self.mail.lock().unwrap().iter().skip(before).filter_map(|m| m["text"].as_str())
                .find_map(|text| text.split(|c: char| !c.is_ascii_digit()).find(|s| s.len() == 6).map(str::to_string));
            if let Some(code) = code { break code; }
            assert!(Instant::now() < deadline, "fresh step-up mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let verified = self.ok("POST", "/api/auth/step-up/verify", json!({"challenge":start["challenge"],"email_code":code})).await;
        let response = self.client.post(format!("{}/api/instance/rotate-master", self.base)).bearer_auth("owner")
            .header("x-openwarp-step-up", verified["token"].as_str().unwrap()).json(&json!({"new_key":next})).send().await.unwrap();
        let status = response.status(); let body: Value = response.json().await.unwrap(); assert_eq!(status, 200, "master rotation: {}", body);
    }
    async fn ok(&self, method: &str, path: &str, input: Value) -> Value {
        let (status, body) = self.call(method, path, "owner", input).await;
        assert_eq!(status, 200, "{} {}: {}", method, path, body); body
    }
}
struct Mock { url: String, task: tokio::task::JoinHandle<()> }
impl Drop for Mock { fn drop(&mut self) { self.task.abort(); } }
async fn serve(app: Router) -> Mock {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    Mock { url, task }
}

#[tokio::test]
async fn concurrent_fresh_kms_boots_adopt_one_root_and_read_each_others_transit_state() {
    let data = Database::new().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let calls = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
    let sink = calls.clone();
    let bridge = serve(Router::new().route("/{op}", post(move |axum::extract::Path(op): axum::extract::Path<String>, Json(body): Json<Value>| {
        let barrier = barrier.clone(); let sink = sink.clone(); async move {
            sink.lock().unwrap().push((op.clone(), body.clone()));
            if op == "wrap" {
                assert_eq!(body["context"], "master");
                tokio::time::timeout(Duration::from_secs(8), barrier.wait()).await.expect("both fresh boots must reach root wrapping");
                Json(json!({"wrapped":body["plaintext"]}))
            } else { Json(json!({"plaintext":body["wrapped"]})) }
        }
    }))).await;
    // Schema and seed writes finish before either child starts; only root initialization races.
    let mut a = Server::start(&data, Some(&bridge.url));
    let mut b = Server::start(&data, Some(&bridge.url));
    tokio::join!(a.healthy(), b.healthy());
    let root = data.db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap().unwrap()["v"].as_str().unwrap().to_string();
    assert!(data.db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().is_none());
    {
        let calls = calls.lock().unwrap();
        let wraps: Vec<_> = calls.iter().filter(|(op, _)| op == "wrap").collect();
        assert_eq!(wraps.len(), 2);
        assert_ne!(wraps[0].1["plaintext"], wraps[1].1["plaintext"], "fixture must generate distinct candidate roots");
        let blob = root.strip_prefix("owkms:test:").unwrap();
        assert!(calls.iter().any(|(op, body)| op == "unwrap" && body["wrapped"] == blob && body["context"] == "master"), "losing boot never adopted persisted winner: {:?}", calls);
    }
    for (writer, reader, name) in [(&a, &b, "from-a"), (&b, &a, "from-b")] {
        let key = writer.ok("POST", "/api/orgs/org/transit-compat/keys", json!({"name":name})).await;
        let base = format!("/api/orgs/org/transit-compat/keys/{}", key["id"].as_str().unwrap());
        let encrypted = writer.ok("POST", &format!("{}/encrypt", base), json!({"plaintext":oc::b64(name.as_bytes()),"context":"race"})).await;
        let plain = reader.ok("POST", &format!("{}/decrypt", base), json!({"ciphertext":encrypted["ciphertext"],"context":"race"})).await;
        assert_eq!(plain["plaintext"], oc::b64(name.as_bytes()), "replicas disagree on the root");
    }
    assert_eq!(data.db.one("SELECT v FROM meta WHERE k='kms_root'", &[]).await.unwrap().unwrap()["v"], root);
}

#[tokio::test]
async fn transit_old_ciphertext_survives_native_root_rotation_and_restart() {
    let data = Database::new().await;
    let mut server = Server::start(&data, None); server.healthy().await;
    let key = server.ok("POST", "/api/orgs/org/transit-compat/keys", json!({"name":"persistent"})).await;
    let base = format!("/api/orgs/org/transit-compat/keys/{}", key["id"].as_str().unwrap());
    let payload = oc::b64(b"old-version\0root-rotation");
    let encrypted = server.ok("POST", &format!("{}/encrypt", base), json!({"plaintext":payload,"context":"persistent"})).await;
    server.ok("POST", &format!("{}/rotate", base), json!({})).await;
    let decode = json!({"ciphertext":encrypted["ciphertext"],"context":"persistent"});
    assert_eq!(server.ok("POST", &format!("{}/decrypt", base), decode.clone()).await["plaintext"], payload);
    let next = oc::b64(&[19;32]);
    server.rotate_master(&next).await;
    assert_eq!(server.ok("POST", &format!("{}/decrypt", base), decode.clone()).await["plaintext"], payload);
    assert_eq!(data.db.one("SELECT v FROM meta WHERE k='master'", &[]).await.unwrap().unwrap()["v"], next);
    drop(server);
    let mut restarted = Server::start(&data, None); restarted.healthy().await;
    assert_eq!(restarted.ok("POST", &format!("{}/decrypt", base), decode).await["plaintext"], payload);
}

struct Issuer { mock: Mock, encoding: jsonwebtoken::EncodingKey }
impl Issuer {
    async fn new() -> Self {
        use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts};
        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let url64 = |bytes: &[u8]| oc::b64(bytes).trim_end_matches('=').replace('+', "-").replace('/', "_");
        let jwks = json!({"keys":[{"kty":"RSA","kid":"edge","alg":"RS256","use":"sig","n":url64(&key.n().to_bytes_be()),"e":url64(&key.e().to_bytes_be())}]});
        let mock = serve(Router::new().route("/jwks", get(move || { let jwks = jwks.clone(); async move { Json(jwks) } }))).await;
        Self { mock, encoding }
    }
    async fn bind(&self, server: &Server, iid: &str, subject: &str) {
        server.ok("PUT", &format!("/api/orgs/org/identities/{}/workload", iid), json!({"issuer":self.mock.url,"jwks_url":format!("{}/jwks", self.mock.url),"audience":"openwarp","subject":subject,"max_ttl_secs":120})).await;
    }
    fn jwt(&self, unique: &str, subject: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256); header.kid = Some("edge".into());
        jsonwebtoken::encode(&header, &json!({"iss":self.mock.url,"aud":"openwarp","sub":subject,"iat":now(),"exp":now()+120,"jti":unique}), &self.encoding).unwrap()
    }
    async fn login(&self, server: &Server, iid: &str, jwt: &str) -> (u16, Value) {
        server.call("POST", "/api/v1/machine/auth/workload/login", "", json!({"identity_id":iid,"jwt":jwt})).await
    }
}
#[tokio::test]
async fn simultaneous_workload_exchange_has_one_winner_and_duplicate_binding_cannot_replay() {
    let data = Database::new().await;
    let mut server = Server::start(&data, None); server.healthy().await;
    let issuer = Issuer::new().await;
    for iid in ["machine", "duplicate"] { issuer.bind(&server, iid, "runner").await; }
    let jwt = issuer.jwt("concurrent", "runner");
    let (a, b) = tokio::join!(issuer.login(&server, "machine", &jwt), issuer.login(&server, "machine", &jwt));
    assert_eq!([a.0, b.0].iter().filter(|s| **s == 200).count(), 1, "exactly one exchange must win: {:?} {:?}", a, b);
    let loser = if a.0 == 200 { &b } else { &a };
    assert!(matches!(loser.0, 400 | 401 | 403 | 409), "unexpected loser: {:?}", loser);
    let duplicate = issuer.login(&server, "duplicate", &jwt).await;
    assert!(matches!(duplicate.0, 400 | 401 | 403 | 409), "duplicate binding bypassed global replay protection: {:?}", duplicate);
    let rows = data.db.query("SELECT id FROM tokens WHERE created_by IN ('machine','duplicate')", &[]).await.unwrap();
    assert_eq!(rows.len(), 1, "multiple tokens minted from one assertion");
}

#[tokio::test]
async fn workload_binding_update_and_deletion_invalidate_previously_issued_tokens() {
    let data = Database::new().await;
    let mut server = Server::start(&data, None); server.healthy().await;
    let issuer = Issuer::new().await;
    issuer.bind(&server, "machine", "runner").await;
    let (status, issued) = issuer.login(&server, "machine", &issuer.jwt("before-update", "runner")).await;
    assert_eq!(status, 200, "{}", issued);
    let first = issued["accessToken"].as_str().unwrap();
    let probe = "/api/orgs/org/apps";
    assert_eq!(server.call("GET", probe, first, Value::Null).await.0, 200);
    issuer.bind(&server, "machine", "replacement").await;
    let revoked = server.call("GET", probe, first, Value::Null).await;
    assert!(matches!(revoked.0, 401 | 403), "updated binding left old token valid: {:?}", revoked);
    let (status, issued) = issuer.login(&server, "machine", &issuer.jwt("before-delete", "replacement")).await;
    assert_eq!(status, 200, "{}", issued);
    let second = issued["accessToken"].as_str().unwrap();
    assert_eq!(server.call("GET", probe, second, Value::Null).await.0, 200);
    server.ok("DELETE", "/api/orgs/org/identities/machine/workload", Value::Null).await;
    let revoked = server.call("GET", probe, second, Value::Null).await;
    assert!(matches!(revoked.0, 401 | 403), "deleted binding left token valid: {:?}", revoked);
    let denied = issuer.login(&server, "machine", &issuer.jwt("after-delete", "replacement")).await;
    assert!(matches!(denied.0, 400 | 401 | 403), "deleted binding accepted fresh assertion: {:?}", denied);
}
