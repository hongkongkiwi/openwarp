use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::Mac;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Public dummy material only. Never fund or use these keys.
const PRIVATE: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
const PHRASE: &str = "  abandon  abandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon about  ";
const LITERAL: &str = "  opaque ${NORMAL}\ntrailing  ";
static SUITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy)]
enum Auth<'a> { Bearer(&'a str), Cookie(&'a str) }
struct Resp { status: u16, body: Value }
struct Account { token: String, cookie: String, org: String, app: String, envs: Vec<String> }
struct Inbox { base: String, requests: Arc<Mutex<Vec<(String, Value)>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Inbox { fn drop(&mut self) { self.task.abort(); } }
impl Inbox {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new())); let sink = requests.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); async move {
                let path = request.uri().path().to_string();
                let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                sink.lock().unwrap().push((path, serde_json::from_slice::<Value>(&bytes).expect("fixture JSON")));
                axum::Json(json!({}))
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { base, requests, task }
    }
    fn len(&self) -> usize { self.requests.lock().unwrap().len() }
    async fn mail_after(&self, before: usize) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(text) = self.requests.lock().unwrap().iter().skip(before).find_map(|(path, body)| if path == "/mail" { body["text"].as_str().map(str::to_string) } else { None }) { return text; }
            assert!(Instant::now() < deadline, "verification mail must reach the local fixture");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Inbox }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start() -> Self {
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = reserved.local_addr().unwrap();
        let base = format!("http://{addr}"); let dir = std::env::temp_dir().join(format!("openwarp-wallets-{}-{}", std::process::id(), addr.port()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
        builder.create(&dir).unwrap();
        let inbox = Inbox::start().await; let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("OPENWARP_") || name.to_ascii_uppercase().ends_with("_PROXY") || name == "REDIS_URL" { cmd.env_remove(key); }
        }
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", format!("{}/mail", inbox.base))
            .env("TOKIO_WORKER_THREADS", "1").stdout(Stdio::null()).stderr(Stdio::null());
        drop(reserved); let child = cmd.spawn().expect("spawn current server binary");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let mut s = Self { child, base, dir, client, inbox }; let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(s.child.try_wait().unwrap().is_none(), "wallet test server exited before readiness");
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() && r.json::<Value>().await.is_ok_and(|v| v["ok"] == true && v["service"] == "openwarp") { return s; }
            }
            assert!(Instant::now() < deadline, "wallet test server readiness"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn call(&self, method: Method, path: &str, auth: Option<Auth<'_>>, body: Option<Value>, grant: Option<&str>) -> Resp {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(auth) = auth { request = match auth { Auth::Bearer(t) => request.bearer_auth(t), Auth::Cookie(c) => request.header("cookie", c).header("origin", &self.base) }; }
        if let Some(body) = body { request = request.json(&body); }
        if let Some(grant) = grant { request = request.header("x-openwarp-step-up", grant); }
        let r = request.send().await.expect("wallet API request"); let status = r.status().as_u16();
        let text = r.text().await.unwrap(); let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, body }
    }
    async fn account(&self, email: &str) -> Account {
        let before = self.inbox.len();
        good(self.call(Method::POST, "/api/auth/register", None, Some(json!({"email":email,"password":"correct-horse-battery"})), None).await);
        let text = self.inbox.mail_after(before).await;
        let path = text.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string())).expect("account verification link");
        good(self.call(Method::GET, &path, None, None, None).await);
        let r = self.client.post(format!("{}/api/auth/login", self.base)).json(&json!({"email":email,"password":"correct-horse-battery"})).send().await.unwrap();
        assert_eq!(r.status(), 200, "real account login");
        let cookie = r.headers().get_all("set-cookie").iter().filter_map(|h| h.to_str().ok()).find_map(|h| h.split(';').next().filter(|c| c.starts_with("ow_session=")).map(str::to_string)).expect("account session cookie");
        let login: Value = r.json().await.unwrap(); let token = field(&login, "token"); let auth = Some(Auth::Bearer(&token));
        let orgs = good(self.call(Method::GET, "/api/orgs", auth, None, None).await); let org = field(&orgs[0], "id");
        let app = field(&good(self.call(Method::POST, &format!("/api/orgs/{org}/apps"), auth, Some(json!({"name":"wallet-storage"})), None).await), "id");
        let rows = good(self.call(Method::GET, &format!("/api/apps/{app}/envs"), auth, None, None).await);
        let envs: Vec<String> = rows.as_array().unwrap().iter().map(|e| field(e, "id")).collect(); assert!(envs.len() >= 2);
        Account { token, cookie, org, app, envs }
    }
    async fn deploy(&self, a: &Account, secrets: Value) {
        let r = self.call(Method::PUT, &format!("/api/envs/{}/secrets", a.envs[0]), Some(Auth::Bearer(&a.token)), Some(json!({"secrets":secrets})), None).await;
        assert_eq!(r.status, 200, "ordinary encrypted PUT must accept wallet storage types");
    }
    async fn list(&self, token: &str, env: &str, query: &str) -> Vec<Value> {
        good(self.call(Method::GET, &format!("/api/envs/{env}/secrets{query}"), Some(Auth::Bearer(token)), None, None).await)["secrets"].as_array().expect("secret list").clone()
    }
    async fn grant(&self, auth: Auth<'_>, risk: &str, totp: Option<&str>) -> String {
        let before = self.inbox.len();
        let start = good(self.call(Method::POST, "/api/auth/step-up/start", Some(auth), Some(json!({"risk":risk})), None).await);
        let mut body = json!({"challenge":field(&start,"challenge")});
        if risk == "very_risky" { body["email_code"] = json!(email_code(&self.inbox.mail_after(before).await)); }
        if let Some(code) = totp { body["totp"] = json!(code); }
        field(&good(self.call(Method::POST, "/api/auth/step-up/verify", Some(auth), Some(body), None).await), "token")
    }
    async fn reveal(&self, a: &Account, sid: &str) -> Value {
        let auth = Auth::Bearer(&a.token); let grant = self.grant(auth, "very_risky", None).await;
        good(self.call(Method::GET, &reveal_path(&a.envs[0], sid), Some(auth), None, Some(&grant)).await)
    }
    async fn service(&self, a: &Account, env: &str, scopes: &str) -> String {
        field(&good(self.call(Method::POST, &format!("/api/apps/{}/tokens", a.app), Some(Auth::Bearer(&a.token)), Some(json!({"name":"wallet-boundary","env_id":env,"scopes":scopes})), None).await), "token")
    }
    async fn oauth(&self, a: &Account) -> String {
        let redirect = "http://127.0.0.1:8917/callback"; let scope = "secrets:read secrets:write";
        let reg = self.call(Method::POST, "/oauth/register", None, Some(json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope})), None).await;
        assert_eq!(reg.status, 201, "register test OAuth client"); let cid = field(&reg.body, "client_id");
        let verifier = "wallet-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"; let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        let r = self.client.post(format!("{}/oauth/authorize/decision", self.base)).bearer_auth(&a.token).form(&[("response_type","code"),("client_id",cid.as_str()),("redirect_uri",redirect),("scope",scope),("state","wallet-test"),("code_challenge",challenge.as_str()),("code_challenge_method","S256"),("resource",self.base.as_str()),("approve","1")]).send().await.unwrap();
        assert_eq!(r.status(), 303, "authorize test OAuth client");
        let location = reqwest::Url::parse(r.headers().get("location").expect("OAuth redirect").to_str().unwrap()).unwrap();
        let code = location.query_pairs().find(|(k,_)| k == "code").expect("OAuth authorization code").1.into_owned();
        let r = self.client.post(format!("{}/oauth/token", self.base)).form(&[("grant_type","authorization_code"),("code",code.as_str()),("client_id",cid.as_str()),("redirect_uri",redirect),("code_verifier",verifier)]).send().await.unwrap();
        assert_eq!(r.status(), 200, "exchange test OAuth code"); field(&r.json::<Value>().await.unwrap(), "access_token")
    }
}
fn field(v: &Value, key: &str) -> String { v[key].as_str().filter(|s| !s.is_empty()).expect(key).to_string() }
fn good(r: Resp) -> Value { assert_eq!(r.status, 200, "fixture/action must succeed (response body withheld)"); r.body }
fn row<'a>(items: &'a [Value], key: &str) -> &'a Value { items.iter().find(|s| s["key"] == key).expect("expected secret row") }
fn fixtures() -> Value { json!([
    {"key":"PRIVATE","value":PRIVATE,"type":"wallet_private_key"},
    {"key":"RECOVERY","value":PHRASE,"type":"wallet_recovery_phrase"},
    {"key":"NORMAL","value":"ordinary","type":"secret"}
]) }
fn reveal_path(env: &str, sid: &str) -> String { format!("/api/envs/{env}/secrets/{sid}/reveal") }
fn email_code(text: &str) -> String { text.split(|c: char| !c.is_ascii_digit()).find(|v| v.len() == 6).expect("emailed step-up code").to_string() }
fn no_wallet_plaintext(value: &Value) {
    let text = value.to_string();
    for plain in [PRIVATE, "abandon", "opaque", "trailing"] { assert!(!text.contains(plain), "wallet plaintext escaped its explicit reveal boundary"); }
}
fn challenged(r: Resp, totp: bool) {
    assert_eq!(r.status, 428, "wallet reveal must require fresh VeryRisky proof");
    assert_eq!(r.body["step_up_required"], true); assert_eq!(r.body["risk"], "very_risky");
    assert_eq!(r.body["email_required"], true); assert_eq!(r.body["totp_required"], totp); no_wallet_plaintext(&r.body);
}
fn totp(secret: &str) -> String {
    let (mut key, mut value, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in secret.chars() { value = (value << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32; bits += 5; if bits >= 8 { key.push(((value >> (bits-8)) & 255) as u8); bits -= 8; } }
    let counter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()/30;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap(); mac.update(&counter.to_be_bytes()); let hash = mac.finalize().into_bytes(); let off = (hash[19] & 15) as usize;
    format!("{:06}", u32::from_be_bytes(hash[off..off+4].try_into().unwrap()) % 0x8000_0000 % 1_000_000)
}

#[tokio::test]
async fn wallet_storage_preserves_exact_bytes_masks_history_and_audits_explicit_reveal() {
    let _serial = SUITE_LOCK.lock().await;
    let s = Server::start().await; let a = s.account("storage@wallet.test.invalid").await;
    s.deploy(&a, fixtures()).await;
    for (version, expected) in [(1, vec![("PRIVATE", PRIVATE), ("RECOVERY", PHRASE)]), (2, vec![("PRIVATE", LITERAL), ("RECOVERY", LITERAL)])] {
        if version == 2 { s.deploy(&a, json!([{"key":"PRIVATE","value":LITERAL,"type":"wallet_private_key"},{"key":"RECOVERY","value":LITERAL,"type":"wallet_recovery_phrase"}])).await; }
        let items = s.list(&a.token, &a.envs[0], "").await;
        for (key, value) in expected {
            let secret = row(&items, key); assert_eq!(secret["version"], version); assert_eq!(secret["value"], Value::Null);
            assert_eq!(secret["type"], if key == "PRIVATE" { "wallet_private_key" } else { "wallet_recovery_phrase" });
            let sid = field(secret, "id"); assert_eq!(s.reveal(&a, &sid).await["value"], value, "reveal must not trim, normalize or interpolate wallet bytes");
            let history = good(s.call(Method::GET, &format!("/api/secrets/{sid}/history"), Some(Auth::Bearer(&a.token)), None, None).await);
            assert_eq!(history.as_array().unwrap().len(), version as usize); no_wallet_plaintext(&history);
        }
        no_wallet_plaintext(&json!(items));
    }
    let audit = good(s.call(Method::GET, &format!("/api/orgs/{}/audit", a.org), Some(Auth::Bearer(&a.token)), None, None).await);
    assert_eq!(audit.as_array().unwrap().iter().filter(|v| v["action"] == "wallet.reveal" && v["env_id"] == a.envs[0]).count(), 4, "each successful explicit reveal needs an audit event");
    no_wallet_plaintext(&audit);
    let audit_text = audit.to_string();
    assert!(!audit_text.contains(&a.token) && !audit_text.contains("correct-horse-battery"), "reveal audit must not include account credentials");
    for (path, body) in s.inbox.requests.lock().unwrap().iter() {
        if path == "/mail" && body["text"].as_str().is_some_and(|v| v.contains("Your verification code is")) {
            let code = email_code(body["text"].as_str().unwrap());
            assert!(!audit.as_array().unwrap().iter().filter_map(|v| v["detail"].as_str()).any(|detail| detail.split(|c: char| !c.is_ascii_alphanumeric()).any(|word| word == code)), "reveal audit must not include emailed proof codes");
        }
    }
    let db = rusqlite::Connection::open(s.dir.join("test.db")).unwrap(); db.busy_timeout(Duration::from_secs(5)).unwrap();
    for (table, count) in [("secrets", 2), ("secret_versions", 4)] {
        let mut query = db.prepare(&format!("SELECT value_enc FROM {table} WHERE secret_type IN ('wallet_private_key','wallet_recovery_phrase')")).unwrap();
        let encrypted: Vec<String> = query.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(encrypted.len(), count, "wallet current and history rows must be persisted");
        for value in encrypted { assert!(!value.is_empty()); no_wallet_plaintext(&json!(value)); }
    }
}

#[tokio::test]
async fn wallet_reveal_is_session_only_and_requires_email_plus_configured_totp() {
    let _serial = SUITE_LOCK.lock().await;
    let s = Server::start().await; let a = s.account("reveal@wallet.test.invalid").await; let outsider = s.account("outsider@wallet.test.invalid").await;
    s.deploy(&a, fixtures()).await;
    let items = s.list(&a.token, &a.envs[0], "").await; let sid = field(row(&items, "PRIVATE"), "id"); let path = reveal_path(&a.envs[0], &sid);
    assert_eq!(s.call(Method::GET, &path, None, None, None).await.status, 401);
    let service = s.service(&a, &a.envs[0], "secrets:read secrets:write").await;
    let wrong_env = s.service(&a, &a.envs[1], "secrets:read").await; let oauth = s.oauth(&a).await;
    let identity = good(s.call(Method::POST, &format!("/api/orgs/{}/identities", a.org), Some(Auth::Bearer(&a.token)), Some(json!({"name":"wallet-machine"})), None).await);
    let machine = field(&good(s.call(Method::POST, "/api/v1/machine/auth/universal/login", None, Some(json!({"client_id":identity["client_id"],"client_secret":identity["client_secret"]})), None).await), "accessToken");
    challenged(s.call(Method::GET, &path, Some(Auth::Bearer(&a.token)), None, None).await, false);
    let grant = s.grant(Auth::Cookie(&a.cookie), "very_risky", None).await;
    for token in [&service, &wrong_env, &oauth, &machine, &outsider.token] {
        let r = s.call(Method::GET, &path, Some(Auth::Bearer(token)), None, Some(&grant)).await;
        assert_eq!(r.status, 403, "automation or foreign principals must not reveal wallets, even with an owner's proof"); no_wallet_plaintext(&r.body);
    }
    let r = s.call(Method::GET, &reveal_path(&a.envs[1], &sid), Some(Auth::Cookie(&a.cookie)), None, Some(&grant)).await;
    assert!(matches!(r.status, 403 | 404), "wallet id cannot be resolved through another environment"); no_wallet_plaintext(&r.body);
    assert_eq!(good(s.call(Method::GET, &path, Some(Auth::Cookie(&a.cookie)), None, Some(&grant)).await)["value"], PRIVATE);
    challenged(s.call(Method::GET, &path, Some(Auth::Cookie(&a.cookie)), None, Some(&grant)).await, false);
    let auth = Some(Auth::Bearer(&a.token));
    let setup = good(s.call(Method::POST, "/api/me/totp/setup", auth, Some(json!({})), None).await); let secret = field(&setup, "secret");
    good(s.call(Method::POST, "/api/me/totp/verify", auth, Some(json!({"code":totp(&secret)})), None).await);
    challenged(s.call(Method::GET, &path, auth, None, None).await, true);
    let recovery = setup["recovery_codes"][0].as_str().expect("real unused setup recovery code");
    let minor = s.grant(Auth::Bearer(&a.token), "two_factor", Some(recovery)).await;
    challenged(s.call(Method::GET, &path, auth, None, Some(&minor)).await, true);
    let before = s.inbox.len(); let start = good(s.call(Method::POST, "/api/auth/step-up/start", auth, Some(json!({"risk":"very_risky"})), None).await);
    let email = email_code(&s.inbox.mail_after(before).await); let challenge = field(&start, "challenge");
    for body in [json!({"challenge":challenge,"email_code":email}), json!({"challenge":challenge,"totp":totp(&secret)})] {
        assert_eq!(s.call(Method::POST, "/api/auth/step-up/verify", auth, Some(body), None).await.status, 401, "neither configured factor alone may authorize reveal");
    }
    let verified = good(s.call(Method::POST, "/api/auth/step-up/verify", auth, Some(json!({"challenge":challenge,"email_code":email,"totp":totp(&secret)})), None).await); let grant = field(&verified, "token");
    assert_eq!(good(s.call(Method::GET, &path, auth, None, Some(&grant)).await)["value"], PRIVATE);
    challenged(s.call(Method::GET, &path, auth, None, Some(&grant)).await, true);
}

#[tokio::test]
async fn ordinary_consumers_never_receive_wallet_values_or_resolve_wallet_references() {
    let _serial = SUITE_LOCK.lock().await;
    let s = Server::start().await; let a = s.account("consumers@wallet.test.invalid").await; s.deploy(&a, fixtures()).await;
    s.deploy(&a, json!([{"key":"PRIVATE_ALIAS","value":"${PRIVATE}"},{"key":"PHRASE_ALIAS","value":"${/RECOVERY}"},{"key":"CHAINED","value":"prefix-${PRIVATE_ALIAS}"},{"key":"NORMAL_ALIAS","value":"prefix-${NORMAL}"}])).await;
    let service = s.service(&a, &a.envs[0], "secrets:read").await;
    for token in [&a.token, &service] { for query in ["", "?raw=1", "?base=1"] {
        let items = s.list(token, &a.envs[0], query).await; no_wallet_plaintext(&json!(items));
        assert_eq!(row(&items, "PRIVATE")["value"], Value::Null); assert_eq!(row(&items, "RECOVERY")["value"], Value::Null);
        assert_eq!(row(&items, "NORMAL_ALIAS")["value"], "prefix-ordinary");
    } }
    for query in ["", "?base=1"] {
        let path = format!("/api/envs/{}/export{query}", a.envs[0]);
        for auth in [Auth::Bearer(&a.token), Auth::Bearer(&service)] {
            let proof = if matches!(auth, Auth::Bearer(t) if t == a.token.as_str()) { Some(s.grant(auth, "very_risky", None).await) } else { None };
            let exported = good(s.call(Method::GET, &path, Some(auth), None, proof.as_deref()).await); no_wallet_plaintext(&exported);
            let rows = exported["secrets"].as_array().unwrap(); assert_eq!(row(rows, "NORMAL")["value"], "ordinary"); assert_eq!(row(rows, "NORMAL_ALIAS")["value"], "prefix-ordinary");
            assert!(!rows.iter().any(|v| v["key"] == "PRIVATE" || v["key"] == "RECOVERY"), "exports must omit wallet bindings, not export empty stand-ins");
            let text = exported["text"].as_str().unwrap(); assert!(text.lines().any(|l| l == "NORMAL=ordinary"));
            assert!(!text.lines().any(|l| l.starts_with("PRIVATE=") || l.starts_with("RECOVERY=")));
        }
    }
    let cloned = good(s.call(Method::POST, &format!("/api/envs/{}/clone", a.envs[0]), Some(Auth::Bearer(&a.token)), Some(json!({"target_env_id":a.envs[1]})), None).await);
    let target = s.list(&a.token, &a.envs[1], "").await; assert_eq!(cloned["cloned"], target.len());
    assert!(!target.iter().any(|v| v["key"] == "PRIVATE" || v["key"] == "RECOVERY"));
    assert_eq!(row(&target, "NORMAL")["value"], "ordinary"); assert_eq!(row(&target, "NORMAL_ALIAS")["value"], "prefix-ordinary"); no_wallet_plaintext(&json!(target));
    let source = s.list(&a.token, &a.envs[0], "").await; assert_eq!(row(&source, "PRIVATE")["type"], "wallet_private_key"); assert_eq!(row(&source, "RECOVERY")["type"], "wallet_recovery_phrase");
    let integration = good(s.call(Method::POST, &format!("/api/envs/{}/integrations", a.envs[0]), Some(Auth::Bearer(&a.token)), Some(json!({"kind":"webhook","config":{"url":format!("{}/sync",s.inbox.base),"auto_sync":false}})), None).await);
    good(s.call(Method::POST, &format!("/api/integrations/{}/sync", field(&integration,"id")), Some(Auth::Bearer(&a.token)), None, None).await);
    // /sync completion is the barrier: the fixture records the payload before replying.
    let requests = s.inbox.requests.lock().unwrap(); let pushes: Vec<_> = requests.iter().filter(|(path,_)| path == "/sync").collect(); assert_eq!(pushes.len(), 1);
    let payload = &pushes[0].1; no_wallet_plaintext(payload); assert_eq!(payload["secrets"]["NORMAL"], "ordinary"); assert_eq!(payload["secrets"]["NORMAL_ALIAS"], "prefix-ordinary");
    assert!(payload["secrets"].get("PRIVATE").is_none() && payload["secrets"].get("RECOVERY").is_none(), "provider sync must omit wallet names and values");
}

#[tokio::test]
async fn ordinary_edits_cannot_downgrade_wallet_types_to_expose_current_or_historical_values() {
    let _serial = SUITE_LOCK.lock().await;
    let s = Server::start().await; let a = s.account("types@wallet.test.invalid").await; s.deploy(&a, fixtures()).await;
    for key in ["PRIVATE", "RECOVERY"] { for kind in [None, Some("secret"), Some("config"), Some("sealed"), Some("ssh_key"), Some(if key == "PRIVATE" { "wallet_recovery_phrase" } else { "wallet_private_key" })] {
        let value = if kind == Some("ssh_key") { "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYQJZ7VR/OW5fqVOvmn+BRt5SLWDPx2UVO3ALmn21ZE openwarp-test" } else { "replacement" };
        let mut input = json!({"key":key,"value":value}); if let Some(kind) = kind { input["type"] = json!(kind); }
        let r = s.call(Method::PUT, &format!("/api/envs/{}/secrets", a.envs[0]), Some(Auth::Bearer(&a.token)), Some(json!({"secrets":[input]})), None).await;
        assert_eq!(r.status, 400, "ordinary PUT must not silently downgrade a protected wallet type"); no_wallet_plaintext(&r.body);
    } }
    let items = s.list(&a.token, &a.envs[0], "").await;
    for (key, expected) in [("PRIVATE", PRIVATE), ("RECOVERY", PHRASE)] {
        let secret = row(&items, key); assert_eq!(secret["version"], 1); assert_eq!(secret["value"], Value::Null);
        let sid = field(secret, "id"); assert_eq!(s.reveal(&a, &sid).await["value"], expected);
        let history = good(s.call(Method::GET, &format!("/api/secrets/{sid}/history"), Some(Auth::Bearer(&a.token)), None, None).await);
        assert_eq!(history.as_array().unwrap().len(), 1); no_wallet_plaintext(&history);
    }
    s.deploy(&a, json!([{"key":"PROMOTED","value":"previously-shared"}])).await;
    s.deploy(&a, json!([{"key":"PROMOTED","value":LITERAL,"type":"wallet_private_key"}])).await;
    let items = s.list(&a.token, &a.envs[0], "").await; let promoted = row(&items, "PROMOTED");
    assert_eq!(promoted["type"], "wallet_private_key"); assert_eq!(promoted["value"], Value::Null);
    let sid = field(promoted, "id"); assert_eq!(s.reveal(&a, &sid).await["value"], LITERAL);
    let history = good(s.call(Method::GET, &format!("/api/secrets/{sid}/history"), Some(Auth::Bearer(&a.token)), None, None).await);
    assert_eq!(history.as_array().unwrap().len(), 2); no_wallet_plaintext(&history);
    assert!(!history.to_string().contains("previously-shared"), "current wallets mask all history, including pre-promotion ordinary versions");
}

#[tokio::test]
async fn wallet_storage_obeys_tenant_environment_and_write_permissions() {
    let _serial = SUITE_LOCK.lock().await;
    let s = Server::start().await; let a = s.account("owner@wallet.test.invalid").await; let foreign = s.account("foreign@wallet.test.invalid").await;
    let path = format!("/api/envs/{}/secrets", a.envs[0]);
    for (auth, expected) in [(None, 401), (Some(Auth::Bearer(&foreign.token)), 403)] {
        for method in [Method::GET, Method::PUT] {
            let r = s.call(method, &path, auth, Some(json!({"secrets":fixtures()})), None).await; assert_eq!(r.status, expected); no_wallet_plaintext(&r.body);
        }
    }
    let readonly = s.service(&a, &a.envs[0], "secrets:read").await;
    assert!(s.list(&readonly, &a.envs[0], "").await.is_empty());
    assert_eq!(s.call(Method::PUT, &path, Some(Auth::Bearer(&readonly)), Some(json!({"secrets":fixtures()})), None).await.status, 403);
    for method in [Method::GET, Method::PUT] {
        assert_eq!(s.call(method, &format!("/api/envs/{}/secrets", a.envs[1]), Some(Auth::Bearer(&readonly)), Some(json!({"secrets":fixtures()})), None).await.status, 403);
    }
    assert!(s.list(&a.token, &a.envs[0], "").await.is_empty(), "denied writes must not leave wallet rows");
    s.deploy(&a, fixtures()).await;
    let readable = s.list(&readonly, &a.envs[0], "").await; assert_eq!(readable.len(), 3); no_wallet_plaintext(&json!(readable));
}

#[tokio::test]
async fn ordinary_secret_config_sealed_and_invalid_type_contracts_remain_compatible() {
    let _serial = SUITE_LOCK.lock().await;
    let s = Server::start().await; let a = s.account("ordinary@wallet.test.invalid").await;
    s.deploy(&a, json!([{"key":"NORMAL","value":"ordinary"},{"key":"CONFIG","value":"${NORMAL}","type":"config"},{"key":"SEALED","value":"dummy-sealed","type":"sealed"}])).await;
    let items = s.list(&a.token, &a.envs[0], "").await;
    assert_eq!(row(&items, "NORMAL")["type"], "secret"); assert_eq!(row(&items, "NORMAL")["value"], "ordinary");
    assert_eq!(row(&items, "CONFIG")["type"], "config"); assert_eq!(row(&items, "CONFIG")["value"], "ordinary"); assert_eq!(row(&items, "SEALED")["value"], Value::Null);
    let history = good(s.call(Method::GET, &format!("/api/secrets/{}/history", field(row(&items,"NORMAL"),"id")), Some(Auth::Bearer(&a.token)), None, None).await);
    assert_eq!(history[0]["value"], "ordinary", "ordinary history remains readable");
    let sealed_history = good(s.call(Method::GET, &format!("/api/secrets/{}/history", field(row(&items,"SEALED"),"id")), Some(Auth::Bearer(&a.token)), None, None).await);
    assert_eq!(sealed_history[0]["value"], "[SEALED]", "sealed history retains its existing mask");
    let path = format!("/api/envs/{}/secrets", a.envs[0]);
    for input in [json!({"key":"UNKNOWN","value":"dummy","type":"wallet_typo"}), json!({"key":"SEALED","value":"replacement","type":"secret"})] {
        assert_eq!(s.call(Method::PUT, &path, Some(Auth::Bearer(&a.token)), Some(json!({"secrets":[input]})), None).await.status, 400);
    }
    let grant = s.grant(Auth::Bearer(&a.token), "very_risky", None).await;
    let exported = good(s.call(Method::GET, &format!("/api/envs/{}/export", a.envs[0]), Some(Auth::Bearer(&a.token)), None, Some(&grant)).await);
    let rows = exported["secrets"].as_array().unwrap(); assert_eq!(rows.len(), 2); assert_eq!(row(rows, "NORMAL")["value"], "ordinary"); assert_eq!(row(rows, "CONFIG")["value"], "ordinary");
    assert_eq!(s.list(&a.token, &a.envs[0], "").await.len(), 3);
}
