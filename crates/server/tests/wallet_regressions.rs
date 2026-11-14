#![cfg(feature = "change-requests")]

use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Public dummy material only. Never fund or use this key.
const WALLET: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
const OLD: &str = "wallet-regression-pre-promotion-canary";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp { status: u16, body: Value }
struct Account { token: String, id: String, org: String }
struct Inbox { base: String, messages: Arc<Mutex<Vec<Value>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Inbox { fn drop(&mut self) { self.task.abort(); } }
impl Inbox {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let messages = Arc::new(Mutex::new(Vec::new())); let sink = messages.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let sink = sink.clone(); async move {
                let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                sink.lock().unwrap().push(serde_json::from_slice::<Value>(&bytes).expect("mail fixture JSON"));
                axum::Json(json!({}))
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { base, messages, task }
    }
    fn len(&self) -> usize { self.messages.lock().unwrap().len() }
    async fn after(&self, before: usize) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(text) = self.messages.lock().unwrap().iter().skip(before).find_map(|m| m["text"].as_str().map(str::to_string)) { return text; }
            assert!(Instant::now() < deadline, "mail must reach the local fixture");
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
        let base = format!("http://{addr}");
        let dir = std::env::temp_dir().join(format!("openwarp-wallet-regressions-{}-{}", std::process::id(), addr.port()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
        builder.create(&dir).unwrap();
        let inbox = Inbox::start().await; let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("OPENWARP_") || name.to_ascii_uppercase().ends_with("_PROXY") || name == "REDIS_URL" { cmd.env_remove(key); }
        }
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", &inbox.base).env("OPENWARP_LICENSE", "development")
            .env("TOKIO_WORKER_THREADS", "1").stdout(Stdio::null()).stderr(Stdio::null());
        drop(reserved); let child = cmd.spawn().expect("spawn current server binary");
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let mut s = Self { child, base, dir, client, inbox }; let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(s.child.try_wait().unwrap().is_none(), "wallet regression server exited before readiness");
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() && r.json::<Value>().await.is_ok_and(|v| v["ok"] == true && v["service"] == "openwarp") { return s; }
            }
            assert!(Instant::now() < deadline, "wallet regression server readiness");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>, grant: Option<&str>) -> Resp {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(token) = token { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        if let Some(grant) = grant { request = request.header("x-openwarp-step-up", grant); }
        let response = request.send().await.expect("wallet regression API request"); let status = response.status().as_u16();
        let text = response.text().await.expect("API response body");
        let body = serde_json::from_str(&text).unwrap_or(Value::Null); Resp { status, body }
    }
    async fn account(&self, email: &str) -> Account {
        let before = self.inbox.len();
        good(self.call(Method::POST, "/api/auth/register", None, Some(json!({"email":email,"password":"correct-horse-battery"})), None).await, "register account");
        let text = self.inbox.after(before).await;
        let path = text.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string())).expect("verification link");
        good(self.call(Method::GET, &path, None, None, None).await, "verify account email");
        let login = good(self.call(Method::POST, "/api/auth/login", None, Some(json!({"email":email,"password":"correct-horse-battery"})), None).await, "account login");
        let token = field(&login, "token"); let id = field(&login, "user_id");
        let orgs = good(self.call(Method::GET, "/api/orgs", Some(&token), None, None).await, "list own workspaces");
        Account { token, id, org: field(&orgs[0], "id") }
    }
    async fn invite(&self, owner: &Account, member: &Account, email: &str, role: &str) {
        let invited = good(self.call(Method::POST, &format!("/api/orgs/{}/members", owner.org), Some(&owner.token), Some(json!({"email":email,"role":role})), None).await, "invite member");
        good(self.call(Method::POST, "/api/auth/accept-invite", Some(&member.token), Some(json!({"token":invited["invite_token"]})), None).await, "accept membership invitation");
    }
    async fn envs(&self, owner: &Account) -> Vec<String> {
        let app = good(self.call(Method::POST, &format!("/api/orgs/{}/apps", owner.org), Some(&owner.token), Some(json!({"name":"wallet-regressions"})), None).await, "create application");
        let envs = good(self.call(Method::GET, &format!("/api/apps/{}/envs", field(&app,"id")), Some(&owner.token), None, None).await, "list environments");
        let ids: Vec<_> = envs.as_array().unwrap().iter().map(|v| field(v,"id")).collect(); assert!(ids.len() >= 2); ids
    }
    async fn put(&self, token: &str, env: &str, secrets: Value) {
        good(self.call(Method::PUT, &format!("/api/envs/{env}/secrets"), Some(token), Some(json!({"secrets":secrets})), None).await, "write secret records");
    }
    async fn list(&self, token: &str, env: &str) -> Value {
        good(self.call(Method::GET, &format!("/api/envs/{env}/secrets"), Some(token), None, None).await, "list secrets")["secrets"].clone()
    }
    async fn policy(&self, owner: &Account, env: &str, prefix: &str) {
        good(self.call(Method::PUT, &format!("/api/envs/{env}/path-policy/developer"), Some(&owner.token), Some(json!({"rules":[{"prefix":prefix,"capabilities":["read"]}]})), None).await, "set developer read path policy");
    }
    async fn grant(&self, token: &str) -> String {
        let before = self.inbox.len();
        let start = good(self.call(Method::POST, "/api/auth/step-up/start", Some(token), Some(json!({"risk":"very_risky"})), None).await, "start real VeryRisky proof");
        assert_eq!(start["email_sent"], true);
        let text = self.inbox.after(before).await;
        let code = text.split(|c: char| !c.is_ascii_digit()).find(|v| v.len() == 6).expect("emailed six-digit code");
        field(&good(self.call(Method::POST, "/api/auth/step-up/verify", Some(token), Some(json!({"challenge":start["challenge"],"email_code":code})), None).await, "verify delivered email proof"), "token")
    }
    fn grant_used(&self, grant: &str) -> i64 {
        let db = rusqlite::Connection::open_with_flags(self.dir.join("test.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db.query_row("SELECT used FROM step_up_grants WHERE token_hash=?", [openwarp_crypto::hash_token(grant)], |r| r.get(0)).expect("API-issued proof persisted")
    }
}
fn field(v: &Value, key: &str) -> String { v[key].as_str().filter(|s| !s.is_empty()).expect(key).to_string() }
fn good(r: Resp, action: &str) -> Value { assert_eq!(r.status, 200, "{action} (response withheld)"); r.body }
fn row<'a>(rows: &'a Value, key: &str) -> &'a Value { rows.as_array().unwrap().iter().find(|s| s["key"] == key).expect("expected secret row") }
fn item<'a>(detail: &'a Value, key: &str) -> &'a Value { detail["changes"][0]["items"].as_array().unwrap().iter().find(|s| s["key"] == key).expect("expected proposal item") }
fn no_wallet(value: &Value) {
    let text = value.to_string();
    assert!(!text.contains(WALLET) && !text.contains(OLD), "pre-promotion wallet material escaped in an ordinary response");
}
fn reveal(env: &str, sid: &str) -> String { format!("/api/envs/{env}/secrets/{sid}/reveal") }

async fn proposal_promotion(existing: bool) {
    let s = Server::start().await;
    let owner = s.account("owner@wallet-regressions.test.invalid").await;
    let author = s.account("author@wallet-regressions.test.invalid").await;
    s.invite(&owner, &author, "author@wallet-regressions.test.invalid", "developer").await;
    let envs = s.envs(&owner).await; let env = &envs[0];
    let grant = good(s.call(Method::PUT, "/api/instance/features", Some(&owner.token), Some(json!({"org":owner.org,"features":["change-requests"]})), None).await, "grant change-requests feature");
    assert_eq!(grant["features"], json!(["change-requests"]));
    if existing { s.put(&owner.token, env, json!([{"key":"PROMOTED","path":"/team/","value":OLD}])).await; }
    let created = good(s.call(Method::POST, &format!("/api/orgs/{}/change-requests", owner.org), Some(&author.token), Some(json!({"title":"Review wallet candidate","changes":[{"env_id":env,"secrets":[{"key":"PROMOTED","path":"/team/","value":WALLET},{"key":"ORDINARY","path":"/team/","value":"ordinary-reviewed"}]}]})), None).await, "create ordinary change request");
    assert_eq!(created["status"], "pending"); assert_eq!(created["revision"], 1);
    let pid = field(&created,"id"); let detail_path = format!("/api/change-requests/{pid}");
    let pending = good(s.call(Method::GET, &detail_path, Some(&author.token), None, None).await, "read pending ordinary proposal");
    let proposed = item(&pending,"PROMOTED"); assert_eq!(proposed["after"]["value"].as_str(), Some(WALLET));
    if existing { assert_eq!(proposed["before"]["value"].as_str(), Some(OLD)); } else { assert!(proposed["before"].is_null(), "create proposal has no previous record"); }
    for (action, expected) in [("approve","approved"),("apply","applied")] {
        let result = good(s.call(Method::POST, &format!("{detail_path}/{action}"), Some(&owner.token), Some(json!({"revision":1})), None).await, "different account approves/applies proposal");
        assert_eq!(result["status"], expected);
    }
    let applied = good(s.call(Method::GET, &detail_path, Some(&author.token), None, None).await, "read applied ordinary proposal");
    assert_eq!(applied["status"], "applied"); assert_eq!(item(&applied,"PROMOTED")["after"]["value"].as_str(), Some(WALLET));
    let before = s.list(&author.token,env).await; let record = row(&before,"PROMOTED"); let sid = field(record,"id");
    assert_eq!(record["value"].as_str(), Some(WALLET)); assert_eq!(record["type"], "secret");
    if existing { assert_eq!(item(&pending,"PROMOTED")["before"]["id"], sid); }
    let version = record["version"].as_i64().unwrap();
    s.put(&owner.token,env,json!([{"key":"PROMOTED","path":"/team/","value":WALLET,"type":"wallet_private_key"}])).await;
    let current = s.list(&author.token,env).await; let promoted = row(&current,"PROMOTED");
    assert_eq!(promoted["id"], sid, "promotion must preserve the exact applied record"); assert_eq!(promoted["version"], version+1);
    assert_eq!(promoted["type"], "wallet_private_key"); assert!(promoted["value"].is_null()); no_wallet(&current);
    let history = good(s.call(Method::GET, &format!("/api/secrets/{sid}/history"), Some(&author.token), None, None).await, "read promoted wallet history without proof"); no_wallet(&history);
    let detail = good(s.call(Method::GET, &detail_path, Some(&author.token), None, None).await, "ordinary reader gets applied proposal without reveal proof");
    assert_eq!(detail["status"], "applied"); assert_eq!(detail["revision"], 1);
    assert_eq!(item(&detail,"ORDINARY")["after"]["value"], "ordinary-reviewed", "unpromoted proposal values remain readable");
    let target = item(&detail,"PROMOTED");
    assert!(target["after"]["value"].is_null(), "applied proposal after.value must be null once its exact record is promoted to a wallet");
    if existing { assert!(target["before"]["value"].is_null(), "pre-promotion before.value must also be null"); } else { assert!(target["before"].is_null()); }
    no_wallet(&detail);
}

#[tokio::test]
async fn applied_create_proposal_masks_value_after_same_record_wallet_promotion() {
    let _serial = SERIAL.lock().await; proposal_promotion(false).await;
}

#[tokio::test]
async fn existing_record_proposal_masks_both_snapshots_but_keeps_ordinary_values() {
    let _serial = SERIAL.lock().await; proposal_promotion(true).await;
}

#[tokio::test]
async fn developer_wallet_reveal_honors_target_path_and_preserves_denied_proof() {
    let _serial = SERIAL.lock().await;
    let s = Server::start().await; let owner = s.account("owner@wallet-path.test.invalid").await;
    let member = s.account("developer@wallet-path.test.invalid").await;
    s.invite(&owner,&member,"developer@wallet-path.test.invalid","developer").await;
    let envs = s.envs(&owner).await; let target = &envs[0];
    s.put(&owner.token,target,json!([{"key":"ALLOWED","path":"/team/","value":WALLET,"type":"wallet_private_key"},{"key":"DENIED","path":"/other/","value":OLD,"type":"wallet_recovery_phrase"}])).await;
    let records = s.list(&owner.token,target).await;
    let allowed = reveal(target,&field(row(&records,"ALLOWED"),"id")); let denied = reveal(target,&field(row(&records,"DENIED"),"id"));
    s.policy(&owner,&envs[1],"/elsewhere/").await;
    let unrelated_policy = s.call(Method::GET,&allowed,Some(&member.token),None,None).await;
    s.policy(&owner,target,"/team/").await;
    let visible = s.list(&member.token,target).await; assert_eq!(visible.as_array().unwrap().len(),1);
    assert_eq!(row(&visible,"ALLOWED")["value"],Value::Null); no_wallet(&visible);
    let challenge = s.call(Method::GET,&allowed,Some(&member.token),None,None).await;
    let grant = s.grant(&member.token).await; assert_eq!(s.grant_used(&grant),0);
    let forbidden = s.call(Method::GET,&denied,Some(&member.token),None,Some(&grant)).await;
    assert_eq!(forbidden.status,403,"a valid proof must not authorize another path"); no_wallet(&forbidden.body);
    assert_eq!(s.grant_used(&grant),0,"path denial must leave the API-issued grant unused");
    let revealed = s.call(Method::GET,&allowed,Some(&member.token),None,Some(&grant)).await;
    let replay = s.call(Method::GET,&allowed,Some(&member.token),None,Some(&grant)).await;
    assert_eq!([unrelated_policy.status,challenge.status,forbidden.status,revealed.status,replay.status],[428,428,403,200,428],"allowed developer reads must reach VeryRisky verification and reveal; another environment's policy must not blanket-deny the target");
    for response in [&unrelated_policy,&challenge,&replay] {
        assert_eq!(response.body["step_up_required"],true); assert_eq!(response.body["risk"],"very_risky"); assert_eq!(response.body["email_required"],true); no_wallet(&response.body);
    }
    assert_eq!(revealed.body["value"].as_str(),Some(WALLET),"the same grant survives the denied path and reveals the allowed wallet");
    assert_eq!(s.grant_used(&grant),1);
    let audit = good(s.call(Method::GET,&format!("/api/orgs/{}/audit",owner.org),Some(&owner.token),None,None).await,"read reveal audit");
    assert_eq!(audit.as_array().unwrap().iter().filter(|v| v["action"]=="wallet.reveal" && v["actor"]==member.id).count(),1); no_wallet(&audit);
}
