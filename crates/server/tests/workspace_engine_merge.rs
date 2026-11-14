// Independently authored failing-first tests for the PR7 engine merge.
// The engine's fresh-database path (baseline 1, squashed 2..=17, applied 18+)
// lost PR7's former migration 18: invites.id/invited_by columns, the
// idx_invites_id unique index, and the guarded workspace policy meta rows.
// These tests pin the schema, the ledger delivering it as a new migration 29,
// and the invitation/policy behaviour that depends on it. The provider_consent
// module is a verbatim copy of the independently authored suite from the
// workspace-policy-merge worktree (tests/provider_invite_merge.rs, untracked):
// provider sign-in (OIDC/SAML/LDAP) is authentication, not consent to redeem
// a pending invitation.
use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};

static START_RETRIES: AtomicU32 = AtomicU32::new(0);
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "engine-merge-test-password";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Mock { base: String, inbox: Arc<Mutex<Vec<Value>>>, task: tokio::task::JoinHandle<()> }
impl Drop for Mock { fn drop(&mut self) { self.task.abort(); } }
impl Mock {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let relay = inbox.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                loop {
                    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await.unwrap().unwrap();
                    if n == 0 { break; }
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let length = header.lines().find_map(|line| { let (k, v) = line.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().unwrap()) }).unwrap_or(0);
                        if bytes.len() >= end + 4 + length { break; }
                    }
                }
                let request = String::from_utf8_lossy(&bytes);
                if request.split_whitespace().nth(1) == Some("/mail") {
                    relay.lock().unwrap().push(serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap());
                }
                let body = r#"{"ok":true}"#;
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self { base, inbox, task }
    }
}
struct Resp { status: u16, body: Value }
impl Resp { fn expect(&self, status: u16, context: &str) { assert_eq!(self.status, status, "{}: error={}", context, self.body["error"]); } }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, mock: Mock }
impl Drop for Server { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); } }
impl Server {
    async fn start() -> Self {
        let mock = Mock::start().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        let dir = std::env::temp_dir().join(format!("openwarp-engine-merge-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir(&dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "1")
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", format!("{}/mail", mock.base))
            .stdout(Stdio::null()).stderr(Stdio::null());
        drop(listener);
        let child = cmd.spawn().expect("spawn current server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir: dir.clone(), client, mock };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { return Box::pin(Server::start()).await; }
        panic!("server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        let r = req.send().await.expect("HTTP request");
        Resp { status: r.status().as_u16(), body: serde_json::from_str(&r.text().await.unwrap()).unwrap_or(Value::Null) }
    }
    fn db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.dir.join("test.db")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap(); db
    }
    async fn verify(&self, email: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let link = self.mock.inbox.lock().unwrap().iter().rev().filter(|m| m["to"] == email).find_map(|m| {
                m["text"].as_str()?.split_whitespace().find(|s| s.contains("/api/auth/verify?token=")).map(str::to_string)
            });
            if let Some(link) = link {
                let path = link.strip_prefix(&self.base).expect("local verification URL");
                self.call(Method::GET, path, None, None).await.expect(200, "verify email through relay"); return;
            }
            assert!(Instant::now() < deadline, "verification email missing from local relay");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
struct Account { token: String }
fn account(body: &Value) -> Account {
    Account { token: body["token"].as_str().expect("session token").into() }
}
async fn register(s: &Server, email: &str) -> Account {
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email":email,"password":PASSWORD}))).await;
    r.expect(200, "register account");
    assert_eq!(r.body["verification_required"], true);
    assert!(r.body.get("token").is_none(), "registration must not bypass email verification");
    s.verify(email).await;
    let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email":email,"password":PASSWORD}))).await;
    login.expect(200, "verified account login"); account(&login.body)
}
async fn orgs(s: &Server, token: &str) -> Vec<Value> {
    let r = s.call(Method::GET, "/api/orgs", Some(token), None).await; r.expect(200, "list workspaces");
    r.body.as_array().expect("workspace list").clone()
}
async fn owner(s: &Server) -> (Account, String) {
    let user = register(s, "owner@test.invalid").await;
    let org = orgs(s, &user.token).await[0]["id"].as_str().unwrap().to_string(); (user, org)
}
async fn invite(s: &Server, owner: &Account, org: &str, email: &str) -> Value {
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(&owner.token), Some(json!({"email":email,"role":"developer"}))).await;
    r.expect(200, "issue invitation"); r.body
}
fn token(inv: &Value) -> &str { inv["invite_token"].as_str().expect("invitation must return a consent token") }
async fn accept(s: &Server, inv: &str) -> Resp {
    s.call(Method::POST, "/api/auth/accept-invite", None, Some(json!({"token":inv,"password":PASSWORD}))).await
}
async fn policy(s: &Server, owner: &Account, open: bool) -> Resp {
    s.call(Method::PUT, "/api/instance/workspaces", Some(&owner.token), Some(json!({"open":open}))).await
}

#[tokio::test]
async fn engine_schema_carries_pr7_invitation_columns_index_and_policy_defaults() {
    let _serial = SERIAL.lock().await;
    let s = Server::start().await;
    let db = s.db();
    let columns: Vec<(String, String, i64, Option<String>)> = db.prepare("PRAGMA table_info(invites)").unwrap()
        .query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap()
        .collect::<Result<_, _>>().unwrap();
    let id = columns.iter().find(|c| c.0 == "id")
        .unwrap_or_else(|| panic!("invites.id column missing after engine migrations: {:?}", columns.iter().map(|c| &c.0).collect::<Vec<_>>()));
    assert_eq!(id.1.to_uppercase(), "TEXT", "invites.id stays TEXT like PR7 migration 18");
    assert_eq!(id.2, 0, "invites.id stays nullable so legacy rows survive");
    let invited_by = columns.iter().find(|c| c.0 == "invited_by")
        .unwrap_or_else(|| panic!("invites.invited_by column missing after engine migrations: {:?}", columns.iter().map(|c| &c.0).collect::<Vec<_>>()));
    assert_eq!(invited_by.1.to_uppercase(), "TEXT");
    assert_eq!(invited_by.3.as_deref(), Some("''"), "invites.invited_by defaults to '' like PR7 migration 18");
    let unique: i64 = db.query_row("SELECT COUNT(*) FROM pragma_index_list('invites') WHERE name='idx_invites_id' AND \"unique\"=1", [], |r| r.get(0)).unwrap();
    assert_eq!(unique, 1, "idx_invites_id must exist as a UNIQUE index on invites");
    let indexed: Option<String> = db.query_row("SELECT group_concat(name) FROM pragma_index_info('idx_invites_id')", [], |r| r.get(0)).unwrap();
    assert_eq!(indexed.as_deref(), Some("id"), "idx_invites_id covers exactly invites.id");
    for key in ["workspace_policy_lock", "workspace_creation_open"] {
        let v: Option<String> = db.query_row("SELECT v FROM meta WHERE k=?", [key], |r| r.get(0)).ok();
        assert_eq!(v.as_deref(), Some("1"), "meta {} must be seeded by the engine with PR7's exact default '1'", key);
    }
    let migration: (String, String, i64) = db.query_row("SELECT name,checksum,success FROM schema_migrations WHERE version=29", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap_or_else(|_| panic!("the schema repair must ship as new migration 29, not as edits to shipped files"));
    assert_eq!(migration.2, 1, "migration 29 completed");
    assert!(!migration.0.is_empty(), "migration 29 is named");
    assert_ne!(migration.1, "squashed", "migration 29 is a real applied migration, not a squash marker");
    assert_eq!(migration.1.len(), 64, "migration 29 records its file checksum");
    let insert = "INSERT INTO invites(id,token_hash,email,org_id,role,invited_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)";
    db.execute(insert, rusqlite::params!["dup-id","hash-a","a@engine.test","org-engine","developer","",1,2]).unwrap();
    let dup = db.execute(insert, rusqlite::params!["dup-id","hash-b","b@engine.test","org-engine","developer","",1,2]).unwrap_err();
    assert!(dup.to_string().contains("invites.id"), "duplicate invitation management ids must be rejected: {}", dup);
}

#[tokio::test]
async fn invitation_lifecycle_works_on_a_fresh_engine_database() {
    let _serial = SERIAL.lock().await;
    let s = Server::start().await;
    let (plain, _) = owner(&s).await;
    let defaults = orgs(&s, &plain.token).await;
    assert_eq!(defaults.len(), 1, "signup still creates the default workspace through the seeded policy rows");
    let (owner, org) = (&plain, defaults[0]["id"].as_str().unwrap());
    let invited = invite(&s, owner, org, "member@engine.test").await;
    let raw = token(&invited);
    let list = s.call(Method::GET, &format!("/api/orgs/{}/invites", org), Some(&owner.token), None).await;
    list.expect(200, "admin lists pending invitations");
    let pending = list.body.as_array().expect("pending invitations");
    assert_eq!(pending.len(), 1);
    assert!(!pending[0]["id"].as_str().unwrap_or("").is_empty(), "invitations carry an opaque management id");
    let joined = accept(&s, raw).await;
    joined.expect(200, "invitee consents through the share token");
    let member = account(&joined.body);
    let memberships = orgs(&s, &member.token).await;
    assert_eq!(memberships.len(), 1, "joining by invitation must not create a second workspace");
    assert_eq!(memberships[0]["id"], *org);
    accept(&s, raw).await.expect(400, "consent token is single use");
}

#[tokio::test]
async fn seeded_policy_rows_keep_instance_creation_control_working() {
    let _serial = SERIAL.lock().await;
    let s = Server::start().await; let (owner, _) = owner(&s).await;
    let providers = s.call(Method::GET, "/api/auth/providers", None, None).await;
    providers.expect(200, "public policy"); assert_eq!(providers.body["workspace_creation_open"], true);
    policy(&s, &owner, false).await.expect(200, "owner closes creation through the seeded policy lock row");
    let other = register(&s, "other@test.invalid").await;
    assert!(orgs(&s, &other.token).await.is_empty(), "closed creation suppresses the default workspace on signup");
    s.call(Method::POST, "/api/orgs", Some(&other.token), Some(json!({"name":"blocked"}))).await.expect(403, "invitation-only policy blocks self-service workspaces");
    let info = s.call(Method::GET, "/api/instance", Some(&owner.token), None).await;
    info.expect(200, "instance policy reads back"); assert_eq!(info.body["workspace_creation_open"], false);
    policy(&s, &owner, true).await.expect(200, "reopen creation");
    s.call(Method::POST, "/api/orgs", Some(&other.token), Some(json!({"name":"allowed"}))).await.expect(200, "reopening restores self-service creation");
}

#[cfg(feature = "ldap")]
mod provider_consent {
// Provider authentication is not consent to redeem a workspace invitation.
use openwarp_crypto as oc;
use reqwest::{Client, Method, Url};
use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "provider-invite-test-password";
const EMAIL: &str = "invitee@test.invalid";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
fn url_b64(bytes: &[u8]) -> String { oc::b64(bytes).trim_end_matches('=').replace('+', "-").replace('/', "_") }

struct Idp {
    base: String, inbox: Arc<Mutex<Vec<Value>>>, identity: Arc<Mutex<(String, String)>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Idp { fn drop(&mut self) { self.task.abort(); } }
impl Idp {
    async fn start() -> Self {
        let rsa = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pem = rsa.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let signing = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let jwks = json!({"keys":[{"kty":"RSA","kid":"fixture","use":"sig","alg":"RS256","n":url_b64(&rsa.n().to_bytes_be()),"e":url_b64(&rsa.e().to_bytes_be())}]});
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let identity = Arc::new(Mutex::new((EMAIL.to_string(), String::new())));
        let (issuer, mail, profile) = (base.clone(), inbox.clone(), identity.clone());
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = Vec::new(); let mut chunk = [0; 4096];
                loop {
                    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await.unwrap().unwrap();
                    if n == 0 { break; } bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let len = header.lines().find_map(|line| { let (k,v) = line.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().unwrap()) }).unwrap_or(0);
                        if bytes.len() >= end + 4 + len { break; }
                    }
                }
                let request = String::from_utf8_lossy(&bytes);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let body = match path {
                    "/mail" => { mail.lock().unwrap().push(serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()); json!({"ok":true}) }
                    "/.well-known/openid-configuration" => json!({"issuer":issuer,"authorization_endpoint":format!("{}/authorize",issuer),"token_endpoint":format!("{}/token",issuer),"jwks_uri":format!("{}/jwks",issuer)}),
                    "/jwks" => jwks.clone(),
                    "/token" => {
                        let (email, nonce) = profile.lock().unwrap().clone();
                        let claims = json!({"iss":issuer,"aud":"test-client","sub":email,"email":email,"email_verified":true,"iat":now(),"exp":now()+300,"nonce":nonce});
                        let header = jsonwebtoken::Header { alg:jsonwebtoken::Algorithm::RS256, kid:Some("fixture".into()), ..Default::default() };
                        json!({"access_token":"fixture-access","token_type":"Bearer","id_token":jsonwebtoken::encode(&header,&claims,&signing).unwrap()})
                    }
                    _ => panic!("unexpected IdP route"),
                }.to_string();
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await;
            }
        });
        Self { base, inbox, identity, task }
    }
}
struct Reply { status: u16, body: Value, text: String, headers: reqwest::header::HeaderMap }
impl Reply { fn expect(&self, status: u16, reason: &str) { assert_eq!(self.status,status,"{}: error={}",reason,self.body["error"]); } }
async fn reply(r: reqwest::Response) -> Reply {
    let status=r.status().as_u16(); let headers=r.headers().clone(); let text=r.text().await.unwrap();
    let body=serde_json::from_str(&text).unwrap_or(Value::Null); Reply { status, body, text, headers }
}
struct Server { child: Child, base: String, dir: PathBuf, client: Client, idp: Idp }
impl Drop for Server { fn drop(&mut self) { let _=self.child.kill(); let _=self.child.wait(); let _=std::fs::remove_dir_all(&self.dir); } }
impl Server {
    async fn start() -> Self {
        let idp=Idp::start().await;
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap();
        let base=format!("http://{}",addr);
        let dir=std::env::temp_dir().join(format!("openwarp-provider-invite-{}-{}",std::process::id(),addr.port()));
        std::fs::create_dir(&dir).unwrap();
        let mut cmd=Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string())
            .env("OPENWARP_LICENSE","development")
            .env("OPENWARP_PUBLIC_URL",&base).env("TOKIO_WORKER_THREADS","1")
            .env("OPENWARP_EMAIL_PROVIDER","webhook").env("OPENWARP_EMAIL_WEBHOOK",format!("{}/mail",idp.base))
            .env("OPENWARP_ALLOW_PRIVATE_EGRESS","1").stdout(Stdio::null()).stderr(Stdio::null());
        drop(listener); let child=cmd.spawn().unwrap();
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(25)).build().unwrap();
        let s=Self { child, base, dir, client, idp }; let deadline=Instant::now()+Duration::from_secs(30);
        while Instant::now()<deadline {
            if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { return Box::pin(Server::start()).await; }
        panic!("fixture server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Reply {
        let mut req=self.client.request(method,format!("{}{}",self.base,path));
        if let Some(t)=token { req=req.bearer_auth(t); }
        if let Some(b)=body { req=req.json(&b); }
        reply(req.send().await.expect("fixture HTTP request")).await
    }
    async fn call_stepped_up(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Reply {
        let r=self.call(method.clone(),path,token,body.clone()).await;
        if r.status!=428 || r.body["step_up_required"]!=true { return r; }
        let Some(token)=token else { return r; };
        let Some(risk)=r.body["risk"].as_str() else { return r; };
        let before=self.idp.inbox.lock().unwrap().len();
        let start=self.call(Method::POST,"/api/auth/step-up/start",Some(token),Some(json!({"risk":risk}))).await;
        start.expect(200,"start provider configuration proof"); assert_eq!(start.body["email_sent"],true);
        let challenge=start.body["challenge"].as_str().expect("provider configuration proof challenge");
        let deadline=Instant::now()+Duration::from_secs(10);
        let code=loop {
            let found=self.idp.inbox.lock().unwrap().iter().skip(before).rev()
                .filter(|m|m["subject"]=="Your OpenWarp verification code")
                .filter_map(|m|m["text"].as_str()).filter(|text|text.contains("Your verification code is "))
                .find_map(|text|text.split(|c:char|!c.is_ascii_digit()).find(|part|part.len()==6).map(str::to_string));
            if let Some(code)=found { break code; }
            assert!(Instant::now()<deadline,"new provider configuration proof mail missing");
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let verified=self.call(Method::POST,"/api/auth/step-up/verify",Some(token),Some(json!({"challenge":challenge,"email_code":code}))).await;
        verified.expect(200,"verify provider configuration proof");
        let grant=verified.body["token"].as_str().expect("provider configuration proof grant");
        let mut req=self.client.request(method,format!("{}{}",self.base,path)).bearer_auth(token).header("x-openwarp-step-up",grant);
        if let Some(body)=body { req=req.json(&body); }
        reply(req.send().await.expect("stepped-up fixture HTTP request")).await
    }
    fn db(&self) -> rusqlite::Connection { let db=rusqlite::Connection::open(self.dir.join("test.db")).unwrap(); db.busy_timeout(Duration::from_secs(5)).unwrap(); db }
    async fn register(&self, email: &str) -> String {
        let r=self.call(Method::POST,"/api/auth/register",None,Some(json!({"email":email,"password":PASSWORD}))).await;
        r.expect(200,"register password fixture"); assert_eq!(r.body["verification_required"],true);
        let deadline=Instant::now()+Duration::from_secs(10);
        let link=loop {
            let found=self.idp.inbox.lock().unwrap().iter().rev().filter(|m|m["to"]==email).find_map(|m|
                m["text"].as_str()?.split_whitespace().find(|s|s.contains("/api/auth/verify?token=")).map(str::to_string));
            if let Some(link)=found { break link; }
            assert!(Instant::now()<deadline,"fixture verification mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        self.call(Method::GET,link.strip_prefix(&self.base).unwrap(),None,None).await.expect(200,"verify fixture account");
        let login=self.call(Method::POST,"/api/auth/login",None,Some(json!({"email":email,"password":PASSWORD}))).await;
        login.expect(200,"login fixture account"); login.body["token"].as_str().unwrap().into()
    }
    async fn orgs(&self, session: &str) -> Vec<Value> {
        let r=self.call(Method::GET,"/api/orgs",Some(session),None).await; r.expect(200,"provider session lists workspaces"); r.body.as_array().unwrap().clone()
    }
    async fn owner(&self) -> (String,String) {
        let token=self.register("owner@test.invalid").await;
        let org=self.orgs(&token).await[0]["id"].as_str().unwrap().to_string(); (token,org)
    }
    async fn invite(&self, owner: &str, org: &str) -> String {
        let r=self.call(Method::POST,&format!("/api/orgs/{}/members",org),Some(owner),Some(json!({"email":EMAIL,"role":"admin"}))).await;
        r.expect(200,"owner issues tracked privileged invitation"); r.body["invite_token"].as_str().unwrap().into()
    }
    fn invitation_state(&self, org: &str) -> (i64,i64) {
        self.db().query_row("SELECT (SELECT COUNT(*) FROM org_members m JOIN users u ON u.id=m.user_id WHERE m.org_id=? AND u.email=?),accepted FROM invites WHERE org_id=? AND email=?",rusqlite::params![org,EMAIL,org,EMAIL],|r|Ok((r.get(0)?,r.get(1)?))).unwrap()
    }
    async fn close_signups(&self, owner: &str) {
        self.call(Method::PUT,"/api/instance/signups",Some(owner),Some(json!({"open":false}))).await.expect(200,"close independent self-signup policy");
    }
    async fn check_session(&self, session: &str) {
        let r=self.call(Method::GET,"/api/me",Some(session),None).await; r.expect(200,"provider establishes an account session"); assert_eq!(r.body["email"],EMAIL);
    }
}

#[derive(Clone,Copy)] enum Kind { Oidc, Saml, Ldap }
enum Provider { Oidc, Saml(Box<risaml::Saml<risaml::Idp>>), Ldap(Directory) }
impl Provider {
    async fn configure(kind: Kind, s: &Server, owner: &str, org: &str, auto: bool, domains: &str) -> Self {
        // The provider being configured must hold its workspace grant; the
        // build compiles it (the module is feature-gated), the license unlocks
        // it, and this is the per-workspace third gate.
        // Per-org OIDC is not a gated surface; SAML and LDAP hold workspace grants.
        let feature = match kind { Kind::Saml => Some("saml"), Kind::Ldap => Some("ldap"), Kind::Oidc => None };
        if let Some(feature) = feature {
            s.call(Method::PUT,"/api/instance/features",Some(owner),Some(json!({"org":org,"features":[feature]}))).await.expect(200,"grant the provider surface");
        }
        match kind {
            Kind::Oidc => {
                s.call_stepped_up(Method::PUT,&format!("/api/orgs/{}/settings",org),Some(owner),Some(json!({
                    "oidc_issuer":s.idp.base,"oidc_client_id":"test-client","oidc_client_secret":"fixture-secret",
                    "oidc_redirect_uri":format!("{}/api/auth/oidc/callback",s.base),"oidc_auto_provision":auto,"oidc_allowed_domains":domains
                }))).await.expect(200,"configure workspace OIDC"); Self::Oidc
            }
            Kind::Saml => {
                use risaml::{CertificatePem,Credentials,EntityId,IdpConfig,IdpValidationPolicy,PrivateKeyPem,Saml,SsoEndpoint};
                let rsa=rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng,2048).unwrap();
                let pem=rsa.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
                let key=rcgen::KeyPair::from_pem(&pem).unwrap();
                let cert=rcgen::CertificateParams::new(vec!["idp.test".into()]).unwrap().self_signed(&key).unwrap();
                let idp=Saml::idp(IdpConfig::builder(EntityId::try_new("https://idp.test/metadata").unwrap())
                    .sso_endpoint(SsoEndpoint::post("https://idp.test/sso").unwrap()).sso_endpoint(SsoEndpoint::redirect("https://idp.test/sso").unwrap())
                    .credentials(Credentials { signing_key:Some(PrivateKeyPem::new(pem)),signing_certificate:Some(CertificatePem::new(cert.pem())),..Credentials::default() })
                    .validation(IdpValidationPolicy::strict()).build().unwrap()).unwrap();
                s.call_stepped_up(Method::PUT,&format!("/api/orgs/{}/saml",org),Some(owner),Some(json!({"idp_entity_id":"https://idp.test/metadata","metadata_xml":idp.metadata_xml().to_string(),"allow_unsigned_metadata":true,"auto_provision":auto,"allowed_domains":domains}))).await.expect(200,"configure signed SAML fixture");
                Self::Saml(Box::new(idp))
            }
            Kind::Ldap => {
                let dir=Directory::start();
                s.call_stepped_up(Method::PUT,&format!("/api/orgs/{}/ldap",org),Some(owner),Some(json!({"url":format!("ldaps://127.0.0.1:{}",dir.port),"bind_dn":SERVICE_DN,"bind_password":"service-secret","base_dn":"dc=test,dc=invalid","user_filter":"(uid={username})","ca_cert_pem":dir.ca_pem,"auto_provision":auto,"allowed_domains":domains}))).await.expect(200,"configure TLS LDAP fixture");
                Self::Ldap(dir)
            }
        }
    }
    async fn login(&self, s: &Server, org: &str) -> Reply {
        match self {
            Self::Oidc => {
                let start=s.call(Method::GET,&format!("/api/auth/oidc/{}/start",org),None,None).await;
                start.expect(307,"OIDC starts through real discovery");
                let url=Url::parse(start.headers["location"].to_str().unwrap()).unwrap();
                let pairs=url.query_pairs().collect::<std::collections::HashMap<_,_>>();
                *s.idp.identity.lock().unwrap()=(EMAIL.into(),pairs["nonce"].to_string());
                s.call(Method::GET,&format!("/api/auth/oidc/callback?code=fixture&state={}",pairs["state"]),None,None).await
            }
            Self::Saml(idp) => {
                use risaml::{AuthnRequest,BrowserInput,EntityId,MetadataTrustPolicy,NameId,ReplayPolicy,RespondSso,SamlValidationContext,SpDescriptor,Subject};
                let metadata=s.call(Method::GET,&format!("/api/auth/saml/{}/metadata",org),None,None).await;
                metadata.expect(200,"retrieve SP metadata");
                let sp=SpDescriptor::from_metadata_xml_for(EntityId::try_new(format!("{}/api/auth/saml/{}/metadata",s.base,org)).unwrap(),&metadata.text,MetadataTrustPolicy::UnsignedForCompatibility).unwrap();
                let start=s.call(Method::GET,&format!("/api/auth/saml/{}/start",org),None,None).await;
                start.expect(307,"SAML starts through signed AuthnRequest");
                let query=start.headers["location"].to_str().unwrap().split_once('?').unwrap().1.to_string();
                let request=idp.receive_sso(&sp,BrowserInput::<AuthnRequest>::redirect(query),SamlValidationContext::new(SystemTime::now(),ReplayPolicy::DisabledForCompatibility)).unwrap();
                let response=idp.respond_sso(&sp,&request,Subject::new(NameId::new(EMAIL,None),Vec::new()),RespondSso::post()).unwrap();
                let fields=response.post_form().unwrap().fields().iter().map(|f|(f.name().to_string(),f.value().to_string())).collect::<Vec<_>>();
                reply(s.client.post(format!("{}/api/auth/saml/{}/acs",s.base,org)).form(&fields).send().await.unwrap()).await
            }
            Self::Ldap(_directory) => s.call(Method::POST,"/api/auth/ldap",None,Some(json!({"org_id":org,"username":"invitee","password":"user-secret"}))).await,
        }
    }
    fn session(&self, r: &Reply) -> String {
        match self {
            Self::Oidc => { r.expect(307,"OIDC authenticates admitted address");
                r.headers["location"].to_str().unwrap().split_once("token=").expect("OIDC account session").1.split('&').next().unwrap().to_string() }
            Self::Saml(_) => { r.expect(303,"signed SAML authenticates admitted address");
                r.headers.get_all("set-cookie").iter().filter_map(|h|h.to_str().ok()).find_map(|h|h.strip_prefix("ow_session=").map(|v|v.split(';').next().unwrap().to_string())).expect("SAML account session") }
            Self::Ldap(_) => { r.expect(200,"TLS LDAP authenticates admitted address"); r.body["token"].as_str().expect("LDAP account session").to_string() }
        }
    }
}

async fn explicit_consent(kind: Kind) {
    let _serial=SERIAL.lock().await;
    let s=Server::start().await; let (owner,org)=s.owner().await;
    let invitation=s.invite(&owner,&org).await;
    let provider=Provider::configure(kind,&s,&owner,&org,false,"other.invalid").await;
    s.close_signups(&owner).await;
    let session=provider.session(&provider.login(&s,&org).await); s.check_session(&session).await;
    assert_eq!(s.invitation_state(&org),(0,0),"provider sign-in must neither grant pending-invite membership nor consume its token");
    assert!(s.orgs(&session).await.is_empty(),"pending invite is not a workspace membership");
    let second=provider.session(&provider.login(&s,&org).await); s.check_session(&second).await;
    assert_eq!(s.invitation_state(&org),(0,0),"repeat bound-identity login still requires consent");
    let preview=s.call(Method::GET,&format!("/api/auth/invite?token={}",invitation),None,None).await;
    preview.expect(200,"provider login leaves invitation previewable"); assert_eq!(preview.body["existing_account"],true);
    for token in [None,Some(owner.as_str())] {
        let denied=s.call(Method::POST,"/api/auth/accept-invite",token,Some(json!({"token":invitation}))).await;
        denied.expect(if token.is_none() {401} else {403},"anonymous or wrong account cannot consent");
        assert_eq!(s.invitation_state(&org),(0,0));
    }
    s.call(Method::POST,"/api/auth/accept-invite",Some(&session),Some(json!({"token":invitation}))).await.expect(200,"matching provider session explicitly accepts");
    assert_eq!(s.invitation_state(&org),(1,1),"explicit acceptance atomically joins and consumes");
    let orgs=s.orgs(&session).await; assert_eq!(orgs.len(),1); assert_eq!(orgs[0]["id"],org); assert_eq!(orgs[0]["role"],"admin");
    s.call(Method::POST,"/api/auth/accept-invite",Some(&session),Some(json!({"token":invitation}))).await.expect(400,"consumed invitation is single use");
}
async fn stale_inviter(kind: Kind) {
    let _serial=SERIAL.lock().await;
    let s=Server::start().await; let (owner,org)=s.owner().await;
    let invitation=s.invite(&owner,&org).await;
    let provider=Provider::configure(kind,&s,&owner,&org,false,"").await; s.close_signups(&owner).await;
    assert_eq!(s.db().execute("UPDATE users SET active=0 WHERE email='owner@test.invalid'",[]).unwrap(),1);
    let r=provider.login(&s,&org).await;
    assert_eq!(s.invitation_state(&org),(0,0),"inactive inviter cannot grant membership through a provider callback or consume consent");
    if [200,303,307].contains(&r.status) {
        let session=provider.session(&r); s.check_session(&session).await;
        assert!(s.orgs(&session).await.is_empty());
        s.call(Method::POST,"/api/auth/accept-invite",Some(&session),Some(json!({"token":invitation}))).await.expect(403,"explicit acceptance rechecks inactive inviter");
        assert_eq!(s.invitation_state(&org),(0,0));
    } else { assert!([401,403].contains(&r.status),"stale invite may deny admission, not cause an unrelated error"); }
}
async fn independent_admission(kind: Kind) {
    let _serial=SERIAL.lock().await;
    for (auto,domains,closed,expected) in [(false,"",false,403),(true,"test.invalid",false,200),(true,"other.invalid",false,403),(true,"test.invalid",true,403)] {
        let s=Server::start().await; let (owner,org)=s.owner().await;
        let provider=Provider::configure(kind,&s,&owner,&org,auto,domains).await;
        if closed { s.close_signups(&owner).await; }
        let r=provider.login(&s,&org).await;
        if expected==200 {
            let session=provider.session(&r); s.check_session(&session).await;
            let memberships=s.orgs(&session).await;
            assert_eq!(memberships.len(),1,"explicit auto provisioning independently admits members");
            assert_eq!(memberships[0]["id"],org); assert_eq!(memberships[0]["role"],"developer");
        } else { r.expect(403,"auto provisioning still requires enablement, allowed domain and open signups"); }
    }
    let s=Server::start().await; let (owner,org)=s.owner().await;
    let password=s.register(EMAIL).await; s.invite(&owner,&org).await;
    let provider=Provider::configure(kind,&s,&owner,&org,true,"test.invalid").await;
    let r=provider.login(&s,&org).await;
    if let Kind::Oidc = kind {
        r.expect(307,"existing OIDC email requires account proof");
        let location=r.headers["location"].to_str().unwrap();
        assert!(location.starts_with("/#link="),"OIDC must return an account-proof challenge: {}",location);
        assert!(!location.contains("token="),"OIDC must not issue a session before account proof");
        assert!(!r.headers.get_all("set-cookie").iter().any(|h|h.to_str().unwrap().starts_with("ow_session=")),"OIDC must not issue a session cookie before account proof");
        let challenge=location.strip_prefix("/#link=").unwrap().split('&').next().unwrap();
        assert!(!challenge.is_empty(),"OIDC account-proof challenge must not be empty");
        let sessions_before:i64=s.db().query_row("SELECT COUNT(*) FROM sessions",[],|r|r.get(0)).unwrap();
        let denied=s.call(Method::POST,"/api/auth/link/complete",None,Some(json!({"token":challenge,"password":"wrong-password"}))).await;
        denied.expect(401,"wrong account proof cannot link an invited identity");
        assert!(!denied.headers.get_all("set-cookie").iter().any(|h|h.to_str().unwrap().starts_with("ow_session=")),"wrong account proof must not issue a session cookie");
        let sessions_after:i64=s.db().query_row("SELECT COUNT(*) FROM sessions",[],|r|r.get(0)).unwrap();
        assert_eq!(sessions_after,sessions_before,"wrong account proof must not create a server session");
        let bindings:i64=s.db().query_row("SELECT COUNT(*) FROM oidc_subjects WHERE issuer=? AND subject=?",rusqlite::params![s.idp.base,EMAIL],|r|r.get(0)).unwrap();
        assert_eq!(bindings,0,"failed account proof must not bind the OIDC identity");
    } else { r.expect(409,"pending invite cannot silently crosslink a password account by email"); }
    assert_eq!(s.invitation_state(&org),(0,0)); s.check_session(&password).await;
}
macro_rules! provider_tests {
    ($consent:ident,$stale:ident,$admission:ident,$kind:expr) => {
        #[tokio::test] async fn $consent() { explicit_consent($kind).await; }
        #[tokio::test] async fn $stale() { stale_inviter($kind).await; }
        #[tokio::test] async fn $admission() { independent_admission($kind).await; }
    };
}
provider_tests!(oidc_pending_invite_requires_explicit_consent,oidc_inactive_inviter_cannot_grant_through_login,oidc_preserves_independent_admission_and_email_conflict,Kind::Oidc);
provider_tests!(saml_pending_invite_requires_explicit_consent,saml_inactive_inviter_cannot_grant_through_login,saml_preserves_independent_admission_and_email_conflict,Kind::Saml);
provider_tests!(ldap_pending_invite_requires_explicit_consent,ldap_inactive_inviter_cannot_grant_through_login,ldap_preserves_independent_admission_and_email_conflict,Kind::Ldap);

// The LDAPS fixture follows ldap.rs: trust a private CA, service-bind, search, then user-bind.
const SERVICE_DN: &str="cn=openwarp,dc=test,dc=invalid";
const USER_DN: &str="uid=invitee,dc=test,dc=invalid";
struct Directory { port:u16, ca_pem:String }
impl Directory {
    fn start() -> Self {
        use rcgen::{BasicConstraints,CertificateParams,DnType,IsCa,KeyPair};
        use rustls::pki_types::{PrivateKeyDer,PrivatePkcs8KeyDer};
        // OpenSSL (native-tls on Linux) rejects an empty-DN issuer during chain
        // verification, so both certificates carry explicit CommonNames.
        let ca_key=KeyPair::generate().unwrap(); let mut params=CertificateParams::new(Vec::new()).unwrap();
        params.is_ca=IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName,"OpenWarp workspace CA");
        let ca=params.self_signed(&ca_key).unwrap();
        let leaf_key=KeyPair::generate().unwrap();
        let mut leaf=CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        leaf.distinguished_name.push(DnType::CommonName,"127.0.0.1");
        let leaf=leaf.signed_by(&leaf_key,&ca,&ca_key).unwrap();
        let _=rustls::crypto::ring::default_provider().install_default();
        let config=Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![leaf.der().clone()],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()))).unwrap());
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let port=listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let config=config.clone(); let stream=incoming.unwrap();
                std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    let mut stream=rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(),stream);
                    let mut service=false;
                    while let Some(frame)=read_frame(&mut stream) {
                        let (_,body,_)=parse_tlv(&frame).unwrap(); let (_,id,used)=parse_tlv(body).unwrap();
                        let (op,body,_)=parse_tlv(&body[used..]).unwrap();
                        let (tag,payload)=match op {
                            0x42 => break,
                            0x60 => {
                                let (_,_,n)=parse_tlv(body).unwrap(); let (_,dn,m)=parse_tlv(&body[n..]).unwrap(); let (_,pw,_)=parse_tlv(&body[n+m..]).unwrap();
                                let ok=(dn==SERVICE_DN.as_bytes() && pw==b"service-secret") || (dn==USER_DN.as_bytes() && pw==b"user-secret");
                                service=ok && dn==SERVICE_DN.as_bytes();
                                (0x61,[tlv(0x0a,&[if ok {0} else {49}]),tlv(4,b""),tlv(4,b"")].concat())
                            }
                            0x63 => {
                                if service {
                                    let attrs=[("mail",EMAIL),("displayName","Invitee")].iter().flat_map(|(k,v)|tlv(0x30,&[tlv(4,k.as_bytes()),tlv(0x31,&tlv(4,v.as_bytes()))].concat())).collect::<Vec<_>>();
                                    let entry=[tlv(4,USER_DN.as_bytes()),tlv(0x30,&attrs)].concat();
                                    if stream.write_all(&ldap_reply(id,0x64,&entry)).is_err() { break; }
                                }
                                (0x65,[tlv(0x0a,&[0]),tlv(4,b""),tlv(4,b"")].concat())
                            }
                            _ => break,
                        };
                        if stream.write_all(&ldap_reply(id,tag,&payload)).and_then(|_|stream.flush()).is_err() { break; }
                    }
                });
            }
        });
        Self { port, ca_pem:ca.pem() }
    }
}
fn ldap_reply(id:&[u8],tag:u8,body:&[u8])->Vec<u8> { tlv(0x30,&[tlv(2,id),tlv(tag,body)].concat()) }
fn tlv(tag:u8,body:&[u8])->Vec<u8> {
    let mut bytes=vec![tag];
    if body.len()<128 { bytes.push(body.len() as u8); } else {
        let len=body.len().to_be_bytes(); let start=len.iter().position(|b|*b!=0).unwrap(); bytes.push(0x80|(len.len()-start) as u8); bytes.extend_from_slice(&len[start..]);
    }
    bytes.extend_from_slice(body); bytes
}
fn parse_tlv(bytes:&[u8])->Option<(u8,&[u8],usize)> {
    if bytes.len()<2 { return None; }
    let (len,header)=if bytes[1]&0x80==0 { (bytes[1] as usize,2) } else {
        let n=(bytes[1]&0x7f) as usize; if n==0 || n>4 || bytes.len()<2+n { return None; }
        (bytes[2..2+n].iter().fold(0usize,|a,b|(a<<8)|*b as usize),2+n)
    };
    if bytes.len()<header+len { return None; } Some((bytes[0],&bytes[header..header+len],header+len))
}
fn read_frame(stream:&mut impl Read)->Option<Vec<u8>> {
    let mut header=[0;2]; stream.read_exact(&mut header).ok()?; let mut bytes=header.to_vec();
    let len=if header[1]&0x80==0 { header[1] as usize } else {
        let n=(header[1]&0x7f) as usize; if n==0 || n>4 { return None; }
        let mut raw=vec![0;n]; stream.read_exact(&mut raw).ok()?; bytes.extend_from_slice(&raw); raw.iter().fold(0usize,|a,b|(a<<8)|*b as usize)
    };
    let mut body=vec![0;len]; stream.read_exact(&mut body).ok()?; bytes.extend(body); Some(bytes)
}
}
