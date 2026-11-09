use openwarp_server::db::{self, Db};
use openwarp_server::migrate::{self, MIGRATIONS};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);
static START_RETRIES: AtomicU32 = AtomicU32::new(0);
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
struct Disposable(PathBuf);
impl Disposable {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-workspace-review-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
    fn url(&self) -> String { format!("sqlite://{}/test.db", self.0.display()) }
}
impl Drop for Disposable { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[tokio::test]
async fn migration_18_retries_after_sql_committed_before_ledger_and_preserves_policy() {
    let dir = Disposable::new();
    let db = Db::open(&dir.url()).await.expect("fresh database migrates");
    assert_eq!(db.exec("UPDATE meta SET v='0' WHERE k='workspace_creation_open'", &[]).await.unwrap(), 1, "migration seeds the workspace creation policy");
    db.exec("UPDATE meta SET v='retained-lock-value' WHERE k='workspace_policy_lock'", &[]).await.unwrap();
    db.exec("INSERT INTO invites(token_hash,org_id,email,role,created_at,expires_at,id,invited_by) VALUES('fixture-hash','fixture-org','invitee@test.invalid','developer',1,9999999999,'fixture-invite','fixture-inviter')", &[]).await.unwrap();
    assert_eq!(db.exec("DELETE FROM schema_migrations WHERE version=18", &[]).await.unwrap(), 1);
    drop(db);

    // This is the durable state of a crash between the final SQL statement and its ledger write.
    // The engine refuses a ledger gap on purpose: replaying an unrecorded
    // migration cannot be told apart from one whose SQL never ran. The
    // operator proves the SQL committed and marks it applied, exactly as
    // openwarp-migrate repair documents.
    let reopened = Db::open(&dir.url()).await;
    let gap = reopened.as_ref().err().map(|e| e.to_string()).expect("startup must refuse the ledger gap");
    assert!(gap.contains("migration 18 is missing"), "the refusal must name the gap: {}", gap);
    {
        // The SQL committed, so the operator records migration 18 by hand after
        // checking the schema; the engine refuses to guess on its behalf.
        let repair = Db::connect(&dir.url()).await.expect("connect without migrating");
        let migration18 = MIGRATIONS.iter().find(|m| m.version == 18).expect("migration 18 in the manifest");
        repair.exec(&format!("INSERT INTO schema_migrations(version,applied_at,name,checksum,success,execution_ms) VALUES(18,{},'{}','{}',1,0)",
            now(), migration18.name, migrate::checksum(migration18.sql)), &[]).await.expect("record the committed migration");
    }
    let db = Db::open(&dir.url()).await.expect("startup proceeds once the gap is repaired");
    for (key, expected) in [("workspace_creation_open", "0"), ("workspace_policy_lock", "retained-lock-value")] {
        let row = db.one("SELECT v FROM meta WHERE k=?", &[json!(key)]).await.unwrap().unwrap();
        assert_eq!(db::s(&row, "v"), expected, "retry must not reset existing policy data");
    }
    let invite = db.one("SELECT id,invited_by FROM invites WHERE token_hash='fixture-hash'", &[]).await.unwrap().unwrap();
    assert_eq!(db::s(&invite, "id"), "fixture-invite");
    assert_eq!(db::s(&invite, "invited_by"), "fixture-inviter");
    let ledger = db.query("SELECT version FROM schema_migrations WHERE version=18", &[]).await.unwrap();
    assert_eq!(ledger.len(), 1, "retry records migration 18 exactly once");
}

struct Resp { status: u16, body: Value }
impl Resp {
    fn expect(&self, status: u16, context: &str) {
        assert_eq!(self.status, status, "{}: error={}", context, self.body["error"]);
    }
}
struct Server { child: Child, base: String, client: Client, db: Db, _dir: Disposable }
impl Drop for Server { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }
impl Server {
    async fn start() -> Self {
        let dir = Disposable::new();
        let db = Db::open(&dir.url()).await.unwrap();
        for (uid, email) in [("owner", "owner@test.invalid"), ("admin", "admin@test.invalid"), ("invitee", "invitee@test.invalid")] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,'fixture-unused','','',?,1,1)", &[json!(uid), json!(email), json!(now())]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(openwarp_crypto::hash_token(&format!("review-{}-session", uid))), json!(uid), json!(now())]).await.unwrap();
        }
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('review-org','Review workspace',?)", &[json!(now())]).await.unwrap();
        for (uid, role) in [("owner", "owner"), ("admin", "admin")] {
            db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('review-org',?,?)", &[json!(uid), json!(role)]).await.unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); let base = format!("http://{}", addr);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL", dir.url()).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "1")
            .stdout(Stdio::null()).stderr(Stdio::null());
        drop(listener);
        let child = cmd.spawn().expect("start current server");
        let client = Client::builder().no_proxy().timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, client, db, _dir: dir };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // A probed port can be taken before the child binds it, and the loser
        // exits at once, so health never arrives. Retry with a fresh database
        // and port; release the startup lock first so the next attempt can
        // take it.
        if START_RETRIES.fetch_add(1, Ordering::SeqCst) < 3 { return Box::pin(Server::start()).await; }
        panic!("server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path)).bearer_auth(token);
        if let Some(body) = body { req = req.json(&body); }
        let r = req.send().await.expect("HTTP response"); let status = r.status().as_u16();
        let body = serde_json::from_str(&r.text().await.unwrap()).unwrap_or(Value::Null); Resp { status, body }
    }
    async fn invite(&self, inviter: &str) -> String {
        let r = self.call(Method::POST, "/api/orgs/review-org/members", inviter, Some(json!({"email":"invitee@test.invalid","role":"developer"}))).await;
        r.expect(200, "authorized admin issues an invitation");
        self.assert_membership(false).await;
        r.body["invite_token"].as_str().expect("explicit consent token").to_string()
    }
    async fn accept(&self, invite: &str) -> Resp {
        self.call(Method::POST, "/api/auth/accept-invite", "review-invitee-session", Some(json!({"token":invite}))).await
    }
    async fn assert_membership(&self, present: bool) {
        let r = self.call(Method::GET, "/api/orgs", "review-invitee-session", None).await;
        r.expect(200, "invitee can inspect its workspaces");
        assert_eq!(r.body.as_array().unwrap().iter().any(|o| o["id"] == "review-org"), present);
    }
    async fn machine(&self) -> (String, String) {
        let identity = self.call(Method::POST, "/api/orgs/review-org/identities", "review-owner-session", Some(json!({"name":"review-bot","role":"admin"}))).await;
        identity.expect(200, "owner creates machine admin");
        let login = self.call(Method::POST, "/api/v1/machine/auth/universal/login", "", Some(json!({"client_id":identity.body["client_id"],"client_secret":identity.body["client_secret"]}))).await;
        login.expect(200, "machine admin authenticates");
        (identity.body["id"].as_str().unwrap().into(), login.body["accessToken"].as_str().unwrap().into())
    }
    async fn assert_pending(&self, invite: &str) {
        let row = self.db.one("SELECT accepted FROM invites WHERE token_hash=?", &[json!(openwarp_crypto::hash_token(invite))]).await.unwrap().unwrap();
        assert_eq!(db::n(&row, "accepted"), 0, "denial must not consume the invitation");
    }
}

#[tokio::test]
async fn machine_admin_invitation_allows_existing_account_explicit_consent() {
    let s = Server::start().await; let (_, machine) = s.machine().await;
    let invite = s.invite(&machine).await;
    let accepted = s.accept(&invite).await;
    accepted.expect(200, "existing invitee must be able to accept a valid machine-admin invitation");
    assert_eq!(accepted.body["org_id"], "review-org");
    s.assert_membership(true).await;
    s.accept(&invite).await.expect(400, "consent token is single-use");
}

#[tokio::test]
async fn deleted_machine_inviter_cannot_authorize_existing_account_join() {
    let s = Server::start().await; let (iid, machine) = s.machine().await;
    let invite = s.invite(&machine).await;
    s.call(Method::DELETE, &format!("/api/orgs/review-org/identities/{}", iid), "review-owner-session", None).await.expect(200, "owner revokes machine identity");
    let r = s.accept(&invite).await;
    assert!((400..500).contains(&r.status), "deleted inviter must be denied, got {}", r.status);
    s.assert_membership(false).await; s.assert_pending(&invite).await;
}

#[tokio::test]
async fn active_human_admin_invitation_still_allows_existing_account_join() {
    let s = Server::start().await; let invite = s.invite("review-admin-session").await;
    s.accept(&invite).await.expect(200, "active human admin invitation remains valid");
    s.assert_membership(true).await;
}

#[tokio::test]
async fn demoted_human_inviter_cannot_authorize_existing_account_join() {
    let s = Server::start().await; let invite = s.invite("review-admin-session").await;
    s.call(Method::PATCH, "/api/orgs/review-org/members/admin", "review-owner-session", Some(json!({"role":"developer"}))).await.expect(200, "owner demotes inviter");
    let r = s.accept(&invite).await;
    assert!((400..500).contains(&r.status), "demoted inviter must be denied, got {}", r.status);
    s.assert_membership(false).await; s.assert_pending(&invite).await;
}

#[tokio::test]
async fn inactive_or_unverified_human_inviter_cannot_authorize_existing_account_join() {
    let mut results = Vec::new();
    for column in ["active", "email_verified"] {
        let s = Server::start().await; let invite = s.invite("review-admin-session").await;
        // Operator account eligibility changes need not remove workspace membership.
        s.db.exec(&format!("UPDATE users SET {}=0 WHERE id='admin'", column), &[]).await.unwrap();
        let r = s.accept(&invite).await;
        let member = s.db.one("SELECT role FROM org_members WHERE org_id='review-org' AND user_id='invitee'", &[]).await.unwrap().is_some();
        let row = s.db.one("SELECT accepted FROM invites WHERE token_hash=?", &[json!(openwarp_crypto::hash_token(&invite))]).await.unwrap().unwrap();
        results.push((column, r.status, member, db::n(&row, "accepted")));
    }
    for (column, status, member, consumed) in results {
        assert!((400..500).contains(&status), "inviter with {}=0 must be denied, got {}", column, status);
        assert!(!member, "ineligible inviter must not create membership");
        assert_eq!(consumed, 0, "ineligible inviter must not consume the invitation");
    }
}
