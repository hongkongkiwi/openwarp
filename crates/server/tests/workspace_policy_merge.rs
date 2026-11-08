// HTTP contracts for the workspace policy port, using the current account lifecycle.
use hmac::Mac;
use openwarp_crypto as oc;
use reqwest::{redirect::Policy, Client, Method, Url};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "correct-horse-battery";
const AUTH_KEY: [u8; 32] = [7; 32];
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Mock {
    base: String,
    inbox: Arc<Mutex<Vec<Value>>>,
    email: Arc<Mutex<String>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Mock { fn drop(&mut self) { self.task.abort(); } }
impl Mock {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let email = Arc::new(Mutex::new("social@test.invalid".to_string()));
        let (mail, profile) = (inbox.clone(), email.clone());
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
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let payload = match path {
                    "/mail" => { mail.lock().unwrap().push(serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()); json!({"ok":true}) }
                    "/api/oauth2/token" => json!({"access_token":"dummy-access", "token_type":"Bearer"}),
                    "/api/users/@me" => { let email = profile.lock().unwrap().clone(); json!({"id":email,"email":email,"verified":true}) }
                    _ => Value::Null,
                };
                let status = if payload.is_null() { "404 Not Found" } else { "200 OK" };
                let body = payload.to_string();
                let response = format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, body.len(), body);
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self { base, inbox, email, task }
    }
}
struct Resp { status: u16, body: Value, headers: reqwest::header::HeaderMap }
impl Resp {
    fn expect(&self, status: u16, context: &str) {
        assert_eq!(self.status, status, "{}: error={}", context, self.body["error"]);
    }
}
struct Server { child: Child, base: String, dir: PathBuf, client: Client, mock: Mock }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start(extra: &[(&str, &str)]) -> Self {
        let mock = Mock::start().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        let dir = std::env::temp_dir().join(format!("openwarp-workspace-policy-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir(&dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "1")
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", format!("{}/mail", mock.base))
            .env("OPENWARP_DISCORD_CLIENT_ID", "dummy-client").env("OPENWARP_DISCORD_CLIENT_SECRET", "dummy-secret")
            .env("OPENWARP_DISCORD_API", &mock.base).env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1")
            .stdout(Stdio::null()).stderr(Stdio::null());
        for (key, value) in extra { cmd.env(key, value); }
        drop(listener);
        let child = cmd.spawn().expect("spawn current server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client, mock };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        response(req.send().await.expect("HTTP request")).await
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
    async fn social(&self, email: &str) -> String {
        *self.mock.email.lock().unwrap() = email.to_string();
        let start = self.call(Method::GET, "/api/auth/social/discord/start", None, None).await;
        start.expect(307, "start explicit mock provider");
        let url = Url::parse(start.headers["location"].to_str().unwrap()).unwrap();
        let state = url.query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned();
        let cookies = start.headers.get_all("set-cookie").iter().filter_map(|h| h.to_str().ok()).filter_map(|h| h.split(';').next())
            .filter(|c| c.starts_with("ow_social_")).collect::<Vec<_>>().join("; ");
        assert!(!cookies.is_empty(), "social flow must retain current browser-state binding");
        let r = response(self.client.get(format!("{}/api/auth/social/discord/callback?code=dummy-code&state={}", self.base, state))
            .header("cookie", cookies).send().await.unwrap()).await;
        r.expect(307, "verified provider signs in");
        let location = r.headers["location"].to_str().unwrap();
        location.split_once("#token=").expect("social session redirect").1.to_string()
    }
}
async fn response(r: reqwest::Response) -> Resp {
    let status = r.status().as_u16(); let headers = r.headers().clone();
    let body = serde_json::from_str(&r.text().await.unwrap()).unwrap_or(Value::Null);
    Resp { status, body, headers }
}
struct Account { token: String, uid: String }
fn account(body: &Value) -> Account {
    Account { token: body["token"].as_str().expect("session token").into(), uid: body["user_id"].as_str().expect("user id").into() }
}
fn v2_body() -> Value {
    json!({"salt":oc::b64(&[1;16]),"iterations":600000,"algo":"pbkdf2-sha256","auth_key":oc::b64(&AUTH_KEY),
        "public_key":oc::Keypair::generate().public,"wrapped_privkey":format!("owv2:{}", oc::b64(&[9;40]))})
}
async fn login(s: &Server, email: &str, v2: bool) -> Account {
    let r = if v2 {
        let challenge = s.call(Method::POST, "/api/auth/challenge", None, Some(json!({"email":email}))).await;
        challenge.expect(200, "v2 challenge");
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&AUTH_KEY).unwrap();
        mac.update(format!("{}|{}", challenge.body["challenge"].as_str().unwrap(), challenge.body["challenge_id"].as_str().unwrap()).as_bytes());
        let proof = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        s.call(Method::POST, "/api/auth/login-v2", None, Some(json!({"email":email,"challenge_id":challenge.body["challenge_id"],"proof":proof}))).await
    } else { s.call(Method::POST, "/api/auth/login", None, Some(json!({"email":email,"password":PASSWORD}))).await };
    r.expect(200, "verified account login"); account(&r.body)
}
async fn register(s: &Server, email: &str, v2: bool) -> (Account, Value) {
    let mut body = if v2 { v2_body() } else { json!({"password":PASSWORD}) }; body["email"] = json!(email);
    let r = s.call(Method::POST, if v2 { "/api/auth/register-v2" } else { "/api/auth/register" }, None, Some(body)).await;
    r.expect(200, "register account");
    assert_eq!(r.body["verification_required"], true);
    assert!(r.body.get("token").is_none(), "registration must not bypass email verification");
    s.verify(email).await;
    (login(s, email, v2).await, r.body)
}
async fn orgs(s: &Server, token: &str) -> Vec<Value> {
    let r = s.call(Method::GET, "/api/orgs", Some(token), None).await; r.expect(200, "list workspaces");
    r.body.as_array().expect("workspace list").clone()
}
async fn owner(s: &Server) -> (Account, String) {
    let (user, _) = register(s, "owner@test.invalid", false).await;
    let org = orgs(s, &user.token).await[0]["id"].as_str().unwrap().to_string(); (user, org)
}
async fn invite(s: &Server, owner: &Account, org: &str, email: &str) -> Value {
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(&owner.token), Some(json!({"email":email,"role":"developer"}))).await;
    r.expect(200, "issue invitation"); r.body
}
fn token(inv: &Value) -> &str { inv["invite_token"].as_str().expect("invitation must return a consent token for every account") }
async fn accept(s: &Server, inv: &str, session: Option<&str>, v2: bool) -> Resp {
    let mut body = if v2 { v2_body() } else { json!({"password":PASSWORD}) }; body["token"] = json!(inv);
    s.call(Method::POST, if v2 { "/api/auth/accept-invite-v2" } else { "/api/auth/accept-invite" }, session, Some(body)).await
}
async fn policy(s: &Server, owner: &Account, open: bool) -> Resp {
    s.call(Method::PUT, "/api/instance/workspaces", Some(&owner.token), Some(json!({"open":open}))).await
}
fn no_credentials(body: &Value, raw: &str) {
    let text = body.to_string();
    assert!(!text.contains(raw), "metadata must not echo the share token");
    assert!(!text.contains(&oc::hash_token(raw)), "metadata must not disclose the credential hash");
    if let Value::Object(map) = body {
        for key in ["token", "invite_token", "token_hash", "pass_hash", "wrapped_privkey", "recovery_kit"] {
            assert!(!map.contains_key(key), "metadata credential field: {}", key);
        }
    }
}
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }

#[tokio::test]
async fn instance_owner_controls_creation_independently_of_signups() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, _) = owner(&s).await;
    let (other, _) = register(&s, "other@test.invalid", false).await;
    policy(&s, &owner, false).await.expect(200, "instance owner can close creation");
    s.call(Method::PUT, "/api/instance/workspaces", None, Some(json!({"open":true}))).await.expect(401, "anonymous policy write denied");
    policy(&s, &other, true).await.expect(403, "workspace ownership is not instance ownership");
    s.call(Method::PUT, "/api/instance/workspaces", Some(&owner.token), Some(json!({"open":"true"}))).await.expect(400, "policy requires boolean");
    let info = s.call(Method::GET, "/api/instance", Some(&owner.token), None).await;
    info.expect(200, "instance policy"); assert_eq!(info.body["workspace_creation_open"], false); assert_eq!(info.body["signups_open"], true);
    let public = s.call(Method::GET, "/api/auth/providers", None, None).await;
    public.expect(200, "public policy"); assert_eq!(public.body["workspace_creation_open"], false);
    s.call(Method::POST, "/api/orgs", Some(&owner.token), Some(json!({"name":"blocked"}))).await.expect(403, "creation closed even for instance owner");
    policy(&s, &owner, true).await.expect(200, "reopen creation");
    s.call(Method::POST, "/api/orgs", Some(&other.token), Some(json!({"name":"allowed"}))).await.expect(200, "reopening restores self service");
}

#[tokio::test]
async fn env_closed_suppresses_default_workspaces_for_both_password_protocols() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[("OPENWARP_WORKSPACE_CREATION", "closed")]).await;
    let mut users = Vec::new();
    for (email, v2) in [("legacy@test.invalid", false), ("v2@test.invalid", true)] { users.push(register(&s, email, v2).await); }
    let counts = [orgs(&s, &users[0].0.token).await.len(), orgs(&s, &users[1].0.token).await.len()];
    assert_eq!(counts, [0, 0], "creation override must suppress defaults for legacy and v2 registration");
    for (user, registration) in &users {
        assert!(registration.get("org_id").is_none(), "disabled creation must not advertise a default workspace");
        s.call(Method::POST, "/api/orgs", Some(&user.token), Some(json!({"name":"blocked"}))).await.expect(403, "environment closes creation");
    }
    let info = s.call(Method::GET, "/api/instance", Some(&users[0].0.token), None).await;
    info.expect(200, "environment policy"); assert_eq!(info.body["workspace_creation_open"], false); assert_eq!(info.body["workspace_creation_env_locked"], true);
    policy(&s, &users[0].0, true).await.expect(409, "environment policy cannot be overridden through API");
}

#[tokio::test]
async fn social_signup_does_not_create_workspace_when_creation_is_closed() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[("OPENWARP_WORKSPACE_CREATION", "disabled")]).await;
    let session = s.social("social@test.invalid").await;
    s.call(Method::GET, "/api/me", Some(&session), None).await.expect(200, "provider-issued session remains usable");
    assert!(orgs(&s, &session).await.is_empty(), "social signup must obey disabled default-workspace policy");
    s.call(Method::POST, "/api/orgs", Some(&session), Some(json!({"name":"blocked"}))).await.expect(403, "social account cannot bypass creation policy");
}

#[tokio::test]
async fn invited_social_signup_requires_explicit_join_even_with_signups_and_creation_closed() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    let invitation = invite(&s, &owner, &org, "social@test.invalid").await;
    s.call(Method::PUT, "/api/instance/signups", Some(&owner.token), Some(json!({"open":false}))).await.expect(200, "close self signup");
    // Seed only the policy fixture so the missing policy route cannot mask consent behavior.
    assert_eq!(s.db().execute("UPDATE meta SET v='0' WHERE k='workspace_creation_open'", []).unwrap(), 1, "migration seeds the workspace creation policy");
    let session = s.social("social@test.invalid").await;
    assert!(orgs(&s, &session).await.is_empty(), "social sign-in must neither consume a pending invitation nor silently join its workspace");
    let preview = s.call(Method::GET, &format!("/api/auth/invite?token={}", token(&invitation)), None, None).await;
    preview.expect(200, "unconsumed invitation remains previewable"); assert_eq!(preview.body["existing_account"], true);
    accept(&s, token(&invitation), Some(&session), false).await.expect(200, "explicit consent joins despite both closed policies");
    let joined = orgs(&s, &session).await; assert_eq!(joined.len(), 1); assert_eq!(joined[0]["id"], org);
}

#[tokio::test]
async fn existing_v2_account_requires_matching_consent_and_preserves_credentials() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    let (user, _) = register(&s, "existing@test.invalid", true).await;
    let before = s.call(Method::GET, "/api/me/auth", Some(&user.token), None).await; before.expect(200, "existing v2 credentials");
    let original_orgs = orgs(&s, &user.token).await;
    let inv = invite(&s, &owner, &org, "existing@test.invalid").await;
    assert_eq!(orgs(&s, &user.token).await, original_orgs, "issuing an invitation must not silently add an existing account");
    accept(&s, token(&inv), None, false).await.expect(401, "existing account needs a session");
    accept(&s, token(&inv), Some(&owner.token), false).await.expect(403, "another account cannot consent");
    assert_eq!(orgs(&s, &user.token).await, original_orgs, "failed acceptance must not alter membership");
    s.call(Method::POST, "/api/auth/accept-invite", Some(&user.token), Some(json!({"token":token(&inv)}))).await.expect(200, "existing account consents without submitting a password");
    let after = s.call(Method::GET, "/api/me/auth", Some(&user.token), None).await; after.expect(200, "credentials after joining");
    assert_eq!(after.body, before.body, "acceptance must preserve v2 KDF, key wrapping and auth version");
    assert_eq!(login(&s, "existing@test.invalid", true).await.uid, user.uid, "original auth key still signs in");
    assert!(orgs(&s, &user.token).await.iter().any(|o| o["id"] == org && o["role"] == "developer"));
    accept(&s, token(&inv), Some(&user.token), false).await.expect(400, "consent token is single use");
}

#[tokio::test]
async fn signed_in_wrong_account_cannot_create_invitee_on_either_acceptance_protocol() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    let mut cases = Vec::new(); let mut statuses = Vec::new();
    for (email, v2) in [("new-legacy@test.invalid", false), ("new-v2@test.invalid", true)] {
        let inv = invite(&s, &owner, &org, email).await;
        statuses.push(accept(&s, token(&inv), Some(&owner.token), v2).await.status); cases.push((inv, v2));
    }
    assert_eq!(statuses, [403, 403], "a signed-in account must sign out before creating a different invited account, on legacy and v2 paths");
    for (inv, v2) in cases {
        let accepted = accept(&s, token(&inv), None, v2).await; accepted.expect(200, "refusal leaves token redeemable after signout");
        let user = account(&accepted.body); let joined = orgs(&s, &user.token).await;
        assert_eq!(joined.len(), 1); assert_eq!(joined[0]["id"], org);
    }
}

#[tokio::test]
async fn invitation_join_links_remain_single_use_and_expiring_when_creation_is_disabled() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    assert_eq!(s.db().execute("UPDATE meta SET v='0' WHERE k='workspace_creation_open'", []).unwrap(), 1, "migration seeds the workspace creation policy");
    for (email, v2) in [("join-legacy@test.invalid", false), ("join-v2@test.invalid", true)] {
        let before = now(); let inv = invite(&s, &owner, &org, email).await;
        let expires = inv["expires_at"].as_i64().expect("invitation expiry");
        assert!((before + 7*86400..=now() + 7*86400).contains(&expires), "invitation lifetime is seven days");
        let accepted = accept(&s, token(&inv), None, v2).await; accepted.expect(200, "join remains available when creation is disabled");
        let user = account(&accepted.body); let joined = orgs(&s, &user.token).await;
        assert_eq!(joined.len(), 1, "invite acceptance must not create an extra personal workspace"); assert_eq!(joined[0]["id"], org);
        accept(&s, token(&inv), None, v2).await.expect(400, "join token is one use");
        let expired = invite(&s, &owner, &org, &format!("expired-{}", email)).await;
        s.db().execute("UPDATE invites SET expires_at=? WHERE token_hash=?", rusqlite::params![now()-1, oc::hash_token(token(&expired))]).unwrap();
        accept(&s, token(&expired), None, v2).await.expect(400, "expired join token cannot create an account");
    }
}

#[tokio::test]
async fn public_preview_and_admin_rotation_revocation_do_not_disclose_invite_credentials() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    let (outsider, _) = register(&s, "outsider@test.invalid", false).await;
    let inv = invite(&s, &owner, &org, " Pending@Test.Invalid ").await; let raw = token(&inv);
    let preview = s.call(Method::GET, &format!("/api/auth/invite?token={}", raw), None, None).await;
    preview.expect(200, "public invitation preview");
    let name = orgs(&s, &owner.token).await[0]["name"].clone();
    assert_eq!(preview.body["org_id"], org); assert_eq!(preview.body["org_name"], name);
    assert_eq!(preview.body["email"], "pending@test.invalid"); assert_eq!(preview.body["existing_account"], false);
    assert_eq!(preview.body["role"], "developer"); assert_eq!(preview.body["expires_at"], inv["expires_at"]); no_credentials(&preview.body, raw);
    let path = format!("/api/orgs/{}/invites", org);
    s.call(Method::GET, &path, None, None).await.expect(401, "pending list is not public");
    s.call(Method::GET, &path, Some(&outsider.token), None).await.expect(403, "outsider cannot list pending invites");
    let list = s.call(Method::GET, &path, Some(&owner.token), None).await; list.expect(200, "owner pending list");
    assert_eq!(list.body.as_array().unwrap().len(), 1); no_credentials(&list.body, raw);
    let iid = list.body[0]["id"].as_str().expect("opaque management id");
    let manage = format!("{}/{}", path, iid);
    s.call(Method::POST, &format!("{}/resend", manage), Some(&outsider.token), Some(json!({}))).await.expect(403, "outsider cannot rotate");
    s.call(Method::DELETE, &manage, Some(&outsider.token), None).await.expect(403, "outsider cannot revoke");
    let rotated = s.call(Method::POST, &format!("{}/resend", manage), Some(&owner.token), Some(json!({}))).await; rotated.expect(200, "owner resends");
    assert!(token(&rotated.body) != raw, "resend rotates credential"); assert_eq!(rotated.body["id"], iid);
    accept(&s, raw, None, false).await.expect(400, "rotation invalidates old credential");
    s.call(Method::GET, &format!("/api/auth/invite?token={}", raw), None, None).await.expect(400, "old preview is invalid");
    s.call(Method::GET, &format!("/api/auth/invite?token={}", token(&rotated.body)), None, None).await.expect(200, "rotated preview works");
    s.call(Method::DELETE, &manage, Some(&owner.token), None).await.expect(200, "owner revokes");
    accept(&s, token(&rotated.body), None, false).await.expect(400, "revoked token cannot join");
    let list = s.call(Method::GET, &path, Some(&owner.token), None).await; list.expect(200, "pending list after revoke"); assert_eq!(list.body, json!([]));
}

#[tokio::test]
async fn rename_leave_delete_preserve_current_account_and_unresolved_lease_guards() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    let inv = invite(&s, &owner, &org, "member@test.invalid").await;
    let joined = accept(&s, token(&inv), None, true).await; joined.expect(200, "v2 member fixture"); let member = account(&joined.body);
    let path = format!("/api/orgs/{}", org);
    s.call(Method::PATCH, &path, Some(&member.token), Some(json!({"name":"forbidden"}))).await.expect(403, "developer cannot rename");
    s.call(Method::PATCH, &path, Some(&owner.token), Some(json!({"name":" Renamed "}))).await.expect(200, "owner rename");
    assert_eq!(orgs(&s, &member.token).await[0]["name"], "Renamed");
    s.call(Method::POST, &format!("{}/leave", path), Some(&owner.token), Some(json!({}))).await.expect(409, "last owner cannot leave");
    s.call(Method::DELETE, "/api/me?confirm=true", Some(&owner.token), None).await.expect(409, "workspace ownership still blocks account deletion");
    s.call(Method::POST, &format!("{}/leave", path), Some(&member.token), Some(json!({}))).await.expect(200, "ordinary member may leave");
    assert!(orgs(&s, &member.token).await.is_empty());
    s.call(Method::GET, "/api/me", Some(&member.token), None).await.expect(200, "leaving preserves account session");
    s.call(Method::DELETE, &path, Some(&owner.token), None).await.expect(409, "deletion still requires query confirmation");
    let app = s.call(Method::POST, &format!("{}/apps", path), Some(&owner.token), Some(json!({"name":"leased"}))).await; app.expect(200, "lease fixture app");
    let envs = s.call(Method::GET, &format!("/api/apps/{}/envs", app.body["id"].as_str().unwrap()), Some(&owner.token), None).await; envs.expect(200, "lease fixture environment");
    // No provider call is needed to exercise teardown's unresolved-reservation boundary.
    s.db().execute("INSERT INTO leases(id,env_id,name,value_enc,expires_at,revoked,created_at) VALUES('policy-pending',?,'pending','',?,2,?)", rusqlite::params![envs.body[0]["id"].as_str().unwrap(), now()+3600, now()]).unwrap();
    s.call(Method::DELETE, &format!("{}?confirm=true", path), Some(&owner.token), None).await.expect(409, "unresolved lease blocks confirmed deletion");
    assert_eq!(orgs(&s, &owner.token).await.len(), 1, "failed deletion retains workspace");
    s.db().execute("UPDATE leases SET revoked=1 WHERE id='policy-pending'", []).unwrap();
    s.call(Method::DELETE, &format!("{}?confirm=true", path), Some(&owner.token), None).await.expect(200, "confirmed deletion after fixture reconciliation");
    assert!(orgs(&s, &owner.token).await.is_empty());
    s.call(Method::DELETE, "/api/me", Some(&owner.token), None).await.expect(409, "instance owner with another eligible account cannot self-delete");
    s.call(Method::GET, "/api/me", Some(&owner.token), None).await.expect(200, "refused account deletion preserves session");
}

#[tokio::test]
async fn closed_creation_protects_last_workspace_and_zero_workspace_policy_is_recoverable() {
    let _serial = SERIAL.lock().await;
    let s = Server::start(&[]).await; let (owner, org) = owner(&s).await;
    policy(&s, &owner, false).await.expect(200, "close creation with existing workspace");
    s.call(Method::DELETE, &format!("/api/orgs/{}?confirm=true", org), Some(&owner.token), None).await.expect(409, "closed creation protects last workspace");
    policy(&s, &owner, true).await.expect(200, "reopen before deleting last workspace");
    s.call(Method::DELETE, &format!("/api/orgs/{}?confirm=true", org), Some(&owner.token), None).await.expect(200, "current confirmation contract deletes last workspace when open");
    policy(&s, &owner, false).await.expect(409, "cannot close creation with zero workspaces");
    let info = s.call(Method::GET, "/api/instance", Some(&owner.token), None).await; info.expect(200, "policy after refused update"); assert_eq!(info.body["workspace_creation_open"], true);
    let again = login(&s, "owner@test.invalid", false).await; assert!(orgs(&s, &again.token).await.is_empty(), "login does not recreate deleted default workspace");
    s.call(Method::POST, "/api/orgs", Some(&again.token), Some(json!({"name":"recovered"}))).await.expect(200, "zero-workspace account can recover when creation is open");
}
