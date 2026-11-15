// HTTP contracts for outgoing hooks and signed integration triggers.
// Each test owns a private server and database; provider credentials are dummy data.
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use hmac::Mac;
use reqwest::{redirect::Policy, Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Resp { status: u16, text: String, body: Value, headers: reqwest::header::HeaderMap }
struct Server { child: Child, base: String, dir: PathBuf, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill(); let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Server {
    async fn start() -> Self { Self::start_with(&[]).await }
    async fn start_with(extra: &[(&str,&str)]) -> Self {
        let _start = START_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("openwarp-webhooks-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).expect("private temp dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("server port");
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let (mail_url, inbox) = start_inbox();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", mail_url).env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS").env_remove("OPENWARP_ALLOWED_DB_HOSTS")
            .env_remove("OPENWARP_TRUST_PROXY")
            .envs(extra.iter().map(|(k,v)| ((*k).to_string(), (*v).to_string())))
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn server");
        let client = Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let s = Self { child, base, dir, client, inbox };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() { return s; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if let Some(t) = token { req = req.bearer_auth(t); }
        if let Some(b) = body { req = req.json(&b); }
        finish(req.send().await).await
    }
    async fn call_stepped_up(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let before = self.inbox.lock().unwrap().len();
        let start = self.call(Method::POST, "/api/auth/step-up/start", Some(token), Some(json!({"risk":"very_risky"}))).await; ok(&start);
        assert_eq!(start.body["email_sent"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        let code = loop {
            let code = self.inbox.lock().unwrap().iter().skip(before).filter_map(|m| m["text"].as_str())
                .find_map(|text| text.split(|c: char| !c.is_ascii_digit()).find(|s| s.len() == 6).map(str::to_string));
            if let Some(code) = code { break code; }
            assert!(Instant::now() < deadline, "fresh step-up mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let verified = self.call(Method::POST, "/api/auth/step-up/verify", Some(token), Some(json!({"challenge":start.body["challenge"],"email_code":code}))).await; ok(&verified);
        let mut request = self.client.request(method, format!("{}{}", self.base, path)).bearer_auth(token).header("x-openwarp-step-up", verified.body["token"].as_str().unwrap());
        if let Some(body) = body { request = request.json(&body); }
        finish(request.send().await).await
    }
    async fn signed(&self, hook: &str, secret: &str, mid: &str, timestamp: i64, signed_body: &[u8], sent_body: &[u8]) -> Resp {
        let key = secret.strip_prefix("whsec_").expect("whsec prefix");
        let key = Base64::decode_vec(key).expect("standard base64 signing key");
        assert_eq!(key.len(), 32, "signing key must be 32 bytes");
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(format!("{}.{}.", mid, timestamp).as_bytes()); mac.update(signed_body);
        let sig = format!("v1,{}", Base64::encode_string(&mac.finalize().into_bytes()));
        finish(self.client.post(format!("{}/hooks/integrations/{}", self.base, hook))
            .header("content-type", "application/json").header("webhook-id", mid)
            .header("webhook-timestamp", timestamp.to_string()).header("webhook-signature", sig)
            .body(sent_body.to_vec()).send().await).await
    }
}
async fn finish(result: Result<reqwest::Response, reqwest::Error>) -> Resp {
    let r = result.expect("HTTP request"); let status = r.status().as_u16(); let headers = r.headers().clone();
    let text = r.text().await.expect("response body"); let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Resp { status, text, body, headers }
}
fn ok(r: &Resp) { assert!((200..300).contains(&r.status), "expected success, got {} {}", r.status, r.text); }
fn denied(r: &Resp) { assert!(matches!(r.status, 403 | 404), "expected authorization denial, got {} {}", r.status, r.text); }
fn id(v: &Value) -> String { v["id"].as_str().expect("id").to_string() }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn secret(r: &Resp) -> String {
    ok(r); let s = r.body["secret"].as_str().expect("one-time secret").to_string();
    let raw = Base64::decode_vec(s.strip_prefix("whsec_").expect("whsec prefix")).expect("base64 key");
    assert_eq!(raw.len(), 32); s
}
fn redacted(r: &Resp, needles: &[&str]) {
    ok(r);
    for needle in needles { assert!(!r.text.contains(needle), "sensitive material in response: {}", r.text); }
    fn inspect(v: &Value) {
        match v {
            Value::Object(m) => for (k, v) in m {
                assert!(!matches!(k.as_str(), "secret" | "signing_secret" | "body" | "raw_body" | "config" | "credentials"), "sensitive field {}", k);
                inspect(v);
            },
            Value::Array(a) => for v in a { inspect(v); },
            _ => (),
        }
    }
    inspect(&r.body);
}
fn start_inbox() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
    let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = incoming.expect("mail connection");
            let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0); if n == 0 { break; } buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break; }
                }
            }
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                if let Ok(v) = serde_json::from_slice(&buf[end + 4..]) { sink.lock().unwrap().push(v); }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    (format!("http://{}/mail", addr), inbox)
}
async fn register(s: &Server, email: &str) -> Value {
    s.inbox.lock().unwrap().clear();
    let r = s.call(Method::POST, "/api/auth/register", None, Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
    assert_eq!(r.status, 200, "{}", r.text); let mut user = r.body;
    if user["verification_required"] == json!(true) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let path = loop {
            let link = s.inbox.lock().unwrap().iter().rev().find_map(|m| m["text"].as_str().and_then(|text| text.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string()))));
            if let Some(link) = link { break link; }
            assert!(Instant::now() < deadline, "verification mail missing");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        ok(&s.call(Method::GET, &path, None, None).await);
        let login = s.call(Method::POST, "/api/auth/login", None, Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(login.status, 200, "{}", login.text);
        user["token"] = login.body["token"].clone(); user["user_id"] = login.body["user_id"].clone();
    }
    user
}
async fn app(s: &Server, token: &str, org: &str) -> (String, String) {
    let r = s.call(Method::POST, &format!("/api/orgs/{}/apps", org), Some(token), Some(json!({"name":"hooks"}))).await; ok(&r);
    let aid = id(&r.body);
    let r = s.call(Method::GET, &format!("/api/apps/{}/envs", aid), Some(token), None).await; ok(&r);
    (aid, id(&r.body.as_array().expect("env array")[0]))
}
async fn member(s: &Server, owner: &str, org: &str, email: &str, role: &str, permissions: &[&str]) -> Value {
    let user = register(s, email).await;
    ok(&s.call(Method::POST, &format!("/api/orgs/{}/roles", org), Some(owner), Some(json!({"name":role,"permissions":permissions}))).await);
    // Issuing an invite never adds membership; the invitee accepts explicitly
    // with their own session.
    let r = s.call(Method::POST, &format!("/api/orgs/{}/members", org), Some(owner), Some(json!({"email":email,"role":role}))).await; ok(&r);
    let invite_token = r.body["invite_token"].as_str().expect("invite token").to_string();
    ok(&s.call(Method::POST, "/api/auth/accept-invite", Some(user["token"].as_str().unwrap()), Some(json!({"token":invite_token,"password":"correct-horse-battery"}))).await);
    user
}
async fn oauth(s: &Server, session: &str) -> String {
    let redirect = "http://127.0.0.1:8917/callback";
    let scope = "secrets:read secrets:write";
    let r = s.call(Method::POST, "/oauth/register", None, Some(json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope}))).await;
    assert_eq!(r.status, 201, "{}", r.text);
    let client_id = r.body["client_id"].as_str().unwrap();
    let verifier = "integration-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    let resource = format!("{}/mcp",s.base);
    let form = [("response_type","code"),("client_id",client_id),("redirect_uri",redirect),("scope",scope),("state","hooks"),("code_challenge",challenge.as_str()),("code_challenge_method","S256"),("resource",resource.as_str()),("approve","1")];
    let r = finish(s.client.post(format!("{}/oauth/authorize/decision",s.base)).bearer_auth(session).form(&form).send().await).await;
    let location = r.headers.get("location").expect("OAuth redirect").to_str().unwrap();
    let code = location.split_once('?').expect("query").1.split('&').find_map(|p| p.strip_prefix("code=")).expect("authorization code");
    let r = finish(s.client.post(format!("{}/oauth/token",s.base)).form(&[("grant_type","authorization_code"),("code",code),("client_id",client_id),("redirect_uri",redirect),("code_verifier",verifier)]).send().await).await;
    assert_eq!(r.status, 200, "{}", r.text); r.body["access_token"].as_str().unwrap().to_string()
}
fn outgoing() -> Value { json!({"name":"audit hook","url":"https://example.invalid/hooks","events":["*"],"enabled":true}) }
async fn integration(s: &Server, token: &str, env: &str) -> String {
    let r = s.call(Method::POST, &format!("/api/envs/{}/integrations",env), Some(token), Some(json!({"kind":"webhook","name":"dummy target","config":{"url":"http://127.0.0.1:9/never","token":"dummy-provider-credential","auto_sync":false}}))).await;
    ok(&r); id(&r.body)
}
async fn incoming(s: &Server, token: &str, iid: &str) -> (String, String) {
    let r = s.call(Method::POST, &format!("/api/integrations/{}/webhooks",iid), Some(token), Some(json!({"name":"trigger","enabled":true}))).await;
    let key = secret(&r); let hid = id(&r.body);
    assert_eq!(r.body["url"], json!(format!("{}/hooks/integrations/{}",s.base,hid)));
    (hid, key)
}

#[tokio::test]
async fn outgoing_lifecycle_redacts_keys_and_rejects_private_or_false_app_scope() {
    let s = Server::start().await; let u = register(&s,"outgoing@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let (aid, _) = app(&s,t,org).await; let list = format!("/api/orgs/{}/webhooks",org);
    let other = register(&s,"other-outgoing@test.invalid").await;
    let (foreign_app, _) = app(&s,other["token"].as_str().unwrap(),other["org_id"].as_str().unwrap()).await;
    for url in ["http://127.0.0.1:9/hook","http://10.0.0.1/hook","http://169.254.169.254/latest/meta-data/"] {
        let mut body = outgoing(); body["url"] = json!(url);
        let r = s.call(Method::POST,&list,Some(t),Some(body)).await;
        assert_eq!(r.status,400,"private URL accepted: {} {}",r.status,r.text);
    }
    let mut body = outgoing(); body["app_id"] = json!(foreign_app);
    let r = s.call(Method::POST,&list,Some(t),Some(body)).await;
    assert!(matches!(r.status,400|403|404),"foreign app accepted: {} {}",r.status,r.text);
    let mut body = outgoing(); body["app_id"] = json!(aid);
    let r = s.call(Method::POST,&list,Some(t),Some(body)).await; let first = secret(&r); let hid = id(&r.body);
    let path = format!("/api/webhooks/{}",hid);
    for p in [&list,&path,&format!("{}/deliveries",path)] {
        redacted(&s.call(Method::GET,p,Some(t),None).await,&[&first,"whsec_"]);
    }
    let r = s.call(Method::PATCH,&path,Some(t),Some(json!({"name":"renamed","enabled":false,"events":["*"]}))).await;
    redacted(&r,&[&first,"whsec_"]);
    let r = s.call(Method::GET,&path,Some(t),None).await; ok(&r);
    assert_eq!(r.body["name"],"renamed"); assert_eq!(r.body["enabled"],false); assert_eq!(r.body["events"],json!(["*"]));
    let rotated = secret(&s.call(Method::POST,&format!("{}/rotate",path),Some(t),Some(json!({}))).await);
    assert_ne!(first,rotated);
    redacted(&s.call(Method::GET,&path,Some(t),None).await,&[&first,&rotated,"whsec_"]);
    ok(&s.call(Method::DELETE,&path,Some(t),None).await);
    let r = s.call(Method::GET,&list,Some(t),None).await; ok(&r);
    assert!(!r.body.as_array().expect("hook array").iter().any(|v| v["id"] == hid));
}

#[tokio::test]
async fn outgoing_management_requires_org_admin_even_for_app_hooks_and_scoped_tokens() {
    let s = Server::start().await; let u = register(&s,"outgoing-perms@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap(); let (aid,eid) = app(&s,t,org).await;
    let viewer = member(&s,t,org,"hook-reader@test.invalid","hook-reader",&["secrets:read","secrets:write","integrations:write"]).await;
    let foreign = register(&s,"hook-foreign@test.invalid").await;
    let r = s.call(Method::POST,&format!("/api/apps/{}/tokens",aid),Some(t),Some(json!({"name":"env token","env_id":eid}))).await; ok(&r);
    let env_token = r.body["token"].as_str().expect("service token"); let oat = oauth(&s,t).await;
    let list = format!("/api/orgs/{}/webhooks",org); let mut body = outgoing(); body["app_id"] = json!(aid);
    let r = s.call(Method::POST,&list,Some(t),Some(body.clone())).await; let _key = secret(&r); let path = format!("/api/webhooks/{}",id(&r.body));
    for denied_token in [viewer["token"].as_str().unwrap(),foreign["token"].as_str().unwrap(),env_token,&oat] {
        denied(&s.call(Method::GET,&list,Some(denied_token),None).await);
        denied(&s.call(Method::POST,&list,Some(denied_token),Some(body.clone())).await);
        for (method,p,b) in [(Method::GET,path.clone(),None),(Method::PATCH,path.clone(),Some(json!({"enabled":false}))),(Method::DELETE,path.clone(),None),(Method::POST,format!("{}/rotate",path),Some(json!({}))),(Method::GET,format!("{}/deliveries",path),None),(Method::POST,format!("{}/test",path),Some(json!({})))] {
            denied(&s.call(method,&p,Some(denied_token),b).await);
        }
    }
    ok(&s.call(Method::GET,&path,Some(t),None).await);
}

#[tokio::test]
async fn incoming_authenticates_raw_bytes_rejects_replays_with_changed_body_and_redacts_receipts() {
    let s = Server::start().await; let u = register(&s,"incoming-signatures@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let (_,eid) = app(&s,t,u["org_id"].as_str().unwrap()).await;
    let iid = integration(&s,t,&eid).await; let (hid,key) = incoming(&s,t,&iid).await; let path = format!("/hooks/integrations/{}",hid);
    let raw = b"{ \"marker\" : \"private-body-marker\", \"config\": {\"token\":\"supplied-secret-marker\"} }\n";
    let unsigned = s.call(Method::POST,&path,None,Some(json!({}))).await; assert_eq!(unsigned.status,401,"{}",unsigned.text);
    let bad = s.signed(&hid,&key,"changed-bytes",now(),b"{}",raw).await; assert_eq!(bad.status,401,"{}",bad.text);
    for timestamp in [now()-601,now()+601] {
        let r = s.signed(&hid,&key,"stale",timestamp,raw,raw).await; assert_eq!(r.status,401,"{}",r.text);
    }
    let timestamp = now();
    let r = s.signed(&hid,&key,"message_1",timestamp,raw,raw).await; assert_eq!(r.status,202,"{}",r.text);
    assert!(!r.text.contains("private-body-marker")); assert!(!r.text.contains("supplied-secret-marker"));
    let r = s.signed(&hid,&key,"message_1",timestamp,raw,raw).await; assert_eq!(r.status,200,"{}",r.text); assert_eq!(r.body["duplicate"],true);
    let r = s.signed(&hid,&key,"message_1",timestamp,b"{}",b"{}").await; assert_eq!(r.status,409,"{}",r.text);
    let receipts = format!("/api/incoming-webhooks/{}/receipts",hid);
    let r = s.call(Method::GET,&receipts,Some(t),None).await;
    redacted(&r,&[&key,"whsec_","private-body-marker","supplied-secret-marker","dummy-provider-credential"]);
    let rows = r.body.as_array().expect("receipt array"); assert_eq!(rows.len(),1,"replay must not enqueue another receipt"); assert_eq!(rows[0]["message_id"],"message_1");
    let (hid2,key2) = incoming(&s,t,&iid).await;
    let r = s.signed(&hid2,&key2,"message_1",timestamp,raw,raw).await; assert_eq!(r.status,202,"replay identity must include hook: {}",r.text);
    let r = s.call(Method::GET,&format!("/api/integrations/{}/webhooks",iid),Some(t),None).await;
    redacted(&r,&[&key,&key2,"whsec_"]); assert_eq!(r.body.as_array().expect("incoming array").len(),2);
}

#[tokio::test]
async fn incoming_bounds_rotation_disable_and_delete_are_enforced() {
    let s = Server::start().await; let u = register(&s,"incoming-limits@test.invalid").await; let t = u["token"].as_str().unwrap();
    let (_,eid) = app(&s,t,u["org_id"].as_str().unwrap()).await; let iid = integration(&s,t,&eid).await; let (hid,key) = incoming(&s,t,&iid).await;
    for mid in ["bad.id".to_string(),"x".repeat(129)] {
        let r = s.signed(&hid,&key,&mid,now(),b"{}",b"{}").await;
        assert!(matches!(r.status,400|401),"invalid message id accepted: {} {}",r.status,r.text);
    }
    let big = vec![b'x';65537]; let r = s.signed(&hid,&key,"oversize",now(),&big,&big).await; assert_eq!(r.status,413,"{}",r.text);
    let path = format!("/api/incoming-webhooks/{}",hid);
    let new_key = secret(&s.call(Method::POST,&format!("{}/rotate",path),Some(t),Some(json!({}))).await); assert_ne!(key,new_key);
    let r = s.signed(&hid,&key,"old-key",now(),b"{}",b"{}").await; assert_eq!(r.status,401,"{}",r.text);
    let r = s.signed(&hid,&new_key,"new-key",now(),b"{}",b"{}").await; assert_eq!(r.status,202,"{}",r.text);
    redacted(&s.call(Method::PATCH,&path,Some(t),Some(json!({"enabled":false}))).await,&[&new_key,"whsec_"]);
    let r = s.signed(&hid,&new_key,"disabled",now(),b"{}",b"{}").await; denied(&r);
    ok(&s.call(Method::DELETE,&path,Some(t),None).await);
    let r = s.signed(&hid,&new_key,"deleted",now(),b"{}",b"{}").await; denied(&r);
}

#[tokio::test]
async fn incoming_rechecks_creator_permissions_and_environment_policy() {
    let s = Server::start().await; let u = register(&s,"incoming-policy@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap(); let (_,eid) = app(&s,t,org).await;
    let creator = member(&s,t,org,"hook-creator@test.invalid","hook-writer",&["secrets:read","secrets:write","integrations:write"]).await;
    let ct = creator["token"].as_str().unwrap(); let iid = integration(&s,ct,&eid).await; let (hid,key) = incoming(&s,ct,&iid).await;
    let foreign = register(&s,"incoming-foreign@test.invalid").await; let ft = foreign["token"].as_str().unwrap();
    let path = format!("/api/incoming-webhooks/{}",hid);
    for (method,p,b) in [(Method::GET,format!("/api/integrations/{}/webhooks",iid),None),(Method::POST,format!("/api/integrations/{}/webhooks",iid),Some(json!({"name":"steal","enabled":true}))),(Method::PATCH,path.clone(),Some(json!({"enabled":false}))),(Method::DELETE,path.clone(),None),(Method::POST,format!("{}/rotate",path),Some(json!({}))),(Method::GET,format!("{}/receipts",path),None)] {
        denied(&s.call(method,&p,Some(ft),b).await);
    }
    let r = s.signed(&hid,&key,"allowed",now(),b"{}",b"{}").await; assert_eq!(r.status,202,"{}",r.text);
    ok(&s.call(Method::PUT,&format!("/api/envs/{}/policy",eid),Some(t),Some(json!({"restricted":true}))).await);
    let r = s.signed(&hid,&key,"restricted",now(),b"{}",b"{}").await; denied(&r);
    ok(&s.call(Method::PUT,&format!("/api/envs/{}/policy",eid),Some(t),Some(json!({"restricted":false}))).await);
    ok(&s.call(Method::POST,&format!("/api/orgs/{}/roles",org),Some(t),Some(json!({"name":"hook-no-sync","permissions":["secrets:read","secrets:write"]}))).await);
    ok(&s.call(Method::PATCH,&format!("/api/orgs/{}/members/{}",org,creator["user_id"].as_str().unwrap()),Some(t),Some(json!({"role":"hook-no-sync"}))).await);
    let r = s.signed(&hid,&key,"revoked-permission",now(),b"{}",b"{}").await; denied(&r);
    let r = s.call(Method::GET,&format!("{}/receipts",path),Some(t),None).await; redacted(&r,&[&key,"whsec_"]);
    assert_eq!(r.body.as_array().expect("receipts").len(),1,"denied invocations must not enqueue work");
}

#[tokio::test]
async fn incoming_receipts_capture_inspect_replay_and_master_rotation_clears_payloads() {
    let s = Server::start().await; let u = register(&s,"incoming-inspect@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let (_,eid) = app(&s,t,u["org_id"].as_str().unwrap()).await;
    let iid = integration(&s,t,&eid).await; let (hid,key) = incoming(&s,t,&iid).await;
    let raw = br#"{"inspected":"captured-payload-marker"}"#;
    ok(&s.signed(&hid,&key,"inspect_1",now(),raw,raw).await);
    let list = format!("/api/incoming-webhooks/{}/receipts",hid);
    let r = s.call(Method::GET,&list,Some(t),None).await; ok(&r);
    assert!(!r.text.contains("captured-payload-marker"),"receipt lists must stay redacted: {}",r.text);
    let rows = r.body.as_array().expect("receipt array"); assert_eq!(rows.len(),1);
    assert!(rows[0].get("body").is_none(),"lists must not carry captured payloads");
    let rid = id(&rows[0]);
    let detail = format!("{}/{}",list,rid);
    let r = s.call(Method::GET,&detail,Some(t),None).await; ok(&r);
    assert_eq!(r.body["body_available"],true,"capture must decrypt for the operator: {}",r.text);
    assert!(r.body["body"].as_str().expect("captured body").contains("captured-payload-marker"));
    assert_eq!(r.body["content_type"],"application/json");
    // Inspection and replay are integrations:write surfaces, not read-only ones.
    let viewer = member(&s,t,u["org_id"].as_str().unwrap(),"receipt-reader@test.invalid","receipt-reader",&["secrets:read"]).await;
    let vt = viewer["token"].as_str().unwrap();
    denied(&s.call(Method::GET,&detail,Some(vt),None).await);
    denied(&s.call(Method::POST,&format!("{}/replay",detail),Some(vt),Some(json!({}))).await);
    // The dummy sync target always fails, so the receipt reaches a terminal
    // state and becomes replayable; a replay resets attempts to zero.
    let deadline = Instant::now()+Duration::from_secs(45);
    loop {
        let r = s.call(Method::GET,&list,Some(t),None).await; ok(&r);
        let status = r.body[0]["status"].as_str().unwrap_or("").to_string();
        if ["delivered","failed","dead_lettered"].contains(&status.as_str()) {
            let r = s.call(Method::POST,&format!("{}/replay",detail),Some(t),Some(json!({}))).await;
            ok(&r); assert_eq!(r.body["queued"],true);
            let r = s.call(Method::GET,&detail,Some(t),None).await; ok(&r);
            assert_eq!(r.body["status"],"pending","replay must requeue: {}",r.text);
            assert_eq!(r.body["attempts"],0,"replay resets the attempt counter");
            break;
        }
        assert!(Instant::now()<deadline,"receipt never reached a terminal state: {}",status);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Captured payloads are sealed with the instance master. Rotating that key
    // erases them rather than rewrapping debug data.
    let new_key = Base64::encode_string(&Sha256::digest(b"rotate-incoming-receipts"));
    ok(&s.call_stepped_up(Method::POST,"/api/instance/rotate-master",t,Some(json!({"new_key":new_key}))).await);
    let r = s.call(Method::GET,&detail,Some(t),None).await; ok(&r);
    assert_eq!(r.body["body_available"],false,"rotation must erase captured payloads: {}",r.text);
    assert!(r.body["body"].is_null());
    assert!(!r.text.contains("captured-payload-marker"));
}

// A minimal HTTP receiver so outgoing deliveries can be captured and their
// Standard Webhooks signatures verified byte for byte.
struct Receiver { url: String, got: Arc<Mutex<Vec<(String, String, String)>>>, }
impl Receiver {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("receiver port");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let got: Arc<Mutex<Vec<(String,String,String)>>> = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock,_)) = listener.accept().await else { break };
                let g = g.clone();
                tokio::spawn(async move {
                    let mut data = Vec::new(); let mut buf = [0u8; 16384];
                    loop {
                        if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&data[..p]).to_lowercase();
                            let clen: usize = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0usize))).unwrap_or(0);
                            if data.len() >= p + 4 + clen { break; }
                        }
                        match sock.read(&mut buf).await { Ok(0) => break, Ok(n) => data.extend_from_slice(&buf[..n]), Err(_) => break }
                        if data.len() > 200_000 { break; }
                    }
                    let text = String::from_utf8_lossy(&data).to_string();
                    let head = text.split("\r\n\r\n").next().unwrap_or("").to_string();
                    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                    let method = head.lines().next().unwrap_or("").split_whitespace().next().unwrap_or("").to_string();
                    g.lock().unwrap().push((head, body, method));
                    let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                });
            }
        });
        Receiver { url, got }
    }
}
fn header_of(head: &str, name: &str) -> String {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())).unwrap_or_default()
}

#[tokio::test]
async fn outgoing_asymmetric_signing_survives_master_rotation() {
    let s = Server::start_with(&[("OPENWARP_ALLOW_PRIVATE_EGRESS","1")]).await;
    let u = register(&s,"asym-signing@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let list = format!("/api/orgs/{}/webhooks",org);
    let rx = Receiver::start().await;
    let mut body = outgoing(); body["url"] = json!(rx.url); body["asymmetric"] = json!(true);
    let hook_secret = secret(&s.call(Method::POST,&list,Some(t),Some(body)).await);
    let r = s.call(Method::GET,&list,Some(t),None).await; ok(&r);
    let row = r.body.as_array().expect("hooks").iter().find(|h| h["public_key"].as_str().is_some_and(|k| k.starts_with("whpk_"))).expect("asymmetric hook");
    let pk_b64 = row["public_key"].as_str().unwrap().trim_start_matches("whpk_").to_string();
    assert!(!r.text.contains("sign_key_enc"),"private signing key must never leave the server");
    let hid = id(row); let path = format!("/api/webhooks/{}",hid);
    let verify = |head: &str, payload: &str, secret: &str, pk_b64: &str| {
        let mid = header_of(head,"webhook-id"); let ts = header_of(head,"webhook-timestamp"); let sigs = header_of(head,"webhook-signature");
        let material = format!("{}.{}.{}", mid, ts, payload);
        let key = Base64::decode_vec(secret.strip_prefix("whsec_").unwrap()).unwrap();
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(material.as_bytes());
        let want_v1 = format!("v1,{}", Base64::encode_string(&mac.finalize().into_bytes()));
        assert!(sigs.split_whitespace().any(|s| s == want_v1), "valid v1 HMAC expected, got {}", sigs);
        let v1a = sigs.split_whitespace().find_map(|s| s.strip_prefix("v1a,")).expect("v1a signature present");
        use ed25519_dalek::{Verifier, Signature as EdSig, VerifyingKey};
        let pk: [u8;32] = Base64::decode_vec(pk_b64).expect("pk base64").try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let sig = EdSig::from_bytes(Base64::decode_vec(v1a).expect("sig base64").as_slice().try_into().expect("64 bytes"));
        vk.verify(material.as_bytes(), &sig).expect("v1a signature must verify");
    };
    // The subscription matches its own audit events too, so select the test
    // event by its returned id rather than by delivery order.
    async fn wait_for(rx: &Receiver, ev: &str, secs: u64) -> (String, String, String) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let snap = rx.got.lock().unwrap().clone();
            if let Some(hit) = snap.iter().find(|(head,_,_)| header_of(head,"webhook-id")==ev) { return hit.clone(); }
            if Instant::now() >= deadline { panic!("event {} never delivered", ev); }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
    let r = s.call(Method::POST,&format!("{}/test",path),Some(t),Some(json!({}))).await; ok(&r);
    let ev = r.body["event_id"].as_str().expect("test event id").to_string();
    let got = wait_for(&rx,&ev,30).await;
    verify(&got.0, &got.1, &hook_secret, &pk_b64);
    // Master rotation rewraps the encrypted seed and key rotation regenerates
    // the pair; the next test event must verify under the new keys.
    let new_key = Base64::encode_string(&Sha256::digest(b"asym-rotate-master"));
    ok(&s.call_stepped_up(Method::POST,"/api/instance/rotate-master",t,Some(json!({"new_key":new_key}))).await);
    let rotated = secret(&s.call(Method::POST,&format!("{}/rotate",path),Some(t),Some(json!({}))).await);
    let r = s.call(Method::GET,&path,Some(t),None).await; ok(&r);
    let pk_b64 = r.body["public_key"].as_str().expect("rotated public key").trim_start_matches("whpk_").to_string();
    let r = s.call(Method::POST,&format!("{}/test",path),Some(t),Some(json!({}))).await; ok(&r);
    let ev = r.body["event_id"].as_str().expect("test event id").to_string();
    let got = wait_for(&rx,&ev,30).await;
    verify(&got.0, &got.1, &rotated, &pk_b64);
}

#[tokio::test]
async fn outgoing_auto_pauses_after_consecutive_dead_letters_and_reenables() {
    let s = Server::start_with(&[("OPENWARP_ALLOW_PRIVATE_EGRESS","1"),("OPENWARP_WEBHOOK_RETRY_BASE_SECS","0")]).await;
    let u = register(&s,"auto-pause@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let list = format!("/api/orgs/{}/webhooks",org);
    let mut body = outgoing(); body["url"] = json!("http://127.0.0.1:9/never");
    let hook_secret = secret(&s.call(Method::POST,&list,Some(t),Some(body)).await);
    let hid = { let r = s.call(Method::GET,&list,Some(t),None).await; ok(&r); id(&r.body.as_array().expect("hooks")[0]) };
    let path = format!("/api/webhooks/{}",hid);
    for _ in 0..5 { ok(&s.call(Method::POST,&format!("{}/test",path),Some(t),Some(json!({}))).await); }
    // Fast retries drive the five events to eight failed attempts each; the
    // fifth consecutive dead-letter pauses the subscription by itself.
    let deadline = Instant::now() + Duration::from_secs(150);
    let mut disabled = false;
    while Instant::now() < deadline {
        let r = s.call(Method::GET,&path,Some(t),None).await; ok(&r);
        if r.body["enabled"] == json!(false) && r.body["disabled_reason"] == json!("consecutive_dead_letters") { disabled = true; break; }
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    assert!(disabled, "subscription never auto-paused");
    let r = s.call(Method::GET,&format!("/api/orgs/{}/audit",org),Some(t),None).await; ok(&r);
    assert!(r.body.as_array().expect("audit").iter().any(|e| e["action"] == json!("webhook.auto_disabled")), "auto-pause must be audited");
    let r = s.call(Method::POST,&format!("{}/test",path),Some(t),Some(json!({}))).await;
    assert_eq!(r.status, 400, "a paused subscription must reject test events: {}", r.text);
    // A manager re-enable clears the reason and the flow resumes.
    ok(&s.call(Method::PATCH,&path,Some(t),Some(json!({"enabled":true}))).await);
    let r = s.call(Method::GET,&path,Some(t),None).await; ok(&r);
    assert_eq!(r.body["enabled"],json!(true)); assert_eq!(r.body["disabled_reason"],json!(""));
    ok(&s.call(Method::POST,&format!("{}/test",path),Some(t),Some(json!({}))).await);
    redacted(&s.call(Method::GET,&list,Some(t),None).await,&[&hook_secret,"whsec_"]);
}
