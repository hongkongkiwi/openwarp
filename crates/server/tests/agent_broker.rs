use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
const CREDENTIAL: &str = "dummy-broker-credential-never-return";
struct Resp { status: u16, body: Value, text: String }
struct Server { child: Child, dir: PathBuf, base: String, client: Client, inbox: Arc<Mutex<Vec<Value>>> }
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-broker-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let api_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = api_listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mail_url = format!("http://{}/mail", listener.local_addr().unwrap());
        let inbox = Arc::new(Mutex::new(Vec::new())); let sink = inbox.clone();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { break }; let mut buf = Vec::new(); let mut chunk = [0; 8192]; let mut accepted = false;
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 { break; } buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]);
                        if head.lines().next() != Some("POST /mail HTTP/1.1") { break; }
                        let len = head.lines().find_map(|l| { let (k,v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                        if buf.len() >= end + 4 + len { if let Ok(v) = serde_json::from_slice(&buf[end+4..end+4+len]) { sink.lock().unwrap().push(v); accepted = true; } break; }
                    }
                }
                let status = if accepted { "200 OK" } else { "400 Bad Request" };
                let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            }
        });
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        for (key, _) in std::env::vars().filter(|(k,_)| k.starts_with("OPENWARP_") || k.ends_with("_PROXY") || k == "REDIS_URL") { cmd.env_remove(key); }
        cmd.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", format!("127.0.0.1:{port}"))
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_WEBHOOK", mail_url).env("TOKIO_WORKER_THREADS", "1")
            .stdout(Stdio::null()).stderr(Stdio::null());
        // Reserve the API port until the mail listener and child configuration are ready.
        drop(api_listener);
        let child = cmd.spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().unwrap();
        let mut s = Self { child, dir, base, client, inbox }; let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            assert!(s.child.try_wait().unwrap().is_none(), "private broker test server exited before readiness");
            if server_is_healthy(s.client.get(format!("{}/health", s.base)).send().await).await {
                assert!(s.child.try_wait().unwrap().is_none(), "private broker test server exited during readiness");
                return s;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("private broker test server did not start");
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = req.bearer_auth(token); }
        if let Some(v) = body { req = req.json(&v); }
        finish(req.send().await.unwrap()).await
    }
    async fn register(&self, email: &str) -> Value {
        let r = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(r.status, 200, "account registration: {}", r.text); let mut user = r.body;
        let deadline = Instant::now() + Duration::from_secs(10);
        let link = loop {
            let found = self.inbox.lock().unwrap().iter().rev().filter(|v| v.to_string().contains(email)).find_map(|v| v["text"].as_str().and_then(|t| t.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string()))));
            if let Some(link) = found { break link; } assert!(Instant::now() < deadline, "verification mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(self.call(Method::GET, &link, "", None).await.status, 200);
        let login = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(login.status, 200); user["token"] = login.body["token"].clone(); user["user_id"] = login.body["user_id"].clone(); user
    }
}
async fn server_is_healthy(response: Result<reqwest::Response, reqwest::Error>) -> bool {
    let Ok(response) = response else { return false };
    response.status().is_success() && response.json::<Value>().await.is_ok_and(|body| body["ok"] == true && body["service"] == "openwarp")
}

#[tokio::test]
async fn broker_fixture_health_requires_server_identity() {
    async fn probe(status: u16, body: &str) -> bool {
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/health", listener.local_addr().unwrap());
        let sink = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut request = Vec::new(); let mut chunk = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).unwrap(); assert!(n > 0, "health request ended before headers");
                request.extend_from_slice(&chunk[..n]); assert!(request.len() <= 4096, "health request headers too large");
            }
            stream.write_all(response.as_bytes()).unwrap();
        });
        let client = Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
        let healthy = server_is_healthy(client.get(url).send().await).await;
        sink.join().unwrap(); healthy
    }
    assert!(!probe(200, "{}").await, "mail sink HTTP 200 must not satisfy server readiness");
    assert!(probe(200, r#"{"ok":true,"service":"openwarp"}"#).await);
    assert!(!probe(503, r#"{"ok":true,"service":"openwarp"}"#).await);
    assert!(!probe(200, r#"{"ok":false,"service":"openwarp"}"#).await);
    assert!(!probe(200, r#"{"ok":true,"service":"other"}"#).await);
    assert!(!probe(200, "not-json").await);
}

async fn finish(r: reqwest::Response) -> Resp { let status = r.status().as_u16(); let text = r.text().await.unwrap(); let body = serde_json::from_str(&text).unwrap_or(Value::Null); Resp { status, body, text } }
fn id(v: &Value, key: &str) -> String { v[key].as_str().unwrap_or_else(|| panic!("missing {key}")).to_string() }
struct Fixture { s: Server, owner: String, uid: String, org: String, app: String, env: String, other_env: String, secret: String }
impl Fixture {
    async fn new() -> Self {
        let s = Server::start().await; let u = s.register("owner@broker.test.invalid").await;
        let owner = id(&u,"token"); let org = id(&u,"org_id"); let uid = id(&u,"user_id");
        assert_eq!(s.call(Method::GET,"/api/me",&owner,None).await.status,200);
        let r = s.call(Method::POST,"/mcp",&owner,Some(rpc("initialize",json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"broker-test","version":"1"}})))).await;
        assert_eq!(r.status,200,"existing human MCP must still operate"); assert!(r.body["result"].is_object());
        let r = s.call(Method::POST,&format!("/api/orgs/{org}/apps"),&owner,Some(json!({"name":"broker-test"}))).await; assert_eq!(r.status,200); let app = id(&r.body,"id");
        let r = s.call(Method::GET,&format!("/api/apps/{app}/envs"),&owner,None).await; assert_eq!(r.status,200);
        let env = id(&r.body[0],"id"); let other_env = id(&r.body[1],"id");
        let r = s.call(Method::PUT,&format!("/api/envs/{env}/secrets"),&owner,Some(json!({"secrets":[{"key":"BROKER_CREDENTIAL","value":CREDENTIAL}]}))).await; assert_eq!(r.status,200);
        let r = s.call(Method::GET,&format!("/api/envs/{env}/secrets"),&owner,None).await; assert_eq!(r.status,200); let secret = id(&r.body["secrets"][0],"id");
        Self { s, owner, uid, org, app, env, other_env, secret }
    }
    fn path(&self, suffix: &str) -> String { format!("/api/orgs/{}/broker/{suffix}", self.org) }
    fn service(&self) -> Value { json!({"name":"approved","env_id":self.env,"kind":"http","credential_secret_id":self.secret,"enabled":true,"policy":{"allowed_member_ids":[self.uid],"auth":{"type":"bearer"},"operations":[{"id":"lookup","url":"https://service.example/lookup","method":"POST","privileged":false,"input_schema":{"type":"object","properties":{"query":{"type":"string"}},"required":[],"additionalProperties":false},"response_fields":{"answer":"/answer"}}]}}) }
    async fn create(&self, body: Value) -> Value { let r = self.s.call(Method::POST,&self.path("services"),&self.owner,Some(body)).await; assert_eq!(r.status,201,"approved broker service creation: {}",r.text); r.body }
    async fn issue(&self, sid: &str, uid: &str, ttl: u64) -> Resp { self.s.call(Method::POST,&self.path("sessions"),&self.owner,Some(json!({"service_id":sid,"subject_user_id":uid,"capabilities":["lookup"],"approved_privileged_capabilities":[],"ttl_seconds":ttl}))).await }
    async fn session(&self, sid: &str) -> Value { let r = self.issue(sid,&self.uid,300).await; assert_eq!(r.status,201,"issue session: {}",r.text); assert!(id(&r.body,"token").starts_with("owb_")); r.body }
    async fn ping(&self, token: &str) -> Resp { self.s.call(Method::POST,"/api/broker/mcp",token,Some(rpc("ping",json!({})))).await }
}
fn rpc(method: &str, params: Value) -> Value { json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}) }
fn denied(r: &Resp, status: u16) { assert_eq!(r.status,status,"unexpected broker status: {}",r.text); assert!(r.body["error"].is_string(),"fixed error code required"); assert!(r.body["request_id"].is_string(),"request id required"); assert_eq!(r.body.as_object().unwrap().len(),2,"no diagnostic payload in error"); assert!(!r.text.contains(CREDENTIAL)); }

#[tokio::test]
async fn broker_service_creation_and_agent_auth_are_separate() {
    let f = Fixture::new().await; let service = f.create(f.service()).await; let session = f.session(&id(&service,"id")).await; let token = id(&session,"token");
    assert_eq!(f.ping(&token).await.status,200);
    for path in ["/api/me".to_string(),format!("/api/envs/{}/secrets",f.env),f.path("services"),f.path("sessions")] {
        let r = f.s.call(Method::GET,&path,&token,None).await; assert!(matches!(r.status,401|403),"agent authenticated normal/control API: {path}");
    }
    let r = f.s.call(Method::POST,"/mcp",&token,Some(rpc("tools/list",json!({})))).await; assert!(matches!(r.status,401|403));
    denied(&f.ping(&f.owner).await,401);
    let r = f.s.client.post(format!("{}/api/broker/mcp",f.s.base)).bearer_auth(&token).header("cookie",format!("ow_session={}",f.owner)).json(&rpc("ping",json!({}))).send().await.unwrap(); denied(&finish(r).await,401);
    let r = f.s.call(Method::POST,&format!("/api/apps/{}/tokens",f.app),&f.owner,Some(json!({"name":"not-human"}))).await; assert_eq!(r.status,200); let pat = id(&r.body,"token");
    let r = f.s.call(Method::POST,&f.path("services"),&pat,Some(f.service())).await; assert_eq!(r.status,403,"service tokens cannot administer broker even for same uid");
}

#[tokio::test]
async fn broker_policy_rejects_destination_schema_and_credential_escapes() {
    let f = Fixture::new().await;
    for url in ["http://service.example/lookup","https://127.0.0.1/","https://[::1]/","https://169.254.169.254/","https://10.0.0.1/","https://localhost/","https://user:pass@service.example/","https://service.example/lookup?token=hidden","https://service.example/#fragment"] {
        let mut v = f.service(); v["policy"]["operations"][0]["url"] = json!(url);
        denied(&f.s.call(Method::POST,&f.path("services"),&f.owner,Some(v)).await,400);
    }
    let mut v = f.service(); v["env_id"] = json!(f.other_env); denied(&f.s.call(Method::POST,&f.path("services"),&f.owner,Some(v)).await,409);
    for schema in [json!({"type":"object","additionalProperties":true}),json!({"type":"object","properties":{"nested":{"type":"object"}},"additionalProperties":false})] {
        let mut v = f.service(); v["policy"]["operations"][0]["input_schema"] = schema; denied(&f.s.call(Method::POST,&f.path("services"),&f.owner,Some(v)).await,400);
    }
    for kind in ["sealed","config"] {
        let r = f.s.call(Method::PUT,&format!("/api/envs/{}/secrets",f.env),&f.owner,Some(json!({"secrets":[{"key":format!("INVALID_{kind}"),"value":"dummy-invalid-credential","type":kind}]}))).await; assert_eq!(r.status,200);
        let r = f.s.call(Method::GET,&format!("/api/envs/{}/secrets",f.env),&f.owner,None).await; assert_eq!(r.status,200);
        let secret = r.body["secrets"].as_array().unwrap().iter().find(|s| s["key"] == format!("INVALID_{kind}").to_uppercase()).expect("invalid-source fixture secret");
        let mut v=f.service(); v["credential_secret_id"]=secret["id"].clone(); denied(&f.s.call(Method::POST,&f.path("services"),&f.owner,Some(v)).await,409);
    }
    let kp=openwarp_crypto::Keypair::generate();
    let runner=f.s.call(Method::POST,&format!("/api/orgs/{}/runners",f.org),&f.owner,Some(json!({"name":"broker-runner","public_key":kp.public}))).await; assert_eq!(runner.status,200);
    for mode in ["e2e","delegated"] {
        let (path,body)=if mode == "e2e" { (format!("/api/apps/{}/envs/e2e",f.app),json!({"name":"broker-e2e","wrapped_key":openwarp_crypto::b64(&[8u8; 64])})) } else { (format!("/api/apps/{}/envs",f.app),json!({"name":"broker-delegated","mode":"delegated","runner_id":runner.body["id"],"wrapped_key":openwarp_crypto::b64(&[8u8; 64]),"runner_wrapped_key":openwarp_crypto::b64(&[9u8; 64])})) };
        let r=f.s.call(Method::POST,&path,&f.owner,Some(body)).await; assert_eq!(r.status,200); let env=id(&r.body,"id");
        let r=f.s.call(Method::PUT,&format!("/api/envs/{env}/e2e/secrets"),&f.owner,Some(json!({"secrets":[{"key_enc":"ciphertext-key","key_hash":"fixture-key-hash","value_enc":"ciphertext-value"}]}))).await; assert_eq!(r.status,200,"{} -> {}", r.status, r.text);
        let r=f.s.call(Method::GET,&format!("/api/envs/{env}/e2e/secrets"),&f.owner,None).await; assert_eq!(r.status,200);
        let mut v=f.service(); v["env_id"]=json!(env); v["credential_secret_id"]=r.body["secrets"][0]["id"].clone(); denied(&f.s.call(Method::POST,&f.path("services"),&f.owner,Some(v)).await,409);
    }
    f.create(f.service()).await;
}

#[tokio::test]
async fn broker_sessions_expire_revoke_and_policy_updates_invalidate() {
    let f = Fixture::new().await; let service = f.create(f.service()).await; let sid = id(&service,"id");
    for ttl in [0,901] { denied(&f.issue(&sid,&f.uid,ttl).await,400); }
    let short = f.issue(&sid,&f.uid,1).await; assert_eq!(short.status,201); let short_token = id(&short.body,"token");
    let a = f.session(&sid).await; let b = f.session(&sid).await; assert_ne!(a["token"],b["token"]);
    assert_eq!(f.ping(&short_token).await.status,200); tokio::time::sleep(Duration::from_millis(1200)).await; denied(&f.ping(&short_token).await,401);
    let r = f.s.call(Method::DELETE,&f.path(&format!("sessions/{}",id(&a,"id"))),&f.owner,None).await; assert_eq!(r.status,204); denied(&f.ping(&id(&a,"token")).await,401); assert_eq!(f.ping(&id(&b,"token")).await.status,200);
    let mut update = f.service(); update["expected_revision"] = service["revision"].clone();
    let r = f.s.call(Method::PUT,&f.path(&format!("services/{sid}")),&f.owner,Some(update)).await; assert_eq!(r.status,200,"policy update: {}",r.text); denied(&f.ping(&id(&b,"token")).await,401);
    let fresh = f.session(&sid).await; assert_eq!(f.ping(&id(&fresh,"token")).await.status,200);
    assert_eq!(f.s.call(Method::DELETE,&f.path(&format!("services/{sid}")),&f.owner,None).await.status,204); denied(&f.ping(&id(&fresh,"token")).await,401);
}

#[tokio::test]
async fn broker_member_grants_need_use_permission_and_live_environment_access() {
    let f = Fixture::new().await; let member = f.s.register("member@broker.test.invalid").await; let uid = id(&member,"user_id"); let member_token = id(&member,"token");
    let r = f.s.call(Method::POST,&format!("/api/orgs/{}/roles",f.org),&f.owner,Some(json!({"name":"broker-user","permissions":["broker:use"]}))).await; assert_eq!(r.status,200);
    let r = f.s.call(Method::POST,&format!("/api/orgs/{}/members",f.org),&f.owner,Some(json!({"email":"member@broker.test.invalid","role":"broker-user"}))).await; assert_eq!(r.status,200);
    let invite = id(&r.body,"invite_token");
    let r = f.s.call(Method::POST,"/api/auth/accept-invite",&member_token,Some(json!({"token":invite}))).await; assert_eq!(r.status,200,"existing members must accept the invitation: {}",r.text);
    let service = f.create(f.service()).await; denied(&f.issue(&id(&service,"id"),&uid,300).await,403);
    let mut allowed = f.service(); allowed["policy"]["allowed_member_ids"] = json!([uid]); let service = f.create(allowed).await; let sid = id(&service,"id");
    let r = f.issue(&sid,&uid,300).await; assert_eq!(r.status,201,"broker:use must not require secrets:read: {}",r.text); let token = id(&r.body,"token"); assert_eq!(f.ping(&token).await.status,200);
    assert_eq!(f.s.call(Method::GET,&format!("/api/envs/{}/secrets",f.env),&member_token,None).await.status,403);
    let r = f.s.call(Method::PUT,&format!("/api/envs/{}/policy",f.env),&f.owner,Some(json!({"restricted":true}))).await; assert_eq!(r.status,200); denied(&f.ping(&token).await,403); denied(&f.issue(&sid,&uid,300).await,403);
    let r = f.s.call(Method::PUT,&format!("/api/envs/{}/policy",f.env),&f.owner,Some(json!({"restricted":false}))).await; assert_eq!(r.status,200);
    let r = f.issue(&sid,&uid,300).await; assert_eq!(r.status,201); let token = id(&r.body,"token");
    assert_eq!(f.s.call(Method::DELETE,&format!("/api/orgs/{}/members/{uid}",f.org),&f.owner,None).await.status,200); denied(&f.ping(&token).await,403);
}

#[tokio::test]
async fn broker_tenants_and_privileged_capabilities_are_not_interchangeable() {
    let f = Fixture::new().await; let foreign = f.s.register("foreign@broker.test.invalid").await;
    let mut policy = f.service(); policy["policy"]["operations"][0]["privileged"] = json!(true); let service = f.create(policy).await; let sid = id(&service,"id");
    denied(&f.issue(&sid,&id(&foreign,"user_id"),300).await,403);
    let foreign_path = format!("/api/orgs/{}/broker/sessions",id(&foreign,"org_id"));
    let r = f.s.call(Method::POST,&foreign_path,&id(&foreign,"token"),Some(json!({"service_id":sid,"subject_user_id":id(&foreign,"user_id"),"capabilities":["lookup"],"ttl_seconds":300}))).await; assert!(matches!(r.status,403|404));
    denied(&f.issue(&sid,&f.uid,300).await,403);
    let mut request = json!({"service_id":sid,"subject_user_id":f.uid,"capabilities":["lookup"],"approved_privileged_capabilities":["lookup"],"ttl_seconds":300});
    let r = f.s.call(Method::POST,&f.path("sessions"),&f.owner,Some(request.clone())).await; assert_eq!(r.status,201); assert_eq!(f.ping(&id(&r.body,"token")).await.status,200);
    request["capabilities"] = json!(["lookup_extra"]); let r = f.s.call(Method::POST,&f.path("sessions"),&f.owner,Some(request)).await; assert!(matches!(r.status,400|403));
}

#[tokio::test]
async fn broker_mcp_discovery_is_exact_and_plaintext_methods_are_absent() {
    let f = Fixture::new().await; let mut v = f.service(); v["kind"] = json!("mcp"); v["policy"].as_object_mut().unwrap().remove("operations");
    v["policy"]["endpoint"] = json!("https://service.example/mcp"); v["policy"]["tools"] = json!([{"id":"lookup","name":"upstream_lookup","privileged":false,"input_schema":{"type":"object","properties":{},"additionalProperties":false},"response_fields":{"answer":"/answer"}}]);
    let service = f.create(v).await; let token = id(&f.session(&id(&service,"id")).await,"token");
    let r = f.s.call(Method::POST,"/api/broker/mcp",&token,Some(rpc("tools/list",json!({})))).await; assert_eq!(r.status,200); let tools = r.body["result"]["tools"].as_array().expect("tool list"); assert_eq!(tools.len(),1); assert_eq!(tools[0]["name"],"lookup"); assert!(!r.text.contains("upstream_lookup")); assert!(!r.text.contains(CREDENTIAL));
    for method in ["resources/list","resources/read","prompts/list","secrets/get"] {
        let r = f.s.call(Method::POST,"/api/broker/mcp",&token,Some(rpc(method,json!({})))).await; assert!(r.status == 403 || r.body["error"].is_object(),"unapproved MCP method succeeded: {method}"); assert!(r.body.get("result").is_none());
    }
    let r = f.s.call(Method::POST,"/api/broker/mcp",&token,Some(rpc("tools/call",json!({"name":"list_secrets","arguments":{"env_id":f.env}})))).await; assert!(r.status == 403 || r.body["error"].is_object()); assert!(!r.text.contains(CREDENTIAL));
}

#[tokio::test]
async fn broker_arguments_and_audit_never_become_secret_exfiltration_paths() {
    let f = Fixture::new().await; let service = f.create(f.service()).await; let token = id(&f.session(&id(&service,"id")).await,"token");
    for args in [json!({"url":"https://attacker.example/"}),json!({"headers":{"authorization":"stolen"}}),json!({"query":17}),json!({"query":"x".repeat(4097)})] {
        denied(&f.s.call(Method::POST,"/api/broker/http",&token,Some(json!({"operation":"lookup","arguments":args}))).await,400);
    }
    denied(&f.s.call(Method::POST,"/api/broker/http",&token,Some(json!({"operation":"lookup_extra","arguments":{}}))).await,403);
    let r = f.s.client.post(format!("{}/api/broker/http",f.s.base)).bearer_auth(&token).header("content-type","application/json").body("{").send().await.unwrap(); assert_eq!(r.status().as_u16(),400);
    let r = f.s.call(Method::GET,&f.path("audit"),&f.owner,None).await; assert_eq!(r.status,200); assert!(!r.text.contains(CREDENTIAL)); assert!(!r.text.contains(&token)); assert!(!r.text.contains("attacker.example")); assert!(!r.text.contains("stolen"));
}

#[tokio::test]
async fn broker_emergency_lockdown_revokes_live_agent_sessions() {
    let f = Fixture::new().await; let service = f.create(f.service()).await; let sid = id(&service,"id");
    let issued = f.issue(&sid,&f.uid,900).await; assert_eq!(issued.status,201,"{}: {}",issued.status,issued.text);
    let token = id(&issued.body,"token");
    assert_eq!(f.ping(&token).await.status,200,"healthy delegation must execute");
    // The emergency endpoints take the owner's cookie session, not a bearer token.
    let lock = f.s.client.put(format!("{}/api/orgs/{}/emergency",f.s.base,f.org)).header("cookie",format!("ow_session={}",f.owner)).json(&json!({"locked":true})).send().await.unwrap();
    assert_eq!(lock.status().as_u16(),200,"{}: {}",lock.status(),lock.text().await.unwrap_or_default());
    let during = f.ping(&token).await.status;
    assert_ne!(during,200,"a locked workspace must not execute agent operations");
    let restore = f.s.client.put(format!("{}/api/orgs/{}/emergency",f.s.base,f.org)).header("cookie",format!("ow_session={}",f.owner)).json(&json!({"locked":false})).send().await.unwrap();
    assert_eq!(restore.status().as_u16(),200,"{}: {}",restore.status(),restore.text().await.unwrap_or_default());
    denied(&f.ping(&token).await,401);
}

#[tokio::test]
async fn broker_issue_is_refused_while_a_lockdown_is_active() {
    let f = Fixture::new().await; let service = f.create(f.service()).await; let sid = id(&service,"id");
    // Lockdown first: authority itself must refuse, and the write batch's
    // lockdown guard must keep a racing issuance from committing a token that
    // would survive the lockdown that deletes the sessions.
    let lock = f.s.client.put(format!("{}/api/orgs/{}/emergency",f.s.base,f.org)).header("cookie",format!("ow_session={}",f.owner)).json(&json!({"locked":true})).send().await.unwrap();
    assert_eq!(lock.status().as_u16(),200,"{}: {}",lock.status(),lock.text().await.unwrap_or_default());
    let issued = f.issue(&sid,&f.uid,900).await;
    assert_ne!(issued.status,201,"a locked workspace must not issue broker sessions: {} {}",issued.status,issued.text);
    let restore = f.s.client.put(format!("{}/api/orgs/{}/emergency",f.s.base,f.org)).header("cookie",format!("ow_session={}",f.owner)).json(&json!({"locked":false})).send().await.unwrap();
    assert_eq!(restore.status().as_u16(),200,"{}: {}",restore.status(),restore.text().await.unwrap_or_default());
    let after = f.issue(&sid,&f.uid,900).await;
    assert_eq!(after.status,201,"issuance must work again after restore: {} {}",after.status,after.text);
}

#[tokio::test]
async fn broker_sessions_stop_when_the_credential_path_becomes_restricted() {
    let f = Fixture::new().await;
    let admin = f.s.register("broker-admin@test.invalid").await;
    let at = id(&admin,"token"); let auid = id(&admin,"user_id");
    let inv = f.s.call(Method::POST,&format!("/api/orgs/{}/members",f.org),&f.owner,Some(json!({"email":"broker-admin@test.invalid","role":"admin"}))).await;
    assert_eq!(inv.status,200,"{}: {}",inv.status,inv.text);
    let acc = f.s.call(Method::POST,"/api/auth/accept-invite",&at,Some(json!({"token":inv.body["invite_token"]}))).await;
    assert_eq!(acc.status,200,"{}: {}",acc.status,acc.text);
    let mut v = f.service(); v["policy"]["allowed_member_ids"] = json!([auid]);
    let service = f.create(v).await; let sid = id(&service,"id");
    let issued = f.issue(&sid,&auid,900).await; assert_eq!(issued.status,201,"{}: {}",issued.status,issued.text);
    let token = id(&issued.body,"token");
    assert_eq!(f.ping(&token).await.status,200,"a healthy admin delegation must execute");
    let rules = json!({"rules":[{"prefix":"/public/","capabilities":["read"]}]});
    let pol = f.s.call(Method::PUT,&format!("/api/envs/{}/path-policy/admin",f.env),&f.owner,Some(rules)).await;
    assert_eq!(pol.status,200,"{}: {}",pol.status,pol.text);
    let pr = f.ping(&token).await;
    denied(&pr,403); assert_eq!(pr.body["error"], json!("forbidden"), "{}", pr.text);
    let r = f.s.call(Method::POST,&f.path("sessions"),&at,Some(json!({"service_id":sid,"subject_user_id":auid,"capabilities":["lookup"],"approved_privileged_capabilities":[],"ttl_seconds":300}))).await;
    assert_eq!(r.status,403,"{}: {}",r.status,r.text);
}

#[tokio::test]
async fn a_session_dies_when_its_issuer_becomes_restricted_even_if_the_path_stays_allowed() {
    // Isolates the issuer guard from the credential-path check: the policy
    // explicitly allows the credential's path with read, so a surviving
    // session could only be explained by the missing issuer restriction.
    let f = Fixture::new().await;
    let admin = f.s.register("broker-restricted-issuer@test.invalid").await;
    let at = id(&admin,"token"); let auid = id(&admin,"user_id");
    let inv = f.s.call(Method::POST,&format!("/api/orgs/{}/members",f.org),&f.owner,Some(json!({"email":"broker-restricted-issuer@test.invalid","role":"admin"}))).await;
    assert_eq!(inv.status,200,"{}: {}",inv.status,inv.text);
    let acc = f.s.call(Method::POST,"/api/auth/accept-invite",&at,Some(json!({"token":inv.body["invite_token"]}))).await;
    assert_eq!(acc.status,200,"{}: {}",acc.status,acc.text);
    let mut v = f.service(); v["policy"]["allowed_member_ids"] = json!([auid]);
    let service = f.create(v).await; let sid = id(&service,"id");
    // The admin is the ISSUER here: Fixture::issue always authenticates as the
    // owner, which would leave the issuer unrestricted no matter what the
    // policy says.
    let issued = f.s.call(Method::POST,&f.path("sessions"),&at,Some(json!({"service_id":sid,"subject_user_id":auid,"capabilities":["lookup"],"approved_privileged_capabilities":[],"ttl_seconds":900}))).await;
    assert_eq!(issued.status,201,"{}: {}",issued.status,issued.text);
    let token = id(&issued.body,"token");
    assert_eq!(f.ping(&token).await.status,200,"a healthy admin delegation must execute");
    // The catch-all rule allows every path with read, so the credential path
    // stays reachable; the issuer (admin) is nonetheless now path-restricted.
    let rules = json!({"rules":[{"prefix":"/","capabilities":["read"]}]});
    let pol = f.s.call(Method::PUT,&format!("/api/envs/{}/path-policy/admin",f.env),&f.owner,Some(rules)).await;
    assert_eq!(pol.status,200,"{}: {}",pol.status,pol.text);
    denied(&f.ping(&token).await,403);
}
