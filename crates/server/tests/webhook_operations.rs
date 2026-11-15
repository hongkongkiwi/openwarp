use base64ct::{Base64, Encoding};
use hmac::Mac;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU16, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Capture { head: String, body: Vec<u8> }
struct Receiver {
    url: String, calls: Arc<Mutex<Vec<Capture>>>, status: Arc<AtomicU16>,
    stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>>,
}
impl Receiver {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/capture", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new())); let sink = calls.clone();
        let status = Arc::new(AtomicU16::new(200)); let code = status.clone();
        let stop = Arc::new(AtomicBool::new(false)); let done = stop.clone();
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(5)); continue; }
                    Err(e) => panic!("receiver accept: {e}"),
                };
                // Darwin inherits the listener's nonblocking mode on accepted sockets.
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut bytes = Vec::new(); let mut buf = [0; 8192];
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(n) => n,
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                        Err(e) => panic!("receiver read: {e}"),
                    };
                    if n == 0 { break; }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..end]);
                        let len = head.lines().find_map(|l| { let (k,v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                        if bytes.len() >= end + 4 + len { break; }
                    }
                }
                // An unused connection is not an HTTP request; partial requests still fail.
                if bytes.is_empty() { continue; }
                let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").expect("HTTP headers");
                sink.lock().unwrap().push(Capture { head: String::from_utf8(bytes[..end].to_vec()).unwrap(), body: bytes[end+4..].to_vec() });
                let response = format!("HTTP/1.1 {} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}", code.load(Ordering::SeqCst));
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self { url, calls, status, stop, thread: Some(thread) }
    }
}
impl Drop for Receiver { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); self.thread.take().unwrap().join().unwrap(); } }
#[test]
fn receiver_waits_for_request_bytes_after_accept() {
    let receiver = Receiver::start();
    let url = reqwest::Url::parse(&receiver.url).unwrap();
    let mut stream = std::net::TcpStream::connect((url.host_str().unwrap(), url.port().unwrap())).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut byte = [0];
    // TCP establishment can precede HTTP bytes; the receiver must keep the connection open.
    let result = stream.read(&mut byte);
    assert!(matches!(&result, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)), "receiver closed before request bytes: {result:?}");
    stream.write_all(b"POST /capture HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
    let mut response = String::new(); stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "), "receiver response: {response}");
    let calls = receiver.calls.lock().unwrap(); assert_eq!(calls.len(), 1); assert_eq!(calls[0].body, b"{}");
}
struct Server { child: Child, base: String, dir: std::path::PathBuf, client: Client, mail: Receiver }
impl Drop for Server { fn drop(&mut self) {
    let _ = self.child.kill(); let _ = self.child.wait();
    if std::thread::panicking() {
        let stderr = std::fs::read_to_string(self.dir.join("server.stderr")).unwrap_or_default();
        eprintln!("dummy mail fixture: captured={}, relay_finished={}, delivery_error={}, stderr_bytes={}, private_stderr={}", self.mail.calls.lock().map(|m|m.len()).unwrap_or_default(), self.mail.thread.as_ref().is_some_and(|t|t.is_finished()), stderr.contains("email delivery failed:"), stderr.len(), self.dir.join("server.stderr").display());
    } else { let _ = std::fs::remove_dir_all(&self.dir); }
} }
impl Server {
    async fn start() -> Self { Self::launch(false).await }
    // Only delivery fixtures opt into isolated loopback egress; policy fixtures never do.
    async fn delivery_fixture() -> Self { Self::launch(true).await }
    async fn launch(loopback_delivery: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{addr}");
        let dir = std::env::temp_dir().join(format!("openwarp-hook-operations-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir_all(&dir).unwrap(); let mail = Receiver::start();
        let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        command.env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display())).env("ADDR", addr.to_string())
            .env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", &mail.url).env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS").env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ALLOWED_DB_HOSTS");
        if loopback_delivery { command.env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1"); }
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap(); }
        let mut stderr_options = std::fs::OpenOptions::new(); stderr_options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; stderr_options.mode(0o600); }
        let stderr = stderr_options.open(dir.join("server.stderr")).unwrap();
        let child = command.stdout(Stdio::null()).stderr(Stdio::from(stderr)).spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s = Self { child, base, dir, client, mail }; let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { break; } }
            assert!(Instant::now() < deadline, "server startup timed out"); tokio::time::sleep(Duration::from_millis(100)).await;
        }
        s
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { req = req.bearer_auth(token); }
        if let Some(body) = body { req = req.json(&body); }
        let r = req.send().await.unwrap(); let status = r.status().as_u16(); let text = r.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(json!({"raw":text})))
    }
    async fn call_stepped_up(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> (u16, Value) {
        let before = self.mail.calls.lock().unwrap().len();
        let start = success(self.call(Method::POST, "/api/auth/step-up/start", token, Some(json!({"risk":"very_risky"}))).await);
        assert_eq!(start["email_sent"], true);
        let deadline = Instant::now() + Duration::from_secs(5);
        let code = loop {
            let code = self.mail.calls.lock().unwrap().iter().skip(before).filter_map(|c| serde_json::from_slice::<Value>(&c.body).ok())
                .find_map(|m| m["text"].as_str()?.split(|c: char| !c.is_ascii_digit()).find(|s| s.len() == 6).map(str::to_string));
            if let Some(code) = code { break code; }
            assert!(Instant::now() < deadline, "fresh step-up mail missing"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let verified = success(self.call(Method::POST, "/api/auth/step-up/verify", token, Some(json!({"challenge":start["challenge"],"email_code":code}))).await);
        let mut request = self.client.request(method, format!("{}{}", self.base, path)).bearer_auth(token).header("x-openwarp-step-up", verified["token"].as_str().unwrap());
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.unwrap(); let status = response.status().as_u16(); let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(json!({"raw":text})))
    }
    async fn register(&self, email: &str) -> Value {
        let (_, mut u) = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let path = loop {
            let link = self.mail.calls.lock().unwrap().iter().filter_map(|c| serde_json::from_slice::<Value>(&c.body).ok()).find_map(|v| {
                if !v.to_string().contains(email) { return None; }
                v["text"].as_str()?.split_whitespace().find_map(|w| w.find("/api/auth/verify?token=").map(|i| w[i..].to_string()))
            });
            if let Some(path) = link { break path; }
            assert!(Instant::now() < deadline, "verification mail missing: {u}"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        success(self.call(Method::GET, &path, "", None).await);
        let login = success(self.call(Method::POST, "/api/auth/login", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await);
        u["token"] = login["token"].clone(); u["user_id"] = login["user_id"].clone(); u
    }
    async fn app(&self, t: &str, org: &str) -> (String, String) {
        let a = success(self.call(Method::POST, &format!("/api/orgs/{org}/apps"), t, Some(json!({"name":"operations"}))).await);
        let aid = id(&a); let envs = success(self.call(Method::GET, &format!("/api/apps/{aid}/envs"), t, None).await);
        (aid, id(&envs[0]))
    }
    async fn integration(&self, t: &str, eid: &str, url: &str) -> String {
        id(&success(self.call(Method::POST, &format!("/api/envs/{eid}/integrations"), t, Some(json!({"kind":"webhook","name":"fixed target","config":{"url":url,"auto_sync":false,"token":"dummy-provider-credential"}}))).await))
    }
    async fn incoming(&self, t: &str, iid: &str) -> (String, String) {
        let v = success(self.call(Method::POST, &format!("/api/integrations/{iid}/webhooks"), t, Some(json!({"name":"operations"}))).await);
        (id(&v), v["secret"].as_str().unwrap().to_string())
    }
    async fn signed(&self, hid: &str, key: &str, mid: &str, body: &[u8]) -> (u16, Value) {
        let ts = now().to_string(); let raw = Base64::decode_vec(key.strip_prefix("whsec_").unwrap()).unwrap();
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&raw).unwrap(); mac.update(format!("{mid}.{ts}.").as_bytes()); mac.update(body);
        let r = self.client.post(format!("{}/hooks/integrations/{hid}", self.base)).header("webhook-id", mid).header("webhook-timestamp", ts)
            .header("webhook-signature", format!("v1,{}", Base64::encode_string(&mac.finalize().into_bytes()))).body(body.to_vec()).send().await.unwrap();
        let status = r.status().as_u16(); (status, r.json().await.unwrap())
    }
    async fn history(&self, t: &str, hid: &str, incoming: bool) -> Value {
        let path = if incoming { format!("/api/incoming-webhooks/{hid}/receipts?limit=100") } else { format!("/api/webhooks/{hid}/deliveries?limit=100") };
        success(self.call(Method::GET, &path, t, None).await)
    }
    async fn wait_status(&self, t: &str, hid: &str, incoming: bool, state: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let rows = self.history(t, hid, incoming).await;
            if let Some(row) = rows.as_array().unwrap().iter().find(|v| v["status"] == state) { return row.clone(); }
            assert!(Instant::now() < deadline, "missing {state}: {rows}"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
fn success(r: (u16, Value)) -> Value { assert!((200..300).contains(&r.0), "HTTP {}: {}", r.0, r.1); r.1 }
fn id(v: &Value) -> String { v["id"].as_str().expect("id").to_string() }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn header<'a>(head: &'a str, name: &str) -> &'a str { head.lines().find_map(|l| { let (k,v) = l.split_once(':')?; if k.eq_ignore_ascii_case(name) { Some(v.trim()) } else { None } }).expect("required header") }
async fn deploy(s: &Server, t: &str, eid: &str) { success(s.call(Method::PUT, &format!("/api/envs/{eid}/secrets"), t, Some(json!({"secrets":[{"key":"PRIVATE_KEY_MARKER","value":"private-secret-value-marker"}]}))).await); }

#[tokio::test]
async fn outgoing_success_signs_exact_bytes_and_filters_app_and_event_metadata() {
    let s = Server::delivery_fixture().await; let receiver = Receiver::start();
    let u = s.register("delivery@test.invalid").await; let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let (aid,eid) = s.app(t,org).await; let (_,other_env) = s.app(t,org).await;
    let sub = success(s.call(Method::POST, &format!("/api/orgs/{org}/webhooks"), t, Some(json!({"url":receiver.url,"app_id":aid,"events":["secret.deploy"]}))).await);
    let hid = id(&sub); let key = Base64::decode_vec(sub["secret"].as_str().unwrap().strip_prefix("whsec_").unwrap()).unwrap();
    deploy(&s,t,&other_env).await;
    success(s.call(Method::PATCH, &format!("/api/apps/{aid}"), t, Some(json!({"name":"unsubscribed event"}))).await);
    // A positive delivery is the worker barrier before asserting excluded events stayed absent.
    deploy(&s,t,&eid).await; let row = s.wait_status(t,&hid,false,"delivered").await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let calls = receiver.calls.lock().unwrap(); assert_eq!(calls.len(),1,"cross-app or nonmatching event delivered"); let c = &calls[0];
    let v: Value = serde_json::from_slice(&c.body).unwrap();
    assert_eq!(v["type"],"secret.deploy"); assert_eq!(v["app_id"],aid); assert_eq!(v["env_id"],eid); assert_eq!(v["workspace_id"],org);
    let mut fields = v.as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(); fields.sort_unstable();
    assert_eq!(fields,vec!["actor_id","app_id","env_id","id","timestamp","type","workspace_id"]);
    assert_eq!(header(&c.head,"webhook-id"),v["id"].as_str().unwrap()); assert_eq!(row["event_id"],v["id"]); assert_eq!(row["http_status"],200);
    let ts = header(&c.head,"webhook-timestamp"); assert!(ts.parse::<i64>().unwrap().abs_diff(now()) <= 30);
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&key).unwrap(); mac.update(format!("{}.{ts}.",header(&c.head,"webhook-id")).as_bytes()); mac.update(&c.body);
    mac.verify_slice(&Base64::decode_vec(header(&c.head,"webhook-signature").strip_prefix("v1,").unwrap()).unwrap()).expect("signature must authenticate exact received bytes");
    assert!(!c.head.to_ascii_lowercase().contains("authorization:"));
    assert!(!String::from_utf8_lossy(&c.body).contains("private-secret-value-marker"));
}

#[tokio::test]
async fn outgoing_failed_delivery_retries_once_and_disable_cancels_pending_work() {
    let s = Server::delivery_fixture().await; let receiver = Receiver::start(); receiver.status.store(503,Ordering::SeqCst);
    let u = s.register("retry@test.invalid").await; let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let sub = success(s.call(Method::POST,&format!("/api/orgs/{org}/webhooks"),t,Some(json!({"url":receiver.url,"events":["never.match"]}))).await); let hid = id(&sub);
    success(s.call(Method::POST,&format!("/api/webhooks/{hid}/test"),t,Some(json!({}))).await);
    let failed = s.wait_status(t,&hid,false,"failed").await; assert_eq!(failed["attempts"],1); assert_eq!(failed["http_status"],503);
    receiver.status.store(200,Ordering::SeqCst);
    success(s.call(Method::POST,&format!("/api/webhook-deliveries/{}/retry",id(&failed)),t,Some(json!({}))).await);
    let delivered = s.wait_status(t,&hid,false,"delivered").await; assert_eq!(delivered["id"],failed["id"]); assert_eq!(delivered["event_id"],failed["event_id"]);
    assert_eq!(receiver.calls.lock().unwrap().len(),2);
    assert_eq!(s.call(Method::POST,&format!("/api/webhook-deliveries/{}/retry",id(&failed)),t,Some(json!({}))).await.0,409);
    receiver.status.store(503,Ordering::SeqCst);
    success(s.call(Method::POST,&format!("/api/webhooks/{hid}/test"),t,Some(json!({}))).await);
    let _ = s.wait_status(t,&hid,false,"failed").await;
    success(s.call(Method::PATCH,&format!("/api/webhooks/{hid}"),t,Some(json!({"enabled":false}))).await);
    let before = receiver.calls.lock().unwrap().len(); tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(receiver.calls.lock().unwrap().len(),before,"disabled subscription dispatched work");
    let rows = s.history(t,&hid,false).await; assert!(rows.as_array().unwrap().iter().any(|v|v["status"]=="cancelled"));
    assert!(!rows.to_string().contains("whsec_"));
}

#[tokio::test]
async fn incoming_quota_accepts_sixty_unique_messages_without_charging_replays() {
    let s = Server::start().await; let u = s.register("quota@test.invalid").await; let t = u["token"].as_str().unwrap();
    let (_,eid) = s.app(t,u["org_id"].as_str().unwrap()).await; let iid = s.integration(t,&eid,"http://127.0.0.1:9/never").await; let (hid,key) = s.incoming(t,&iid).await;
    let start = Instant::now();
    for n in 0..60 { assert_eq!(s.signed(&hid,&key,&format!("quota_{n}"),b"{}").await.0,202,"unique message {n}"); }
    assert!(start.elapsed() < Duration::from_secs(55),"quota test crossed its rate window");
    assert_eq!(s.signed(&hid,&key,"quota_0",b"{}").await,(200,json!({"duplicate":true})));
    assert_eq!(s.signed(&hid,&key,"quota_60",b"{}").await.0,429);
    let rows = s.history(t,&hid,true).await; assert_eq!(rows.as_array().unwrap().len(),60,"quota denial or replay inserted a receipt");
}

#[tokio::test]
async fn incoming_concurrent_replays_create_one_receipt_and_conflicting_bytes_never_replace_it() {
    let s = Server::start().await; let u = s.register("concurrency@test.invalid").await; let t = u["token"].as_str().unwrap();
    let (_,eid) = s.app(t,u["org_id"].as_str().unwrap()).await; let iid = s.integration(t,&eid,"http://127.0.0.1:9/never").await; let (hid,key) = s.incoming(t,&iid).await;
    let (a,b,c,d) = tokio::join!(s.signed(&hid,&key,"concurrent",b"private-raw-body"),s.signed(&hid,&key,"concurrent",b"private-raw-body"),s.signed(&hid,&key,"concurrent",b"private-raw-body"),s.signed(&hid,&key,"concurrent",b"private-raw-body"));
    let results = [a,b,c,d]; assert_eq!(results.iter().filter(|r|r.0==202).count(),1);
    assert_eq!(results.iter().filter(|r|r.0==200 && r.1["duplicate"]==true).count(),3);
    assert_eq!(s.signed(&hid,&key,"concurrent",b"different bytes").await.0,409);
    let rows = s.history(t,&hid,true).await; assert_eq!(rows.as_array().unwrap().len(),1); assert_eq!(rows[0]["message_id"],"concurrent");
    for marker in ["private-raw-body","different bytes","body_hash","dummy-provider-credential","whsec_"] { assert!(!rows.to_string().contains(marker)); }
}

#[tokio::test]
async fn incoming_logout_revokes_creator_credential_without_creating_another_receipt() {
    let s = Server::start().await; let u = s.register("revocation@test.invalid").await; let t = u["token"].as_str().unwrap();
    let (_,eid) = s.app(t,u["org_id"].as_str().unwrap()).await; let iid = s.integration(t,&eid,"http://127.0.0.1:9/never").await; let (hid,key) = s.incoming(t,&iid).await;
    assert_eq!(s.signed(&hid,&key,"before_logout",b"{}").await.0,202);
    success(s.call(Method::POST,"/api/auth/logout",t,None).await);
    assert_eq!(s.signed(&hid,&key,"after_logout",b"{}").await.0,403);
    let login = success(s.call(Method::POST,"/api/auth/login","",Some(json!({"email":"revocation@test.invalid","password":"correct-horse-battery"}))).await);
    let fresh = login["token"].as_str().unwrap();
    assert_eq!(s.history(fresh,&hid,true).await.as_array().unwrap().len(),1);
    assert_eq!(s.signed(&hid,&key,"after_new_login",b"{}").await.0,403,"new login must not resurrect old creator credential");
}

#[tokio::test]
async fn incoming_ip_policy_and_mcp_cannot_be_bypassed_by_forwarded_headers() {
    let s = Server::start().await; let u = s.register("ip@test.invalid").await; let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let (_,eid) = s.app(t,org).await; let iid = s.integration(t,&eid,"http://127.0.0.1:9/never").await; let (hid,key) = s.incoming(t,&iid).await;
    assert_eq!(s.signed(&hid,&key,"before_ip_change",b"{}").await.0,202);
    success(s.call_stepped_up(Method::PUT,&format!("/api/orgs/{org}/settings"),t,Some(json!({"ip_allowlist":"192.0.2.0/24"}))).await);
    assert_eq!(s.signed(&hid,&key,"after_ip_change",b"{}").await.0,403);
    let r = s.client.post(format!("{}/mcp",s.base)).bearer_auth(t).header("X-Forwarded-For","192.0.2.5")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_request","arguments":{"method":"GET","path":format!("/api/envs/{eid}/integrations")}}})).send().await.unwrap();
    assert_eq!(r.status().as_u16(),403,"untrusted forwarded IP bypassed MCP allowlist");
}

#[tokio::test]
async fn incoming_manual_sync_uses_only_bound_integration_despite_body_and_auto_sync_false() {
    let s = Server::delivery_fixture().await; let target = Receiver::start(); let decoy = Receiver::start();
    let u = s.register("fixed-target@test.invalid").await; let t = u["token"].as_str().unwrap();
    let (_,eid) = s.app(t,u["org_id"].as_str().unwrap()).await; let iid = s.integration(t,&eid,&target.url).await; let other = s.integration(t,&eid,&decoy.url).await;
    deploy(&s,t,&eid).await; assert!(target.calls.lock().unwrap().is_empty()); assert!(decoy.calls.lock().unwrap().is_empty());
    let (hid,key) = s.incoming(t,&iid).await;
    let body = json!({"integration_id":other,"url":decoy.url,"config":{"url":decoy.url,"token":"attacker-token"},"secrets":{"INJECTED":"attacker-value"},"marker":"private-trigger-body"}).to_string();
    assert_eq!(s.signed(&hid,&key,"fixed_target",body.as_bytes()).await.0,202);
    s.wait_status(t,&hid,true,"delivered").await;
    let (head, sent_body) = {
        let calls = target.calls.lock().unwrap(); assert_eq!(calls.len(),1);
        (calls[0].head.clone(), calls[0].body.clone())
    };
    let payload: Value = serde_json::from_slice(&sent_body).unwrap();
    assert_eq!(payload["secrets"]["PRIVATE_KEY_MARKER"],"private-secret-value-marker"); assert!(payload["secrets"].get("INJECTED").is_none());
    assert_eq!(header(&head,"authorization"),"Bearer dummy-provider-credential");
    assert!(!String::from_utf8_lossy(&sent_body).contains("private-trigger-body")); assert!(decoy.calls.lock().unwrap().is_empty(),"incoming body selected a different integration");
    assert_eq!(s.signed(&hid,&key,"fixed_target",body.as_bytes()).await,(200,json!({"duplicate":true})));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(target.calls.lock().unwrap().len(),1,"replay caused another provider write");
    assert!(decoy.calls.lock().unwrap().is_empty(),"replay reached unbound provider");
    let rows = s.history(t,&hid,true).await; assert_eq!(rows.as_array().unwrap().len(),1); for marker in ["private-trigger-body","attacker-token","attacker-value","private-secret-value-marker","dummy-provider-credential","raw_body"] { assert!(!rows.to_string().contains(marker)); }
}

#[tokio::test]
async fn incoming_delegated_environment_rejects_trigger_creation_without_runner_work() {
    use openwarp_crypto as oc;
    let s = Server::start().await; let u = s.register("delegated-hook@test.invalid").await;
    let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap(); let (aid,_) = s.app(t,org).await;
    let login = success(s.call(Method::POST,"/api/auth/login","",Some(json!({"email":"delegated-hook@test.invalid","password":"correct-horse-battery"}))).await);
    let owner_public = login["public_key"].as_str().unwrap(); let runner_key = oc::Keypair::generate(); let env_key = oc::random_key();
    let runner = success(s.call(Method::POST,&format!("/api/orgs/{org}/runners"),t,Some(json!({"name":"hook-runner","public_key":runner_key.public}))).await);
    let env = success(s.call(Method::POST,&format!("/api/apps/{aid}/envs"),t,Some(json!({"name":"delegatedhooks","mode":"delegated","runner_id":id(&runner),
        "wrapped_key":oc::encrypt_to(owner_public,&env_key).unwrap(),"runner_wrapped_key":oc::encrypt_to(&runner_key.public,&env_key).unwrap()}))).await);
    let iid = s.integration(t,&id(&env),"https://example.invalid/never").await;
    let r = s.call(Method::POST,&format!("/api/integrations/{iid}/webhooks"),t,Some(json!({"name":"must-not-exist"}))).await;
    assert_eq!(r.0,409,"delegated trigger accepted: {}",r.1);
    assert_eq!(success(s.call(Method::GET,&format!("/api/integrations/{iid}/webhooks"),t,None).await),json!([]));
    let jobs = success(s.call(Method::GET,"/api/runner/jobs",runner["token"].as_str().unwrap(),None).await);
    assert_eq!(jobs["jobs"],json!([]),"rejected webhook must not enqueue runner work");
}

#[tokio::test]
async fn incoming_signing_key_survives_instance_master_rotation() {
    let s = Server::start().await; let u = s.register("master-rotation-hook@test.invalid").await; let t = u["token"].as_str().unwrap();
    let (_,eid) = s.app(t,u["org_id"].as_str().unwrap()).await;
    let iid = s.integration(t,&eid,"http://127.0.0.1:9/never").await; let (hid,key) = s.incoming(t,&iid).await;
    assert_eq!(s.signed(&hid,&key,"before_master_rotation",b"{}").await.0,202);
    let new_key = Base64::encode_string(&openwarp_crypto::random_key());
    success(s.call_stepped_up(Method::POST,"/api/instance/rotate-master",t,Some(json!({"new_key":new_key}))).await);
    assert_eq!(s.signed(&hid,&key,"after_master_rotation",b"{}").await.0,202,"master rotation must preserve the externally issued signing key");
    let rows = s.history(t,&hid,true).await; assert_eq!(rows.as_array().unwrap().len(),2);
    for marker in [key.as_str(),new_key.as_str(),"body_hash","raw_body"] { assert!(!rows.to_string().contains(marker)); }
}

#[tokio::test]
async fn mcp_query_pagination_and_custom_role_preserve_route_permissions() {
    let s = Server::start().await; let u = s.register("mcp-owner@test.invalid").await; let t = u["token"].as_str().unwrap(); let org = u["org_id"].as_str().unwrap();
    let (_,eid) = s.app(t,org).await; deploy(&s,t,&eid).await;
    let user = s.register("mcp-reader@test.invalid").await; let reader = user["token"].as_str().unwrap();
    success(s.call(Method::POST,&format!("/api/orgs/{org}/roles"),t,Some(json!({"name":"operations-reader","permissions":["secrets:read"]}))).await);
    let invite = success(s.call(Method::POST,&format!("/api/orgs/{org}/members"),t,Some(json!({"email":"mcp-reader@test.invalid","role":"operations-reader"}))).await);
    // Issuing an invite never adds membership; the invitee accepts explicitly.
    success(s.call(Method::POST,"/api/auth/accept-invite",reader,Some(json!({"token":invite["invite_token"],"password":"correct-horse-battery"}))).await);
    for (method,path,body,status) in [
        ("GET",format!("/api/envs/{eid}/secrets?limit=1&offset=0"),Value::Null,200),
        ("GET",format!("/api/envs/{eid}/secrets?limit=1&offset=1"),Value::Null,200),
        ("PUT",format!("/api/envs/{eid}/secrets"),json!({"secrets":[{"key":"DENIED","value":"must-not-land"}]}),403),
    ] {
        let mut arguments = json!({"method":method,"path":path}); if !body.is_null() { arguments["body"] = body; }
        let rpc = success(s.call(Method::POST,"/mcp",reader,Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_request","arguments":arguments}}))).await);
        assert!(rpc.get("error").is_none(),"{rpc}"); let envelope = &rpc["result"]["structuredContent"]; assert_eq!(envelope["status"],status,"{rpc}");
        if status == 200 { assert_eq!(envelope["body"]["secrets"].as_array().unwrap().len(),if path.ends_with("offset=0") {1} else {0}); }
        else { assert_eq!(rpc["result"]["isError"],true); }
    }
    let secrets = success(s.call(Method::GET,&format!("/api/envs/{eid}/secrets"),t,None).await);
    assert!(!secrets.to_string().contains("must-not-land")); assert_eq!(secrets["secrets"].as_array().unwrap().len(),1);
}
