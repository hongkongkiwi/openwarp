use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use hmac::Mac;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Server { child: Child, base: String, dir: std::path::PathBuf, client: Client, mail: Arc<Mutex<Vec<Value>>>, stop: Arc<AtomicBool>, relay: Option<std::thread::JoinHandle<()>> }
impl Drop for Server { fn drop(&mut self) {
    let _ = self.child.kill(); let _ = self.child.wait(); self.stop.store(true,Ordering::SeqCst);
    if std::thread::panicking() {
        let stderr = std::fs::read_to_string(self.dir.join("server.stderr")).unwrap_or_default();
        eprintln!("dummy mail fixture: captured={}, relay_finished={}, delivery_error={}, stderr_bytes={}, private_stderr={}", self.mail.lock().map(|m|m.len()).unwrap_or_default(), self.relay.as_ref().is_some_and(|t|t.is_finished()), stderr.contains("email delivery failed:"), stderr.len(), self.dir.join("server.stderr").display());
    }
    self.relay.take().unwrap().join().unwrap(); if !std::thread::panicking() { let _ = std::fs::remove_dir_all(&self.dir); }
} }
impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap(); drop(listener);
        let relay = TcpListener::bind("127.0.0.1:0").unwrap(); let mail_addr = relay.local_addr().unwrap(); relay.set_nonblocking(true).unwrap();
        let mail = Arc::new(Mutex::new(Vec::new())); let sink = mail.clone(); let stop = Arc::new(AtomicBool::new(false)); let done = stop.clone();
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream,_) = match relay.accept() { Ok(v)=>v, Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{ std::thread::sleep(Duration::from_millis(5)); continue; }, Err(e)=>panic!("mail accept: {e}") };
                // Darwin inherits the listener's nonblocking mode on accepted sockets.
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap(); let mut bytes=Vec::new(); let mut buf=[0;8192];
                loop {
                    let n=match stream.read(&mut buf) { Ok(n)=>n, Err(e) if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut)=>break, Err(e)=>panic!("mail read: {e}") };
                    if n==0 { break; } bytes.extend_from_slice(&buf[..n]);
                    if let Some(end)=bytes.windows(4).position(|w|w==b"\r\n\r\n") {
                        let head=String::from_utf8_lossy(&bytes[..end]); let len=head.lines().find_map(|l|{let(k,v)=l.split_once(':')?; if k.eq_ignore_ascii_case("content-length"){v.trim().parse::<usize>().ok()}else{None}}).unwrap_or(0);
                        if bytes.len()>=end+4+len { break; }
                    }
                }
                if bytes.is_empty() { continue; }
                let end=bytes.windows(4).position(|w|w==b"\r\n\r\n").expect("mail headers")+4;
                sink.lock().unwrap().push(serde_json::from_slice(&bytes[end..]).expect("mail JSON"));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
            }
        });
        let base=format!("http://{addr}"); let dir=std::env::temp_dir().join(format!("openwarp-hardening-{}-{}",std::process::id(),addr.port())); std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap(); }
        let mut stderr_options=std::fs::OpenOptions::new(); stderr_options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; stderr_options.mode(0o600); }
        let stderr=stderr_options.open(dir.join("server.stderr")).unwrap();
        let child=Command::new(env!("CARGO_BIN_EXE_openwarp-server")).env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string())
            .env("OPENWARP_PUBLIC_URL",&base).env("OPENWARP_EMAIL_WEBHOOK",format!("http://{mail_addr}/mail")).env("TOKIO_WORKER_THREADS","1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL").env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS").env_remove("OPENWARP_TRUST_PROXY")
            .stdout(Stdio::null()).stderr(Stdio::from(stderr)).spawn().unwrap();
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s=Self{child,base,dir,client,mail,stop,relay:Some(thread)}; let deadline=Instant::now()+Duration::from_secs(20);
        loop { if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await { if r.status().is_success(){break;} } assert!(Instant::now()<deadline,"server health"); tokio::time::sleep(Duration::from_millis(50)).await; } s
    }
    async fn request(&self, method: Method, path: &str, token: &str, cookie: bool, body: Option<Value>) -> (u16,Value) {
        let mut r=self.client.request(method,format!("{}{}",self.base,path));
        if !token.is_empty() { r=if cookie {r.header("Cookie",format!("ow_session={token}"))}else{r.bearer_auth(token)}; }
        if let Some(body)=body {r=r.json(&body);}
        let r=r.send().await.unwrap(); let status=r.status().as_u16(); let text=r.text().await.unwrap(); (status,serde_json::from_str(&text).unwrap_or(json!({"raw":text})))
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> (u16,Value) { self.request(method,path,token,false,body).await }
    async fn login(&self,email:&str)->Value { good(self.call(Method::POST,"/api/auth/login","",Some(json!({"email":email,"password":"correct-horse-battery"}))).await) }
    async fn register(&self,email:&str)->Value {
        let mut u=good(self.call(Method::POST,"/api/auth/register","",Some(json!({"email":email,"password":"correct-horse-battery"}))).await);
        let deadline=Instant::now()+Duration::from_secs(8);
        let path=loop {
            let link=self.mail.lock().unwrap().iter().rev().find_map(|m|{if !m.to_string().contains(email){return None;} m["text"].as_str()?.split_whitespace().find_map(|w|w.find("/api/auth/verify?token=").map(|i|w[i..].to_string()))});
            if let Some(path)=link{break path;} assert!(Instant::now()<deadline,"verification mail"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        good(self.call(Method::GET,&path,"",None).await); let login=self.login(email).await; u["token"]=login["token"].clone(); u["user_id"]=login["user_id"].clone(); u
    }
    async fn app(&self,t:&str,org:&str)->(String,String) {
        let a=good(self.call(Method::POST,&format!("/api/orgs/{org}/apps"),t,Some(json!({"name":"hardening"}))).await); let aid=id(&a);
        let envs=good(self.call(Method::GET,&format!("/api/apps/{aid}/envs"),t,None).await); (aid,id(&envs[0]))
    }
    async fn oauth(&self,t:&str,scope:&str,audience:&str)->String {
        let redirect="http://127.0.0.1:8917/callback";
        let reg=good(self.call(Method::POST,"/oauth/register","",Some(json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope}))).await);
        let cid=reg["client_id"].as_str().unwrap(); let verifier="hardening-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"; let challenge=Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes())); let resource=format!("{}{audience}",self.base);
        let r=self.client.post(format!("{}/oauth/authorize/decision",self.base)).bearer_auth(t).form(&[("response_type","code"),("client_id",cid),("redirect_uri",redirect),("scope",scope),("state","hardening"),("code_challenge",challenge.as_str()),("code_challenge_method","S256"),("resource",resource.as_str()),("approve","1")]).send().await.unwrap();
        let url=reqwest::Url::parse(r.headers().get("location").unwrap().to_str().unwrap()).unwrap(); let code=url.query_pairs().find(|(k,_)|k=="code").unwrap().1.into_owned();
        let token:Value=self.client.post(format!("{}/oauth/token",self.base)).form(&[("grant_type","authorization_code"),("code",code.as_str()),("client_id",cid),("redirect_uri",redirect),("code_verifier",verifier)]).send().await.unwrap().json().await.unwrap(); token["access_token"].as_str().unwrap().into()
    }
    async fn incoming(&self,t:&str,eid:&str,kind:&str)->(u16,Value) {
        let integration=good(self.call(Method::POST,&format!("/api/envs/{eid}/integrations"),t,Some(json!({"kind":kind,"name":"hardening","config":{"url":"https://example.invalid/never","host":"127.0.0.1","port":9,"username":"nobody","private_key":"dummy-no-execution","auto_sync":false}}))).await);
        self.call(Method::POST,&format!("/api/integrations/{}/webhooks",id(&integration)),t,Some(json!({"name":"hardening"}))).await
    }
    async fn signed(&self,hid:&str,key:&str,mid:&str)->u16 {
        let ts=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string(); let raw=Base64::decode_vec(key.strip_prefix("whsec_").unwrap()).unwrap(); let mut mac=hmac::Hmac::<Sha256>::new_from_slice(&raw).unwrap(); mac.update(format!("{mid}.{ts}.{{}}").as_bytes());
        self.client.post(format!("{}/hooks/integrations/{hid}",self.base)).header("webhook-id",mid).header("webhook-timestamp",ts).header("webhook-signature",format!("v1,{}",Base64::encode_string(&mac.finalize().into_bytes()))).body("{}").send().await.unwrap().status().as_u16()
    }
}
fn good(r:(u16,Value))->Value { assert!((200..300).contains(&r.0),"HTTP {}: {}",r.0,r.1); r.1 }
fn id(v:&Value)->String {v["id"].as_str().unwrap().into()}
fn encoded(s:&str)->String { s.bytes().map(|b|format!("%{b:02X}")).collect() }
fn deny(r:&(u16,Value)) {assert!(matches!(r.0,401|403|404),"unauthorized request succeeded: {} {}",r.0,r.1);}
fn outgoing()->Value {json!({"url":"https://example.invalid/never","events":["never.match"]})}

#[tokio::test]
async fn oauth_cookie_never_gains_workspace_admin_or_rest_audience() {
    let s=Server::start().await; let u=s.register("cookie-oauth@test.invalid").await; let t=u["token"].as_str().unwrap(); let org=u["org_id"].as_str().unwrap();
    let list=format!("/api/orgs/{org}/webhooks"); let sub=good(s.request(Method::POST,&list,t,true,Some(outgoing())).await);
    let rest_read=s.oauth(t,"secrets:read","").await; let mcp_admin=s.oauth(t,"secrets:read secrets:write org:admin","/mcp").await;
    let mut failures=Vec::new();
    for (label,token) in [("read-only REST",rest_read),("MCP audience",mcp_admin)] {
        for path in [list.clone(),format!("/api/webhooks/{}/rotate",id(&sub))] {
            let body=if path==list{outgoing()}else{json!({})};
            let r=s.request(Method::POST,&path,&token,true,Some(body)).await;
            if !matches!(r.0,401|403|404) {failures.push(format!("{label} {path}: {}",r.0));}
        }
    }
    assert!(failures.is_empty(),"cookie bypass: {failures:?}");
}

#[tokio::test]
async fn readonly_api_oauth_lists_existing_org_apps_without_webhook_admin_scope() {
    let s=Server::start().await; let u=s.register("readonly-apps@test.invalid").await; let t=u["token"].as_str().unwrap(); let org=u["org_id"].as_str().unwrap();
    let (aid,_)=s.app(t,org).await; let token=s.oauth(t,"secrets:read","").await;
    let apps=good(s.call(Method::GET,&format!("/api/orgs/{org}/apps"),&token,None).await);
    assert!(apps.as_array().unwrap().iter().any(|v|v["id"]==aid));
    let hooks=s.call(Method::GET,&format!("/api/orgs/{org}/webhooks"),&token,None).await;
    assert_eq!(hooks.0,403,"read-only app discovery must not grant webhook administration");
}

#[tokio::test]
async fn environment_pat_cookie_cannot_administer_workspace_but_session_cookie_can() {
    let s=Server::start().await; let u=s.register("cookie-pat@test.invalid").await; let t=u["token"].as_str().unwrap(); let org=u["org_id"].as_str().unwrap(); let (aid,eid)=s.app(t,org).await;
    let pat=good(s.call(Method::POST,&format!("/api/apps/{aid}/tokens"),t,Some(json!({"name":"scoped","env_id":eid}))).await);
    let list=format!("/api/orgs/{org}/webhooks"); let sub=good(s.request(Method::POST,&list,t,true,Some(outgoing())).await);
    let mut failures=Vec::new();
    for path in [list.clone(),format!("/api/webhooks/{}/rotate",id(&sub))] {
        let r=s.request(Method::POST,&path,pat["token"].as_str().unwrap(),true,Some(if path==list{outgoing()}else{json!({})})).await;
        if !matches!(r.0,401|403|404){failures.push(format!("{path}: {}",r.0));}
    }
    assert!(failures.is_empty(),"scoped PAT cookie bypass: {failures:?}");
    good(s.request(Method::GET,&list,t,true,None).await);
}

#[tokio::test]
async fn encoded_workspace_path_cannot_escape_ip_allowlist_or_missing_org_denial() {
    let s=Server::start().await; let u=s.register("encoded-ip@test.invalid").await; let t=u["token"].as_str().unwrap(); let org=u["org_id"].as_str().unwrap();
    good(s.call(Method::PUT,&format!("/api/orgs/{org}/settings"),t,Some(json!({"ip_allowlist":"192.0.2.0/24"}))).await);
    let raw=s.call(Method::GET,&format!("/api/orgs/{org}/apps"),t,None).await; assert_eq!(raw.0,403);
    let encoded=s.call(Method::GET,&format!("/api/orgs/{}/apps",encoded(org)),t,None).await;
    assert_eq!(encoded.0,400,"encoded org bypassed policy: {}",encoded.1);
    deny(&s.call(Method::GET,"/api/orgs/does-not-exist/apps",t,None).await);
}

#[tokio::test]
async fn encoded_environment_does_not_bypass_pat_scope() {
    let s=Server::start().await; let u=s.register("encoded-env@test.invalid").await; let t=u["token"].as_str().unwrap(); let (aid,eid)=s.app(t,u["org_id"].as_str().unwrap()).await;
    let envs=good(s.call(Method::GET,&format!("/api/apps/{aid}/envs"),t,None).await); let other=envs.as_array().unwrap().iter().find(|v|v["id"]!=eid).unwrap()["id"].as_str().unwrap();
    let pat=good(s.call(Method::POST,&format!("/api/apps/{aid}/tokens"),t,Some(json!({"name":"scope","env_id":eid}))).await); let pt=pat["token"].as_str().unwrap();
    // Percent-encoded API paths are rejected outright now; the bypass is
    // impossible because routing never sees a decoded spelling.
    assert_eq!(s.call(Method::GET,&format!("/api/envs/{}/integrations",encoded(&eid)),pt,None).await.0,400);
    deny(&s.call(Method::GET,&format!("/api/envs/{other}/integrations"),pt,None).await);
    assert_eq!(s.call(Method::GET,&format!("/api/envs/{}/integrations",encoded(other)),pt,None).await.0,400);
}

#[tokio::test]
async fn explicit_reauthorization_rebinds_credential_without_rotating_url_or_key() {
    let s=Server::start().await; let u=s.register("reauthorize@test.invalid").await; let old=u["token"].as_str().unwrap(); let (_,eid)=s.app(old,u["org_id"].as_str().unwrap()).await;
    let hook=good(s.incoming(old,&eid,"webhook").await); let hid=id(&hook); let key=hook["secret"].as_str().unwrap(); let path=format!("/api/incoming-webhooks/{hid}/reauthorize");
    assert_eq!(s.signed(&hid,key,"before_reauth").await,202);
    let login=s.login("reauthorize@test.invalid").await; let fresh=login["token"].as_str().unwrap();
    let r=good(s.call(Method::POST,&path,fresh,Some(json!({}))).await); assert!(r.get("secret").is_none(),"reauthorization must not rotate or disclose key");
    good(s.call(Method::POST,"/api/auth/logout",old,None).await);
    assert_eq!(s.signed(&hid,key,"after_old_logout").await,202,"hook must use explicitly renewed credential");
    let iid=hook["integration_id"].as_str().unwrap(); let list=good(s.call(Method::GET,&format!("/api/integrations/{iid}/webhooks"),fresh,None).await);
    let row=list.as_array().unwrap().iter().find(|v|v["id"]==hid).unwrap(); assert_eq!(row["url"],hook["url"]);
}

#[tokio::test]
async fn reauthorization_denies_foreign_and_readonly_users_and_rotation_does_not_renew() {
    let s=Server::start().await; let u=s.register("reauth-owner@test.invalid").await; let old=u["token"].as_str().unwrap(); let org=u["org_id"].as_str().unwrap(); let (_,eid)=s.app(old,org).await;
    let hook=good(s.incoming(old,&eid,"webhook").await); let hid=id(&hook);
    let reader=s.register("reauth-reader@test.invalid").await; let foreign=s.register("reauth-foreign@test.invalid").await;
    good(s.call(Method::POST,&format!("/api/orgs/{org}/roles"),old,Some(json!({"name":"hook-readonly","permissions":["secrets:read"]}))).await);
    good(s.call(Method::POST,&format!("/api/orgs/{org}/members"),old,Some(json!({"email":"reauth-reader@test.invalid","role":"hook-readonly"}))).await);
    for user in [&reader,&foreign] { let r=s.call(Method::POST,&format!("/api/incoming-webhooks/{hid}/reauthorize"),user["token"].as_str().unwrap(),Some(json!({}))).await; assert_eq!(r.0,403,"reauthorization must enforce current integration permission: {}",r.1); }
    let login=s.login("reauth-owner@test.invalid").await; let fresh=login["token"].as_str().unwrap();
    let rotated=good(s.call(Method::POST,&format!("/api/incoming-webhooks/{hid}/rotate"),fresh,Some(json!({}))).await);
    good(s.call(Method::POST,"/api/auth/logout",old,None).await);
    assert_eq!(s.signed(&hid,rotated["secret"].as_str().unwrap(),"rotate_not_renew").await,403,"rotation silently renewed creator authority");
}

#[tokio::test]
async fn file_ssh_rejects_incoming_trigger_but_cloud_ssh_key_api_remains_available() {
    let s=Server::start().await; let u=s.register("ssh-hook@test.invalid").await; let t=u["token"].as_str().unwrap(); let (_,eid)=s.app(t,u["org_id"].as_str().unwrap()).await;
    let file=s.incoming(t,&eid,"ssh").await; assert_eq!(file.0,409,"unsafe incoming SSH file trigger accepted: {}",file.1);
    let cloud=s.incoming(t,&eid,"digitalocean_ssh").await; assert_eq!(cloud.0,200,"async cloud SSH-key API must remain available: {}",cloud.1);
}
