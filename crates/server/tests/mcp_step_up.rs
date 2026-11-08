use base64ct::{Base64UrlUnpadded, Encoding};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

struct Server { child: Child, base: String, dir: std::path::PathBuf, client: Client, mail: Arc<Mutex<Vec<Value>>>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Drop for Server { fn drop(&mut self) { let _=self.child.kill(); let _=self.child.wait(); self.stop.store(true,Ordering::SeqCst); self.thread.take().unwrap().join().unwrap(); let _=std::fs::remove_dir_all(&self.dir); } }
impl Server {
    async fn start() -> Self {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap(); drop(listener);
        let relay=TcpListener::bind("127.0.0.1:0").unwrap(); let mail_addr=relay.local_addr().unwrap(); relay.set_nonblocking(true).unwrap();
        let mail=Arc::new(Mutex::new(Vec::new())); let sink=mail.clone(); let stop=Arc::new(AtomicBool::new(false)); let done=stop.clone();
        let thread=std::thread::spawn(move || { while !done.load(Ordering::SeqCst) {
            let (mut stream,_)=match relay.accept() {Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;},Err(e)=>panic!("mail accept: {e}")};
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap(); let mut bytes=Vec::new(); let mut buf=[0;8192];
            loop {
                let n=match stream.read(&mut buf){Ok(n)=>n,Err(e) if matches!(e.kind(),std::io::ErrorKind::TimedOut|std::io::ErrorKind::WouldBlock)=>break,Err(e)=>panic!("mail read: {e}")};
                if n==0 {break;} bytes.extend_from_slice(&buf[..n]);
                if let Some(end)=bytes.windows(4).position(|w|w==b"\r\n\r\n") {
                    let head=String::from_utf8_lossy(&bytes[..end]); let len=head.lines().find_map(|l|{let(k,v)=l.split_once(':')?;if k.eq_ignore_ascii_case("content-length"){v.trim().parse::<usize>().ok()}else{None}}).unwrap_or(0);
                    if bytes.len()>=end+4+len {break;}
                }
            }
            if bytes.is_empty(){continue;} let end=bytes.windows(4).position(|w|w==b"\r\n\r\n").expect("mail headers")+4;
            sink.lock().unwrap().push(serde_json::from_slice(&bytes[end..]).expect("mail JSON"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
        }});
        let base=format!("http://{addr}"); let dir=std::env::temp_dir().join(format!("openwarp-mcp-step-up-{}-{}",std::process::id(),addr.port())); std::fs::create_dir_all(&dir).unwrap();
        let child=Command::new(env!("CARGO_BIN_EXE_openwarp-server")).env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string()).env("OPENWARP_PUBLIC_URL",&base)
            .env("OPENWARP_EMAIL_WEBHOOK",format!("http://{mail_addr}/mail")).env("TOKIO_WORKER_THREADS","1").env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS").env_remove("OPENWARP_TRUST_PROXY").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s=Self{child,base,dir,client,mail,stop,thread:Some(thread)}; let deadline=Instant::now()+Duration::from_secs(20);
        loop {if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await {if r.status().is_success(){break;}} assert!(Instant::now()<deadline,"server health");tokio::time::sleep(Duration::from_millis(50)).await;} s
    }
    async fn call(&self,method:Method,path:&str,token:&str,body:Option<Value>)->(u16,Value) {
        let mut r=self.client.request(method,format!("{}{}",self.base,path)); if !token.is_empty(){r=r.bearer_auth(token);}
        if let Some(body)=body {r=r.json(&body);} let r=r.send().await.unwrap(); let status=r.status().as_u16();let text=r.text().await.unwrap();(status,serde_json::from_str(&text).unwrap_or(json!({"raw":text})))
    }
    async fn register(&self)->String {
        good(self.call(Method::POST,"/api/auth/register","",Some(json!({"email":"step-up@test.invalid","password":"correct-horse-battery"}))).await);
        let deadline=Instant::now()+Duration::from_secs(8);
        let path=loop {let path=self.mail.lock().unwrap().iter().find_map(|m|m["text"].as_str()?.split_whitespace().find_map(|w|w.find("/api/auth/verify?token=").map(|i|w[i..].to_string()))); if let Some(path)=path{break path;} assert!(Instant::now()<deadline,"verification email");tokio::time::sleep(Duration::from_millis(25)).await;};
        good(self.call(Method::GET,&path,"",None).await);
        good(self.call(Method::POST,"/api/auth/login","",Some(json!({"email":"step-up@test.invalid","password":"correct-horse-battery"}))).await)["token"].as_str().unwrap().into()
    }
    async fn oauth(&self,t:&str)->String {
        let redirect="http://127.0.0.1:8917/callback";let scope="secrets:read";
        let reg=good(self.call(Method::POST,"/oauth/register","",Some(json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope}))).await);
        let cid=reg["client_id"].as_str().unwrap();let verifier="stepup-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";let challenge=Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));let resource=format!("{}/mcp",self.base);
        let r=self.client.post(format!("{}/oauth/authorize/decision",self.base)).bearer_auth(t).form(&[("response_type","code"),("client_id",cid),("redirect_uri",redirect),("scope",scope),("state","stepup"),("code_challenge",challenge.as_str()),("code_challenge_method","S256"),("resource",resource.as_str()),("approve","1")]).send().await.unwrap();
        let url=reqwest::Url::parse(r.headers().get("location").unwrap().to_str().unwrap()).unwrap();let code=url.query_pairs().find(|(k,_)|k=="code").unwrap().1.into_owned();
        let token:Value=self.client.post(format!("{}/oauth/token",self.base)).form(&[("grant_type","authorization_code"),("code",code.as_str()),("client_id",cid),("redirect_uri",redirect),("code_verifier",verifier)]).send().await.unwrap().json().await.unwrap();token["access_token"].as_str().unwrap().into()
    }
    async fn rpc(&self,t:&str,args:Value)->Value {good(self.call(Method::POST,"/mcp",t,Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_request","arguments":args}}))).await)}
}
fn good(r:(u16,Value))->Value {assert!((200..300).contains(&r.0),"HTTP {}: {}",r.0,r.1);r.1}
fn envelope(rpc:&Value)->&Value {assert!(rpc.get("error").is_none(),"route must dispatch through API authorization, not fail at MCP path validation: {rpc}");let v=&rpc["result"]["structuredContent"];assert!(v["status"].is_u64(),"missing HTTP envelope: {rpc}");v}
fn rejected(rpc:&Value) {assert!(rpc.get("error").is_some()||rpc["result"]["isError"]==true,"invalid request accepted: {rpc}");}

#[tokio::test]
async fn mcp_can_start_step_up_without_broadening_auth_routes_or_accepting_header_injection() {
    let s=Server::start().await;let token=s.register().await;
    for args in [json!({"method":"POST","path":"/api/auth/login","body":{}}),json!({"method":"POST","path":"/mcp","body":{}}),
        json!({"method":"GET","path":"/api/me","headers":{"Authorization":"Bearer forged"}}),json!({"method":"GET","path":"/api/me","unknown":true}),
        json!({"method":"GET","path":"/api/me","step_up":"grant\r\nAuthorization: forged"}),json!({"method":"GET","path":"/api/me","step_up":"grant\u{0000}"})] {
        rejected(&s.rpc(&token,args).await);
    }
    let rpc=s.rpc(&token,json!({"method":"POST","path":"/api/auth/step-up/start","body":{"risk":"two_factor"}})).await;
    let result=envelope(&rpc);assert_eq!(result["status"],200);assert_eq!(result["body"]["not_required"],true);assert_ne!(rpc["result"]["isError"],true);
    let invalid=s.rpc(&token,json!({"method":"POST","path":"/api/auth/step-up/verify","body":{"challenge":"not-a-real-challenge"}})).await;
    assert_eq!(envelope(&invalid)["status"],400,"verify must dispatch without manufacturing a grant");
}

#[tokio::test]
async fn mcp_step_up_preserves_readonly_oauth_and_accepts_only_safe_optional_grant() {
    let s=Server::start().await;let session=s.register().await;let readonly=s.oauth(&session).await;
    let rpc=s.rpc(&readonly,json!({"method":"POST","path":"/api/auth/step-up/start","body":{"risk":"two_factor"}})).await;
    assert_eq!(envelope(&rpc)["status"],403,"step-up transport must not grant OAuth write scope");assert_eq!(rpc["result"]["isError"],true);
    let safe=s.rpc(&session,json!({"method":"GET","path":"/api/me","step_up":"stepupg_safe-nonexistent-grant"})).await;
    assert_eq!(envelope(&safe)["status"],200,"safe optional grant must be accepted without overriding caller authentication");
    let direct=good(s.call(Method::GET,"/api/me",&session,None).await);assert_eq!(envelope(&safe)["body"],direct);
}
