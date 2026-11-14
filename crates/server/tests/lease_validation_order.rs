use hmac::Mac;
use openwarp_crypto as oc;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU32, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);
const AUTH_KEY: [u8; 32] = [37; 32];
struct Reply { status: u16, body: Value }
impl Reply { fn ok(self)->Value { assert_eq!(self.status,200,"fixture/action must succeed, HTTP {}",self.status); self.body } }
struct Account { token: String, env: String }
struct Server { child: Child, base: String, dir: std::path::PathBuf, client: Client, mail: Arc<Mutex<Vec<Value>>>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Drop for Server {
    fn drop(&mut self) { let _=self.child.kill(); let _=self.child.wait(); self.stop.store(true,Ordering::SeqCst); if let Some(thread)=self.thread.take() { thread.join().unwrap(); } let _=std::fs::remove_dir_all(&self.dir); }
}
impl Server {
    async fn start()->Self {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap(); drop(listener);
        let relay=TcpListener::bind("127.0.0.1:0").unwrap(); let mail_addr=relay.local_addr().unwrap(); relay.set_nonblocking(true).unwrap();
        let mail=Arc::new(Mutex::new(Vec::new())); let sink=mail.clone(); let stop=Arc::new(AtomicBool::new(false)); let done=stop.clone();
        let thread=std::thread::spawn(move || { while !done.load(Ordering::SeqCst) {
            let (mut stream,_)=match relay.accept() { Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;},Err(e)=>panic!("mail accept: {e}") };
            stream.set_nonblocking(false).unwrap(); stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap(); let mut bytes=Vec::new(); let mut buf=[0;8192];
            loop { let n=stream.read(&mut buf).expect("mail read"); if n==0 {break;} bytes.extend_from_slice(&buf[..n]);
                if let Some(end)=bytes.windows(4).position(|w|w==b"\r\n\r\n") {
                    let head=String::from_utf8_lossy(&bytes[..end]); let len=head.lines().find_map(|l|{let(k,v)=l.split_once(':')?;if k.eq_ignore_ascii_case("content-length"){v.trim().parse::<usize>().ok()}else{None}}).unwrap_or(0);
                    if bytes.len()>=end+4+len {break;}
                }
            }
            let end=bytes.windows(4).position(|w|w==b"\r\n\r\n").expect("mail headers")+4;
            sink.lock().unwrap().push(serde_json::from_slice(&bytes[end..]).expect("mail JSON"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
        }});
        let base=format!("http://{addr}"); let dir=std::env::temp_dir().join(format!("openwarp-lease-validation-order-{}-{}",std::process::id(),SEQ.fetch_add(1,Ordering::SeqCst))); std::fs::create_dir(&dir).unwrap();
        let child=Command::new(env!("CARGO_BIN_EXE_openwarp-server")).env_clear()
            .env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string()).env("OPENWARP_PUBLIC_URL",&base)
            .env("OPENWARP_EMAIL_PROVIDER","webhook").env("OPENWARP_EMAIL_WEBHOOK",format!("http://{mail_addr}/mail"))
            .env("OPENWARP_AUTH_PROVIDERS","password").env("OPENWARP_ENV","test").env("TOKIO_WORKER_THREADS","1")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let mut s=Self{child,base,dir,client,mail,stop,thread:Some(thread)}; let deadline=Instant::now()+Duration::from_secs(20);
        loop { assert!(s.child.try_wait().unwrap().is_none(),"server exited before health"); if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await {if r.status().is_success(){break;}} assert!(Instant::now()<deadline,"server health timeout");tokio::time::sleep(Duration::from_millis(50)).await; } s
    }
    async fn call(&self,method:Method,path:&str,token:Option<&str>,body:Option<Value>,grant:Option<&str>)->Reply {
        let mut r=self.client.request(method,format!("{}{}",self.base,path));
        if let Some(t)=token {r=r.bearer_auth(t);}
        if let Some(b)=body {r=r.json(&b);}
        if let Some(g)=grant {r=r.header("x-openwarp-step-up",g);}
        let r=r.send().await.unwrap(); let status=r.status().as_u16(); let text=r.text().await.unwrap(); Reply{status,body:serde_json::from_str(&text).unwrap_or(Value::Null)}
    }
    async fn mail_after(&self,before:usize)->String {
        let deadline=Instant::now()+Duration::from_secs(8);
        loop {if let Some(text)=self.mail.lock().unwrap().get(before).and_then(|m|m["text"].as_str()).map(str::to_string){return text;} assert!(Instant::now()<deadline,"local verification email timeout");tokio::time::sleep(Duration::from_millis(25)).await;}
    }
    async fn account(&self)->Account {
        let email="owner@test.invalid"; let before=self.mail.lock().unwrap().len(); let kp=oc::Keypair::generate();
        self.call(Method::POST,"/api/auth/register-v2",None,Some(json!({"email":email,"salt":oc::b64(&[11;16]),"iterations":600000,"algo":"pbkdf2-sha256","auth_key":oc::b64(&AUTH_KEY),"public_key":kp.public,"wrapped_privkey":format!("owv2:{}",oc::b64(&[19;40]))})),None).await.ok();
        let text=self.mail_after(before).await;
        let path=text.split_whitespace().find_map(|w|w.find("/api/auth/verify?token=").map(|i|w[i..].to_string())).expect("verification link");
        self.call(Method::GET,&path,None,None,None).await.ok();
        let ch=self.call(Method::POST,"/api/auth/challenge",None,Some(json!({"email":email})),None).await.ok(); let cid=field(&ch,"challenge_id");
        let mut mac=hmac::Hmac::<sha2::Sha256>::new_from_slice(&AUTH_KEY).unwrap(); mac.update(format!("{}|{}",field(&ch,"challenge"),cid).as_bytes());
        let proof:String=mac.finalize().into_bytes().iter().map(|b|format!("{b:02x}")).collect();
        let login=self.call(Method::POST,"/api/auth/login-v2",None,Some(json!({"email":email,"challenge_id":cid,"proof":proof})),None).await.ok();
        let token=field(&login,"token"); let auth=Some(token.as_str());
        let orgs=self.call(Method::GET,"/api/orgs",auth,None,None).await.ok(); let org=field(&orgs[0],"id");
        let app=field(&self.call(Method::POST,&format!("/api/orgs/{org}/apps"),auth,Some(json!({"name":"lease-validation-order"})),None).await.ok(),"id");
        let envs=self.call(Method::GET,&format!("/api/apps/{app}/envs"),auth,None,None).await.ok(); let env=field(&envs[0],"id"); Account{token,env}
    }
    async fn enable_totp(&self,a:&Account)->Vec<String> {
        let auth=Some(a.token.as_str());
        let setup=self.call(Method::POST,"/api/me/totp/setup",auth,Some(json!({})),None).await.ok();
        let recovery=setup["recovery_codes"].as_array().expect("setup recovery codes").iter().map(|code|code.as_str().expect("recovery code").to_string()).collect();
        let confirmed=self.call(Method::POST,"/api/me/totp/verify",auth,Some(json!({"code":totp(&field(&setup,"secret"))})),None).await.ok(); assert_eq!(confirmed["enabled"],true); recovery
    }
    async fn grant(&self,a:&Account,recovery:&str)->String {
        let auth=Some(a.token.as_str());
        let start=self.call(Method::POST,"/api/auth/step-up/start",auth,Some(json!({"risk":"two_factor"})),None).await.ok();
        assert_eq!(start["methods"],json!(["totp"]));
        // Recovery proof avoids replaying the TOTP counter used to enable MFA.
        let verified=self.call(Method::POST,"/api/auth/step-up/verify",auth,Some(json!({"challenge":field(&start,"challenge"),"totp":recovery})),None).await.ok();
        assert_eq!(verified["expires_in"],300); field(&verified,"token")
    }
}
fn field(v:&Value,key:&str)->String { v[key].as_str().expect(key).to_string() }
fn challenged(r:&Reply) { assert_eq!(r.status,428,"unproven issuance must require step-up"); assert_eq!(r.body["step_up_required"],true); assert_eq!(r.body["risk"],"two_factor"); assert_eq!(r.body["totp_required"],true); }
fn totp(secret:&str)->String {
    let(mut key,mut value,mut bits)=(Vec::new(),0u32,0u32);
    for c in secret.chars(){value=(value<<5)|"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;bits+=5;if bits>=8{key.push(((value>>(bits-8))&255) as u8);bits-=8;}}
    let counter=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()/30; let mut mac=hmac::Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();mac.update(&counter.to_be_bytes());let hash=mac.finalize().into_bytes();let off=(hash[19]&15) as usize;
    format!("{:06}",u32::from_be_bytes(hash[off..off+4].try_into().unwrap())%0x8000_0000%1_000_000)
}

async fn local_rejection_preserves_lease_list_and_proof(invalid_body:Value) {
    let s=Server::start().await; let a=s.account().await; let recovery=s.enable_totp(&a).await; let auth=Some(a.token.as_str()); let path=format!("/api/envs/{}/dynamic",a.env);
    let before=s.call(Method::GET,&path,auth,None,None).await.ok(); let before_count=before.as_array().expect("lease list").len(); assert_eq!(before_count,0);
    let valid_body=json!({"name":"valid-after-local-rejection","type":"generic"});
    challenged(&s.call(Method::POST,&path,auth,Some(valid_body.clone()),None).await);
    let unproven=s.call(Method::GET,&path,auth,None,None).await.ok(); assert_eq!(unproven.as_array().expect("lease list").len(),before_count,"unproven issuance must not reserve a lease");
    let grant=s.grant(&a,&recovery[0]).await;
    let invalid=s.call(Method::POST,&path,auth,Some(invalid_body),Some(&grant)).await;
    assert_eq!(invalid.status,400,"invalid provider config must be rejected locally");
    let after=s.call(Method::GET,&path,auth,None,None).await.ok(); let after_count=after.as_array().expect("lease list").len();
    let valid=s.call(Method::POST,&path,auth,Some(valid_body.clone()),Some(&grant)).await;
    let replay=s.call(Method::POST,&path,auth,Some(valid_body),Some(&grant)).await;
    challenged(&replay);
    assert_eq!((after_count,valid.status),(before_count,200),"local validation must not reserve a lease or consume proof: listed leases {}, same-grant generic issuance HTTP {}",after_count,valid.status);
    let listed=s.call(Method::GET,&path,auth,None,None).await.ok(); let rows=listed.as_array().expect("lease list");
    assert_eq!(rows.len(),before_count+1,"only the successful issuance persists; replay adds no lease");
    assert_eq!(rows[0]["id"],field(&valid.body,"id"));
    let value=field(&valid.body,"value"); assert!(!value.is_empty(),"generic issuance returns a credential");
    assert!(rows[0]["value"].as_str()==Some(value.as_str()),"lease listing returns the issued generic value");
}

#[tokio::test]
async fn empty_openrouter_config_does_not_reserve_a_lease_or_consume_proof() {
    local_rejection_preserves_lease_list_and_proof(json!({"type":"openrouter","config":{}})).await;
}

#[tokio::test]
async fn empty_planetscale_config_does_not_reserve_a_lease_or_consume_proof() {
    local_rejection_preserves_lease_list_and_proof(json!({"type":"planetscale","config":{}})).await;
}

#[tokio::test]
async fn empty_instabox_config_does_not_reserve_a_lease_or_consume_proof() {
    local_rejection_preserves_lease_list_and_proof(json!({"type":"instabox","config":{}})).await;
}

#[tokio::test]
async fn malformed_aws_sts_endpoint_does_not_reserve_a_lease_or_consume_proof() {
    local_rejection_preserves_lease_list_and_proof(json!({"type":"aws_iam","config":{
        "region":"us-east-1","access_key_id":"dummy-access-key","secret_access_key":"dummy-secret-key",
        "role_arn":"arn:aws:iam::123456789012:role/test","sts_endpoint":"not a URL"
    }})).await;
}

#[tokio::test]
async fn aws_sts_endpoint_credentials_do_not_reserve_a_lease_or_consume_proof() {
    local_rejection_preserves_lease_list_and_proof(json!({"type":"aws_iam","config":{
        "region":"us-east-1","access_key_id":"dummy-access-key","secret_access_key":"dummy-secret-key",
        "role_arn":"arn:aws:iam::123456789012:role/test","sts_endpoint":"https://user:password@sts.amazonaws.com/"
    }})).await;
}
