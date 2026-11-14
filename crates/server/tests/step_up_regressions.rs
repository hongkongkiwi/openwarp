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
struct Account { token: String, cookie: String, env: String }
#[derive(Clone, Copy)]
enum Auth<'a> { Bearer(&'a str), Cookie(&'a str) }
struct Challenge { id: String, email: String }
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
        let base=format!("http://{addr}"); let dir=std::env::temp_dir().join(format!("openwarp-step-up-regressions-{}-{}",std::process::id(),SEQ.fetch_add(1,Ordering::SeqCst))); std::fs::create_dir(&dir).unwrap();
        let child=Command::new(env!("CARGO_BIN_EXE_openwarp-server")).env_clear()
            .env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string()).env("OPENWARP_PUBLIC_URL",&base)
            .env("OPENWARP_EMAIL_PROVIDER","webhook").env("OPENWARP_EMAIL_WEBHOOK",format!("http://{mail_addr}/mail"))
            .env("OPENWARP_AUTH_PROVIDERS","password").env("OPENWARP_ENV","test").env("TOKIO_WORKER_THREADS","1")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let mut s=Self{child,base,dir,client,mail,stop,thread:Some(thread)}; let deadline=Instant::now()+Duration::from_secs(20);
        loop { assert!(s.child.try_wait().unwrap().is_none(),"server exited before health"); if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await {if r.status().is_success(){break;}} assert!(Instant::now()<deadline,"server health timeout");tokio::time::sleep(Duration::from_millis(50)).await; } s
    }
    async fn call(&self,method:Method,path:&str,auth:Option<Auth<'_>>,body:Option<Value>,grant:Option<&str>)->Reply {
        let mut r=self.client.request(method,format!("{}{}",self.base,path));
        if let Some(auth)=auth {r=match auth {Auth::Bearer(t)=>r.bearer_auth(t),Auth::Cookie(c)=>r.header("cookie",c).header("origin",&self.base)};}
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
        let r=self.client.post(format!("{}/api/auth/login-v2",self.base)).json(&json!({"email":email,"challenge_id":cid,"proof":proof})).send().await.unwrap(); assert_eq!(r.status(),200,"v2 login");
        let cookie=r.headers().get_all("set-cookie").iter().filter_map(|h|h.to_str().ok()).find_map(|h|h.split(';').next().filter(|c|c.starts_with("ow_session=")).map(str::to_string)).expect("login session cookie");
        let token=field(&r.json::<Value>().await.unwrap(),"token"); let auth=Some(Auth::Bearer(&token));
        let orgs=self.call(Method::GET,"/api/orgs",auth,None,None).await.ok(); let org=field(&orgs[0],"id");
        let app=field(&self.call(Method::POST,&format!("/api/orgs/{org}/apps"),auth,Some(json!({"name":"step-up-regression"})),None).await.ok(),"id");
        let envs=self.call(Method::GET,&format!("/api/apps/{app}/envs"),auth,None,None).await.ok(); let env=field(&envs[0],"id"); Account{token,cookie,env}
    }
    async fn setup_totp(&self,a:&Account)->(String,Vec<String>) {
        let setup=self.call(Method::POST,"/api/me/totp/setup",Some(Auth::Bearer(&a.token)),Some(json!({})),None).await.ok();
        let recovery=setup["recovery_codes"].as_array().expect("setup recovery codes").iter().map(|code|code.as_str().expect("recovery code").to_string()).collect(); (field(&setup,"secret"),recovery)
    }
    async fn confirm_totp(&self,a:&Account,secret:&str) {
        let confirmed=self.call(Method::POST,"/api/me/totp/verify",Some(Auth::Bearer(&a.token)),Some(json!({"code":totp(secret)})),None).await.ok(); assert_eq!(confirmed["enabled"],true);
    }
    async fn enable_totp(&self,a:&Account)->String { let (secret,_)=self.setup_totp(a).await; self.confirm_totp(a,&secret).await; secret }
    async fn start_email(&self,auth:Auth<'_>,with_totp:bool)->Challenge {
        let before=self.mail.lock().unwrap().len(); let start=self.call(Method::POST,"/api/auth/step-up/start",Some(auth),Some(json!({"risk":"very_risky"})),None).await.ok();
        assert_eq!(start["methods"],if with_totp {json!(["totp","email"])} else {json!(["email"])});
        let text=self.mail_after(before).await; let email=text.split(|c:char|!c.is_ascii_digit()).find(|v|v.len()==6).expect("emailed code").to_string(); Challenge{id:field(&start,"challenge"),email}
    }
    async fn verify_email(&self,auth:Auth<'_>,challenge:&Challenge,code:Option<String>)->Reply {
        let mut body=json!({"challenge":challenge.id,"email_code":challenge.email}); if let Some(code)=code {body["totp"]=json!(code);}
        self.call(Method::POST,"/api/auth/step-up/verify",Some(auth),Some(body),None).await
    }
    async fn email_grant(&self,auth:Auth<'_>,secret:Option<&str>)->String {
        let challenge=self.start_email(auth,secret.is_some()).await; let verified=self.verify_email(auth,&challenge,secret.map(totp)).await.ok(); assert_eq!(verified["expires_in"],300); field(&verified,"token")
    }
    async fn export(&self,a:&Account,auth:Auth<'_>,grant:Option<&str>)->Reply { self.call(Method::GET,&format!("/api/envs/{}/export",a.env),Some(auth),None,grant).await }
    async fn fresh_export(&self,a:&Account,auth:Auth<'_>,secret:&str) {
        let grant=self.email_grant(auth,Some(secret)).await; self.export(a,auth,Some(&grant)).await.ok(); challenged(&self.export(a,auth,Some(&grant)).await,"very_risky");
    }
}
fn field(v:&Value,key:&str)->String { v[key].as_str().expect(key).to_string() }
fn challenged(r:&Reply,risk:&str) { assert_eq!(r.status,428,"unproven action must require step-up"); assert_eq!(r.body["step_up_required"],true); assert_eq!(r.body["risk"],risk); assert_eq!(r.body["totp_required"],true); }
fn totp(secret:&str)->String {
    let(mut key,mut value,mut bits)=(Vec::new(),0u32,0u32);
    for c in secret.chars(){value=(value<<5)|"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;bits+=5;if bits>=8{key.push(((value>>(bits-8))&255) as u8);bits-=8;}}
    let counter=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()/30; let mut mac=hmac::Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();mac.update(&counter.to_be_bytes());let hash=mac.finalize().into_bytes();let off=(hash[19]&15) as usize;
    format!("{:06}",u32::from_be_bytes(hash[off..off+4].try_into().unwrap())%0x8000_0000%1_000_000)
}

#[tokio::test]
async fn enabling_totp_rejects_an_outstanding_email_only_challenge() {
    let s=Server::start().await; let a=s.account().await; let auth=Auth::Bearer(&a.token);
    let old=s.start_email(auth,false).await; let secret=s.enable_totp(&a).await;
    challenged(&s.export(&a,auth,None).await,"very_risky");
    let stale=s.verify_email(auth,&old,None).await;
    let stale_action=if stale.status==200 {Some(s.export(&a,auth,Some(&field(&stale.body,"token"))).await.status)} else {None};
    s.fresh_export(&a,auth,&secret).await;
    assert!(matches!(stale.status,400|401|428),"challenge created before TOTP enablement must not issue an email-only grant: verify HTTP {}, export HTTP {:?}",stale.status,stale_action);
}

#[tokio::test]
async fn enabling_totp_invalidates_an_already_issued_email_only_grant() {
    let s=Server::start().await; let a=s.account().await; let auth=Auth::Cookie(&a.cookie);
    let old=s.email_grant(auth,None).await; let secret=s.enable_totp(&a).await;
    challenged(&s.export(&a,auth,None).await,"very_risky"); let stale=s.export(&a,auth,Some(&old)).await;
    s.fresh_export(&a,auth,&secret).await;
    assert!(matches!(stale.status,401|428),"email-only grant issued before TOTP enablement must not authorize export: HTTP {}",stale.status);
}

#[tokio::test]
async fn completed_totp_reenrollment_invalidates_grants_but_pending_setup_does_not() {
    let s=Server::start().await; let a=s.account().await; let auth=Auth::Bearer(&a.token); let (secret,recovery)=s.setup_totp(&a).await; s.confirm_totp(&a,&secret).await;
    let old=s.email_grant(auth,Some(&secret)).await; let (replacement,_)=s.setup_totp(&a).await;
    // A pending setup has not changed the active factor, so its existing proof remains valid.
    s.export(&a,auth,Some(&old)).await.ok();
    let challenge=s.start_email(auth,true).await;
    // Recovery proof avoids waiting for another single-use TOTP counter.
    let grant=field(&s.verify_email(auth,&challenge,Some(recovery[0].clone())).await.ok(),"token");
    s.confirm_totp(&a,&replacement).await; let stale=s.export(&a,auth,Some(&grant)).await;
    s.fresh_export(&a,auth,&replacement).await;
    assert!(matches!(stale.status,401|428),"grant proved with the replaced TOTP enrollment must not authorize export: HTTP {}",stale.status);
}

#[tokio::test]
async fn invalid_aws_lease_config_does_not_reserve_a_lease_or_consume_the_grant() {
    let s=Server::start().await; let a=s.account().await; let auth=Auth::Bearer(&a.token); let secret=s.enable_totp(&a).await; let path=format!("/api/envs/{}/dynamic",a.env);
    let before=s.call(Method::GET,&path,Some(auth),None,None).await.ok(); assert!(before.as_array().expect("lease list").is_empty());
    let start=s.call(Method::POST,"/api/auth/step-up/start",Some(auth),Some(json!({"risk":"two_factor"})),None).await.ok();
    let grant=field(&s.call(Method::POST,"/api/auth/step-up/verify",Some(auth),Some(json!({"challenge":field(&start,"challenge"),"totp":totp(&secret)})),None).await.ok(),"token");
    let invalid=s.call(Method::POST,&path,Some(auth),Some(json!({"type":"aws_iam","config":{}})),Some(&grant)).await;
    assert_eq!(invalid.status,400,"empty AWS config is a local validation error");
    let after=s.call(Method::GET,&path,Some(auth),None,None).await.ok(); let count=after.as_array().expect("lease list").len();
    let valid_body=json!({"name":"valid-after-rejection","type":"generic"});
    let valid=s.call(Method::POST,&path,Some(auth),Some(valid_body.clone()),Some(&grant)).await;
    let replay=s.call(Method::POST,&path,Some(auth),Some(valid_body),Some(&grant)).await;
    challenged(&replay,"two_factor");
    assert_eq!((count,valid.status),(0,200),"local validation must leave no pending lease and preserve proof for a valid issuance; listed leases {}, same-grant valid issuance HTTP {}",count,valid.status);
    let id=field(&valid.body,"id"); let listed=s.call(Method::GET,&path,Some(auth),None,None).await.ok(); let rows=listed.as_array().expect("lease list");
    assert_eq!(rows.len(),1,"only the successful issuance persists"); assert_eq!(rows[0]["id"],id); assert!(!rows[0]["value"].as_str().expect("issued value").is_empty());
}
