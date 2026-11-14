use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::Mac;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Server { child: Child, base: String, dir: std::path::PathBuf, client: Client, mail: Arc<Mutex<Vec<Value>>>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
struct Account { token: String, cookie: String, org: String, app: String, env: String }
struct TotpProof { secret: String, recovery: std::vec::IntoIter<String>, first: bool }
impl TotpProof {
    fn next(&mut self)->String {
        if self.first {self.first=false;return totp(&self.secret);}
        // TOTP counters are single-use; subsequent grants use authentic unused recovery codes.
        self.recovery.next().expect("unused setup recovery code")
    }
}
#[derive(Clone, Copy)]
enum Auth<'a> { Bearer(&'a str), Cookie(&'a str) }
impl Drop for Server { fn drop(&mut self) { let _=self.child.kill(); let _=self.child.wait(); self.stop.store(true,Ordering::SeqCst); self.thread.take().unwrap().join().unwrap(); let _=std::fs::remove_dir_all(&self.dir); } }
impl Server {
    async fn start() -> Self {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap(); drop(listener);
        let relay=TcpListener::bind("127.0.0.1:0").unwrap(); let mail_addr=relay.local_addr().unwrap(); relay.set_nonblocking(true).unwrap();
        let mail=Arc::new(Mutex::new(Vec::new())); let sink=mail.clone(); let stop=Arc::new(AtomicBool::new(false)); let done=stop.clone();
        let thread=std::thread::spawn(move || { while !done.load(Ordering::SeqCst) {
            let (mut stream,_)=match relay.accept() {Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;},Err(e)=>panic!("mail accept: {e}")};
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
        let base=format!("http://{addr}"); let dir=std::env::temp_dir().join(format!("openwarp-step-up-contract-{}-{}",std::process::id(),addr.port())); std::fs::create_dir_all(&dir).unwrap();
        let child=Command::new(env!("CARGO_BIN_EXE_openwarp-server")).env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string()).env("OPENWARP_PUBLIC_URL",&base)
            .env("OPENWARP_EMAIL_WEBHOOK",format!("http://{mail_addr}/mail")).env("TOKIO_WORKER_THREADS","1").env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_ENV").env_remove("REDIS_URL")
            .env_remove("OPENWARP_ALLOW_PRIVATE_EGRESS").env_remove("OPENWARP_TRUST_PROXY").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let s=Self{child,base,dir,client,mail,stop,thread:Some(thread)}; let deadline=Instant::now()+Duration::from_secs(20);
        loop {if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await {if r.status().is_success(){break;}} assert!(Instant::now()<deadline,"server health");tokio::time::sleep(Duration::from_millis(50)).await;} s
    }
    async fn call(&self,method:Method,path:&str,auth:Option<Auth<'_>>,body:Option<Value>,grant:Option<&str>)->(u16,Value) {
        let mut r=self.client.request(method,format!("{}{}",self.base,path));
        if let Some(auth)=auth {r=match auth {Auth::Bearer(t)=>r.bearer_auth(t),Auth::Cookie(c)=>r.header("cookie",c).header("origin",&self.base)};}
        if let Some(b)=body {r=r.json(&b);}
        if let Some(g)=grant {r=r.header("x-openwarp-step-up",g);}
        let r=r.send().await.unwrap(); let status=r.status().as_u16(); let text=r.text().await.unwrap(); (status,serde_json::from_str(&text).unwrap_or(json!({"raw":text})))
    }
    async fn mail_after(&self,before:usize)->String {
        let deadline=Instant::now()+Duration::from_secs(8);
        loop {if let Some(text)=self.mail.lock().unwrap().get(before).and_then(|m|m["text"].as_str()).map(str::to_string){return text;} assert!(Instant::now()<deadline,"local verification email");tokio::time::sleep(Duration::from_millis(25)).await;}
    }
    async fn account(&self,email:&str)->Account {
        let before=self.mail.lock().unwrap().len();
        good(self.call(Method::POST,"/api/auth/register",None,Some(json!({"email":email,"password":"correct-horse-battery"})),None).await);
        let text=self.mail_after(before).await;
        let path=text.split_whitespace().find_map(|w|w.find("/api/auth/verify?token=").map(|i|w[i..].to_string())).expect("account verification link");
        good(self.call(Method::GET,&path,None,None,None).await);
        let r=self.client.post(format!("{}/api/auth/login",self.base)).json(&json!({"email":email,"password":"correct-horse-battery"})).send().await.unwrap();
        assert_eq!(r.status(),200,"real account login");
        let cookie=r.headers().get_all("set-cookie").iter().filter_map(|h|h.to_str().ok()).find_map(|h|h.split(';').next().filter(|c|c.starts_with("ow_session=")).map(str::to_string)).expect("login session cookie");
        let login:Value=r.json().await.unwrap(); let token=field(&login,"token"); let auth=Some(Auth::Bearer(&token));
        let orgs=good(self.call(Method::GET,"/api/orgs",auth,None,None).await); let org=field(&orgs[0],"id");
        let app=field(&good(self.call(Method::POST,&format!("/api/orgs/{org}/apps"),auth,Some(json!({"name":"step-up-fixture"})),None).await),"id");
        let envs=good(self.call(Method::GET,&format!("/api/apps/{app}/envs"),auth,None,None).await); let env=field(&envs[0],"id");
        Account{token,cookie,org,app,env}
    }
    async fn enable_totp(&self,a:&Account)->TotpProof {
        let auth=Some(Auth::Bearer(&a.token)); let setup=good(self.call(Method::POST,"/api/me/totp/setup",auth,Some(json!({})),None).await); let secret=field(&setup,"secret");
        let recovery:Vec<String>=setup["recovery_codes"].as_array().expect("setup recovery codes").iter().map(|code|code.as_str().expect("recovery code").to_string()).collect();
        good(self.call(Method::POST,"/api/me/totp/verify",auth,Some(json!({"code":totp(&secret)})),None).await); TotpProof{secret,recovery:recovery.into_iter(),first:true}
    }
    async fn grant(&self,auth:Auth<'_>,risk:&str,proof:Option<&mut TotpProof>)->String {
        let before=self.mail.lock().unwrap().len(); let start=good(self.call(Method::POST,"/api/auth/step-up/start",Some(auth),Some(json!({"risk":risk})),None).await);
        let mut body=json!({"challenge":field(&start,"challenge")});
        if risk=="very_risky" {let text=self.mail_after(before).await; body["email_code"]=json!(text.split(|c:char|!c.is_ascii_digit()).find(|v|v.len()==6).expect("emailed code"));}
        if let Some(proof)=proof {body["totp"]=json!(proof.next());}
        let verified=good(self.call(Method::POST,"/api/auth/step-up/verify",Some(auth),Some(body),None).await); assert_eq!(verified["expires_in"],300); field(&verified,"token")
    }
    async fn oauth(&self,a:&Account,scope:&str)->String {
        let redirect="http://127.0.0.1:8917/callback";
        let (status,reg)=self.call(Method::POST,"/oauth/register",None,Some(json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope})),None).await;
        assert_eq!(status,201,"dynamic OAuth client registration");
        let cid=field(&reg,"client_id");let verifier="stepup-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";let challenge=Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));let resource=self.base.clone();
        let r=self.client.post(format!("{}/oauth/authorize/decision",self.base)).bearer_auth(&a.token).form(&[("response_type","code"),("client_id",cid.as_str()),("redirect_uri",redirect),("scope",scope),("state","stepup"),("code_challenge",challenge.as_str()),("code_challenge_method","S256"),("resource",resource.as_str()),("approve","1")]).send().await.unwrap();
        let url=reqwest::Url::parse(r.headers().get("location").expect("OAuth redirect").to_str().unwrap()).unwrap();let code=url.query_pairs().find(|(k,_)|k=="code").expect("authorization code").1.into_owned();
        let r=self.client.post(format!("{}/oauth/token",self.base)).form(&[("grant_type","authorization_code"),("code",code.as_str()),("client_id",cid.as_str()),("redirect_uri",redirect),("code_verifier",verifier)]).send().await.unwrap();assert_eq!(r.status(),200);field(&r.json::<Value>().await.unwrap(),"access_token")
    }
}
fn field(v:&Value,key:&str)->String {v[key].as_str().expect(key).into()}
fn good(r:(u16,Value))->Value {assert_eq!(r.0,200,"expected successful fixture/action, HTTP {}: {}",r.0,r.1);r.1}
fn challenged(r:(u16,Value),risk:&str,totp:bool) {
    assert_eq!(r.0,428,"sensitive action must be challenged before executing: {}",r.1);
    assert_eq!(r.1["step_up_required"],true);assert_eq!(r.1["risk"],risk);assert_eq!(r.1["totp_required"],totp);assert_eq!(r.1["email_required"],risk=="very_risky");
}
fn totp(secret:&str)->String {
    let(mut key,mut value,mut bits)=(Vec::new(),0u32,0u32);
    for c in secret.chars(){value=(value<<5)|"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u32;bits+=5;if bits>=8{key.push(((value>>(bits-8))&255) as u8);bits-=8;}}
    let counter=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()/30;let mut mac=hmac::Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();mac.update(&counter.to_be_bytes());let hash=mac.finalize().into_bytes();let off=(hash[19]&15) as usize;
    format!("{:06}",u32::from_be_bytes(hash[off..off+4].try_into().unwrap())%0x8000_0000%1_000_000)
}

async fn very_risky_route(action:&str,cookie:bool) {
    let s=Server::start().await;let a=s.account("owner@test.invalid").await;
    let (method,path,body)=match action {
        "settings"=>(Method::PUT,format!("/api/orgs/{}/settings",a.org),Some(json!({"reuse_check":false}))),
        "export"=>(Method::GET,format!("/api/envs/{}/export",a.env),None),
        "rotation"=>(Method::POST,"/api/instance/rotate-master".into(),Some(json!({"new_key":openwarp_crypto::b64(&[73;32])}))),
        _=>unreachable!(),
    };
    let auth=if cookie {Auth::Cookie(&a.cookie)} else {Auth::Bearer(&a.token)};
    challenged(s.call(method.clone(),&path,Some(auth),body.clone(),None).await,"very_risky",false);
    let grant=s.grant(auth,"very_risky",None).await;
    good(s.call(method.clone(),&path,Some(auth),body.clone(),Some(&grant)).await);
    let replay=if action=="rotation" {Some(json!({"new_key":openwarp_crypto::b64(&[83;32])}))} else {body};
    challenged(s.call(method,&path,Some(auth),replay,Some(&grant)).await,"very_risky",false);
}
#[tokio::test]
async fn workspace_settings_require_email_for_bearer_sessions() {very_risky_route("settings",false).await;}
#[tokio::test]
async fn workspace_settings_require_email_for_cookie_sessions() {very_risky_route("settings",true).await;}
#[tokio::test]
async fn bulk_export_requires_email_for_bearer_sessions() {very_risky_route("export",false).await;}
#[tokio::test]
async fn bulk_export_requires_email_for_cookie_sessions() {very_risky_route("export",true).await;}
#[tokio::test]
async fn master_rotation_requires_email_for_bearer_sessions() {very_risky_route("rotation",false).await;}
#[tokio::test]
async fn master_rotation_requires_email_for_cookie_sessions() {very_risky_route("rotation",true).await;}

#[tokio::test]
async fn major_secret_writes_require_configured_totp_but_standard_reads_do_not() {
    let s=Server::start().await;let a=s.account("owner@test.invalid").await;let path=format!("/api/envs/{}/secrets",a.env);let body=json!({"secrets":[{"key":"FIXTURE","value":"dummy-before"}]});
    good(s.call(Method::PUT,&path,Some(Auth::Bearer(&a.token)),Some(body.clone()),None).await);
    let mut proof=s.enable_totp(&a).await;
    for auth in [Auth::Bearer(&a.token),Auth::Cookie(&a.cookie)] {
        good(s.call(Method::GET,&path,Some(auth),None,None).await);
        challenged(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),None).await,"two_factor",true);
        let grant=s.grant(auth,"two_factor",Some(&mut proof)).await;
        good(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),Some(&grant)).await);
        challenged(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),Some(&grant)).await,"two_factor",true);
    }
}

#[tokio::test]
async fn insufficient_expired_and_used_grants_do_not_authorize_very_risky_actions() {
    let s=Server::start().await;let a=s.account("owner@test.invalid").await;let mut proof=s.enable_totp(&a).await;let auth=Auth::Bearer(&a.token);let path=format!("/api/orgs/{}/settings",a.org);let body=json!({"reuse_check":false});
    let minor=s.grant(auth,"two_factor",Some(&mut proof)).await;
    challenged(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),Some(&minor)).await,"very_risky",true);
    // A rejected higher-risk request must leave this grant usable at its own tier.
    good(s.call(Method::PUT,&format!("/api/envs/{}/secrets",a.env),Some(auth),Some(json!({"secrets":[{"key":"LOWER","value":"dummy"}]})),Some(&minor)).await);
    challenged(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),Some("stepupg_nonexistent")).await,"very_risky",true);
    let expired=s.grant(auth,"very_risky",Some(&mut proof)).await;
    // Advance only this disposable credential's expiry, rather than sleeping five minutes.
    let db=rusqlite::Connection::open(s.dir.join("test.db")).unwrap();db.busy_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(db.execute("UPDATE step_up_grants SET expires_at=0 WHERE token_hash=?",[openwarp_crypto::hash_token(&expired)]).unwrap(),1);
    challenged(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),Some(&expired)).await,"very_risky",true);
    let valid=s.grant(auth,"very_risky",Some(&mut proof)).await;
    good(s.call(Method::PUT,&path,Some(auth),Some(body.clone()),Some(&valid)).await);
    challenged(s.call(Method::PUT,&path,Some(auth),Some(body),Some(&valid)).await,"very_risky",true);
}

#[tokio::test]
async fn very_risky_proof_needs_both_configured_factors_and_challenges_are_single_use() {
    let s=Server::start().await;let a=s.account("owner@test.invalid").await;let mut proof=s.enable_totp(&a).await;let auth=Some(Auth::Bearer(&a.token));
    let before=s.mail.lock().unwrap().len();
    let start=good(s.call(Method::POST,"/api/auth/step-up/start",auth,Some(json!({"risk":"very_risky"})),None).await);
    let text=s.mail_after(before).await;let email=text.split(|c:char|!c.is_ascii_digit()).find(|v|v.len()==6).unwrap();let challenge=field(&start,"challenge");
    for body in [json!({"challenge":challenge,"email_code":email}),json!({"challenge":challenge,"totp":totp(&proof.secret)})] {
        assert_eq!(s.call(Method::POST,"/api/auth/step-up/verify",auth,Some(body),None).await.0,401,"neither configured factor alone can grant a very risky action");
    }
    let body=json!({"challenge":challenge,"email_code":email,"totp":proof.next()});
    good(s.call(Method::POST,"/api/auth/step-up/verify",auth,Some(body.clone()),None).await);
    assert_eq!(s.call(Method::POST,"/api/auth/step-up/verify",auth,Some(body),None).await.0,400,"a completed challenge cannot issue a second grant");
}

#[tokio::test]
async fn grants_never_replace_authorization_and_denied_requests_do_not_spend_them() {
    let s=Server::start().await;let owner=s.account("owner@test.invalid").await;let outsider=s.account("outsider@test.invalid").await;
    let auth=Auth::Bearer(&owner.token);let grant=s.grant(auth,"very_risky",None).await;let own=format!("/api/orgs/{}/settings",owner.org);let foreign=format!("/api/orgs/{}/settings",outsider.org);let body=json!({"reuse_check":false});
    assert_eq!(s.call(Method::PUT,&own,Some(Auth::Bearer(&outsider.token)),Some(body.clone()),Some(&grant)).await.0,403,"a grant cannot grant workspace membership");
    assert_eq!(s.call(Method::PUT,&foreign,Some(auth),Some(body.clone()),Some(&grant)).await.0,403,"an owner cannot administer another workspace with proof of identity");
    let readonly=field(&good(s.call(Method::POST,&format!("/api/apps/{}/tokens",owner.app),Some(auth),Some(json!({"name":"readonly","scopes":"secrets:read"})),None).await),"token");
    assert_eq!(s.call(Method::PUT,&own,Some(Auth::Bearer(&readonly)),Some(body.clone()),Some(&grant)).await.0,403,"a grant cannot widen service-token scopes");
    good(s.call(Method::PUT,&own,Some(auth),Some(body),Some(&grant)).await);
    let grant=s.grant(auth,"very_risky",None).await;
    good(s.call(Method::POST,"/api/auth/logout",Some(auth),Some(json!({})),None).await);
    assert_eq!(s.call(Method::GET,&format!("/api/envs/{}/export",owner.env),Some(auth),None,Some(&grant)).await.0,401,"a grant must not revive a revoked session");
}

#[tokio::test]
async fn automation_is_not_challenged_and_still_obeys_scopes_and_environment_bounds() {
    let s=Server::start().await;let a=s.account("owner@test.invalid").await;let auth=Some(Auth::Bearer(&a.token));
    let service=field(&good(s.call(Method::POST,&format!("/api/apps/{}/tokens",a.app),auth,Some(json!({"name":"fixture","env_id":a.env,"scopes":"secrets:read secrets:write"})),None).await),"token");
    let oauth=s.oauth(&a,"secrets:read secrets:write").await;let readonly=s.oauth(&a,"secrets:read").await;
    let identity=good(s.call(Method::POST,&format!("/api/orgs/{}/identities",a.org),auth,Some(json!({"name":"fixture-machine"})),None).await);
    let machine=field(&good(s.call(Method::POST,"/api/v1/machine/auth/universal/login",None,Some(json!({"client_id":identity["client_id"],"client_secret":identity["client_secret"]})),None).await),"accessToken");
    s.enable_totp(&a).await;
    for token in [&service,&oauth,&machine] {
        good(s.call(Method::GET,&format!("/api/envs/{}/export",a.env),Some(Auth::Bearer(token)),None,None).await);
        good(s.call(Method::PUT,&format!("/api/envs/{}/secrets",a.env),Some(Auth::Bearer(token)),Some(json!({"secrets":[{"key":"AUTOMATION","value":"dummy"}]})),None).await);
    }
    assert_eq!(s.call(Method::PUT,&format!("/api/envs/{}/secrets",a.env),Some(Auth::Bearer(&readonly)),Some(json!({"secrets":[{"key":"FORBIDDEN","value":"dummy"}]})),None).await.0,403,"OAuth read scope remains read-only");
    let envs=good(s.call(Method::GET,&format!("/api/apps/{}/envs",a.app),auth,None,None).await);let other=envs.as_array().unwrap().iter().find(|e|e["id"]!=a.env).unwrap();
    assert_eq!(s.call(Method::GET,&format!("/api/envs/{}/export",field(other,"id")),Some(Auth::Bearer(&service)),None,None).await.0,403,"the step-up exemption cannot broaden environment scope");
}

#[cfg(feature="ssh-ca")]
#[tokio::test]
async fn privileged_ssh_signing_consumes_one_grant_once_not_in_both_gates() {
    let s=Server::start().await;let a=s.account("owner@test.invalid").await;let auth=Auth::Bearer(&a.token);
    good(s.call(Method::PUT,"/api/instance/features",Some(auth),Some(json!({"org":a.org,"features":["ssh-ca"]})),None).await);
    let ca_grant=s.grant(auth,"very_risky",None).await;
    let ca=field(&good(s.call(Method::POST,&format!("/api/orgs/{}/ssh/cas",a.org),Some(auth),Some(json!({"name":"fixture-ca"})),Some(&ca_grant)).await),"id");
    good(s.call(Method::PUT,&format!("/api/ssh/cas/{ca}/grants"),Some(auth),Some(json!({"grants":[{"role":"owner","principals":["root"],"max_ttl":600}]})),None).await);
    let key=ssh_key::PrivateKey::random(&mut rand_core::OsRng,ssh_key::Algorithm::Ed25519).unwrap();let body=json!({"principal":"root","public_key":key.public_key().to_openssh().unwrap(),"ttl":300});let path=format!("/api/ssh/cas/{ca}/sign");
    challenged(s.call(Method::POST,&path,Some(auth),Some(body.clone()),None).await,"very_risky",false);
    let grant=s.grant(auth,"very_risky",None).await;
    let signed=good(s.call(Method::POST,&path,Some(auth),Some(body.clone()),Some(&grant)).await);assert_eq!(signed["verified"]["principals"],json!(["root"]));
    challenged(s.call(Method::POST,&path,Some(auth),Some(body),Some(&grant)).await,"very_risky",false);
}
