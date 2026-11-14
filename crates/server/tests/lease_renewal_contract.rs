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
const AUTH_KEY: [u8; 32] = [43; 32];
const STS_XML: &str = "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>dummy-issued-access-key</AccessKeyId><SecretAccessKey>dummy-issued-secret-key</SecretAccessKey><SessionToken>dummy-issued-session-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>";
struct Reply { status: u16, body: Value }
impl Reply {
    fn ok(self)->Value { assert_eq!(self.status,200,"fixture/action must succeed, HTTP {}",self.status); self.body }
}
struct Account { token: String, app: String, envs: Vec<String> }
struct Server {
    child: Child, base: String, relay: String, dir: std::path::PathBuf, client: Client,
    mail: Arc<Mutex<Vec<Value>>>, sts: Arc<Mutex<Vec<String>>>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _=self.child.kill(); let _=self.child.wait(); self.stop.store(true,Ordering::SeqCst);
        if let Some(thread)=self.thread.take() { thread.join().unwrap(); }
        let _=std::fs::remove_dir_all(&self.dir);
    }
}
impl Server {
    async fn start()->Self { Self::start_with_db_host(None).await }
    async fn start_with_db_host(db_host:Option<&str>)->Self {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap(); drop(listener);
        let relay=TcpListener::bind("127.0.0.1:0").unwrap(); let relay_addr=relay.local_addr().unwrap(); relay.set_nonblocking(true).unwrap();
        let mail=Arc::new(Mutex::new(Vec::new())); let sink=mail.clone();
        let sts=Arc::new(Mutex::new(Vec::new())); let issued=sts.clone();
        let stop=Arc::new(AtomicBool::new(false)); let done=stop.clone();
        let thread=std::thread::spawn(move || { while !done.load(Ordering::SeqCst) {
            let (mut stream,_)=match relay.accept() {
                Ok(v)=>v, Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;}, Err(e)=>panic!("fixture accept: {e}"),
            };
            stream.set_nonblocking(false).unwrap(); stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut bytes=Vec::new(); let mut buf=[0;8192];
            loop {
                let n=stream.read(&mut buf).expect("fixture read"); if n==0 {break;} bytes.extend_from_slice(&buf[..n]);
                if let Some(end)=bytes.windows(4).position(|w|w==b"\r\n\r\n") {
                    let head=String::from_utf8_lossy(&bytes[..end]);
                    let len=head.lines().find_map(|l|{let(k,v)=l.split_once(':')?;if k.eq_ignore_ascii_case("content-length"){v.trim().parse::<usize>().ok()}else{None}}).unwrap_or(0);
                    if bytes.len()>=end+4+len {break;}
                }
            }
            let end=bytes.windows(4).position(|w|w==b"\r\n\r\n").expect("fixture headers")+4;
            let head=String::from_utf8_lossy(&bytes[..end]);
            let (content_type,body)=if head.starts_with("POST /mail ") {
                sink.lock().unwrap().push(serde_json::from_slice(&bytes[end..]).expect("verification email JSON"));
                ("application/json","{}")
            } else {
                assert!(head.starts_with("POST /sts "),"unexpected local provider request");
                issued.lock().unwrap().push(String::from_utf8(bytes[end..].to_vec()).unwrap());
                ("application/xml",STS_XML)
            };
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).unwrap();
        }});
        let base=format!("http://{addr}"); let relay=format!("http://{relay_addr}");
        let dir=std::env::temp_dir().join(format!("openwarp-lease-renewal-contract-{}-{}",std::process::id(),SEQ.fetch_add(1,Ordering::SeqCst))); std::fs::create_dir(&dir).unwrap();
        let mut command=Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        command.env_clear().env("DATABASE_URL",format!("sqlite://{}/test.db",dir.display())).env("ADDR",addr.to_string()).env("OPENWARP_PUBLIC_URL",&base)
            .env("OPENWARP_EMAIL_PROVIDER","webhook").env("OPENWARP_EMAIL_WEBHOOK",format!("{relay}/mail"))
            .env("OPENWARP_AUTH_PROVIDERS","password").env("OPENWARP_ENV","test").env("TOKIO_WORKER_THREADS","1");
        if let Some(host)=db_host { command.env("OPENWARP_ALLOWED_DB_HOSTS",host); }
        let child=command.stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("private server");
        let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15)).build().unwrap();
        let mut s=Self{child,base,relay,dir,client,mail,sts,stop,thread:Some(thread)}; let deadline=Instant::now()+Duration::from_secs(20);
        loop {
            assert!(s.child.try_wait().unwrap().is_none(),"server exited before health");
            if let Ok(r)=s.client.get(format!("{}/health",s.base)).send().await {if r.status().is_success(){break;}}
            assert!(Instant::now()<deadline,"server health timeout"); tokio::time::sleep(Duration::from_millis(50)).await;
        }
        s
    }
    async fn call(&self,method:Method,path:&str,token:Option<&str>,body:Option<Value>)->Reply {
        let mut r=self.client.request(method,format!("{}{}",self.base,path));
        if let Some(t)=token {r=r.bearer_auth(t);}
        if let Some(b)=body {r=r.json(&b);}
        let r=r.send().await.expect("local API request"); let status=r.status().as_u16(); let text=r.text().await.expect("API response body");
        Reply{status,body:serde_json::from_str(&text).unwrap_or(Value::Null)}
    }
    async fn account(&self,name:&str)->Account {
        let email=format!("{name}@test.invalid"); let before=self.mail.lock().unwrap().len(); let kp=oc::Keypair::generate();
        self.call(Method::POST,"/api/auth/register-v2",None,Some(json!({"email":email,"salt":oc::b64(&[11;16]),"iterations":600000,"algo":"pbkdf2-sha256","auth_key":oc::b64(&AUTH_KEY),"public_key":kp.public,"wrapped_privkey":format!("owv2:{}",oc::b64(&[19;40]))}))).await.ok();
        let deadline=Instant::now()+Duration::from_secs(8);
        let text=loop {
            if let Some(text)=self.mail.lock().unwrap().get(before).and_then(|m|m["text"].as_str()).map(str::to_string) {break text;}
            assert!(Instant::now()<deadline,"local verification email timeout"); tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let path=text.split_whitespace().find_map(|w|w.find("/api/auth/verify?token=").map(|i|w[i..].to_string())).expect("verification link");
        self.call(Method::GET,&path,None,None).await.ok();
        let ch=self.call(Method::POST,"/api/auth/challenge",None,Some(json!({"email":email}))).await.ok(); let cid=field(&ch,"challenge_id");
        let mut mac=hmac::Hmac::<sha2::Sha256>::new_from_slice(&AUTH_KEY).unwrap(); mac.update(format!("{}|{}",field(&ch,"challenge"),cid).as_bytes());
        let proof:String=mac.finalize().into_bytes().iter().map(|b|format!("{b:02x}")).collect();
        let login=self.call(Method::POST,"/api/auth/login-v2",None,Some(json!({"email":email,"challenge_id":cid,"proof":proof}))).await.ok();
        let token=field(&login,"token"); let auth=Some(token.as_str());
        let orgs=self.call(Method::GET,"/api/orgs",auth,None).await.ok(); let org=field(&orgs[0],"id");
        let app=field(&self.call(Method::POST,&format!("/api/orgs/{org}/apps"),auth,Some(json!({"name":"lease-renewal-contract"}))).await.ok(),"id");
        let envs=self.call(Method::GET,&format!("/api/apps/{app}/envs"),auth,None).await.ok().as_array().expect("environment array").iter().map(|e|field(e,"id")).collect();
        Account{token,app,envs}
    }
    async fn generic(&self,a:&Account)->Value {
        self.call(Method::POST,&format!("/api/envs/{}/dynamic",a.envs[0]),Some(&a.token),Some(json!({"name":"local-renewal","type":"generic","ttl_secs":60}))).await.ok()
    }
    async fn aws(&self,a:&Account)->Value {
        let lease=self.call(Method::POST,&format!("/api/envs/{}/dynamic",a.envs[0]),Some(&a.token),Some(json!({"name":"fixed-sts-validity","type":"aws_iam","ttl_secs":60,"config":{
            "region":"us-east-1","access_key_id":"dummy-parent-access-key","secret_access_key":"dummy-parent-secret-key",
            "role_arn":"arn:aws:iam::123456789012:role/lease-contract","duration_secs":900,"sts_endpoint":format!("{}/sts",self.relay)
        }}))).await.ok();
        assert_eq!(lease["type"],"aws_iam"); assert_eq!(lease["credentials"]["access_key_id"],"dummy-issued-access-key");
        let calls=self.sts.lock().unwrap(); assert_eq!(calls.len(),1,"lease must be issued by the local STS fixture"); assert!(calls[0].contains("Action=AssumeRole"));
        lease
    }
    async fn lookup(&self,a:&Account,lid:&str)->Value { self.call(Method::GET,&format!("/api/leases/{lid}"),Some(&a.token),None).await.ok() }
    async fn renew(&self,token:&str,lid:&str)->Reply { self.call(Method::POST,&format!("/api/leases/{lid}/renew"),Some(token),Some(json!({"ttl_secs":3600}))).await }
    async fn service_token(&self,a:&Account,env:&str,scopes:&str)->String {
        field(&self.call(Method::POST,&format!("/api/apps/{}/tokens",a.app),Some(&a.token),Some(json!({"name":"lease-ceiling","env_id":env,"scopes":scopes}))).await.ok(),"token")
    }
}
fn field(v:&Value,key:&str)->String { v[key].as_str().expect(key).to_string() }
fn expiry(v:&Value)->i64 { v["expires_at"].as_i64().expect("lease expiry") }
fn now()->i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn assert_rejected_unchanged(reply:&Reply,before:&Value,after:&Value,reason:&str) {
    assert_eq!((matches!(reply.status,400|404|409|410|422|501),reply.body["error"].is_string(),expiry(after)),(true,true,expiry(before)),"{reason}: HTTP {}; rejection must retain expiry",reply.status);
}

#[tokio::test]
async fn generic_renewal_extends_expiry_and_keeps_the_issued_value() {
    let s=Server::start().await; let a=s.account("owner").await; let lease=s.generic(&a).await; let lid=field(&lease,"id");
    let before=s.lookup(&a,&lid).await; assert_eq!(before["type"],"generic"); assert_eq!(before["renewable"],true); assert_eq!(before["revoked"],false);
    let started=now(); let renewed=s.renew(&a.token,&lid).await.ok(); let finished=now(); let after=s.lookup(&a,&lid).await;
    assert!(expiry(&after)>expiry(&before),"renewal must extend a short local lease");
    assert!((started+3600..=finished+3600).contains(&expiry(&after)),"renewal TTL is measured from renewal time");
    assert_eq!(renewed["id"],lid); assert_eq!(expiry(&renewed),expiry(&after)); assert_eq!(after["renewable"],true);
    let listed=s.call(Method::GET,&format!("/api/envs/{}/dynamic",a.envs[0]),Some(&a.token),None).await.ok();
    let row=listed.as_array().unwrap().iter().find(|row|row["id"]==lid).expect("renewed lease remains listed");
    assert!(row["value"]==lease["value"],"renewal must retain the existing credential"); assert_eq!(expiry(row),expiry(&after));
}

#[tokio::test]
async fn expired_generic_lease_cannot_be_resurrected_by_renewal() {
    let s=Server::start().await; let a=s.account("owner").await; let lease=s.generic(&a).await; let lid=field(&lease,"id");
    // Hold the reaper's retry window in the future so expiry, not revocation, is tested.
    let db=rusqlite::Connection::open(s.dir.join("test.db")).unwrap(); db.busy_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(db.execute("UPDATE leases SET expires_at=?,attempted_at=? WHERE id=?",rusqlite::params![now()-60,now()+86400,lid]).unwrap(),1); drop(db);
    let before=s.lookup(&a,&lid).await; assert_eq!(before["revoked"],false); assert_eq!(before["renewable"],false); assert!(expiry(&before)<now());
    let reply=s.renew(&a.token,&lid).await; let after=s.lookup(&a,&lid).await;
    assert_rejected_unchanged(&reply,&before,&after,"expired lease was renewed"); assert_eq!(after["renewable"],false);
}

#[tokio::test]
async fn revoked_generic_lease_cannot_be_renewed() {
    let s=Server::start().await; let a=s.account("owner").await; let lease=s.generic(&a).await; let lid=field(&lease,"id");
    s.call(Method::DELETE,&format!("/api/leases/{lid}"),Some(&a.token),None).await.ok();
    let before=s.lookup(&a,&lid).await; assert_eq!(before["revoked"],true); assert_eq!(before["renewable"],false);
    let reply=s.renew(&a.token,&lid).await; let after=s.lookup(&a,&lid).await;
    assert_rejected_unchanged(&reply,&before,&after,"revoked lease was renewed"); assert_eq!(after["revoked"],true); assert_eq!(after["renewable"],false);
}

#[tokio::test]
async fn fixed_sts_credentials_are_not_advertised_as_renewable() {
    let s=Server::start().await; let a=s.account("owner").await; let lease=s.aws(&a).await; let metadata=s.lookup(&a,&field(&lease,"id")).await;
    assert_eq!(metadata["type"],"aws_iam"); assert_eq!(metadata["revoked"],false); assert!(expiry(&metadata)>now());
    assert_eq!(metadata["renewable"],false,"a fixed-validity STS session cannot be extended in place");
}

#[tokio::test]
async fn fixed_sts_renewal_rejects_without_rewriting_local_expiry() {
    let s=Server::start().await; let a=s.account("owner").await; let lease=s.aws(&a).await; let lid=field(&lease,"id");
    let before=s.lookup(&a,&lid).await; let reply=s.renew(&a.token,&lid).await; let after=s.lookup(&a,&lid).await;
    assert_rejected_unchanged(&reply,&before,&after,"timestamp-only STS renewal was accepted");
    assert_eq!(s.sts.lock().unwrap().len(),1,"renewal must not silently replace the issued credential");
}

#[tokio::test]
async fn generic_renewal_preserves_tenant_scope_and_service_environment_ceilings() {
    let s=Server::start().await; let a=s.account("owner").await; let outsider=s.account("outsider").await;
    assert!(a.envs.len()>=2,"fixture needs distinct environments"); let lease=s.generic(&a).await; let lid=field(&lease,"id"); let before=s.lookup(&a,&lid).await;
    let readonly=s.service_token(&a,&a.envs[0],"secrets:read").await;
    let other_env=s.service_token(&a,&a.envs[1],"secrets:read secrets:write").await;
    for (label,token) in [("read-only service token",readonly.as_str()),("other-environment service token",other_env.as_str()),("other tenant",outsider.token.as_str())] {
        let reply=s.renew(token,&lid).await; assert_eq!(reply.status,403,"{label} must not renew the lease"); assert!(reply.body["error"].is_string());
        assert_eq!(expiry(&s.lookup(&a,&lid).await),expiry(&before),"{label} changed the lease");
    }
    let writer=s.service_token(&a,&a.envs[0],"secrets:read secrets:write").await;
    s.renew(&writer,&lid).await.ok(); assert!(expiry(&s.lookup(&a,&lid).await)>expiry(&before),"in-scope writer is a positive control");
}

#[cfg(feature="live-db-tests")]
#[tokio::test]
async fn postgres_renewal_extends_remote_role_validity_before_reporting_success() {
    let url=std::env::var("OPENWARP_TEST_LEASE_PG").expect("live-db-tests requires OPENWARP_TEST_LEASE_PG pointing at a disposable loopback PostgreSQL cluster");
    let config:tokio_postgres::Config=url.parse().expect("test PostgreSQL URL");
    assert_eq!(config.get_hosts().len(),1,"exactly one local test database host required"); assert!(config.get_hostaddrs().is_empty()); assert!(config.get_ports().len()<=1);
    let host=match &config.get_hosts()[0] { tokio_postgres::config::Host::Tcp(host)=>host.as_str(), _=>panic!("test requires literal loopback TCP") };
    assert!(matches!(host,"127.0.0.1"|"::1"),"refusing a non-loopback test database");
    assert_eq!(config.get_ssl_mode(),tokio_postgres::config::SslMode::Disable,"private local fixture must explicitly disable TLS");
    let (admin,connection)=config.connect(tokio_postgres::NoTls).await.expect("connect disposable PostgreSQL"); tokio::spawn(async move {let _=connection.await;});
    let port=config.get_ports().first().copied().unwrap_or(5432); let allow=format!("{host}:{port}");
    let s=Server::start_with_db_host(Some(&allow)).await; let a=s.account("owner").await; let issued_at=now();
    let lease=s.call(Method::POST,&format!("/api/envs/{}/dynamic",a.envs[0]),Some(&a.token),Some(json!({"name":"remote-validity-contract","type":"postgres","ttl_secs":60,"config":{"connection":url}}))).await.ok();
    let issued_by=now(); let lid=field(&lease,"id"); let username=field(&lease,"username"); let password=field(&lease,"password");
    let remote_username=username.clone(); let admin=Arc::new(admin); let checker=admin.clone();
    // Catch assertion panics so a failed renewal contract still removes only its own role.
    let result=tokio::spawn(async move {
        let query="SELECT EXTRACT(EPOCH FROM rolvaliduntil)::bigint FROM pg_roles WHERE rolname=$1";
        let original:i64=checker.query_one(query,&[&remote_username]).await.unwrap().get(0);
        assert!((issued_at+60..=issued_by+60).contains(&original),"issuance must establish a short-lived remote role");
        let metadata=s.lookup(&a,&lid).await; assert_eq!(metadata["type"],"postgres"); assert_eq!(metadata["renewable"],true);
        assert!((issued_at+60..=issued_by+60).contains(&expiry(&metadata)),"local issuance deadline must match the requested lifetime");
        let renewed=s.renew(&a.token,&lid).await.ok(); let after=s.lookup(&a,&lid).await;
        let actual:i64=checker.query_one(query,&[&remote_username]).await.unwrap().get(0);
        assert_eq!(actual,expiry(&renewed),"API renewal succeeded without extending PostgreSQL VALID UNTIL");
        assert!(actual>original,"the same database role must outlive its original deadline"); assert_eq!(actual,expiry(&after)); assert_eq!(after["renewable"],true);
        let mut login=config.clone(); login.user(&remote_username).password(&password);
        let (client,connection)=login.connect(tokio_postgres::NoTls).await.expect("renewed role authenticates with the issued password"); tokio::spawn(async move {let _=connection.await;});
        client.simple_query("SELECT 1").await.expect("renewed credential works");
    }).await;
    admin.batch_execute(&format!("DROP ROLE IF EXISTS \"{}\"",username.replace('"',"\"\""))).await.expect("remove the test's own PostgreSQL role");
    if let Err(error)=result { std::panic::resume_unwind(error.into_panic()); }
}
