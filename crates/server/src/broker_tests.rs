use axum::{body::{Body, to_bytes}, http::{Method, Request}, Router};
use rcgen::{CertificateParams, KeyPair};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer}};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

const SECRET: &str = "dummy-internal-broker-header-credential";
struct Reply { status: u16, body: String, headers: Vec<(String,String)> }
struct Upstream { client: reqwest::Client, requests: Arc<Mutex<Vec<String>>>, reply: Arc<Mutex<Reply>> }
impl Upstream {
    fn start() -> Self {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["service.example".to_string()]).unwrap().self_signed(&key).unwrap();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.der().clone()],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new())); let seen = requests.clone();
        let reply = Arc::new(Mutex::new(Reply { status:200, body:json!({"answer":"approved","private":"not-projected"}).to_string(),headers:vec![] })); let response = reply.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break }; let config = config.clone(); let seen = seen.clone(); let response = response.clone();
                std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(),stream); let mut buf = Vec::new(); let mut chunk = [0;8192];
                    loop {
                        let Ok(n) = tls.read(&mut chunk) else { return }; if n == 0 { return; } buf.extend_from_slice(&chunk[..n]);
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..end]); let len = head.lines().find_map(|l| { let (k,v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                            if buf.len() >= end + 4 + len { break; }
                        }
                    }
                    let request = String::from_utf8(buf).unwrap(); let body = request.split_once("\r\n\r\n").map(|(_,b)| serde_json::from_str::<Value>(b).unwrap_or(Value::Null)).unwrap_or(Value::Null);
                    seen.lock().unwrap().push(request);
                    let reply = response.lock().unwrap();
                    let (status, payload) = match body["method"].as_str() {
                        Some("initialize") => (200,json!({"jsonrpc":"2.0","id":body["id"],"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}).to_string()),
                        Some("notifications/initialized") => (202,String::new()),
                        Some("tools/call") => { let mut payload=serde_json::from_str::<Value>(&reply.body).unwrap_or(Value::Null); if payload.is_object() { payload["id"]=body["id"].clone(); (reply.status,payload.to_string()) } else { (reply.status,reply.body.clone()) } },
                        _ => (reply.status,reply.body.clone()),
                    };
                    let headers = reply.headers.iter().map(|(k,v)| format!("{k}: {v}\r\n")).collect::<String>();
                    let text = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{payload}",payload.len()); let _ = tls.write_all(text.as_bytes()); let _ = tls.flush();
                });
            }
        });
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15))
            .add_root_certificate(reqwest::Certificate::from_der(cert.der().as_ref()).unwrap()).resolve("service.example",addr).build().unwrap();
        Self { client, requests, reply }
    }
    fn respond(&self, status: u16, body: String) { let mut r = self.reply.lock().unwrap(); r.status=status; r.body=body; r.headers.clear(); }
}
struct Resp { status: u16, body: Value, text: String }
struct Fixture { app: Router, owner: String, admin: String, uid: String, org: String, env: String, secret: String }
impl Fixture {
    async fn new() -> Self {
        let db = crate::db::Db::open_memory().await.unwrap();
        // Account bootstrap is fixture data; all broker behavior uses the real router.
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)",&[json!("broker-owner"),json!("owner@broker.test.invalid"),json!("unused"),json!("unused"),json!("unused"),json!(crate::clock::now())]).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)",&[json!("broker-org"),json!("test"),json!(crate::clock::now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)",&[json!("broker-org"),json!("broker-owner"),json!("owner")]).await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)",&[json!("broker-admin"),json!("admin@broker.test.invalid"),json!("unused"),json!("unused"),json!("unused"),json!(crate::clock::now())]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)",&[json!("broker-org"),json!("broker-admin"),json!("admin")]).await.unwrap();
        let (live,_) = tokio::sync::broadcast::channel(16);
        let st = crate::app::new_state(db,"sqlite::memory:".into(),"broker-test".into(),"http://localhost".into(),[7;32],live,#[cfg(feature="redis-cache")] None);
        let owner = super::super::make_session(&st,"broker-owner").await.unwrap(); let admin = super::super::make_session(&st,"broker-admin").await.unwrap(); let app = crate::app::router(st);
        let mut f = Self { app, owner, admin, uid:"broker-owner".into(),org:"broker-org".into(),env:String::new(),secret:String::new() };
        let r = f.call(Method::POST,"/api/orgs/broker-org/apps",&f.owner,json!({"name":"broker"})).await; assert_eq!(r.status,200); let aid = r.body["id"].as_str().unwrap();
        let r = f.call(Method::GET,&format!("/api/apps/{aid}/envs"),&f.owner,Value::Null).await; assert_eq!(r.status,200); f.env = r.body[0]["id"].as_str().unwrap().into();
        let r = f.call(Method::PUT,&format!("/api/envs/{}/secrets",f.env),&f.owner,json!({"secrets":[{"key":"BROKER_CREDENTIAL","value":SECRET}]})).await; assert_eq!(r.status,200);
        let r = f.call(Method::GET,&format!("/api/envs/{}/secrets",f.env),&f.owner,Value::Null).await; assert_eq!(r.status,200); f.secret=r.body["secrets"][0]["id"].as_str().unwrap().into(); f
    }
    async fn call(&self, method: Method, path: &str, token: &str, body: Value) -> Resp {
        let req = Request::builder().method(method).uri(path).extension(axum::extract::ConnectInfo("127.0.0.1:32123".parse::<std::net::SocketAddr>().unwrap())).header("authorization",format!("Bearer {token}")).header("content-type","application/json")
            .body(if body.is_null() { Body::empty() } else { Body::from(body.to_string()) }).unwrap();
        let r = self.app.clone().oneshot(req).await.unwrap(); let status=r.status().as_u16(); let text=String::from_utf8(to_bytes(r.into_body(),1024*1024).await.unwrap().to_vec()).unwrap(); let body=serde_json::from_str(&text).unwrap_or(Value::Null); Resp { status,body,text }
    }
    fn service(&self, kind: &str, fields: Value) -> Value {
        let entry=json!({"id":"lookup","url":"https://service.example/lookup","method":"POST","privileged":false,"input_schema":{"type":"object","properties":{"query":{"type":"string"}},"required":[],"additionalProperties":false},"response_fields":fields});
        let mut policy=json!({"allowed_member_ids":[self.uid],"auth":{"type":"bearer"}});
        if kind == "http" { policy["operations"]=json!([entry]); } else { let mut tool=entry; let map=tool.as_object_mut().unwrap(); map.remove("url"); map.remove("method"); map.insert("name".into(),json!("upstream_lookup")); policy["endpoint"]=json!("https://service.example/mcp"); policy["tools"]=json!([tool]); }
        json!({"name":"test","env_id":self.env,"kind":kind,"credential_secret_id":self.secret,"enabled":true,"policy":policy})
    }
    async fn token(&self, config: Value) -> String {
        let r=self.call(Method::POST,&format!("/api/orgs/{}/broker/services",self.org),&self.owner,config).await; assert_eq!(r.status,201,"service: {}",r.text);
        let r=self.call(Method::POST,&format!("/api/orgs/{}/broker/sessions",self.org),&self.owner,json!({"service_id":r.body["id"],"subject_user_id":self.uid,"capabilities":["lookup"],"approved_privileged_capabilities":[],"ttl_seconds":300})).await; assert_eq!(r.status,201,"session: {}",r.text); r.body["token"].as_str().unwrap().into()
    }
    async fn execute(&self, token: &str) -> Resp { self.call(Method::POST,"/api/broker/http",token,json!({"operation":"lookup","arguments":{"query":"safe-query"}})).await }
}
fn safe_error(r: &Resp, status: u16) { assert_eq!(r.status,status,"{}",r.text); assert!(r.body["error"].is_string()); assert!(r.body["request_id"].is_string()); assert_eq!(r.body.as_object().unwrap().len(),2); assert!(!r.text.contains(SECRET)); assert!(!r.text.contains("upstream-private-detail")); }

#[tokio::test]
async fn approved_https_http_injects_header_and_projects_only_scalars() {
    let upstream=Upstream::start(); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let token=f.token(f.service("http",json!({"answer":"/answer"}))).await;
        let r=f.execute(&token).await; assert_eq!(r.status,200,"{}",r.text); assert_eq!(r.body["data"],json!({"answer":"approved"})); assert!(r.body["request_id"].is_string()); assert!(!r.text.contains("not-projected")); assert!(!r.text.contains(SECRET));
        let requests=upstream.requests.lock().unwrap(); assert_eq!(requests.len(),1); let req=&requests[0]; assert!(req.starts_with("POST /lookup HTTP/1.1\r\n")); assert!(req.to_ascii_lowercase().contains(&format!("authorization: bearer {}",SECRET))); assert_eq!(serde_json::from_str::<Value>(req.split_once("\r\n\r\n").unwrap().1).unwrap(),json!({"query":"safe-query"}));
    }).await;
}

#[tokio::test]
async fn empty_projection_returns_no_upstream_data_and_audit_is_safe() {
    let upstream=Upstream::start(); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let token=f.token(f.service("http",json!({}))).await; let r=f.execute(&token).await; assert_eq!(r.status,200); assert_eq!(r.body["data"],json!({}));
        let r=f.call(Method::GET,&format!("/api/orgs/{}/broker/audit",f.org),&f.owner,Value::Null).await; assert_eq!(r.status,200); assert!(r.text.contains("lookup"),"execution must have an audit record");
        for sensitive in [SECRET,&token,"safe-query","approved","not-projected","authorization","https://service.example"] { assert!(!r.text.contains(sensitive),"audit contains sensitive data"); }
    }).await;
}

#[tokio::test]
async fn upstream_redirect_malformed_oversize_and_secret_echo_fail_closed() {
    let upstream=Upstream::start(); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let token=f.token(f.service("http",json!({"answer":"/answer"}))).await;
        for (status,body) in [(500,"upstream-private-detail".to_string()),(200,"{".to_string()),(200,json!({"missing":"answer"}).to_string()),(200,json!({"answer":{"nested":"not-scalar"}}).to_string()),(200,json!({"answer":SECRET}).to_string()),(200,json!({"answer":"x".repeat(4097)}).to_string()),(200,json!({"answer":"fine","padding":"x".repeat(256*1024)}).to_string())] {
            upstream.respond(status,body); safe_error(&f.execute(&token).await,502);
        }
        upstream.respond(302,"upstream-private-detail".into()); upstream.reply.lock().unwrap().headers.push(("Location".into(),"https://service.example/redirect-target".into()));
        let count=upstream.requests.lock().unwrap().len(); safe_error(&f.execute(&token).await,502); let requests=upstream.requests.lock().unwrap(); assert_eq!(requests.len(),count+1,"redirect was followed"); assert!(!requests.iter().any(|r| r.starts_with("POST /redirect-target") || r.starts_with("GET /redirect-target")));
    }).await;
}

#[tokio::test]
async fn remote_mcp_handshake_maps_exact_tool_and_projects_structured_content() {
    let upstream=Upstream::start(); upstream.respond(200,json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"answer":"approved","private":"not-projected"},"content":[{"type":"text","text":"upstream-private-detail"}]}}).to_string()); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let token=f.token(f.service("mcp",json!({"answer":"/answer"}))).await;
        let r=f.call(Method::POST,"/api/broker/mcp",&token,json!({"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"lookup","arguments":{"query":"safe-query"}}})).await;
        assert_eq!(r.status,200,"{}",r.text); assert_eq!(r.body["id"],42); assert_eq!(r.body["result"]["structuredContent"],json!({"answer":"approved"})); assert!(!r.text.contains("not-projected")); assert!(!r.text.contains("upstream-private-detail")); assert!(!r.text.contains(SECRET));
        let requests=upstream.requests.lock().unwrap(); assert_eq!(requests.len(),3); let bodies:Vec<Value>=requests.iter().map(|r| serde_json::from_str(r.split_once("\r\n\r\n").unwrap().1).unwrap()).collect();
        assert_eq!(bodies[0]["method"],"initialize"); assert_eq!(bodies[0]["params"]["protocolVersion"],"2025-06-18"); assert_eq!(bodies[1]["method"],"notifications/initialized"); assert_eq!(bodies[2]["method"],"tools/call"); assert_eq!(bodies[2]["params"]["name"],"upstream_lookup"); assert_eq!(bodies[2]["params"]["arguments"],json!({"query":"safe-query"}));
        assert!(requests.iter().all(|r| r.to_ascii_lowercase().contains(&format!("authorization: bearer {}",SECRET))));
    }).await;
}

#[tokio::test]
async fn live_credential_deletion_and_issuer_access_changes_prevent_dispatch() {
    let upstream=Upstream::start(); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let config=f.service("http",json!({"answer":"/answer"}));
        let service=f.call(Method::POST,&format!("/api/orgs/{}/broker/services",f.org),&f.owner,config).await; assert_eq!(service.status,201);
        let session=f.call(Method::POST,&format!("/api/orgs/{}/broker/sessions",f.org),&f.admin,json!({"service_id":service.body["id"],"subject_user_id":f.uid,"capabilities":["lookup"],"ttl_seconds":300})).await; assert_eq!(session.status,201); let issued=session.body["token"].as_str().unwrap(); assert_eq!(f.execute(issued).await.status,200);
        let r=f.call(Method::PATCH,&format!("/api/orgs/{}/members/broker-admin",f.org),&f.owner,json!({"role":"developer"})).await; assert_eq!(r.status,200);
        let count=upstream.requests.lock().unwrap().len(); safe_error(&f.execute(issued).await,403); assert_eq!(upstream.requests.lock().unwrap().len(),count,"issuer demotion must prevent dispatch");
        let token=f.token(f.service("http",json!({"answer":"/answer"}))).await; assert_eq!(f.execute(&token).await.status,200);
        let r=f.call(Method::DELETE,&format!("/api/secrets/{}",f.secret),&f.owner,Value::Null).await; assert_eq!(r.status,200,"delete credential: {}",r.text);
        let count=upstream.requests.lock().unwrap().len(); let r=f.execute(&token).await; assert!(matches!(r.status,403|409),"deleted credential must fail: {}",r.text); assert_eq!(upstream.requests.lock().unwrap().len(),count);
        let r=f.call(Method::PUT,&format!("/api/orgs/{}/settings",f.org),&f.owner,json!({"ip_allowlist":"192.0.2.0/24"})).await; assert_eq!(r.status,200); let r=f.execute(&token).await; assert_eq!(r.status,403); assert_eq!(upstream.requests.lock().unwrap().len(),count);
    }).await;
}

#[tokio::test]
async fn broker_review_mixed_cookie_cannot_bypass_control_ip_allowlist() {
    let f=Fixture::new().await; let _token=f.token(f.service("http",json!({"answer":"/answer"}))).await;
    let path=format!("/api/orgs/{}/broker/services",f.org);
    let r=f.call(Method::GET,&path,&f.owner,Value::Null).await; assert_eq!(r.status,200); assert_eq!(r.body.as_array().unwrap().len(),1);
    let r=f.call(Method::PUT,&format!("/api/orgs/{}/settings",f.org),&f.owner,json!({"ip_allowlist":"192.0.2.0/24"})).await; assert_eq!(r.status,200);
    let r=f.call(Method::GET,&path,&f.owner,Value::Null).await; assert_eq!(r.status,403,"human bearer alone must respect the IP allowlist");
    let req=Request::builder().method(Method::GET).uri(&path)
        .extension(axum::extract::ConnectInfo("127.0.0.1:32123".parse::<std::net::SocketAddr>().unwrap()))
        .header("authorization",format!("Bearer {}",f.owner)).header("cookie","ow_session=owb_dummy").body(Body::empty()).unwrap();
    let r=f.app.clone().oneshot(req).await.unwrap(); let status=r.status().as_u16();
    let text=String::from_utf8(to_bytes(r.into_body(),1024*1024).await.unwrap().to_vec()).unwrap();
    assert!(matches!(status,401|403),"mixed human bearer and broker cookie must not bypass the IP allowlist: status {status}");
    for sensitive in [SECRET,f.owner.as_str(),f.secret.as_str(),"credential_secret_id","allowed_member_ids"] { assert!(!text.contains(sensitive),"denial must not disclose broker configuration or credentials"); }
}

#[tokio::test]
async fn broker_review_deleted_environment_preserves_owner_visibility_and_cleanup() {
    let upstream=Upstream::start(); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let base=format!("/api/orgs/{}/broker",f.org);
        let service=f.call(Method::POST,&format!("{base}/services"),&f.owner,f.service("http",json!({"answer":"/answer"}))).await; assert_eq!(service.status,201);
        let service_id=service.body["id"].as_str().unwrap();
        let session=f.call(Method::POST,&format!("{base}/sessions"),&f.owner,json!({"service_id":service_id,"subject_user_id":f.uid,"capabilities":["lookup"],"ttl_seconds":300})).await; assert_eq!(session.status,201);
        let session_id=session.body["id"].as_str().unwrap(); let token=session.body["token"].as_str().unwrap();
        let executed=f.execute(token).await; assert_eq!(executed.status,200); assert_eq!(upstream.requests.lock().unwrap().len(),1);
        let before=f.call(Method::GET,&format!("{base}/audit"),&f.owner,Value::Null).await; assert_eq!(before.status,200); assert_eq!(before.body.as_array().unwrap().len(),1);
        let deleted=f.call(Method::DELETE,&format!("/api/envs/{}",f.env),&f.owner,Value::Null).await; assert_eq!(deleted.status,200);
        let denied=f.execute(token).await; assert!(matches!(denied.status,401|403|409),"deleted environment must prevent execution"); assert_eq!(upstream.requests.lock().unwrap().len(),1);
        let services=f.call(Method::GET,&format!("{base}/services"),&f.owner,Value::Null).await;
        let sessions=f.call(Method::GET,&format!("{base}/sessions"),&f.owner,Value::Null).await;
        let audit=f.call(Method::GET,&format!("{base}/audit"),&f.owner,Value::Null).await;
        let revoked=f.call(Method::DELETE,&format!("{base}/sessions/{session_id}"),&f.owner,Value::Null).await;
        let disabled=f.call(Method::DELETE,&format!("{base}/services/{service_id}"),&f.owner,Value::Null).await;
        assert_eq!([services.status,sessions.status,audit.status,revoked.status,disabled.status],[200,200,200,204,204],"owner must retain broker visibility, revocation and service cleanup after environment deletion");
        assert!(services.body.as_array().unwrap().iter().any(|r| r["id"]==service_id));
        assert!(sessions.body.as_array().unwrap().iter().any(|r| r["id"]==session_id));
        assert!(audit.body.as_array().unwrap().iter().any(|r| r["request_id"]==executed.body["request_id"] || r["id"]==executed.body["request_id"]));
        let retained=f.call(Method::GET,&format!("{base}/audit"),&f.owner,Value::Null).await; assert_eq!(retained.status,200); assert!(retained.body.as_array().unwrap().iter().any(|r| r["id"]==executed.body["request_id"]));
        for sensitive in [SECRET,token,"safe-query","approved","not-projected"] { assert!(!retained.text.contains(sensitive),"retained audit must contain metadata only"); }
    }).await;
}

#[tokio::test]
async fn broker_review_integer_bounds_are_exact_before_upstream_dispatch() {
    let upstream=Upstream::start(); let f=Fixture::new().await;
    super::with_test_client(upstream.client.clone(),async {
        let mut config=f.service("http",json!({"answer":"/answer"}));
        config["policy"]["operations"][0]["input_schema"]=json!({"type":"object","properties":{"query":{"type":"integer","minimum":-9007199254740992_i64,"maximum":9007199254740992_u64}},"required":["query"],"additionalProperties":false});
        let token=f.token(config.clone()).await;
        for value in [json!(7),json!(-7),json!(9007199254740992_u64),json!(-9007199254740992_i64)] {
            let r=f.call(Method::POST,"/api/broker/http",&token,json!({"operation":"lookup","arguments":{"query":value}})).await; assert_eq!(r.status,200,"in-range integer must remain usable");
        }
        config["policy"]["operations"][0]["input_schema"]["properties"]["query"]=json!({"type":"integer","minimum":0,"maximum":u64::MAX-1});
        let unsigned=f.token(config).await;
        let r=f.call(Method::POST,"/api/broker/http",&unsigned,json!({"operation":"lookup","arguments":{"query":u64::MAX-1}})).await; assert_eq!(r.status,200,"valid unsigned integer boundary must remain usable");
        assert_eq!(upstream.requests.lock().unwrap().len(),5); upstream.requests.lock().unwrap().clear();
        let mut observed=Vec::new();
        for (token,value) in [(&token,json!(9007199254740993_u64)),(&token,json!(-9007199254740993_i64)),(&unsigned,json!(u64::MAX))] {
            let r=f.call(Method::POST,"/api/broker/http",token,json!({"operation":"lookup","arguments":{"query":value}})).await;
            observed.push((r.status,upstream.requests.lock().unwrap().len()));
        }
        assert_eq!(observed,vec![(400,0),(400,0),(400,0)],"integers one beyond positive, negative and u64 bounds must be rejected without dispatch");
    }).await;
}
