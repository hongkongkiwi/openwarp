use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    base: String,
    dir: std::path::PathBuf,
    client: Client,
    mail: Arc<Mutex<Vec<Value>>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let mail = Arc::new(Mutex::new(Vec::new()));
        let sink = mail.clone();
        std::thread::spawn(move || {
            for incoming in relay.incoming() {
                let mut stream = incoming.unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0; 8192];
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 { break; }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..end]);
                        let len = head.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None }
                        }).unwrap_or(0);
                        if bytes.len() >= end + 4 + len { break; }
                    }
                }
                let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                if let Ok(body) = serde_json::from_slice::<Value>(&bytes[end..]) { sink.lock().unwrap().push(body); }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            }
        });
        let dir = std::env::temp_dir().join(format!("openwarp-management-{}-{}", std::process::id(), port));
        std::fs::create_dir_all(&dir).unwrap();
        let base = format!("http://127.0.0.1:{}", port);
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", format!("127.0.0.1:{}", port))
            .env("OPENWARP_PUBLIC_URL", &base)
            .env("OPENWARP_EMAIL_WEBHOOK", format!("http://{}/mail", relay_addr))
            .env("TOKIO_WORKER_THREADS", "1")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("REDIS_URL")
            .env_remove("OPENWARP_TRUST_PROXY").env_remove("OPENWARP_ENV")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10)).build().unwrap();
        let s = Self { child, base, dir, client, mail };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = s.client.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() { return s; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("management test server not healthy");
    }

    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self.client.request(method, format!("{}{}", self.base, path));
        if !token.is_empty() { request = request.bearer_auth(token); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or(json!({"raw":text}));
        (status, body)
    }

    async fn register(&self, email: &str) -> Value {
        let (status, mut user) = self.call(Method::POST, "/api/auth/register", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(status, 200, "{user}");
        let deadline = Instant::now() + Duration::from_secs(5);
        let link = loop {
            let link = self.mail.lock().unwrap().iter().rev().find_map(|mail| {
                if !mail.to_string().contains(email) { return None; }
                mail["text"].as_str()?.split_whitespace().find(|word| word.contains("/api/auth/verify?token=")).map(str::to_owned)
            });
            if let Some(link) = link { break link; }
            assert!(Instant::now() < deadline, "verification email missing");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let path = &link[link.find("/api/auth/verify?token=").unwrap()..];
        assert_eq!(self.call(Method::GET, path, "", None).await.0, 200);
        let (status, login) = self.call(Method::POST, "/api/auth/login", "", Some(json!({"email":email,"password":"correct-horse-battery"}))).await;
        assert_eq!(status, 200, "{login}");
        user["token"] = login["token"].clone();
        user
    }

    async fn tool(&self, token: &str, name: &str, arguments: Value) -> Value {
        let (status, rpc) = self.call(Method::POST, "/mcp", token,
            Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}}))).await;
        assert_eq!(status, 200, "{rpc}");
        assert!(rpc.get("error").is_none(), "tool must preserve HTTP errors in its result: {rpc}");
        assert!(rpc["result"].is_object(), "missing MCP result: {rpc}");
        rpc["result"].clone()
    }

    async fn api(&self, token: &str, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut args = json!({"method":method,"path":path});
        if let Some(body) = body { args["body"] = body; }
        let result = self.tool(token, "api_request", args).await;
        let envelope = result["structuredContent"].clone();
        assert!(envelope["status"].is_u64(), "missing HTTP status: {result}");
        let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().expect("text envelope")).unwrap();
        assert_eq!(text, envelope);
        let status = envelope["status"].as_u64().unwrap();
        if !(200..300).contains(&status) { assert_eq!(result["isError"], true, "{result}"); }
        else { assert_ne!(result["isError"], true, "{result}"); }
        envelope
    }

    async fn oauth(&self, session: &str, scope: &str) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use sha2::{Digest, Sha256};
        let (_, registration) = self.call(Method::POST, "/oauth/register", "", Some(json!({
            "redirect_uris":["http://127.0.0.1:8917/callback"],"token_endpoint_auth_method":"none","scope":scope
        }))).await;
        let client = registration["client_id"].as_str().expect("OAuth client");
        let verifier = "management-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        let resource = format!("{}/mcp", self.base);
        let response = self.client.post(format!("{}/oauth/authorize/decision", self.base)).bearer_auth(session)
            .form(&[("response_type","code"),("client_id",client),("redirect_uri","http://127.0.0.1:8917/callback"),
                ("scope",scope),("state","management"),("code_challenge",challenge.as_str()),
                ("code_challenge_method","S256"),("resource",resource.as_str()),("approve","1")]).send().await.unwrap();
        let location = response.headers().get("location").expect("authorization redirect").to_str().unwrap();
        let url = reqwest::Url::parse(location).unwrap();
        let code = url.query_pairs().find(|(k,_)| k == "code").expect("authorization code").1.into_owned();
        let response: Value = self.client.post(format!("{}/oauth/token", self.base))
            .form(&[("grant_type","authorization_code"),("code",code.as_str()),("client_id",client),
                ("redirect_uri","http://127.0.0.1:8917/callback"),("code_verifier",verifier)])
            .send().await.unwrap().json().await.unwrap();
        response["access_token"].as_str().expect("access token").to_owned()
    }
}

fn has_route(routes: &Value, method: &str, path: &str) -> bool {
    routes["routes"].as_array().expect("routes array").iter().any(|r| r["method"] == method && r["path"] == path)
}

#[tokio::test]
async fn discovery_and_mcp_integration_crud_use_real_routes() {
    let s = Server::start().await;
    let user = s.register("management@test.invalid").await;
    let session = user["token"].as_str().unwrap();
    let org = user["org_id"].as_str().unwrap();
    let token = s.oauth(session, "secrets:read secrets:write org:admin").await;
    let (status, routes) = s.call(Method::GET, "/api/capabilities", session, None).await;
    assert_eq!(status, 200, "{routes}");
    for (method, path) in [("GET","/api/capabilities"),("GET","/api/envs/{eid}/integrations"),
        ("POST","/api/envs/{eid}/integrations"),("PATCH","/api/integrations/{iid}"),("DELETE","/api/integrations/{iid}")] {
        assert!(has_route(&routes, method, path), "missing {method} {path}: {routes}");
    }
    for route in routes["routes"].as_array().unwrap() {
        assert!(route["path"].as_str().unwrap().starts_with("/api/"));
        assert!(route.get("body").is_none());
    }
    let discovered = s.tool(&token, "api_routes", json!({})).await;
    assert_eq!(discovered["structuredContent"], routes);
    let (_, app) = s.call(Method::POST, &format!("/api/orgs/{org}/apps"), session, Some(json!({"name":"management"}))).await;
    let (_, envs) = s.call(Method::GET, &format!("/api/apps/{}/envs", app["id"].as_str().unwrap()), session, None).await;
    let env = envs[0]["id"].as_str().unwrap();
    let path = format!("/api/envs/{env}/integrations");
    let created = s.api(&token, "POST", &path, Some(json!({"kind":"webhook","name":"before","config":{"url":"https://example.invalid/hook"}}))).await;
    assert_eq!(created["status"], 200, "{created}");
    let iid = created["body"]["id"].as_str().expect("integration id");
    let item = format!("/api/integrations/{iid}");
    let listed = s.api(&token, "GET", &path, None).await;
    assert_eq!(listed["status"], 200);
    assert!(listed["body"].as_array().unwrap().iter().any(|i| i["id"] == iid && i["name"] == "before"));
    assert_eq!(s.api(&token, "PATCH", &item, Some(json!({"name":"after"}))).await["status"], 200);
    let read = s.api(&token, "GET", &path, None).await;
    assert!(read["body"].as_array().unwrap().iter().any(|i| i["id"] == iid && i["name"] == "after"));
    assert_eq!(s.api(&token, "DELETE", &item, None).await["status"], 200);
    let read = s.api(&token, "GET", &path, None).await;
    assert!(!read["body"].as_array().unwrap().iter().any(|i| i["id"] == iid));
    // The standard audience binding answers 403 on REST for an MCP token;
    // only the internal dispatch carries the 401 form.
    assert_eq!(s.call(Method::GET, "/api/me", &token, None).await.0, 403, "MCP audience must not be rewritten into a REST credential");
}

#[tokio::test]
async fn mcp_management_preserves_scope_environment_and_tenant_boundaries() {
    let s = Server::start().await;
    let user = s.register("boundaries@test.invalid").await;
    let session = user["token"].as_str().unwrap();
    let org = user["org_id"].as_str().unwrap();
    let (_, app) = s.call(Method::POST, &format!("/api/orgs/{org}/apps"), session, Some(json!({"name":"boundaries"}))).await;
    let aid = app["id"].as_str().unwrap();
    let (_, envs) = s.call(Method::GET, &format!("/api/apps/{aid}/envs"), session, None).await;
    assert!(envs.as_array().unwrap().len() >= 2);
    let own = envs[0]["id"].as_str().unwrap();
    let other = envs[1]["id"].as_str().unwrap();
    let path = format!("/api/envs/{own}/integrations");
    let readonly = s.oauth(session, "secrets:read").await;
    assert_eq!(s.api(&readonly, "GET", &path, None).await["status"], 200);
    let denied = s.api(&readonly, "POST", &path, Some(json!({"kind":"webhook","name":"denied","config":{}}))).await;
    assert_eq!(denied["status"], 403);
    assert_eq!(s.call(Method::GET, &path, session, None).await.1, json!([]), "denied mutation must not land");
    let write = s.oauth(session, "secrets:read secrets:write").await;
    assert_eq!(s.api(&write, "GET", &format!("/api/orgs/{org}/members"), None).await["status"], 403, "org routes need org:admin in addition to read/write");
    let (_, pat) = s.call(Method::POST, &format!("/api/apps/{aid}/tokens"), session, Some(json!({"name":"scoped","env_id":own}))).await;
    let pat = pat["token"].as_str().unwrap();
    assert_eq!(s.api(pat, "GET", &path, None).await["status"], 200);
    assert_eq!(s.api(pat, "GET", &format!("/api/envs/{other}/integrations"), None).await["status"], 403);
    let outsider = s.register("outsider@test.invalid").await;
    assert_eq!(s.api(outsider["token"].as_str().unwrap(), "GET", &path, None).await["status"], 403);
}

#[tokio::test]
async fn mcp_management_rejects_url_traversal_auth_and_header_injection() {
    let s = Server::start().await;
    let user = s.register("targets@test.invalid").await;
    let token = user["token"].as_str().unwrap();
    for path in ["https://example.invalid/api/me", "//example.invalid/api/me", "/mcp", "/api/auth/login",
        "/api/../mcp", "/api/%2e%2e/mcp", "/api/me%", "/api/me\\other", "/api/me\n", "/api/not-a-real-route"] {
        let (_, rpc) = s.call(Method::POST, "/mcp", token, Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"api_request","arguments":{"method":"GET","path":path}}}))).await;
        assert!(rpc.get("error").is_some() || rpc["result"]["isError"] == true, "unsafe/unknown target accepted: {path:?}: {rpc}");
    }
    for arguments in [json!({"method":"TRACE","path":"/api/me"}),
        json!({"method":"CONNECT","path":"/api/me"}), json!({"method":"BREW","path":"/api/me"}),
        json!({"method":"GET","path":"/api/me","headers":{"Authorization":"Bearer forged","X-Forwarded-For":"192.0.2.1"}})] {
        let (_, rpc) = s.call(Method::POST, "/mcp", token, Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"api_request","arguments":arguments}}))).await;
        assert!(rpc.get("error").is_some() || rpc["result"]["isError"] == true, "unsafe arguments accepted: {rpc}");
    }
}
