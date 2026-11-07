use reqwest::{redirect::Policy, Client, Response, Url};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Server { child: Child, base: String, dir: PathBuf }
struct Flow { state: String, cookies: String }
struct Mock { base: String, requests: Arc<Mutex<Vec<String>>> }

impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

fn browser() -> Client { Client::builder().no_proxy().redirect(Policy::none()).timeout(Duration::from_secs(15)).build().unwrap() }
fn location(r: &Response) -> &str { r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("") }
fn issued_session(r: &Response) -> bool {
    location(r).contains("#token=") || r.headers().get_all("set-cookie").iter().any(|h| h.to_str().unwrap_or("").starts_with("ow_session="))
}
fn cookies(r: &Response) -> String {
    r.headers().get_all("set-cookie").iter().filter_map(|h| h.to_str().ok()).filter_map(|h| h.split(';').next()).collect::<Vec<_>>().join("; ")
}

impl Server {
    async fn start(api: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        let dir = std::env::temp_dir().join(format!("openwarp-social-binding-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir(&dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp-server"));
        cmd.env_clear().env("DATABASE_URL", format!("sqlite://{}/test.db", dir.display()))
            .env("ADDR", addr.to_string()).env("OPENWARP_PUBLIC_URL", &base).env("TOKIO_WORKER_THREADS", "1")
            .env("OPENWARP_EMAIL_PROVIDER", "webhook").env("OPENWARP_EMAIL_WEBHOOK", format!("{}/mail", api))
            .stdout(Stdio::null()).stderr(Stdio::null());
        for provider in ["DISCORD", "WORKOS"] {
            cmd.env(format!("OPENWARP_{}_CLIENT_ID", provider), "test-client")
                .env(format!("OPENWARP_{}_CLIENT_SECRET", provider), "test-secret")
                .env(format!("OPENWARP_{}_API", provider), api);
        }
        drop(listener); let child = cmd.spawn().expect("spawn server");
        let s = Self { child, base, dir }; let client = browser();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(r) = client.get(format!("{}/health", s.base)).send().await { if r.status().is_success() { return s; } }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become healthy");
    }

    async fn start_flow(&self, client: &Client, provider: &str) -> Flow {
        let r = client.get(format!("{}/api/auth/social/{}/start", self.base, provider)).send().await.unwrap();
        assert_eq!(r.status(), 307, "configured provider starts login");
        let url = Url::parse(location(&r)).expect("provider authorization URL");
        let state = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).expect("OAuth state");
        assert!(!state.is_empty()); Flow { state, cookies: cookies(&r) }
    }

    async fn callback(&self, client: &Client, provider: &str, state: &str, cookies: &str) -> Response {
        let mut req = client.get(format!("{}/api/auth/social/{}/callback", self.base, provider)).query(&[("code", "unused-test-code"), ("state", state)]);
        if !cookies.is_empty() { req = req.header("cookie", cookies); }
        req.send().await.unwrap()
    }

    async fn signed_in(&self, client: &Client, r: Response, email: &str) {
        assert_eq!(r.status(), 307, "same-browser callback must sign in");
        let token = location(&r).split_once("#token=").map(|(_, t)| t).unwrap_or("");
        let mut req = client.get(format!("{}/api/me", self.base));
        if !token.is_empty() { req = req.bearer_auth(token); }
        else { let session = cookies(&r); assert!(!session.is_empty(), "callback issues a session"); req = req.header("cookie", session); }
        let me = req.send().await.unwrap(); assert_eq!(me.status(), 200, "issued session authenticates");
        assert_eq!(me.json::<Value>().await.unwrap()["email"], email);
    }
}

impl Mock {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new())); let captured = requests.clone();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let mut stream = incoming.expect("provider connection"); stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = Vec::new(); let mut chunk = [0u8; 8192];
                loop {
                    let n = stream.read(&mut chunk).expect("provider request"); if n == 0 { break; } buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]);
                        let len = head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None } }).unwrap_or(0);
                        if buf.len() >= end + 4 + len { break; }
                    }
                }
                let request = String::from_utf8_lossy(&buf); let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                captured.lock().unwrap().push(path.clone());
                let body = match path.as_str() {
                    "/api/oauth2/token" => json!({"access_token": "dummy-provider-access", "token_type": "Bearer"}),
                    "/api/users/@me" => json!({"id": "discord-user", "email": "discord@test.invalid", "verified": true}),
                    "/user_management/authenticate" => json!({"user": {"id": "workos-user", "email": "workos@test.invalid", "email_verified": true}}),
                    _ => json!({}),
                }.to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).unwrap();
            }
        });
        Self { base, requests }
    }
    fn calls(&self) -> usize { self.requests.lock().unwrap().len() }
}

#[tokio::test]
async fn social_callback_without_initiating_browser_proof_never_contacts_provider_or_issues_session() {
    let mock = Mock::start(); let s = Server::start(&mock.base).await; let mut outcomes = Vec::new();
    for provider in ["discord", "workos"] {
        let attacker = browser(); let victim = browser(); let flow = s.start_flow(&attacker, provider).await;
        let before = mock.calls(); let r = s.callback(&victim, provider, &flow.state, "").await;
        outcomes.push((provider, r.status().as_u16(), mock.calls() - before, issued_session(&r)));
        assert_eq!(victim.get(format!("{}/api/me", s.base)).send().await.unwrap().status(), 401, "victim has no prior session");
    }
    assert_eq!(outcomes, vec![("discord", 400, 0, false), ("workos", 400, 0, false)], "a valid unused state/code is not proof that this browser initiated login");
}

#[tokio::test]
async fn social_callback_with_another_browsers_proof_never_contacts_provider_or_issues_session() {
    let mock = Mock::start(); let s = Server::start(&mock.base).await; let mut outcomes = Vec::new();
    for provider in ["discord", "workos"] {
        let attacker = browser(); let victim = browser();
        let attack = s.start_flow(&attacker, provider).await; let own = s.start_flow(&victim, provider).await;
        let before = mock.calls(); let r = s.callback(&victim, provider, &attack.state, &own.cookies).await;
        outcomes.push((provider, r.status().as_u16(), mock.calls() - before, issued_session(&r)));
    }
    assert_eq!(outcomes, vec![("discord", 400, 0, false), ("workos", 400, 0, false)], "a different browser's login proof cannot authorize the attacker's callback");
}

#[tokio::test]
async fn same_browser_social_login_preserves_identity_and_rejects_replay_and_provider_mismatch() {
    let mock = Mock::start(); let s = Server::start(&mock.base).await;
    for (provider, other, email) in [("discord", "workos", "discord@test.invalid"), ("workos", "discord", "workos@test.invalid")] {
        let client = browser(); let flow = s.start_flow(&client, provider).await; let before = mock.calls();
        s.signed_in(&client, s.callback(&client, provider, &flow.state, &flow.cookies).await, email).await;
        assert!(mock.calls() > before, "same-browser login exchanges provider code");
        let before = mock.calls(); let replay = s.callback(&client, provider, &flow.state, &flow.cookies).await;
        assert_eq!(replay.status(), 400, "state is single use"); assert!(!issued_session(&replay)); assert_eq!(mock.calls(), before);
        let fresh = s.start_flow(&client, provider).await; let before = mock.calls();
        let mismatch = s.callback(&client, other, &fresh.state, &fresh.cookies).await;
        assert_eq!(mismatch.status(), 400, "state is bound to its provider"); assert!(!issued_session(&mismatch)); assert_eq!(mock.calls(), before);
    }
}
