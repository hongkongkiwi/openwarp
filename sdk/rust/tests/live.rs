use openwarp_sdk::{Client as OpenWarpClient, Error, Export};
use reqwest::Method;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct TestServer {
    child: Child,
    dir: PathBuf,
    stop_mail: Arc<AtomicBool>,
    mail: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stop_mail.store(true, Ordering::SeqCst);
        if let Some(handle) = self.mail.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("free port address").port()
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if header_end.is_none() {
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = Some(position + 4);
                let head = String::from_utf8_lossy(&buffer[..position]);
                for line in head.lines() {
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
        }
        if let Some(start) = header_end {
            if buffer.len() >= start + content_length {
                return Some(String::from_utf8_lossy(&buffer[start..start + content_length]).into_owned());
            }
        }
    }
    None
}

async fn start_server() -> (TestServer, String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let binary = std::env::var("OPENWARP_BIN").unwrap_or_else(|_| "../../target/debug/openwarp-server".into());
    assert!(std::path::Path::new(&binary).exists(), "server binary not found at {binary}; build it or set OPENWARP_BIN");
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let mail_listener = TcpListener::bind("127.0.0.1:0").expect("bind mail webhook");
    let mail_url = format!("http://{}", mail_listener.local_addr().expect("mail address"));
    let (mail_tx, mut mail_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let stop_mail = Arc::new(AtomicBool::new(false));
    let stop = stop_mail.clone();
    let mail = std::thread::spawn(move || {
        mail_listener.set_nonblocking(true).ok();
        while !stop.load(Ordering::SeqCst) {
            match mail_listener.accept() {
                Ok((mut stream, _)) => {
                    if let Some(body) = read_request(&mut stream) {
                        if let Ok(message) = serde_json::from_str::<Value>(&body) {
                            if let Some(text) = message["text"].as_str() {
                                let _ = mail_tx.send(text.to_string());
                            }
                        }
                    }
                    let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    let dir = std::env::temp_dir().join(format!("openwarp-rust-sdk-{port}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let child = Command::new(&binary)
        .env_clear()
        .env("DATABASE_URL", format!("sqlite://{}/sdk.db", dir.display()))
        .env("ADDR", format!("127.0.0.1:{port}"))
        .env("OPENWARP_PUBLIC_URL", &base)
        .env("OPENWARP_EMAIL_PROVIDER", "webhook")
        .env("OPENWARP_EMAIL_WEBHOOK", &mail_url)
        .env("OPENWARP_EMAIL_FROM", "no-reply@test.invalid")
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start server");
    let server = TestServer { child, dir, stop_mail, mail: Some(mail) };
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("server did not become healthy");
        }
        if let Ok(response) = reqwest::get(format!("{base}/health")).await {
            if response.status().is_success() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (server, base, mail_rx)
}

fn verification_path(text: &str) -> String {
    const MARKER: &str = "/api/auth/verify?token=";
    let start = text.find(MARKER).expect("verification link");
    let rest = &text[start + MARKER.len()..];
    let end = rest.find(|c: char| c.is_whitespace() || "\"'<>".contains(c)).unwrap_or(rest.len());
    format!("{MARKER}{}", &rest[..end])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_server_round_trip() {
    let (server, base, mut mail) = start_server().await;
    let http = reqwest::Client::new();
    let email = "rust-sdk@test.invalid";
    let password = "rust-sdk-password";
    let registered: Value = http
        .post(format!("{base}/api/auth/register"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await
        .expect("register request")
        .error_for_status()
        .expect("register")
        .json()
        .await
        .expect("register JSON");
    assert_eq!(registered["verification_required"], true);
    let text = tokio::time::timeout(Duration::from_secs(10), mail.recv())
        .await
        .expect("verification mail timed out")
        .expect("verification mail");
    let verified = http
        .get(format!("{base}{}", verification_path(&text)))
        .send()
        .await
        .expect("verify request");
    assert_eq!(verified.status(), reqwest::StatusCode::OK);
    let session: Value = http
        .post(format!("{base}/api/auth/login"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await
        .expect("login request")
        .error_for_status()
        .expect("login")
        .json()
        .await
        .expect("login JSON");
    let token = session["token"].as_str().expect("login token").to_string();

    let org = registered["org_id"].as_str().expect("org id").to_string();
    let client = OpenWarpClient::new(&base, token.clone()).expect("client");
    assert!(client.orgs().await.expect("orgs").iter().any(|item| item.id == org));
    let app: Value = http
        .post(format!("{base}/api/orgs/{org}/apps"))
        .bearer_auth(&token)
        .json(&json!({"name": "rust-sdk"}))
        .send()
        .await
        .expect("create app request")
        .error_for_status()
        .expect("create app")
        .json()
        .await
        .expect("create app JSON");
    let app_id = app["id"].as_str().expect("app id");
    let envs = client.envs(app_id).await.expect("envs");
    assert_eq!(envs.len(), 3);
    let env = &envs[0].id;

    let deployed = client.set_secret(env, "SDK_TOKEN", "v1", "/", "secret", "").await.expect("set secret");
    assert_eq!(deployed.deployed, 1);
    assert_eq!(client.get_secret(env, "sdk_token").await.expect("get secret").expect("secret").value, "v1");
    match client.export(env).await {
        Err(Error::Api { status, body, .. }) => {
            assert_eq!(status, 428);
            assert_eq!(body["step_up_required"], true);
            assert_eq!(body["risk"], "very_risky");
            assert_eq!(body["email_required"], true);
            assert_eq!(body["totp_required"], false);
        }
        _ => panic!("export without a grant must return an HTTP 428 API error"),
    }
    let challenge: Value = client.api(Method::POST, &["auth", "step-up", "start"], Some(json!({"risk": "very_risky"})), &[]).await.expect("start step-up");
    let text = tokio::time::timeout(Duration::from_secs(10), mail.recv())
        .await
        .expect("step-up mail timed out")
        .expect("step-up mail");
    let email_code = text.split(|c: char| !c.is_ascii_digit()).find(|part| part.len() == 6).expect("emailed step-up code");
    let grant: Value = client.api(Method::POST, &["auth", "step-up", "verify"], Some(json!({"challenge": challenge["challenge"].as_str().expect("step-up challenge"), "email_code": email_code})), &[]).await.expect("verify step-up");
    let exported: Export = client.api_with_step_up(Method::GET, &["envs", env, "export"], None, &[], grant["token"].as_str().expect("step-up grant")).await.expect("export");
    assert_eq!(exported.secrets.iter().find(|secret| secret.key == "SDK_TOKEN").expect("exported secret").value, "v1");
    client.set_secret(env, "SDK_TOKEN", "v2", "/", "secret", "").await.expect("update secret");
    assert_eq!(client.get_secret(env, "SDK_TOKEN").await.expect("get updated").expect("updated secret").value, "v2");
    client.delete_secret(env, "SDK_TOKEN").await.expect("delete secret");
    assert!(client.get_secret(env, "SDK_TOKEN").await.expect("get deleted").is_none());
    assert!(client.me().await.expect("me")["id"].as_str().is_some());
    assert!(!client.audit(&org).await.expect("audit").is_empty());
    drop(server);
}
