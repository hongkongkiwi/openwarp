use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-agent-loopback-proxy-{}", std::process::id()));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn path(&self, name: &str) -> PathBuf { self.0.join(name) }
}
impl Drop for Temp { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

struct Mock { host: String, requests: Arc<Mutex<Vec<String>>>, stop: Arc<AtomicBool>, worker: Option<thread::JoinHandle<()>> }
impl Mock {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new())); let stop = Arc::new(AtomicBool::new(false));
        let (q, s) = (requests.clone(), stop.clone());
        let worker = thread::spawn(move || { while !s.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Accepted sockets inherit the listener's O_NONBLOCK on macOS and Linux; read blocking
                    // and serve only complete heads, so a losing first-write race cannot fabricate empty requests.
                    // The 30s read timeout is a hang guard only; it exceeds the agent's 15s client timeout.
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut request = Vec::new(); let mut buf = [0; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => request.extend_from_slice(&buf[..n]) }
                    }
                    if !request.windows(4).any(|w| w == b"\r\n\r\n") { continue; } // preconnect or truncated head: no request to record or answer
                    q.lock().unwrap().push(String::from_utf8_lossy(&request).into_owned());
                    // The proxy records and answers locally; it never forwards traffic.
                    let body = r#"{"secrets":[{"key":"KEY","path":"/","value":"rendered-secret","type":"secret"}]}"#;
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("mock accept: {e}"),
            }
        } });
        Self { host, requests, stop, worker: Some(worker) }
    }
    fn take_requests(&self) -> Vec<String> { std::mem::take(&mut *self.requests.lock().unwrap()) }
}
impl Drop for Mock { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); self.worker.take().unwrap().join().unwrap(); } }

fn command(temp: &Temp, host: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_openwarp"));
    c.current_dir(&temp.0).env("OPENWARP_NO_KEYRING", "1").env("OPENWARP_CONFIG", temp.path("config.json")).env("HOME", &temp.0)
        .env_remove("HTTP_PROXY").env_remove("http_proxy").env_remove("HTTPS_PROXY").env_remove("https_proxy")
        .env_remove("ALL_PROXY").env_remove("all_proxy").env_remove("NO_PROXY").env_remove("no_proxy")
        .args(["--host", host, "--token", "loopback-proxy-dummy-token", "agent", "--env", "env-test", "--template"])
        .arg(temp.path("template")).arg("--out").arg(temp.path("output")).arg("--once"); c
}
fn assert_rendered(temp: &Temp, output: &Output) {
    assert!(output.status.success(), "status={} stderr={}", output.status, String::from_utf8_lossy(&output.stderr));
    assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "rendered-secret");
}
fn assert_direct(requests: &[String]) {
    assert_eq!(requests.len(), 1, "expected exactly one direct export: {requests:?}");
    assert!(requests[0].starts_with("GET /api/envs/env-test/export?base=1 HTTP/1.1\r\n"), "unexpected export request: {requests:?}");
    assert!(requests[0].to_ascii_lowercase().contains("authorization: bearer loopback-proxy-dummy-token\r\n"), "missing bearer: {requests:?}");
}

#[test]
fn agent_loopback_http_bypasses_environment_proxies_without_leaking_bearer() {
    let temp = Temp::new(); let server = Mock::new(); let proxy = Mock::new();
    fs::write(temp.path("template"), "{{secret /KEY}}").unwrap();
    // Both listeners must independently complete export and rendering with proxies unset.
    for mock in [&server, &proxy] {
        let output = command(&temp, &mock.host).output().unwrap();
        assert_rendered(&temp, &output);
        assert_direct(&mock.take_requests());
        fs::remove_file(temp.path("output")).unwrap();
    }
    eprintln!("positive controls passed: server and recording proxy each exported and rendered directly");

    let output = command(&temp, &server.host)
        .env("HTTP_PROXY", &proxy.host).env("http_proxy", &proxy.host)
        .env("ALL_PROXY", &proxy.host).env("all_proxy", &proxy.host)
        .output().unwrap();
    let proxy_requests = proxy.take_requests(); let direct_requests = server.take_requests();
    eprintln!("proxied-environment result: status={} direct_requests={} proxy_requests={} stderr={}", output.status, direct_requests.len(), proxy_requests.len(), String::from_utf8_lossy(&output.stderr));
    assert!(proxy_requests.is_empty(), "loopback agent request reached the environment proxy, exposing its bearer: {proxy_requests:?}");
    assert_direct(&direct_requests);
    assert_rendered(&temp, &output);
}

#[test]
fn agent_loopback_mock_serves_complete_requests_and_ignores_abandoned_connections() {
    let mock = Mock::new();
    let addr = mock.host.trim_start_matches("http://").to_string();
    // Abandoned connection (preconnect or killed client) is not a request.
    { let _ = TcpStream::connect(&addr).unwrap(); }
    // Truncated head (client died mid-request) is not a request either.
    { let mut stream = TcpStream::connect(&addr).unwrap(); stream.write_all(b"GET /api/envs/env-test/export?base=1 HT").unwrap(); }
    // A slow-but-complete request is recorded and answered once its head arrives.
    let sender = thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        thread::sleep(Duration::from_millis(300));
        stream.write_all(b"GET /api/envs/env-test/export?base=1 HTTP/1.1\r\nAuthorization: Bearer loopback-proxy-dummy-token\r\n\r\n").unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"), "mock did not answer the completed request");
    });
    sender.join().unwrap();
    let requests = mock.take_requests();
    assert_eq!(requests.len(), 1, "only the completed request may be recorded: {requests:?}");
    assert!(requests[0].starts_with("GET /api/envs/env-test/export?base=1 HTTP/1.1\r\n"), "unexpected recorded request: {requests:?}");
}
