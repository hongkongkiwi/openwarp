use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-agent-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf { self.0.join(name) }
}
impl Drop for Temp { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

struct Mock {
    host: String,
    replies: Arc<Mutex<Vec<(u16, String)>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Mock {
    fn new(body: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let replies = Arc::new(Mutex::new(vec![(200, body.to_string())]));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (r, q, s) = (replies.clone(), requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets inherit the listener's O_NONBLOCK on macOS and Linux; read blocking
                        // and serve only complete heads, so a losing first-write race cannot fabricate empty requests.
                        // The 30s read timeout is a hang guard only; it exceeds the agent's 15s client timeout.
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                        let mut request = Vec::new();
                        let mut buf = [0; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => request.extend_from_slice(&buf[..n]) }
                        }
                        if !request.windows(4).any(|w| w == b"\r\n\r\n") { continue; } // preconnect or truncated head: no request to record or answer
                        q.lock().unwrap().push(String::from_utf8_lossy(&request).into_owned());
                        let (status, body) = {
                            let mut replies = r.lock().unwrap();
                            if replies.len() > 1 { replies.remove(0) } else { replies[0].clone() }
                        };
                        let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                    Err(e) => panic!("mock accept failed: {e}"),
                }
            }
        });
        Self { host, replies, requests, stop, worker: Some(worker) }
    }
    fn reply(&self, status: u16, body: Value) { *self.replies.lock().unwrap() = vec![(status, body.to_string())]; }
    fn assert_export(&self) {
        let requests = self.requests.lock().unwrap();
        assert!(!requests.is_empty(), "agent never fetched secrets");
        for request in requests.iter() {
            assert!(request.starts_with("GET /api/envs/env-test/export?base=1 HTTP/1.1\r\n"), "unexpected request: {request}");
            assert!(request.to_ascii_lowercase().contains("authorization: bearer agent-test-token\r\n"), "missing explicit bearer token");
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); self.worker.take().unwrap().join().unwrap(); }
}

fn secrets() -> Value {
    json!({"secrets":[
        {"key":"KEY", "path":"/", "value":"root-value", "type":"secret"},
        {"key":"KEY", "path":"/folder/", "value":"folder-value", "type":"secret"}
    ]})
}
fn command(temp: &Temp, mock: &Mock) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openwarp"));
    command.current_dir(&temp.0)
        .env("OPENWARP_NO_KEYRING", "1").env("OPENWARP_CONFIG", temp.path("config.json"))
        .env("HOME", &temp.0).env("NO_PROXY", "127.0.0.1,localhost").env("no_proxy", "127.0.0.1,localhost")
        .args(["--host", &mock.host, "--token", "agent-test-token", "agent", "--env", "env-test", "--template"])
        .arg(temp.path("template")).arg("--out").arg(temp.path("output"));
    command
}
fn once(temp: &Temp, mock: &Mock) -> Output { command(temp, mock).arg("--once").output().unwrap() }
fn success(output: &Output) {
    assert!(output.status.success(), "agent failed: status={} stderr={}", output.status, String::from_utf8_lossy(&output.stderr));
}
fn positive_control(temp: &Temp, mock: &Mock) {
    fs::write(temp.path("template"), "{{secret /KEY}}").unwrap();
    success(&once(temp, mock));
    assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "root-value");
}
struct Running(Child);
impl Drop for Running { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
fn wait_for(mut condition: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        if condition() { return; }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{message}");
}
fn assert_no_cache(dir: &Path, marker: &[u8]) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() { assert_no_cache(&path, marker); }
        else if path.file_name().unwrap() != "output" && path.file_name().unwrap() != "template" {
            assert!(!fs::read(&path).unwrap().windows(marker.len()).any(|w| w == marker), "secret persisted outside rendered output: {}", path.display());
        }
    }
}

#[test]
fn agent_renders_exact_paths_literally_and_atomically_with_private_permissions() {
    let temp = Temp::new();
    let mock = Mock::new(secrets());
    let marker = temp.path("shell-must-not-run");
    let literal = format!("$(touch {}) `touch {}` $HOME", marker.display(), marker.display());
    mock.reply(200, json!({"secrets":[
        {"key":"KEY","path":"/","value":literal,"type":"secret"},
        {"key":"KEY","path":"/folder/","value":"folder-value","type":"secret"}
    ]}));
    fs::write(temp.path("template"), "root={{secret /KEY}}\nfolder={{secret /folder/KEY}}\n").unwrap();
    fs::write(temp.path("output"), "old-output").unwrap();
    #[cfg(unix)]
    let old_inode = fs::metadata(temp.path("output")).unwrap().ino();
    success(&once(&temp, &mock));
    assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), format!("root={literal}\nfolder=folder-value\n"));
    assert!(!marker.exists(), "template rendering evaluated shell syntax");
    #[cfg(unix)] {
        let metadata = fs::metadata(temp.path("output")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_ne!(metadata.ino(), old_inode, "output was overwritten in place instead of atomically replaced");
    }
    mock.assert_export();
    assert_no_cache(&temp.0, literal.as_bytes());
}

#[test]
fn agent_rejects_missing_ambiguous_and_sealed_values_without_partial_output() {
    let temp = Temp::new();
    let mock = Mock::new(secrets());
    positive_control(&temp, &mock);
    for (template, body) in [
        ("prefix={{secret /KEY}} missing={{secret /MISSING}}", secrets()),
        ("{{secret /KEY}}", json!({"secrets":[
            {"key":"KEY","path":"/","value":"one","type":"secret"},
            {"key":"KEY","path":"/","value":"two","type":"secret"}]})),
        ("{{secret /KEY}}", json!({"secrets":[{"key":"KEY","path":"/","value":"ciphertext","type":"sealed"}]})),
    ] {
        fs::write(temp.path("template"), template).unwrap();
        fs::write(temp.path("output"), "keep-existing").unwrap();
        mock.reply(200, body);
        let result = once(&temp, &mock);
        assert!(!result.status.success(), "invalid placeholder unexpectedly succeeded: {template}");
        assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "keep-existing");
    }
    mock.assert_export();
}

#[cfg(unix)]
#[test]
fn agent_refuses_symlink_destination_without_changing_target() {
    let temp = Temp::new();
    let mock = Mock::new(secrets());
    positive_control(&temp, &mock);
    fs::remove_file(temp.path("output")).unwrap();
    fs::write(temp.path("target"), "untouched").unwrap();
    std::os::unix::fs::symlink(temp.path("target"), temp.path("output")).unwrap();
    assert!(!once(&temp, &mock).status.success(), "symlink destination accepted");
    assert_eq!(fs::read_to_string(temp.path("target")).unwrap(), "untouched");
    assert!(fs::symlink_metadata(temp.path("output")).unwrap().file_type().is_symlink());
}

#[test]
fn agent_new_process_cannot_reuse_persisted_secrets_after_denial() {
    let temp = Temp::new();
    let mock = Mock::new(secrets());
    positive_control(&temp, &mock);
    assert_no_cache(&temp.0, b"root-value");
    for status in [401, 403] {
        mock.reply(status, json!({"error":"denied"}));
        fs::write(temp.path("output"), "keep-existing").unwrap();
        assert!(!once(&temp, &mock).status.success(), "HTTP {status} reused stale secrets");
        assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "keep-existing");
    }
    mock.assert_export();
}

#[test]
fn agent_memory_cache_expires_during_outage_and_denials_never_render_stale_values() {
    for status in [401, 403, 503] {
        let temp = Temp::new();
        let mock = Mock::new(secrets());
        fs::write(temp.path("template"), "{{secret /KEY}}").unwrap();
        let mut running = Running(command(&temp, &mock).args(["--interval-secs", "1", "--cache-ttl-secs", "1"])
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        wait_for(|| fs::read_to_string(temp.path("output")).ok().as_deref() == Some("root-value"), "agent failed to perform the initial render");
        mock.reply(status, json!({"error":"unavailable"}));
        thread::sleep(Duration::from_millis(1300));
        fs::write(temp.path("output"), "operator-sentinel").unwrap();
        thread::sleep(Duration::from_millis(1300));
        assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "operator-sentinel", "HTTP {status} rendered an expired or unauthorized cached secret");
        assert_no_cache(&temp.0, b"root-value");
        mock.assert_export();
        let _ = running.0.try_wait().unwrap();
    }
}

#[test]
fn agent_documents_thirty_second_interval_and_cache_defaults() {
    let result = Command::new(env!("CARGO_BIN_EXE_openwarp")).args(["agent", "--help"]).output().unwrap();
    success(&result);
    let help = String::from_utf8(result.stdout).unwrap();
    for flag in ["--interval-secs", "--cache-ttl-secs"] {
        let line = help.lines().find(|line| line.contains(flag)).unwrap_or_else(|| panic!("missing {flag}"));
        assert!(line.contains("[default: 30]"), "missing 30-second default for {flag}: {line}");
    }
}

#[test]
fn agent_mock_serves_complete_requests_and_ignores_abandoned_connections() {
    let mock = Mock::new(secrets());
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
        stream.write_all(b"GET /api/envs/env-test/export?base=1 HTTP/1.1\r\nAuthorization: Bearer agent-test-token\r\n\r\n").unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"), "mock did not answer the completed request");
    });
    sender.join().unwrap();
    mock.assert_export();
}
