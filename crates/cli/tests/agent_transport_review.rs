use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread;
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-agent-transport-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
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
                    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut request = Vec::new(); let mut buf = [0; 1024];
                    while !request.windows(4).any(|w| w==b"\r\n\r\n") {
                        match stream.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => request.extend_from_slice(&buf[..n]) }
                    }
                    q.lock().unwrap().push(String::from_utf8_lossy(&request).into_owned());
                    let body = r#"{"secrets":[{"key":"KEY","path":"/","value":"rendered-secret","type":"secret"}]}"#;
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("mock accept: {e}"),
            }
        } });
        Self { host, requests, stop, worker: Some(worker) }
    }
    fn assert_bearer(&self) {
        let requests = self.requests.lock().unwrap();
        assert!(!requests.is_empty(), "loopback positive control did not fetch");
        assert!(requests.iter().all(|r| r.to_ascii_lowercase().contains("authorization: bearer review-dummy-token\r\n")), "positive control did not exercise bearer transport");
    }
}
impl Drop for Mock { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); self.worker.take().unwrap().join().unwrap(); } }
fn command(temp: &Temp, host: &str, template: &Path, output: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_openwarp"));
    c.current_dir(&temp.0).env("OPENWARP_NO_KEYRING", "1").env("OPENWARP_CONFIG", temp.path("config.json")).env("HOME", &temp.0)
        .env_remove("HTTP_PROXY").env_remove("http_proxy").env_remove("HTTPS_PROXY").env_remove("https_proxy")
        .env_remove("ALL_PROXY").env_remove("all_proxy").env("NO_PROXY", "*").env("no_proxy", "*")
        .args(["--host", host, "--token", "review-dummy-token", "agent", "--env", "env-test", "--template"])
        .arg(template).arg("--out").arg(output).arg("--once"); c
}
fn success(output: &Output) { assert!(output.status.success(), "status={} stderr={}", output.status, String::from_utf8_lossy(&output.stderr)); }
fn positive_control(temp: &Temp, mock: &Mock) {
    fs::write(temp.path("template"), "{{secret /KEY}}").unwrap();
    success(&command(temp, &mock.host, &temp.path("template"), &temp.path("output")).output().unwrap());
    assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "rendered-secret");
    mock.assert_bearer();
}

#[test]
fn agent_allows_explicit_loopback_http_for_development() {
    let temp = Temp::new(); let mock = Mock::new(); positive_control(&temp, &mock);
}

#[test]
fn agent_rejects_remote_http_before_sending_bearer_without_dns() {
    let temp = Temp::new(); let local = Mock::new(); positive_control(&temp, &local);
    let proxy = Mock::new();
    fs::write(temp.path("output"), "keep-existing").unwrap();
    // A local recording proxy makes example.invalid deterministic without DNS or external traffic.
    let output = command(&temp, "http://example.invalid", &temp.path("template"), &temp.path("output"))
        .env("HTTP_PROXY", &proxy.host).env("http_proxy", &proxy.host).env("NO_PROXY", "").env("no_proxy", "")
        .output().unwrap();
    assert!(proxy.requests.lock().unwrap().is_empty(), "agent sent a remote plaintext request (including its bearer) before rejecting the URL");
    assert!(!output.status.success(), "remote plaintext agent succeeded");
    assert_eq!(fs::read_to_string(temp.path("output")).unwrap(), "keep-existing");
}

#[test]
fn agent_rejects_template_output_identity_and_preserves_template() {
    let temp = Temp::new(); let mock = Mock::new(); positive_control(&temp, &mock);
    let original = "original={{secret /KEY}}\n";
    let template = temp.path("template");
    fs::create_dir(temp.path("subdir")).unwrap();
    for output in [template.clone(), temp.path("./template"), temp.path("subdir/../template")] {
        fs::write(&template, original).unwrap();
        assert_eq!(fs::canonicalize(&template).unwrap(), fs::canonicalize(&output).unwrap(), "fixture paths must identify the same canonical file");
        let result = command(&temp, &mock.host, &template, &output).output().unwrap();
        assert_eq!(fs::read_to_string(&template).unwrap(), original, "agent destroyed template via equivalent output path {}", output.display());
        assert!(!result.status.success(), "agent accepted template as output: {}", output.display());
    }
}
