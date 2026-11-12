use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

struct Mock {
    base: String,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    dir: std::path::PathBuf,
}

impl Mock {
    fn new(status: u16, body: &str, location: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let dir = std::env::temp_dir().join(format!("openwarp-cli-management-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let captured = calls.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{}\r\n{body}", body.len(), location.map(|l| format!("Location: {l}\r\n")).unwrap_or_default());
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets can inherit O_NONBLOCK; wait for the declared body before answering.
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                        stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut bytes = Vec::new();
                        let mut complete = false;
                        let mut chunk = [0u8; 4096];
                        loop {
                            let n = stream.read(&mut chunk).unwrap_or(0);
                            if n == 0 { break; }
                            bytes.extend_from_slice(&chunk[..n]);
                            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&bytes[..end]);
                                let len = head.lines().find_map(|l| {
                                    let (key,value) = l.split_once(':')?;
                                    if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None }
                                }).unwrap_or(0);
                                if bytes.len() >= end + 4 + len { complete = true; break; }
                            }
                        }
                        if !complete { continue; }
                        captured.lock().unwrap().push(String::from_utf8(bytes).unwrap());
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                    Err(e) => panic!("mock accept: {e}"),
                }
            }
        });
        Self { base, calls, stop, thread: Some(thread), dir }
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_openwarp"))
            .env_clear().env("HOME", &self.dir).env("OPENWARP_CONFIG", self.dir.join("config.json"))
            .env("OPENWARP_NO_KEYRING", "1").current_dir(&self.dir)
            .args(["--host", &self.base, "--token", "private-test-token"]).args(args)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        if let Some(input) = stdin { child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap(); }
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn success(output: &Output) {
    assert!(output.status.success(), "CLI failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-test-token"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-test-token"));
}

#[test]
fn management_mock_requires_complete_headers_and_declared_body() {
    let mock = Mock::new(200, "{}", None);
    let addr = mock.base.trim_start_matches("http://").to_string();
    let body = "{\"name\":\"雪\"}";
    let head = format!("POST /api/orgs HTTP/1.1\r\nAuthorization: Bearer private-test-token\r\nContent-Length: {}\r\n\r\n", body.len());
    { let _ = TcpStream::connect(&addr).unwrap(); }
    { let mut stream = TcpStream::connect(&addr).unwrap(); stream.write_all(b"POST /api/orgs HT").unwrap(); }
    {
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body.as_bytes()[..1]).unwrap();
    }
    let expected = format!("{head}{body}");
    let sender = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body.as_bytes()[..1]).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        stream.write_all(&body.as_bytes()[1..]).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"), "mock did not answer the completed request");
    });
    sender.join().unwrap();
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "only the complete request and body may be recorded");
    assert_eq!(calls[0], expected, "mock must preserve the complete head and declared body");
}

#[test]
fn api_routes_uses_capabilities_and_prints_json() {
    let body = json!({"routes":[{"method":"GET","path":"/api/me"}]}).to_string();
    let mock = Mock::new(200, &body, None);
    let output = mock.run(&["api-routes"], None);
    success(&output);
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap(), serde_json::from_str::<Value>(&body).unwrap());
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with("GET /api/capabilities HTTP/1.1\r\n"));
    assert!(calls[0].to_ascii_lowercase().contains("authorization: bearer private-test-token\r\n"));
}

#[test]
fn api_reads_file_or_stdin_json_with_repeated_query_and_step_up() {
    let mock = Mock::new(200, "{\"ok\":true}", None);
    let file = mock.dir.join("body.json");
    std::fs::write(&file, "{\"name\":\"雪\"}").unwrap();
    let file_arg = format!("@{}", file.display());
    for (source, input) in [(file_arg.as_str(), None), ("-", Some("{\"name\":\"雪\"}"))] {
        let output = mock.run(&["api","PATCH","/api/orgs/o/settings","--json",source,
            "--query","tag=one","--query","tag=two","--query","search=a&b=雪 +/?#","--step-up","test-step-up"], input);
        success(&output);
        assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap(), json!({"ok":true}));
        let calls = mock.calls.lock().unwrap();
        let request = calls.last().unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("PATCH /api/orgs/o/settings?"));
        let target = head.lines().next().unwrap().split_whitespace().nth(1).unwrap();
        let url = reqwest::Url::parse(&format!("{}{}", mock.base, target)).unwrap();
        assert_eq!(url.query_pairs().map(|(k,v)| (k.into_owned(),v.into_owned())).collect::<Vec<_>>(),
            vec![("tag".into(),"one".into()),("tag".into(),"two".into()),("search".into(),"a&b=雪 +/?#".into())]);
        assert!(head.to_ascii_lowercase().contains("x-openwarp-step-up: test-step-up\r\n"));
        assert_eq!(serde_json::from_str::<Value>(body).unwrap(), json!({"name":"雪"}));
    }
}

#[test]
fn api_all_methods_accept_204_without_json_parse_failure() {
    let mock = Mock::new(204, "", None);
    for method in ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"] {
        let output = mock.run(&["api",method,"/api/me"], None);
        success(&output);
        assert!(output.stdout.is_empty(), "204 must have empty stdout");
        assert!(mock.calls.lock().unwrap().last().unwrap().starts_with(&format!("{method} /api/me HTTP/1.1\r\n")));
    }
}

#[test]
fn api_preserves_http_failure_and_does_not_print_credentials() {
    for status in [400,401,403,404,409,429,500,503] {
        let mock = Mock::new(status, "{\"error\":\"management denied\"}", None);
        let output = mock.run(&["api","GET","/api/me"], None);
        assert!(!output.status.success());
        let diagnostic = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(diagnostic.contains("management denied"), "HTTP body lost: {diagnostic}");
        assert!(diagnostic.contains(&status.to_string()), "HTTP status lost: {diagnostic}");
        assert!(!diagnostic.contains("private-test-token"));
    }
}

#[test]
fn api_rejects_invalid_targets_methods_and_json_before_network() {
    let mock = Mock::new(200, "{}", None);
    for path in ["https://example.invalid/api/me","//example.invalid/api/me","/mcp","/api/../mcp",
        "/api/%252e%252e/mcp","/api/a%252f%252e%252e%252fb","/api/me%","/api/back\\slash","/api/bad\n"] {
        assert!(!mock.run(&["api","GET",path], None).status.success(), "accepted {path:?}");
    }
    for method in ["TRACE","CONNECT","BREW"] {
        assert!(!mock.run(&["api",method,"/api/me"], None).status.success());
    }
    assert!(!mock.run(&["api","POST","/api/orgs","--json","-"], Some("not json")).status.success());
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[test]
fn api_does_not_follow_cross_origin_or_same_origin_redirects() {
    let target = Mock::new(200, "{}", None);
    let source = Mock::new(307, "", Some(&format!("{}/capture", target.base)));
    assert!(!source.run(&["api","POST","/api/orgs","--json","-"], Some("{\"name\":\"private\"}")).status.success());
    assert!(target.calls.lock().unwrap().is_empty());
    assert_eq!(source.calls.lock().unwrap().len(), 1);
    let same = Mock::new(307, "", Some("/capture"));
    assert!(!same.run(&["api","GET","/api/me"], None).status.success());
    assert_eq!(same.calls.lock().unwrap().len(), 1);
}
