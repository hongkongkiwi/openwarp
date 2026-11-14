use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN: &str = "pagination-dummy-token";
static SEQ: AtomicU32 = AtomicU32::new(0);
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-cli-pagination-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); }
        Self(path)
    }
    fn run(&self, api: &Api, operation: &str, path: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp"));
        cmd.current_dir(&self.0).env_clear().env("HOME", &self.0).env("OPENWARP_CONFIG", self.0.join("config.json"))
            .env("OPENWARP_NO_KEYRING", "1").env("OPENWARP_HOST", &api.base).env("OPENWARP_TOKEN", TOKEN)
            .env("NO_PROXY", "*").env("no_proxy", "*").args([operation, "--env", "env", "api_key"]);
        if let Some(path) = path { cmd.args(["--path", path]); }
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap(); let mut stderr = child.stderr.take().unwrap();
        let stdout = std::thread::spawn(move || { let mut bytes = Vec::new(); stdout.read_to_end(&mut bytes).unwrap(); bytes });
        let stderr = std::thread::spawn(move || { let mut bytes = Vec::new(); stderr.read_to_end(&mut bytes).unwrap(); bytes });
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() { return Output { status, stdout: stdout.join().unwrap(), stderr: stderr.join().unwrap() }; }
            if Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("CLI exceeded 30 second deadline"); }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Sandbox { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn rejected(out: &Output) {
    assert!(!out.status.success(), "incomplete or ambiguous pagination unexpectedly succeeded");
    assert!(out.stdout.is_empty(), "rejected selection emitted stdout");
    for marker in [TOKEN, "dummy-first", "dummy-later", "dummy-other"] { assert!(!String::from_utf8_lossy(&out.stderr).contains(marker), "rejected selection exposed fixture material"); }
}
fn success(out: &Output) { assert!(out.status.success(), "CLI failed: {}", String::from_utf8_lossy(&out.stderr).replace(TOKEN, "[REDACTED fixture token]")); }

struct Api {
    base: String,
    calls: Arc<Mutex<Vec<(String, String, bool)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Api {
    fn new(first: Value, later: Value, mode: &str) -> Self {
        let mut pages = [json!({"secrets": first, "total": 4, "limit": 2, "offset": 0}), json!({"secrets": later, "total": 4, "limit": 2, "offset": 2})];
        match mode {
            "legacy" => pages[0] = json!({"secrets": pages[0]["secrets"]}),
            "partial" => pages[0] = json!({"secrets": pages[0]["secrets"], "total": 4}),
            "stalled" => pages[1]["offset"] = json!(0),
            _ => (),
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new())); let stop = Arc::new(AtomicBool::new(false));
        let (recorded, done) = (calls.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut reads = 0;
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() { Ok(v) => v, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(5)); continue; }, Err(_) => break };
                stream.set_nonblocking(false).unwrap(); stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap(); stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut bytes = Vec::new(); let mut buf = [0u8; 2048];
                while bytes.len() < 16384 && !bytes.windows(4).any(|w| w == b"\r\n\r\n") { match stream.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => bytes.extend_from_slice(&buf[..n]) } }
                if !bytes.windows(4).any(|w| w == b"\r\n\r\n") { continue; }
                let raw = String::from_utf8_lossy(&bytes); let mut line = raw.lines().next().unwrap_or("").split_whitespace();
                let method = line.next().unwrap_or("").to_string(); let target = line.next().unwrap_or("").to_string();
                let authorized = raw.lines().any(|l| l.split_once(':').is_some_and(|(k, v)| k.eq_ignore_ascii_case("authorization") && v.trim() == format!("Bearer {}", TOKEN)));
                recorded.lock().unwrap().push((method.clone(), target.clone(), authorized));
                let url = reqwest::Url::parse(&format!("http://127.0.0.1{}", target)).unwrap();
                let offset = url.query_pairs().find(|(k, _)| k == "offset").map(|(_, v)| v.parse::<usize>().unwrap_or(usize::MAX)).unwrap_or(0);
                let (status, reply) = if !authorized { (401, "{}".to_string()) }
                    else if method == "GET" && url.path() == "/api/envs/env/secrets" {
                        reads += 1;
                        if reads > 3 { (500, "{\"error\":\"fixture pagination request budget exceeded\"}".to_string()) }
                        else if (offset == 0 || offset == 2) && url.query_pairs().all(|(k, _)| k == "offset" || k == "limit") { (200, pages[offset / 2].to_string()) }
                        else { (404, "{}".to_string()) }
                    } else if method == "DELETE" && ["/api/secrets/first", "/api/secrets/later"].contains(&target.as_str()) { (200, "{\"deleted\":true}".to_string()) }
                    else { (404, "{}".to_string()) };
                let _ = stream.write_all(format!("HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, reply.len(), reply).as_bytes());
            }
        });
        Self { base, calls, stop, thread: Some(thread) }
    }
    fn assert_calls(&self, offsets: &[usize], deleted: Option<&str>) {
        let calls = self.calls.lock().unwrap(); let mut actual = Vec::new(); let mut deletes = Vec::new();
        for (method, target, authorized) in calls.iter() {
            assert!(authorized, "request omitted fixture bearer token");
            let url = reqwest::Url::parse(&format!("http://127.0.0.1{}", target)).unwrap();
            if method == "GET" { assert_eq!(url.path(), "/api/envs/env/secrets"); actual.push(url.query_pairs().find(|(k, _)| k == "offset").map(|(_, v)| v.parse::<usize>().unwrap()).unwrap_or(0)); }
            else { deletes.push((method.clone(), target.clone())); }
        }
        assert_eq!(actual, offsets, "lookup did not traverse the reported pages");
        let expected: Vec<(String, String)> = deleted.map(|id| vec![("DELETE".into(), format!("/api/secrets/{}", id))]).unwrap_or_default();
        assert_eq!(deletes, expected, "unexpected mutation or wrong target");
    }
}
impl Drop for Api { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); if let Some(thread) = self.thread.take() { thread.join().unwrap(); } } }
fn first() -> Value { json!({"id":"first", "key":"API_KEY", "path":"/", "value":"dummy-first"}) }
fn later() -> Value { json!({"id":"later", "key":"API_KEY", "path":"/team/", "value":"dummy-later"}) }
fn other() -> Value { json!({"id":"other", "key":"OTHER", "path":"/", "value":"dummy-other"}) }
fn other2() -> Value { json!({"id":"other2", "key":"OTHER2", "path":"/", "value":"dummy-other2"}) }

#[test]
fn duplicate_key_on_later_page_rejects_get_and_delete() {
    let s = Sandbox::new();
    for operation in ["get", "delete"] {
        let api = Api::new(json!([first(), other()]), json!([later(), other2()]), "valid");
        let out = s.run(&api, operation, None); api.assert_calls(&[0, 2], None); rejected(&out);
    }
}
#[test]
fn exact_path_target_on_later_page_gets_and_deletes() {
    let s = Sandbox::new();
    for operation in ["get", "delete"] {
        let api = Api::new(json!([other(), other2()]), json!([later(), first()]), "valid");
        let out = s.run(&api, operation, Some("/team/")); success(&out);
        if operation == "get" { assert_eq!(out.stdout, b"dummy-later\n"); }
        api.assert_calls(&[0, 2], if operation == "delete" { Some("later") } else { None });
    }
}
#[test]
fn invalid_pagination_fails_closed_but_legacy_no_metadata_is_complete() {
    let s = Sandbox::new();
    let api = Api::new(json!([first()]), json!([]), "legacy");
    let out = s.run(&api, "get", None); success(&out); assert_eq!(out.stdout, b"dummy-first\n"); success(&s.run(&api, "delete", None)); api.assert_calls(&[0, 0], Some("first"));
    for mode in ["partial", "stalled"] {
        for operation in ["get", "delete"] {
            let api = Api::new(json!([first(), other()]), json!([other(), other2()]), mode);
            let out = s.run(&api, operation, None); rejected(&out); api.assert_calls(if mode == "partial" { &[0] } else { &[0, 2] }, None);
        }
    }
}
