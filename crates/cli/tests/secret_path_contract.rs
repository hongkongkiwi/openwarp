use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN: &str = "path-contract-dummy-token";
static SEQ: AtomicU32 = AtomicU32::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-cli-path-contract-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir(&path).expect("private CLI directory");
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); }
        Self(path)
    }
    fn run(&self, api: &Api, operation: &str, path: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp"));
        cmd.current_dir(&self.0).env_clear().env("HOME", &self.0).env("OPENWARP_CONFIG", self.0.join("config.json"))
            .env("OPENWARP_NO_KEYRING", "1").env("OPENWARP_HOST", &api.base).env("OPENWARP_TOKEN", TOKEN)
            .env("NO_PROXY", "*").env("no_proxy", "*")
            .args([operation, "--env", "env", "aPi_KeY"]);
        if let Some(path) = path { cmd.args(["--path", path]); }
        bounded(&mut cmd)
    }
}
impl Drop for Sandbox { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn bounded(cmd: &mut Command) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn CLI");
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
fn success(out: &Output) {
    assert!(out.status.success(), "CLI failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).replace(TOKEN, "[REDACTED fixture token]"));
}
fn rejected(out: &Output) {
    assert!(!out.status.success(), "ambiguous or missing selection unexpectedly succeeded");
    assert!(out.stdout.is_empty(), "rejected selection emitted stdout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for marker in [TOKEN, "dummy-folder", "dummy-root", "dummy-nested", "dummy-other"] {
        assert!(!stderr.contains(marker), "rejected selection exposed fixture credentials or values");
    }
}

#[derive(Clone)]
struct Recorded { method: String, path: String, authorized: bool }
struct Api {
    base: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Api {
    fn new(secrets: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback API");
        let base = format!("http://{}", listener.local_addr().unwrap()); listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new())); let stop = Arc::new(AtomicBool::new(false));
        let (recorded, done) = (requests.clone(), stop.clone());
        let items = secrets.as_array().unwrap();
        let delete_paths: Vec<String> = items.iter().map(|s| format!("/api/secrets/{}", s["id"].as_str().unwrap())).collect();
        let body = json!({"total": items.len(), "secrets": secrets}).to_string();
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(5)); continue; },
                    Err(_) => break,
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap(); stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut bytes = Vec::new(); let mut buf = [0u8; 2048];
                while bytes.len() < 16384 && !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => bytes.extend_from_slice(&buf[..n]) }
                }
                if !bytes.windows(4).any(|w| w == b"\r\n\r\n") { continue; }
                let request = String::from_utf8_lossy(&bytes);
                let mut line = request.lines().next().unwrap_or("").split_whitespace();
                let method = line.next().unwrap_or("").to_string(); let path = line.next().unwrap_or("").to_string();
                let authorized = request.lines().any(|l| l.split_once(':').is_some_and(|(k, v)| k.eq_ignore_ascii_case("authorization") && v.trim() == format!("Bearer {}", TOKEN)));
                recorded.lock().unwrap().push(Recorded { method: method.clone(), path: path.clone(), authorized });
                let (status, reply) = if !authorized { (401, "{}") }
                    else if method == "GET" && path == "/api/envs/env/secrets" { (200, body.as_str()) }
                    else if method == "DELETE" && delete_paths.contains(&path) { (200, "{\"deleted\":true}") }
                    else { (404, "{\"error\":\"unexpected fixture route\"}") };
                let _ = stream.write_all(format!("HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, reply.len(), reply).as_bytes());
            }
        });
        Self { base, requests, stop, thread: Some(thread) }
    }
    fn assert_calls(&self, expected: &[(&str, &str)]) {
        let calls = self.requests.lock().unwrap();
        for call in calls.iter() { assert!(call.authorized, "request omitted fixture bearer token"); }
        let actual: Vec<(&str, &str)> = calls.iter().map(|call| (call.method.as_str(), call.path.as_str())).collect();
        assert_eq!(actual, expected, "wrong API route or unexpected mutation");
    }
}
impl Drop for Api { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); if let Some(thread) = self.thread.take() { thread.join().unwrap(); } } }
fn secrets() -> Value {
    json!([
        {"id": "other", "key": "OTHER", "path": "/team/", "value": "dummy-other"},
        {"id": "folder", "key": "API_KEY", "path": "/team/", "value": "dummy-folder"},
        {"id": "nested", "key": "API_KEY", "path": "/team/nested/", "value": "dummy-nested"},
        {"id": "root", "key": "API_KEY", "path": "/", "value": "dummy-root"}
    ])
}

#[test]
fn key_only_get_rejects_ambiguity_without_printing_a_value() {
    let sandbox = Sandbox::new(); let api = Api::new(secrets());
    let out = sandbox.run(&api, "get", None);
    api.assert_calls(&[("GET", "/api/envs/env/secrets")]); rejected(&out);
}

#[test]
fn key_only_delete_rejects_ambiguity_without_deleting() {
    let sandbox = Sandbox::new(); let api = Api::new(secrets());
    let out = sandbox.run(&api, "delete", None);
    api.assert_calls(&[("GET", "/api/envs/env/secrets")]); rejected(&out);
}

#[test]
fn explicit_root_and_folder_select_exact_path_and_case_insensitive_key() {
    let sandbox = Sandbox::new();
    for (path, id, value) in [("/", "root", "dummy-root"), ("/team/", "folder", "dummy-folder")] {
        let api = Api::new(secrets());
        let out = sandbox.run(&api, "get", Some(path)); success(&out); assert_eq!(String::from_utf8(out.stdout).unwrap(), format!("{}\n", value));
        success(&sandbox.run(&api, "delete", Some(path)));
        api.assert_calls(&[("GET", "/api/envs/env/secrets"), ("GET", "/api/envs/env/secrets"), ("DELETE", &format!("/api/secrets/{}", id))]);
    }
}

#[test]
fn missing_exact_path_never_returns_a_value_or_deletes() {
    let sandbox = Sandbox::new();
    for path in ["/missing/", "/team", "/TEAM/"] {
        for operation in ["get", "delete"] {
            let api = Api::new(secrets());
            let out = sandbox.run(&api, operation, Some(path));
            api.assert_calls(&[("GET", "/api/envs/env/secrets")]); rejected(&out);
            assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("not found"), "missing selection must report not found");
        }
    }
}

#[test]
fn unique_legacy_calls_work_without_a_path() {
    let sandbox = Sandbox::new(); let items = secrets(); let api = Api::new(json!(&items.as_array().unwrap()[..2]));
    let out = sandbox.run(&api, "get", None); success(&out); assert_eq!(out.stdout, b"dummy-folder\n");
    success(&sandbox.run(&api, "delete", None));
    api.assert_calls(&[("GET", "/api/envs/env/secrets"), ("GET", "/api/envs/env/secrets"), ("DELETE", "/api/secrets/folder")]);
}
