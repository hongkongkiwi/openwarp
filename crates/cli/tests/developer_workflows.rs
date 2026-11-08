use openwarp_crypto::Keypair;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);
const TOKEN: &str = "workflow-test-token-not-a-real-credential";
const BODY_SECRET: &str = "workflow-error-body-must-not-be-printed";
const VALUE: &str = "workflow-resolved-value-must-not-leak-on-error";

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openwarp-cli-workflows-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir(&path).expect("private test directory");
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); }
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf { self.0.join(name) }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path(name); fs::write(&path, bytes).unwrap(); path
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openwarp"));
        cmd.current_dir(&self.0).env("HOME", &self.0).env("OPENWARP_CONFIG", self.path("config.json"))
            .env("OPENWARP_NO_KEYRING", "1").env("OPENWARP_HOST", "http://127.0.0.1:1")
            .env_remove("OPENWARP_TOKEN").env_remove("OPENWARP_PRIVKEY")
            .env_remove("OW_SELECTED").env_remove("OW_UNSELECTED").env_remove("OW_ROOT").env_remove("OW_WORKFLOW_PROBE")
            .env_remove("HTTP_PROXY").env_remove("HTTPS_PROXY").env_remove("ALL_PROXY")
            .env_remove("http_proxy").env_remove("https_proxy").env_remove("all_proxy")
            .env("NO_PROXY", "*").env("no_proxy", "*");
        cmd
    }
    fn cli(&self, args: &[&str]) -> Output { bounded(self.command().args(args)) }
    fn remote(&self, server: &Api, args: &[&str]) -> Output {
        bounded(self.command().env("OPENWARP_HOST", &server.base).env("OPENWARP_TOKEN", TOKEN).args(args))
    }
    fn identity(&self, name: &str) -> (PathBuf, String) {
        let kp = Keypair::generate();
        let path = self.write(name, serde_json::to_vec(&json!({"public_key": kp.public, "private_key": kp.secret_b64()})).unwrap());
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap(); }
        (path, kp.public)
    }
}
impl Drop for Sandbox { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn text(path: &Path) -> &str { path.to_str().unwrap() }
fn bounded(cmd: &mut Command) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn CLI");
    let mut stdout = child.stdout.take().expect("CLI stdout pipe");
    let mut stderr = child.stderr.take().expect("CLI stderr pipe");
    // Drain both pipes while the child runs so a full pipe cannot mask its exit status.
    let stdout = std::thread::spawn(move || { let mut bytes = Vec::new(); stdout.read_to_end(&mut bytes).expect("read CLI stdout"); bytes });
    let stderr = std::thread::spawn(move || { let mut bytes = Vec::new(); stderr.read_to_end(&mut bytes).expect("read CLI stderr"); bytes });
    // Guards against a hung child, not against a slow one. The largest fixture
    // encrypts 16 MiB through the debug build, which takes seconds on an idle
    // machine and much longer when the host is busy, so the budget is generous.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Output { status, stdout: stdout.join().expect("stdout reader"), stderr: stderr.join().expect("stderr reader") };
        }
        if Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("CLI exceeded 120 second deadline"); }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn diagnostic(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).replace(TOKEN, "[REDACTED token]").replace(BODY_SECRET, "[REDACTED response body]").replace(VALUE, "[REDACTED resolved value]")
}
fn success(out: &Output, operation: &str) { assert!(out.status.success(), "{} failed ({}): {}", operation, out.status, diagnostic(out)); }
fn failure(out: &Output) {
    assert!(!out.status.success(), "operation unexpectedly succeeded");
    for marker in [TOKEN, BODY_SECRET, VALUE] {
        assert!(!String::from_utf8_lossy(&out.stdout).contains(marker), "sensitive fixture appeared in stdout");
        assert!(!String::from_utf8_lossy(&out.stderr).contains(marker), "sensitive fixture appeared in stderr");
    }
    assert!(out.stdout.is_empty(), "failed operation emitted partial stdout");
}
fn private(path: &Path) {
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600, "output must be owner read/write only");
    }
    #[cfg(not(unix))] { assert!(path.is_file()); }
}
fn encrypt(s: &Sandbox, input: &Path, recipients: &[&str], output: &Path) -> Output {
    let mut cmd = s.command(); cmd.args(["file", "encrypt", text(input)]);
    for recipient in recipients { cmd.args(["--recipient", recipient]); }
    bounded(cmd.args(["--out", text(output)]))
}
fn decrypt(s: &Sandbox, input: &Path, identity: &Path, output: &Path) -> Output {
    s.cli(&["file", "decrypt", text(input), "--identity", text(identity), "--out", text(output)])
}
fn rekey(s: &Sandbox, input: &Path, identity: &Path, recipients: &[&str], output: &Path) -> Output {
    let mut cmd = s.command(); cmd.args(["file", "rekey", text(input), "--identity", text(identity)]);
    for recipient in recipients { cmd.args(["--recipient", recipient]); }
    bounded(cmd.args(["--out", text(output)]))
}
fn envelope(path: &Path) -> Value {
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).expect("Git-storable JSON envelope");
    assert_eq!(v["version"], 1, "new file envelope version");
    assert!(v["payload"].as_str().is_some_and(|s| !s.is_empty()), "encrypted payload string"); v
}
fn altered_payload(mut v: Value) -> Value {
    let mut bytes = v["payload"].as_str().unwrap().as_bytes().to_vec();
    let start = bytes.iter().position(|b| *b == b':').map(|n| n + 1).unwrap_or(0);
    let n = start + (bytes.len() - start) / 2;
    bytes[n] = if bytes[n] == b'A' { b'B' } else { b'A' };
    v["payload"] = json!(String::from_utf8(bytes).unwrap()); v
}

#[test]
fn file_keygen_writes_a_private_usable_identity_without_login() {
    let s = Sandbox::new(); let path = s.path("identity.json");
    let out = s.cli(&["file", "keygen", "--out", text(&path)]);
    success(&out, "offline file keygen"); private(&path);
    let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let secret = v["private_key"].as_str().expect("private_key string");
    let kp = Keypair::from_secret_b64(secret).expect("valid recovery private key");
    assert_eq!(v["public_key"].as_str(), Some(kp.public.as_str()));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(secret), "private key leaked to stdout");
    assert!(!String::from_utf8_lossy(&out.stderr).contains(secret), "private key leaked to stderr");
}

#[test]
fn file_binary_and_empty_roundtrip_for_each_recipient() {
    let s = Sandbox::new(); let (a, ap) = s.identity("a.json"); let (b, bp) = s.identity("b.json");
    for (name, bytes) in [("binary", (0..=255u8).cycle().take(8193).collect::<Vec<_>>()), ("empty", Vec::new())] {
        let input = s.write(name, &bytes); let encrypted = s.path(&format!("{}.ow", name));
        success(&encrypt(&s, &input, &[&ap, &bp], &encrypted), "offline multiple-recipient encryption");
        envelope(&encrypted); private(&encrypted);
        assert_eq!(fs::read(&input).unwrap(), bytes, "source changed");
        for (i, id) in [&a, &b].iter().enumerate() {
            let output = s.path(&format!("{}.{}.plain", name, i));
            success(&decrypt(&s, &encrypted, id, &output), "recipient decrypt");
            assert_eq!(fs::read(&output).unwrap(), bytes, "binary content changed"); private(&output);
        }
    }
}

#[test]
fn file_wrong_identity_tamper_malformed_and_unknown_version_fail_without_output() {
    let s = Sandbox::new(); let (id, public) = s.identity("id.json"); let (wrong, next) = s.identity("wrong.json");
    let input = s.write("plain", VALUE); let encrypted = s.path("encrypted");
    success(&encrypt(&s, &input, &[&public], &encrypted), "encryption control");
    let v = envelope(&encrypted);
    assert!(!String::from_utf8_lossy(&fs::read(&encrypted).unwrap()).contains(VALUE), "file envelope contains plaintext");
    let output = s.path("wrong-output"); failure(&decrypt(&s, &encrypted, &wrong, &output)); assert!(!output.exists());
    let mut unknown = v.clone(); unknown["version"] = json!(2147483647);
    let cases = [serde_json::to_vec(&altered_payload(v)).unwrap(), serde_json::to_vec(&unknown).unwrap(), b"{}".to_vec(), b"\x00not an envelope".to_vec()];
    for (i, bytes) in cases.iter().enumerate() {
        let bad = s.write(&format!("bad-{}", i), bytes);
        let output = s.path(&format!("bad-{}.plain", i)); failure(&decrypt(&s, &bad, &id, &output)); assert!(!output.exists());
        let output = s.path(&format!("bad-{}.rekey", i)); failure(&rekey(&s, &bad, &id, &[&next], &output)); assert!(!output.exists(), "rekey must authenticate original payload");
    }
    let output = s.path("wrong-rekey"); failure(&rekey(&s, &encrypted, &wrong, &[&next], &output)); assert!(!output.exists());
}

#[test]
fn file_rekey_replaces_recipients_but_preserves_authenticated_payload() {
    let s = Sandbox::new(); let (old, op) = s.identity("old.json"); let (a, ap) = s.identity("a.json"); let (b, bp) = s.identity("b.json");
    let bytes: Vec<u8> = (0..=255u8).cycle().take(10001).collect();
    let input = s.write("plain", &bytes); let encrypted = s.path("original"); let changed = s.path("rekeyed");
    success(&encrypt(&s, &input, &[&op], &encrypted), "encryption control"); let before = fs::read(&encrypted).unwrap();
    success(&rekey(&s, &encrypted, &old, &[&ap, &bp], &changed), "offline recipient rekey"); private(&changed);
    assert_eq!(envelope(&encrypted)["payload"], envelope(&changed)["payload"], "rekey must not reencrypt file payload");
    assert_eq!(fs::read(&encrypted).unwrap(), before, "rekey modified source envelope");
    for (i, id) in [&a, &b].iter().enumerate() {
        let output = s.path(&format!("new-{}", i)); success(&decrypt(&s, &changed, id, &output), "new recipient decrypt"); assert_eq!(fs::read(output).unwrap(), bytes);
    }
    let output = s.path("old-denied"); failure(&decrypt(&s, &changed, &old, &output)); assert!(!output.exists());
}

#[test]
fn file_outputs_refuse_overwrite_source_and_symlinks() {
    let s = Sandbox::new(); let (id, public) = s.identity("id.json");
    let input = s.write("plain", b"source must survive"); let encrypted = s.path("encrypted");
    success(&encrypt(&s, &input, &[&public], &encrypted), "encryption control");
    for operation in ["keygen", "encrypt", "decrypt", "rekey"] {
        let invoke = |output: &Path| match operation {
            "keygen" => s.cli(&["file", "keygen", "--out", text(output)]),
            "encrypt" => encrypt(&s, &input, &[&public], output),
            "decrypt" => decrypt(&s, &encrypted, &id, output),
            _ => rekey(&s, &encrypted, &id, &[&public], output),
        };
        let existing = s.write(&format!("{}-existing", operation), b"do not replace");
        failure(&invoke(&existing)); assert_eq!(fs::read(&existing).unwrap(), b"do not replace");
        #[cfg(unix)] for dangling in [false, true] {
            let target = s.path(&format!("{}-target-{}", operation, dangling));
            if !dangling { fs::write(&target, b"symlink target").unwrap(); }
            let link = s.path(&format!("{}-link-{}", operation, dangling)); std::os::unix::fs::symlink(&target, &link).unwrap();
            failure(&invoke(&link)); assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
            if dangling { assert!(!target.exists()); } else { assert_eq!(fs::read(&target).unwrap(), b"symlink target"); }
        }
    }
    let before = fs::read(&encrypted).unwrap();
    failure(&encrypt(&s, &input, &[&public], &input)); assert_eq!(fs::read(&input).unwrap(), b"source must survive");
    failure(&decrypt(&s, &encrypted, &id, &encrypted));
    failure(&rekey(&s, &encrypted, &id, &[&public], &encrypted)); assert_eq!(fs::read(&encrypted).unwrap(), before);
}

#[test]
fn file_encrypt_accepts_16_mib_and_rejects_larger_input_and_invalid_recipients() {
    let s = Sandbox::new(); let (id, public) = s.identity("id.json");
    let bytes = vec![0xa5; 16 * 1024 * 1024]; let input = s.write("limit", &bytes); let encrypted = s.path("limit.ow");
    success(&encrypt(&s, &input, &[&public], &encrypted), "16 MiB boundary encryption");
    let output = s.path("limit.plain"); success(&decrypt(&s, &encrypted, &id, &output), "16 MiB boundary decrypt"); assert_eq!(fs::read(output).unwrap(), bytes);
    let oversized = s.write("oversized", vec![0xa5; 16 * 1024 * 1024 + 1]); let output = s.path("oversized.ow");
    failure(&encrypt(&s, &oversized, &[&public], &output)); assert!(!output.exists());
    for (i, recipients) in [vec![], vec!["invalid-base64"], vec![public.as_str(), "invalid-base64"]].iter().enumerate() {
        let output = s.path(&format!("invalid-recipient-{}", i)); failure(&encrypt(&s, &input, recipients, &output)); assert!(!output.exists());
    }
}

#[derive(Clone)]
struct Reply { status: u16, body: String }
struct Api {
    base: String,
    routes: Arc<Mutex<HashMap<String, Reply>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Api {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake API");
        let base = format!("http://{}", listener.local_addr().unwrap()); listener.set_nonblocking(true).unwrap();
        let routes = Arc::new(Mutex::new(HashMap::<String, Reply>::new())); let requests = Arc::new(Mutex::new(Vec::new())); let stop = Arc::new(AtomicBool::new(false));
        let (r, q, done) = (routes.clone(), requests.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() { Ok(v) => v, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(5)); continue; }, Err(_) => break };
                // A nonblocking listener hands out nonblocking connections on
                // macOS, so a read that finds no data yet returns WouldBlock and
                // the client is dropped mid-request. Linux does not inherit the
                // flag, which is why this only showed up locally.
                stream.set_nonblocking(false).unwrap();
                // These bound a hung client, not a slow one: the CLI under test
                // shares the host with the rest of the suite, so a two second
                // budget drops requests that are merely waiting for a CPU slot.
                stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap(); stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
                let mut bytes = Vec::new(); let mut buf = [0u8; 8192];
                // Reply only once the whole body has arrived. Answering at the
                // header terminator closes the socket while the client is still
                // writing, and the client then reports a spurious send error.
                loop {
                    match stream.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => bytes.extend_from_slice(&buf[..n]) }
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..end]).to_string();
                        let need = head.lines().find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None }
                        }).unwrap_or(0);
                        if bytes.len() >= end + 4 + need { break; }
                    }
                    if bytes.len() > 8 * 1024 * 1024 { break; }
                }
                if !bytes.windows(4).any(|w| w == b"\r\n\r\n") { continue; }
                let request = String::from_utf8_lossy(&bytes); let line = request.lines().next().unwrap_or("").to_string();
                q.lock().unwrap().push(line.clone());
                let authorized = request.lines().any(|l| l.split_once(':').is_some_and(|(k, v)| k.eq_ignore_ascii_case("authorization") && v.trim() == format!("Bearer {}", TOKEN)));
                let path = line.split_whitespace().nth(1).unwrap_or("").split('?').next().unwrap_or("");
                let reply = if !authorized { Reply { status: 401, body: "{}".into() } } else { r.lock().unwrap().get(path).cloned().unwrap_or(Reply { status: 404, body: "{}".into() }) };
                let _ = stream.write_all(format!("HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.status, reply.body.len(), reply.body).as_bytes());
            }
        });
        Self { base, routes, requests, stop, thread: Some(thread) }
    }
    fn raw(&self, env: &str, status: u16, body: String) { self.routes.lock().unwrap().insert(format!("/api/envs/{}/secrets", env), Reply { status, body }); }
    fn secrets(&self, env: &str, items: Value) {
        let total = items.as_array().unwrap().len(); self.raw(env, 200, json!({"secrets": items, "total": total, "limit": 500, "offset": 0}).to_string());
    }
    fn only_secret_reads(&self) {
        let requests = self.requests.lock().unwrap(); assert!(!requests.is_empty(), "no authorized secret reads");
        for line in requests.iter() { assert!(line.starts_with("GET /api/envs/") && line.split_whitespace().nth(1).unwrap().split('?').next().unwrap().ends_with("/secrets"), "unexpected API route: {}", line); }
    }
}
impl Drop for Api { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst); if let Some(t) = self.thread.take() { t.join().unwrap(); } } }
fn secret(path: &str, key: &str, value: &str) -> Value { json!({"id": format!("{}{}", path, key), "path": path, "key": key, "value": value, "type": "secret", "decrypt_error": false, "version": 1}) }
fn template(s: &Sandbox, contents: &str) -> PathBuf { s.write("template", contents) }

#[test]
fn inject_resolves_root_scoped_and_percent_encoded_references_without_recursive_expansion() {
    let s = Sandbox::new(); let api = Api::new(); let (identity, _) = s.identity("identity.json");
    api.secrets("env-a", json!([secret("/", "ROOT", "root"), secret("/team ops/db/", "API%KEY", "quoted\"\nvalue"), secret("/other/", "ROOT", "wrong path")]));
    api.secrets("env-b", json!([secret("/", "ROOT", "{{ow://env-a/ROOT}}")]));
    let input = template(&s, "root={{ow://env-a/ROOT}}\nscoped={{ow://env-a/team%20ops/db/API%25KEY}}\nliteral={{ow://env-b/ROOT}}\n");
    let expected = b"root=root\nscoped=quoted\"\nvalue\nliteral={{ow://env-a/ROOT}}\n";
    let out = s.remote(&api, &["inject", "--input", text(&input), "--identity", text(&identity)]);
    success(&out, "template injection"); assert_eq!(out.stdout, expected);
    let output = s.path("rendered"); let out = s.remote(&api, &["inject", "--input", text(&input), "--out", text(&output)]);
    success(&out, "template injection to private new file"); assert!(out.stdout.is_empty()); assert_eq!(fs::read(&output).unwrap(), expected); private(&output);
    failure(&s.remote(&api, &["inject", "--input", text(&input), "--out", text(&output)])); assert_eq!(fs::read(&output).unwrap(), expected);
    #[cfg(unix)] {
        let target = s.path("dangling-target"); let link = s.path("rendered-link"); std::os::unix::fs::symlink(&target, &link).unwrap();
        failure(&s.remote(&api, &["inject", "--input", text(&input), "--out", text(&link)])); assert!(!target.exists());
    }
    api.only_secret_reads();
}

#[test]
fn inject_observes_rotation_and_revocation_on_each_consumption() {
    let s = Sandbox::new(); let api = Api::new(); let input = template(&s, "{{ow://env-a/ROOT}}");
    for value in ["first-version", "rotated-version"] {
        api.secrets("env-a", json!([secret("/", "ROOT", value)]));
        let out = s.remote(&api, &["inject", "--input", text(&input)]); success(&out, "fresh reference resolution"); assert_eq!(out.stdout, value.as_bytes());
    }
    api.raw("env-a", 403, json!({"error": BODY_SECRET}).to_string());
    failure(&s.remote(&api, &["inject", "--input", text(&input)])); api.only_secret_reads();
}

#[test]
fn inject_errors_are_atomic_and_do_not_print_tokens_or_response_bodies() {
    let s = Sandbox::new(); let api = Api::new(); api.secrets("env-a", json!([secret("/", "ROOT", VALUE)]));
    let input = template(&s, "{{ow://env-a/ROOT}}"); success(&s.remote(&api, &["inject", "--input", text(&input)]), "inject control");
    for (i, reference) in ["ow://env-a/MISSING", "ow://denied/ROOT", "ow://foreign-tenant/ROOT", "ow://http-error/ROOT", "ow://invalid-json/ROOT", "ow://ambiguous/ROOT", "ow://sealed/ROOT", "ow://broken/ROOT", "ow://", "ow://env-a", "ow://env-a/path/%ZZ", "ow://env-a/ROOT?query=1", "ow://env-a/ROOT#fragment"].iter().enumerate() {
        api.raw("denied", 403, json!({"error": BODY_SECRET}).to_string()); api.raw("foreign-tenant", 404, json!({"error": BODY_SECRET}).to_string());
        api.raw("http-error", 500, json!({"secrets": [secret("/", "ROOT", BODY_SECRET)]}).to_string()); api.raw("invalid-json", 200, BODY_SECRET.into());
        api.secrets("ambiguous", json!([secret("/", "ROOT", BODY_SECRET), secret("/", "ROOT", "duplicate")]));
        let mut sealed = secret("/", "ROOT", BODY_SECRET); sealed["type"] = json!("sealed"); sealed["value"] = Value::Null; api.secrets("sealed", json!([sealed]));
        let mut broken = secret("/", "ROOT", BODY_SECRET); broken["decrypt_error"] = json!(true); api.secrets("broken", json!([broken]));
        let input = template(&s, &format!("prefix={{{{ow://env-a/ROOT}}}};bad={{{{{}}}}}", reference));
        failure(&s.remote(&api, &["inject", "--input", text(&input)]));
        let output = s.path(&format!("failed-render-{}", i)); failure(&s.remote(&api, &["inject", "--input", text(&input), "--out", text(&output)])); assert!(!output.exists());
    }
    let input = template(&s, "prefix={{ow://env-a/ROOT}};unterminated={{ow://env-a/ROOT");
    failure(&s.remote(&api, &["inject", "--input", text(&input)])); api.only_secret_reads();
}

#[test]
fn reference_child_probe() {
    if let Ok(path) = std::env::var("OW_WORKFLOW_PROBE") {
        fs::write(path, serde_json::to_vec(&json!({"selected": std::env::var("OW_SELECTED").ok(), "unselected": std::env::var("OW_UNSELECTED").ok(), "root": std::env::var("OW_ROOT").ok(), "argv": std::env::args().collect::<Vec<_>>()})).unwrap()).unwrap();
    }
}
fn run_refs(s: &Sandbox, api: &Api, refs: &Path, marker: &Path) -> Output {
    bounded(s.command().env("OPENWARP_HOST", &api.base).env("OPENWARP_TOKEN", TOKEN).env("OW_WORKFLOW_PROBE", marker)
        .args(["run", "--env", "env-a", "--refs-file", text(refs), "--", text(&std::env::current_exe().unwrap()), "--exact", "reference_child_probe", "--nocapture", "--skip", "ow://env-a/ROOT"]))
}

#[test]
fn run_refs_file_injects_only_explicit_bindings_and_never_expands_argv() {
    let s = Sandbox::new(); let api = Api::new();
    api.secrets("env-a", json!([secret("/", "ROOT", "root secret"), secret("/", "OW_UNSELECTED", "must not be injected"), secret("/", "OW_ROOT", "must not be injected either"), secret("/nested/", "SELECTED", VALUE)]));
    let refs = s.write("refs.json", json!({"OW_SELECTED": "ow://env-a/nested/SELECTED"}).to_string()); let marker = s.path("child.json");
    let out = run_refs(&s, &api, &refs, &marker); success(&out, "explicit reference child injection");
    let probe: Value = serde_json::from_slice(&fs::read(&marker).expect("child was launched")).unwrap();
    assert_eq!(probe["selected"], VALUE); assert!(probe["unselected"].is_null()); assert!(probe["root"].is_null());
    assert!(probe["argv"].as_array().unwrap().iter().any(|v| v == "ow://env-a/ROOT"), "secret reference argv must stay literal");
    for marker in [TOKEN, VALUE, "root secret", "must not be injected"] {
        assert!(!String::from_utf8_lossy(&out.stdout).contains(marker)); assert!(!String::from_utf8_lossy(&out.stderr).contains(marker));
    }
    api.only_secret_reads();
}

#[test]
fn run_without_refs_file_keeps_existing_whole_environment_export() {
    let s = Sandbox::new(); let api = Api::new();
    api.routes.lock().unwrap().insert("/api/envs/env-a/export".into(), Reply { status: 200, body: json!({"secrets": [secret("/", "OW_SELECTED", VALUE), secret("/", "OW_UNSELECTED", "legacy-export-value")]}).to_string() });
    let marker = s.path("legacy-child");
    let out = bounded(s.command().env("OPENWARP_HOST", &api.base).env("OPENWARP_TOKEN", TOKEN).env("OW_WORKFLOW_PROBE", &marker)
        .args(["run", "--env", "env-a", "--", text(&std::env::current_exe().unwrap()), "--exact", "reference_child_probe", "--nocapture"]));
    success(&out, "legacy whole environment run");
    let probe: Value = serde_json::from_slice(&fs::read(marker).expect("legacy child launched")).unwrap();
    assert_eq!(probe["selected"], VALUE); assert_eq!(probe["unselected"], "legacy-export-value");
    assert_eq!(*api.requests.lock().unwrap(), vec!["GET /api/envs/env-a/export HTTP/1.1"]);
}

#[test]
fn run_refs_file_resolves_every_reference_before_launch_and_fails_closed() {
    let s = Sandbox::new(); let api = Api::new(); api.secrets("env-a", json!([secret("/", "ROOT", VALUE)]));
    let control = s.write("control.json", json!({"OW_SELECTED": "ow://env-a/ROOT"}).to_string()); let marker = s.path("control-child");
    success(&run_refs(&s, &api, &control, &marker), "run refs control"); assert!(marker.exists());
    api.raw("denied", 403, json!({"error": BODY_SECRET}).to_string()); api.raw("foreign-tenant", 404, json!({"error": BODY_SECRET}).to_string());
    api.raw("http-error", 500, json!({"error": BODY_SECRET}).to_string()); api.raw("invalid-json", 200, BODY_SECRET.into());
    for (i, reference) in ["ow://env-a/MISSING", "ow://denied/ROOT", "ow://foreign-tenant/ROOT", "ow://http-error/ROOT", "ow://invalid-json/ROOT", "ow://env-a/%ZZ", "not-a-reference"].iter().enumerate() {
        let refs = s.write("bad-refs.json", json!({"A_VALID": "ow://env-a/ROOT", "Z_INVALID": reference}).to_string()); let marker = s.path(&format!("forbidden-child-{}", i));
        failure(&run_refs(&s, &api, &refs, &marker)); assert!(!marker.exists(), "child launched before all references resolved");
    }
    for (i, body) in ["{", "[]", "{\"OW_SELECTED\":3}"].iter().enumerate() {
        let refs = s.write("malformed.json", body); let marker = s.path(&format!("malformed-child-{}", i)); failure(&run_refs(&s, &api, &refs, &marker)); assert!(!marker.exists());
    }
    let marker = s.path("missing-refs-child"); failure(&run_refs(&s, &api, &s.path("missing-refs.json"), &marker)); assert!(!marker.exists());
    api.only_secret_reads();
}
