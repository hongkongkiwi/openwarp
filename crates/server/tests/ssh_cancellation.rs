// SSH file sync cancellation and process-boundary tests.
//
// These tests drive the public `OPENWARP_SSH_BIN` seam with a disposable fake
// executable instead of a real ssh server. They pin the behaviour a cancelled
// (dropped / timed-out) SSH sync must have: the running ssh process and its
// descendants stop, later file read/write commands do not run, hostile stdout
// is bounded and rejected promptly, and staged credentials are removed. The
// fake is synchronised with the test through marker files, so cancellation is
// triggered only after the fake has actually hung (and recorded its pids),
// never on an incidental sleep.

#![cfg(all(unix, not(target_arch = "wasm32")))]

use openwarp_server::integrations::{ssh_file_pull, ssh_file_sync, ssh_file_test};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// Serialises the tests that mutate process-global environment variables
// (OPENWARP_SSH_BIN, FAKE_DIR, TMPDIR), which the test harness runs concurrently.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SEQ: AtomicU64 = AtomicU64::new(0);

const HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTestOnlyDoNotUse";

// A fake `ssh` executable. It logs every command it receives, records the pids
// of itself and (when hanging) a descendant, and picks its response from
// control files dropped into FAKE_DIR. Marker files hand the test a
// deterministic point to cancel at or to observe:
//
//   probe-present   -> the `if [ -e ... ]; then echo present ...` probe echoes "present"
//   hang-probe      -> the probe hangs forever (with a descendant) until killed; touches `hung`
//   cat-ok          -> `cat <path>` echoes "FOREIGN=keep"
//   cat-then-ok     -> `cat <path>` touches `cat-started`, sleeps 2s, then echoes "FOREIGN=keep"
//   hang-cat        -> `cat <path>` hangs forever
//   hang-write      -> the `mkdir ... && cat > ... && mv ...` write hangs forever
//   capture-write   -> the write command saves its stdin to FAKE_DIR/rendered
//   huge-stdout     -> `whoami` touches `stdout-started` then emits 17 MiB on stdout
//   every `mkdir` write command touches `write-ran`
//
// The hanging commands spawn a `sleep 300` descendant so a fix that kills only
// the direct child (not the process group) is observably wrong.
const FAKE_SCRIPT: &str = r#"#!/bin/sh
d="${FAKE_DIR:?FAKE_DIR not set}"
cmd=""
seen=0
for a in "$@"; do
  if [ "$seen" = "1" ]; then cmd="${cmd}${cmd:+ }$a"; fi
  if [ "$a" = "--" ]; then seen=1; fi
done
echo "$$|$cmd" >> "$d/log"
echo "$$" >> "$d/pids"
hang() {
  sleep 300 &
  c=$!
  echo "$c" >> "$d/pids"
  touch "$d/hung"
  wait "$c" 2>/dev/null
}
case "$cmd" in
  *"echo present"*)
    if [ -f "$d/hang-probe" ]; then hang; fi
    if [ -f "$d/probe-present" ]; then echo present; else echo missing; fi
    ;;
  cat*)
    if [ -f "$d/hang-cat" ]; then hang; fi
    if [ -f "$d/cat-then-ok" ]; then touch "$d/cat-started"; sleep 2; printf 'FOREIGN=keep\n'; fi
    if [ -f "$d/cat-ok" ]; then printf 'FOREIGN=keep\n'; fi
    ;;
  *mkdir*)
    touch "$d/write-ran"
    if [ -f "$d/hang-write" ]; then hang; fi
    if [ -f "$d/capture-write" ]; then cat > "$d/rendered"; fi
    ;;
  whoami*)
    if [ -f "$d/huge-stdout" ]; then touch "$d/stdout-started"; yes A | head -c 17825792; else echo root; fi
    ;;
esac
exit 0
"#;

struct FakeSsh {
    dir: PathBuf,
    staging: PathBuf,
}

// The first `FakeSsh::new` mutates TMPDIR, so `std::env::temp_dir()` would later
// return a previous test's staging dir and nest the fake trees. Cache the real
// temp dir once, before any mutation, and build every fake under it.
fn original_temp_dir() -> &'static Path {
    static BASE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BASE.get_or_init(std::env::temp_dir)
}

impl FakeSsh {
    fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let base = original_temp_dir().join(format!("openwarp-ssh-cancel-{}-{}", std::process::id(), n));
        let dir = base.join("fake");
        let staging = base.join("staging");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&staging).unwrap();
        let script = dir.join("ssh");
        std::fs::write(&script, FAKE_SCRIPT).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::env::set_var("OPENWARP_SSH_BIN", &script);
        std::env::set_var("FAKE_DIR", &dir);
        std::env::set_var("TMPDIR", &staging);
        Self { dir, staging }
    }

    fn control(&self, name: &str) {
        std::fs::write(self.dir.join(name), b"").unwrap();
    }

    fn marker(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
    }

    fn pids(&self) -> Vec<i32> {
        std::fs::read_to_string(self.dir.join("pids"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse::<i32>().ok())
            .collect()
    }

    fn kill_all(&self) {
        for pid in self.pids() {
            let _ = Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    fn rendered(&self) -> String {
        std::fs::read_to_string(self.dir.join("rendered")).unwrap_or_default()
    }
}

impl Drop for FakeSsh {
    fn drop(&mut self) {
        // Panic-safe: reap every recorded pid, then sweep again for late descendants.
        let base = self.dir.parent().map(|p| p.to_path_buf());
        self.kill_all();
        std::thread::sleep(Duration::from_millis(50));
        self.kill_all();
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_dir_all(&self.staging);
        if let Some(base) = base {
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}

fn base_config() -> Value {
    json!({
        "host": "127.0.0.1",
        "port": 22,
        "user": "root",
        "private_key": "fake-private-key-material",
        "known_hosts": HOST_KEY,
    })
}

fn one_file() -> Value {
    json!([{ "path": "/app/.env", "format": "dotenv", "folders": ["/app"] }])
}

fn one_secret() -> Vec<(String, String, String, String)> {
    vec![("/app".into(), "API_KEY".into(), "v1".into(), "secret".into())]
}

fn pid_running(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    match Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "stat="])
        .output()
    {
        Ok(out) => {
            let stat = String::from_utf8_lossy(&out.stdout);
            let stat = stat.trim();
            // A zombie has been stopped but not reaped; treat it as no longer running.
            !stat.is_empty() && !stat.starts_with('Z')
        }
        Err(_) => false,
    }
}

async fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_dead(pids: &[i32], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pids.iter().all(|&p| !pid_running(p)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn assert_no_staged_credentials(staging: &Path) {
    let mut leftovers = Vec::new();
    let mut stack = vec![staging.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("key-") || name.starts_with("hosts-") {
                        leftovers.push(path);
                    }
                }
            }
        }
    }
    assert!(leftovers.is_empty(), "staged ssh credentials left behind: {:?}", leftovers);
}

#[tokio::test]
async fn drop_stops_the_ssh_process_and_its_descendants() {
    let _guard = LOCK.lock().await;
    let fake = FakeSsh::new();
    fake.control("hang-probe");
    let mut config = base_config();
    config["files"] = one_file();
    let secrets = one_secret();
    let hung = fake.marker("hung");

    {
        let fut = ssh_file_sync(&config, &secrets, &[]);
        tokio::pin!(fut);
        let started = tokio::select! {
            _ = &mut fut => false,
            s = wait_for_file(&hung, Duration::from_secs(10)) => s,
        };
        assert!(started, "the fake ssh never hung with its descendant recorded");
        // `fut` drops here: this is the cancellation under test.
    }

    let pids = fake.pids();
    assert!(!pids.is_empty(), "the fake ssh never recorded a pid");
    let dead = wait_until_dead(&pids, Duration::from_secs(3)).await;
    let alive: Vec<i32> = pids.iter().copied().filter(|&p| pid_running(p)).collect();
    assert!(
        dead,
        "dropping the ssh future must stop the ssh process and its descendants; still running: {:?}",
        alive
    );
}

#[tokio::test]
async fn drop_stops_later_file_write_commands() {
    let _guard = LOCK.lock().await;
    let fake = FakeSsh::new();
    fake.control("probe-present");
    fake.control("cat-then-ok");
    let mut config = base_config();
    config["files"] = one_file();
    let secrets = one_secret();
    let cat_started = fake.marker("cat-started");
    let write_ran = fake.marker("write-ran");

    {
        let fut = ssh_file_sync(&config, &secrets, &[]);
        tokio::pin!(fut);
        let started = tokio::select! {
            _ = &mut fut => false,
            s = wait_for_file(&cat_started, Duration::from_secs(10)) => s,
        };
        assert!(started, "the fake ssh never started the cat command");
        // `fut` drops here: cancellation happens while cat is still running.
    }

    // `cat` would return after 2s; the handshake waits for any follow-up write.
    let write_happened = wait_for_file(&write_ran, Duration::from_secs(5)).await;
    assert!(
        !write_happened,
        "after cancellation no later file/write command may run; log:\n{}",
        fake.log()
    );
}

#[tokio::test]
async fn hostile_stdout_is_bounded() {
    let _guard = LOCK.lock().await;
    let fake = FakeSsh::new();
    fake.control("huge-stdout");
    let config = base_config();
    let stdout_started = fake.marker("stdout-started");

    let fut = ssh_file_test(&config);
    let (result, emitted) = tokio::join!(
        async { tokio::time::timeout(Duration::from_secs(4), fut).await },
        async { wait_for_file(&stdout_started, Duration::from_secs(8)).await },
    );
    assert!(emitted, "the fake ssh never started emitting its hostile stdout");

    match result {
        Err(_) => panic!("a hostile 17 MiB stdout made the ssh test hang; output must be bounded and rejected promptly"),
        Ok(Ok(report)) => panic!("a hostile 17 MiB stdout must be rejected, not returned ({} bytes)", report.len()),
        Ok(Err(e)) => assert!(
            !e.contains("could not be started"),
            "the reject must come from the output path, not a launch fixture: {}",
            e
        ),
    }
}

#[tokio::test]
async fn temp_credentials_are_cleaned_up_after_success() {
    let _guard = LOCK.lock().await;
    let fake = FakeSsh::new();
    fake.control("capture-write");
    let mut config = base_config();
    config["files"] = one_file();

    ssh_file_sync(&config, &one_secret(), &[]).await.expect("sync");
    assert!(fake.rendered().contains("API_KEY=v1"), "{}", fake.rendered());
    assert_no_staged_credentials(&fake.staging);
}

#[tokio::test]
async fn temp_credentials_are_cleaned_up_when_ssh_fails_to_launch() {
    let _guard = LOCK.lock().await;
    let fake = FakeSsh::new();
    std::env::set_var("OPENWARP_SSH_BIN", "/nonexistent/ssh-does-not-exist");
    let mut config = base_config();
    config["files"] = one_file();

    let err = ssh_file_sync(&config, &one_secret(), &[]).await.unwrap_err();
    assert!(!err.is_empty(), "a launch failure must surface an error");
    assert_no_staged_credentials(&fake.staging);
}

#[tokio::test]
async fn fake_ssh_preserves_the_sync_test_and_pull_contract() {
    let _guard = LOCK.lock().await;
    let fake = FakeSsh::new();
    let mut sync_config = base_config();
    sync_config["files"] = one_file();

    let (report, managed) = ssh_file_sync(&sync_config, &one_secret(), &[])
        .await
        .expect("normal sync must still succeed");
    assert!(report.contains("/app/.env: created=1"), "{}", report);
    assert_eq!(managed, vec!["/app/.env|API_KEY".to_string()]);

    let connection = ssh_file_test(&base_config()).await.expect("ssh test must succeed");
    assert!(connection.contains("SSH connection OK"), "{}", connection);

    fake.control("probe-present");
    fake.control("cat-ok");
    let mut pull_config = base_config();
    pull_config["path"] = "/app/.env".into();
    let pulled = ssh_file_pull(&pull_config).await.expect("pull must succeed");
    assert!(
        pulled.iter().any(|(k, v)| k == "FOREIGN" && v == "keep"),
        "{:?}",
        pulled
    );
}
