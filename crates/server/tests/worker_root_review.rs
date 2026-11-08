use openwarp_crypto as oc;
use openwarp_server::{app::load_master, db::Db, kms::Kms};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU32 = AtomicU32::new(0);

fn command(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("OPENWARP_ROOT_REVIEW_CASE", name).env("NO_PROXY", "*").env("no_proxy", "*");
    for key in ["OPENWARP_MASTER_KEY", "OPENWARP_KMS_URL", "OPENWARP_KMS_TOKEN", "OPENWARP_KMS_KEY_ID", "OPENWARP_ENV", "OPENWARP_ALLOW_PRIVATE_EGRESS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "OPENWARP_ROOT_REVIEW_CHILD", "OPENWARP_ROOT_REVIEW_DIR"] { command.env_remove(key); }
    command
}
fn isolated(name: &str) -> bool {
    if std::env::var("OPENWARP_ROOT_REVIEW_CASE").ok().as_deref() == Some(name) { return false; }
    let output = command(name).output().expect("start isolated root review test");
    assert!(output.status.success(), "isolated case {name} failed:\n{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    true
}

struct PrivateDb { db: Db, dir: PathBuf }
impl PrivateDb {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-root-review-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap();
        let db = Db::open(&format!("sqlite://{}", dir.join("test.db").display())).await.unwrap();
        Self { db, dir }
    }
}
impl Drop for PrivateDb { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

struct Bridge { kms: Kms, task: tokio::task::JoinHandle<()> }
impl Drop for Bridge { fn drop(&mut self) { self.task.abort(); } }
impl Bridge {
    async fn new() -> Self {
        let app = axum::Router::new().route("/{operation}", axum::routing::post(
            |axum::extract::Path(op): axum::extract::Path<String>, axum::Json(body): axum::Json<Value>| async move {
                assert_eq!(body["context"], "master");
                assert_eq!(body["key_id"], "primary");
                if op == "wrap" { axum::Json(json!({"wrapped": body["plaintext"].clone()})) }
                else { assert_eq!(op, "unwrap"); axum::Json(json!({"plaintext": body["wrapped"].clone()})) }
            }
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        std::env::set_var("OPENWARP_KMS_URL", format!("http://{}", listener.local_addr().unwrap()));
        std::env::set_var("OPENWARP_ALLOW_PRIVATE_EGRESS", "1");
        let kms = Kms::from_env().unwrap().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        Self { kms, task }
    }
}
async fn seed(db: &Db, name: &str, value: &str) {
    db.exec("INSERT INTO meta(k,v) VALUES(?,?)", &[json!(name), json!(value)]).await.unwrap();
}
async fn roots(db: &Db) -> Vec<Value> {
    db.query("SELECT k,v FROM meta WHERE k IN ('master','kms_root','master_key_check') ORDER BY k", &[]).await.unwrap()
}
async fn meta(db: &Db, name: &str) -> Option<String> {
    db.one("SELECT v FROM meta WHERE k=?", &[json!(name)]).await.unwrap().map(|r| r["v"].as_str().unwrap().to_string())
}
fn envelope(root: &[u8]) -> String { format!("owkms:primary:{}", oc::b64(root)) }
async fn verifier(db: &Db, root: &[u8; 32]) {
    seed(db, "master_key_check", &oc::encrypt_symmetric(root, b"openwarp-master-key-v1")).await;
}
async fn account(db: &Db, root: &[u8; 32]) -> String {
    let encrypted = oc::encrypt_symmetric_aad(root, b"auth-key|review-account", &[0x35; 32]);
    db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,auth_key_enc) VALUES(?,?,?,?,?,?,?)",
        &[json!("review-account"), json!("root-review@example.invalid"), json!("unused"), json!("unused"), json!("unused"), json!(1), json!(&encrypted)]).await.unwrap();
    encrypted
}

#[tokio::test]
async fn review_verifier_does_not_hide_mixed_account_inventory() {
    if isolated("review_verifier_does_not_hide_mixed_account_inventory") { return; }
    let fixture = PrivateDb::new().await;
    let bridge = Bridge::new().await;
    let root = [0x81; 32];
    seed(&fixture.db, "master", &oc::b64(&root)).await;
    seed(&fixture.db, "kms_root", &envelope(&root)).await;
    verifier(&fixture.db, &root).await;
    let encrypted = account(&fixture.db, &[0x82; 32]).await;
    let before = roots(&fixture.db).await;
    let result = load_master(&fixture.db, Some(&bridge.kms)).await;
    let after = roots(&fixture.db).await;
    assert!(result.is_err() && after == before, "valid verifier must not bypass mixed account inventory or delete either recovery root (refused={}, roots_unchanged={})", result.is_err(), after == before);
    let row = fixture.db.one("SELECT auth_key_enc FROM users WHERE id='review-account'", &[]).await.unwrap().unwrap();
    assert!(row["auth_key_enc"].as_str() == Some(encrypted.as_str()), "refused adoption must preserve account ciphertext");
}

#[tokio::test]
async fn review_matching_verifier_and_account_allow_kms_adoption() {
    if isolated("review_matching_verifier_and_account_allow_kms_adoption") { return; }
    let fixture = PrivateDb::new().await;
    let bridge = Bridge::new().await;
    let root = [0x83; 32];
    let wrapped = envelope(&root);
    seed(&fixture.db, "master", &oc::b64(&root)).await;
    seed(&fixture.db, "kms_root", &wrapped).await;
    verifier(&fixture.db, &root).await;
    let encrypted = account(&fixture.db, &root).await;
    assert!(load_master(&fixture.db, Some(&bridge.kms)).await.unwrap() == root, "consistent inventory must retain its root");
    assert!(meta(&fixture.db, "master").await.is_none(), "verified adoption may remove the duplicate local root");
    assert!(meta(&fixture.db, "kms_root").await.as_deref() == Some(wrapped.as_str()), "adoption must preserve the KMS envelope");
    let row = fixture.db.one("SELECT auth_key_enc FROM users WHERE id='review-account'", &[]).await.unwrap().unwrap();
    assert!(row["auth_key_enc"].as_str() == Some(encrypted.as_str()), "adoption must not rewrite account ciphertext");
}

#[tokio::test]
async fn review_no_kms_refuses_ambiguous_local_and_wrapped_roots() {
    if isolated("review_no_kms_refuses_ambiguous_local_and_wrapped_roots") { return; }
    let fixture = PrivateDb::new().await;
    let local = [0x84; 32];
    seed(&fixture.db, "master", &oc::b64(&local)).await;
    seed(&fixture.db, "kms_root", &envelope(&[0x85; 32])).await;
    verifier(&fixture.db, &local).await;
    let before = roots(&fixture.db).await;
    let result = load_master(&fixture.db, None).await;
    assert!(result.is_err(), "a local verifier cannot establish the identity of an inaccessible wrapped root");
    assert!(roots(&fixture.db).await == before, "ambiguous no-KMS boot must preserve all root state");
}

#[tokio::test]
async fn review_no_kms_supplied_root_needs_prior_identity_evidence() {
    if isolated("review_no_kms_supplied_root_needs_prior_identity_evidence") { return; }
    let fixture = PrivateDb::new().await;
    seed(&fixture.db, "kms_root", &envelope(&[0x86; 32])).await;
    std::env::set_var("OPENWARP_MASTER_KEY", oc::b64(&[0x87; 32]));
    let before = roots(&fixture.db).await;
    let result = load_master(&fixture.db, None).await;
    let after = roots(&fixture.db).await;
    assert!(result.is_err() && after == before, "unproven supplied root must be refused without manufacturing identity evidence (refused={}, roots_unchanged={})", result.is_err(), after == before);
}

#[tokio::test]
async fn review_no_kms_fallback_accepts_preexisting_verifier() {
    if isolated("review_no_kms_fallback_accepts_preexisting_verifier") { return; }
    let fixture = PrivateDb::new().await;
    let root = [0x88; 32];
    seed(&fixture.db, "kms_root", &envelope(&root)).await;
    verifier(&fixture.db, &root).await;
    std::env::set_var("OPENWARP_MASTER_KEY", oc::b64(&root));
    let before = roots(&fixture.db).await;
    assert!(load_master(&fixture.db, None).await.unwrap() == root, "preexisting matching verifier permits explicit original-root fallback");
    assert!(roots(&fixture.db).await == before, "verified fallback must preserve root custody and verifier");
}

struct Children(Vec<Child>);
impl Drop for Children { fn drop(&mut self) { for child in &mut self.0 { let _ = child.kill(); let _ = child.wait(); } } }
async fn wait_file(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(8), "concurrent loader did not reach its coordination point");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
fn blocked_write(attempt: i32) -> bool {
    let dir = PathBuf::from(std::env::var("OPENWARP_ROOT_REVIEW_DIR").unwrap());
    let id = std::env::var("OPENWARP_ROOT_REVIEW_CHILD").unwrap();
    std::fs::write(dir.join(format!("blocked-{id}")), b"blocked").unwrap();
    std::thread::sleep(Duration::from_millis(10));
    attempt < 1000
}

#[tokio::test]
async fn review_concurrent_supplied_roots_revalidate_verifier_winner() {
    let name = "review_concurrent_supplied_roots_revalidate_verifier_winner";
    if let Ok(id) = std::env::var("OPENWARP_ROOT_REVIEW_CHILD") {
        let dir = PathBuf::from(std::env::var("OPENWARP_ROOT_REVIEW_DIR").unwrap());
        let db = Db::connect_existing(&format!("sqlite://{}", dir.join("test.db").display())).await.unwrap();
        if let Db::Sqlite(conn) = &db { conn.lock().unwrap().busy_handler(Some(blocked_write)).unwrap(); }
        std::fs::write(dir.join(format!("ready-{id}")), b"ready").unwrap();
        wait_file(&dir.join("start")).await;
        let candidate: [u8; 32] = oc::unb64(&std::env::var("OPENWARP_MASTER_KEY").unwrap()).unwrap().try_into().unwrap();
        let result = load_master(&db, None).await;
        let report = json!({"ok": result.is_ok(), "matches_candidate": result.as_ref().map(|root| root == &candidate).unwrap_or(false)});
        std::fs::write(dir.join(format!("result-{id}")), serde_json::to_vec(&report).unwrap()).unwrap();
        return;
    }
    if isolated(name) { return; }
    let fixture = PrivateDb::new().await;
    assert!(roots(&fixture.db).await.is_empty(), "concurrent first boots start without root identity evidence");
    let candidates = [[0x91; 32], [0x92; 32]];
    let mut children = Children(Vec::new());
    for (id, root) in candidates.iter().enumerate() {
        children.0.push(command(name).env("OPENWARP_ROOT_REVIEW_CHILD", id.to_string())
            .env("OPENWARP_ROOT_REVIEW_DIR", &fixture.dir).env("OPENWARP_MASTER_KEY", oc::b64(root)).spawn().unwrap());
    }
    for id in 0..2 { wait_file(&fixture.dir.join(format!("ready-{id}"))).await; }
    let lock = rusqlite::Connection::open(fixture.dir.join("test.db")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    std::fs::write(fixture.dir.join("start"), b"start").unwrap();
    // Hold writes until both independent boots have read the same empty database.
    for id in 0..2 { wait_file(&fixture.dir.join(format!("blocked-{id}"))).await; }
    lock.execute_batch("COMMIT").unwrap();
    for id in 0..2 { wait_file(&fixture.dir.join(format!("result-{id}"))).await; }
    for child in &mut children.0 { assert!(child.wait().unwrap().success(), "concurrent loader subprocess must finish normally"); }
    let mut accepted = Vec::new();
    for (id, root) in candidates.iter().enumerate() {
        let report: Value = serde_json::from_slice(&std::fs::read(fixture.dir.join(format!("result-{id}"))).unwrap()).unwrap();
        if report["ok"] == true {
            assert_eq!(report["matches_candidate"], true, "a supplied root must not be silently replaced");
            accepted.push(root);
        }
    }
    assert_eq!(accepted.len(), 1, "different supplied roots must not both be accepted; the verifier-insert loser must revalidate persisted identity");
    let check = meta(&fixture.db, "master_key_check").await.expect("winning boot persists identity evidence");
    assert!(oc::decrypt_symmetric(accepted[0], &check).unwrap() == b"openwarp-master-key-v1", "accepted root must match persisted identity evidence");
    assert!(meta(&fixture.db, "master").await.is_none(), "externally supplied roots must not be persisted in plaintext");
    assert!(meta(&fixture.db, "kms_root").await.is_none(), "no-KMS boot must not create wrapped root state");
}
