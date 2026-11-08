use openwarp_crypto as oc;
use openwarp_server::{app::load_master, db::Db, kms::Kms};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static SEQ: AtomicU32 = AtomicU32::new(0);

// Configuration is process-global on native builds of the shared Worker loader.
fn isolated(name: &str) -> bool {
    if std::env::var("OPENWARP_WORKER_ROOT_CASE").ok().as_deref() == Some(name) { return false; }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("OPENWARP_WORKER_ROOT_CASE", name).env("NO_PROXY", "*").env("no_proxy", "*");
    for key in ["OPENWARP_MASTER_KEY", "OPENWARP_KMS_URL", "OPENWARP_KMS_TOKEN", "OPENWARP_KMS_KEY_ID", "OPENWARP_ENV", "OPENWARP_ALLOW_PRIVATE_EGRESS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] { command.env_remove(key); }
    let output = command.output().expect("start isolated shared-root test");
    assert!(output.status.success(), "isolated case {name} failed:\n{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    true
}

struct PrivateDb { db: Db, dir: PathBuf }
impl PrivateDb {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-worker-root-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap();
        let db = Db::open(&format!("sqlite://{}", dir.join("test.db").display())).await.unwrap();
        Self { db, dir }
    }
}
impl Drop for PrivateDb { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

struct Bridge { kms: Kms, task: tokio::task::JoinHandle<()> }
impl Drop for Bridge { fn drop(&mut self) { self.task.abort(); } }
impl Bridge {
    async fn new(invalid_unwrap_length: Option<usize>) -> Self {
        let app = axum::Router::new().route("/{operation}", axum::routing::post(
            move |axum::extract::Path(op): axum::extract::Path<String>, axum::Json(body): axum::Json<Value>| {
                let invalid_length = invalid_unwrap_length;
                async move {
                    assert_eq!(body["context"], "master");
                    assert_eq!(body["key_id"], "primary");
                    if op == "wrap" { axum::Json(json!({"wrapped": body["plaintext"].clone()})) }
                    else {
                        assert_eq!(op, "unwrap");
                        let plain = if let Some(length) = invalid_length {
                            let mut bytes = oc::unb64(body["wrapped"].as_str().unwrap()).unwrap();
                            bytes[0] ^= 1;
                            bytes.truncate(length);
                            json!(oc::b64(&bytes))
                        } else { body["wrapped"].clone() };
                        axum::Json(json!({"plaintext": plain}))
                    }
                }
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
async fn roots(db: &Db) -> Vec<openwarp_server::db::Row> {
    db.query("SELECT k,v FROM meta WHERE k IN ('master','kms_root','master_key_check') ORDER BY k", &[]).await.unwrap()
}
async fn meta(db: &Db, name: &str) -> Option<String> {
    db.one("SELECT v FROM meta WHERE k=?", &[json!(name)]).await.unwrap().map(|r| r["v"].as_str().unwrap().to_string())
}
fn envelope(root: &[u8]) -> String { format!("owkms:primary:{}", oc::b64(root)) }

#[tokio::test]
async fn shared_loader_refuses_mixed_roots_without_mutation() {
    if isolated("shared_loader_refuses_mixed_roots_without_mutation") { return; }
    let fixture = PrivateDb::new().await;
    let bridge = Bridge::new(None).await;
    seed(&fixture.db, "master", &oc::b64(&[0x41; 32])).await;
    seed(&fixture.db, "kms_root", &envelope(&[0x42; 32])).await;
    let before = roots(&fixture.db).await;
    let result = load_master(&fixture.db, Some(&bridge.kms)).await;
    assert!(result.is_err(), "shared Worker loader must refuse different plaintext and KMS roots");
    assert!(roots(&fixture.db).await == before, "refusal must preserve both roots and not create a verifier");
}

#[tokio::test]
async fn shared_loader_cleans_up_only_matching_plaintext_root() {
    if isolated("shared_loader_cleans_up_only_matching_plaintext_root") { return; }
    let fixture = PrivateDb::new().await;
    let bridge = Bridge::new(None).await;
    let root = [0x43; 32];
    let wrapped = envelope(&root);
    seed(&fixture.db, "master", &oc::b64(&root)).await;
    seed(&fixture.db, "kms_root", &wrapped).await;
    assert!(load_master(&fixture.db, Some(&bridge.kms)).await.unwrap() == root, "matching roots must retain their identity");
    assert!(meta(&fixture.db, "kms_root").await.as_deref() == Some(wrapped.as_str()), "existing KMS envelope must remain unchanged");
    assert!(meta(&fixture.db, "master").await.is_none(), "successful interrupted adoption must remove duplicate plaintext root");
    assert!(load_master(&fixture.db, Some(&bridge.kms)).await.unwrap() == root, "restart must recover the same root");
}

#[tokio::test]
async fn shared_loader_concurrent_kms_mints_adopt_one_persisted_winner() {
    if isolated("shared_loader_concurrent_kms_mints_adopt_one_persisted_winner") { return; }
    let fixture = PrivateDb::new().await;
    let bridge = Bridge::new(None).await;
    // Both loads are polled before the local HTTP bridge can answer either wrap.
    let (first, second) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(load_master(&fixture.db, Some(&bridge.kms)), load_master(&fixture.db, Some(&bridge.kms)))
    }).await.expect("concurrent root loads must finish");
    assert!(first.is_ok() && second.is_ok(), "concurrent fresh boots must both adopt the persisted winner, not fail on a duplicate insert (first error: {:?}, second error: {:?})", first.as_ref().err(), second.as_ref().err());
    let first = first.unwrap();
    assert!(first == second.unwrap(), "concurrent loaders must never return divergent roots");
    let wrapped = meta(&fixture.db, "kms_root").await.expect("one persisted KMS root");
    assert!(bridge.kms.unwrap(&wrapped, "master").await.unwrap() == first, "returned roots must match the persisted KMS winner");
    assert!(meta(&fixture.db, "master").await.is_none(), "KMS mint must not leave a plaintext root");
    assert!(load_master(&fixture.db, Some(&bridge.kms)).await.unwrap() == first, "restart must recover the winning root");
}

#[tokio::test]
async fn shared_loader_verifies_kms_mint_roundtrip_before_persisting() {
    if isolated("shared_loader_verifies_kms_mint_roundtrip_before_persisting") { return; }
    for invalid in [32, 31] {
        let fixture = PrivateDb::new().await;
        let bridge = Bridge::new(Some(invalid)).await;
        let before = roots(&fixture.db).await;
        let result = load_master(&fixture.db, Some(&bridge.kms)).await;
        assert!(result.is_err(), "a newly wrapped root that unwraps to different or short bytes must be refused");
        assert!(roots(&fixture.db).await == before, "failed roundtrip must persist neither root nor verifier");
    }
}

#[tokio::test]
async fn shared_loader_adopts_plaintext_root_with_a_working_bridge() {
    if isolated("shared_loader_adopts_plaintext_root_with_a_working_bridge") { return; }
    let fixture = PrivateDb::new().await;
    let bridge = Bridge::new(None).await;
    let root = [0x61; 32];
    seed(&fixture.db, "master", &oc::b64(&root)).await;
    assert!(load_master(&fixture.db, Some(&bridge.kms)).await.unwrap() == root, "adoption must preserve the plaintext root identity");
    assert!(meta(&fixture.db, "master").await.is_none(), "verified adoption must remove plaintext root");
    let wrapped = meta(&fixture.db, "kms_root").await.unwrap();
    assert!(bridge.kms.unwrap(&wrapped, "master").await.unwrap() == root, "adopted envelope must recover the original root");
    assert!(load_master(&fixture.db, Some(&bridge.kms)).await.unwrap() == root, "adopted root must survive reload");
}

#[tokio::test]
async fn shared_loader_refuses_kms_root_without_bridge() {
    if isolated("shared_loader_refuses_kms_root_without_bridge") { return; }
    let fixture = PrivateDb::new().await;
    seed(&fixture.db, "kms_root", &envelope(&[0x71; 32])).await;
    let before = roots(&fixture.db).await;
    assert!(load_master(&fixture.db, None).await.is_err(), "missing KMS must not mint a replacement root");
    assert!(roots(&fixture.db).await == before, "missing KMS must leave persisted root state unchanged");
}

#[tokio::test]
async fn shared_loader_refuses_corrupt_roots_without_replacement() {
    if isolated("shared_loader_refuses_corrupt_roots_without_replacement") { return; }
    let bridge = Bridge::new(None).await;
    for value in ["not-base64!".to_string(), oc::b64(&[0x72; 31])] {
        for with_kms_root in [false, true] {
            let fixture = PrivateDb::new().await;
            seed(&fixture.db, "master", &value).await;
            if with_kms_root { seed(&fixture.db, "kms_root", &envelope(&[0x73; 32])).await; }
            let before = roots(&fixture.db).await;
            assert!(load_master(&fixture.db, Some(&bridge.kms)).await.is_err(), "corrupt plaintext root must be refused even when a valid KMS root exists");
            assert!(roots(&fixture.db).await == before, "corruption refusal must preserve recovery material");
        }
    }
    for value in ["not-an-envelope".to_string(), envelope(&[0x74; 31])] {
        let fixture = PrivateDb::new().await;
        seed(&fixture.db, "kms_root", &value).await;
        let before = roots(&fixture.db).await;
        assert!(load_master(&fixture.db, Some(&bridge.kms)).await.is_err(), "malformed or short KMS root must be refused");
        assert!(roots(&fixture.db).await == before, "corrupt KMS root must not be overwritten");
    }
}
