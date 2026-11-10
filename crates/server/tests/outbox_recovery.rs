// Transactional outbox recovery. The audit append, outbox event and per-target
// fan-out rows commit or roll back in one webhook_atomic transaction, and the
// synchronous drain moves a target into webhook_deliveries only while its
// subscription still matches and its delivery queue has room. These tests pin
// the failure modes the outbox must survive: a full queue must retain (not
// drop) its target, a restart between commit and fan-out must recover the
// persisted target exactly once, a full outbox must fail the originating
// business write with no partial audit head, and a full subscription must not
// starve an available hook.
//
// The dummy subscriptions point at a private loopback URL. destination()
// rejects http://127.0.0.1 without the private-egress override, so send()
// returns destination_blocked before any DNS or network I/O, and the delivery
// reaches a terminal state locally.

use openwarp_server::db::{n, s, Db};
use openwarp_server::{new_state, process_webhooks, router, PeerAddr, S};
use openwarp_crypto as oc;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "obr-session";
const ORG: &str = "obr-org";
const USER: &str = "obr-user";
const APP: &str = "obr-app";
const ENV: &str = "obr-env";
const HOOK_A: &str = "obr-hook-a";
const HOOK_B: &str = "obr-hook-b";

// http (not https) to a loopback address: the private-destination guard rejects
// it before the worker can resolve or dial it.
const BLOCKED_URL: &str = "http://127.0.0.1:9/never";

fn build_state(db: Db, master: [u8; 32]) -> S {
    let (live, _) = tokio::sync::broadcast::channel(8);
    new_state(db, String::new(), "obr".into(), "https://example.invalid".into(), master, live, #[cfg(feature = "redis-cache")] None)
}

async fn seed_base(db: &Db, master: &[u8; 32]) {
    let t = openwarp_server::clock::now();
    let env_key = oc::random_key();
    let wrapped = oc::encrypt_symmetric(master, &env_key);
    db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES(?,?,?,?,?,?)",
        &[json!(USER), json!("obr@test.invalid"), json!(""), json!(""), json!(""), json!(t)]).await.unwrap();
    db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(ORG), json!("obr"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(ORG), json!(USER), json!("owner")]).await.unwrap();
    db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(APP), json!(ORG), json!("obr"), json!(t)]).await.unwrap();
    db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,created_at) VALUES(?,?,?,?,?)",
        &[json!(ENV), json!(APP), json!("dev"), json!(wrapped), json!(t)]).await.unwrap();
    db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(TOKEN)), json!(USER), json!(t)]).await.unwrap();
}

async fn add_hook(db: &Db, id: &str) {
    let t = openwarp_server::clock::now();
    db.exec("INSERT INTO webhook_subscriptions(id,org_id,app_id,name,url,events,enabled,secret_enc,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        &[json!(id), json!(ORG), json!(""), json!(id), json!(BLOCKED_URL), json!(r#"["secret.deploy"]"#), json!(1), json!("dummy"), json!(1), json!(t), json!(t)]).await.unwrap();
}

async fn fixture(hooks: &[&str]) -> (S, [u8; 32]) {
    let db = Db::open_memory().await.unwrap();
    let master = oc::random_key();
    let state = build_state(db, master);
    seed_base(state.db(), &master).await;
    for hook in hooks { add_hook(state.db(), hook).await; }
    (state, master)
}

async fn call(state: &S, method: &str, uri: &str, body: Option<Value>) -> (u16, Value) {
    let mut b = axum::http::Request::builder().method(method).uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    if body.is_some() { b = b.header("content-type", "application/json"); }
    let mut req = match body {
        Some(v) => b.body(axum::body::Body::from(v.to_string())).unwrap(),
        None => b.body(axum::body::Body::empty()).unwrap(),
    };
    req.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
    let resp = router(state.to_owned()).oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn count(db: &Db, sql: &str, params: &[Value]) -> i64 {
    db.one(sql, params).await.unwrap().map(|r| n(&r, "n")).unwrap_or(0)
}

async fn head_seq(db: &Db) -> i64 {
    db.one("SELECT seq FROM audit_heads WHERE org_id=?", &[json!(ORG)]).await.unwrap()
        .map(|r| n(&r, "seq")).unwrap_or(0)
}

fn deploy_body(key: &str, value: &str) -> Value {
    json!({"secrets": [{"key": key, "value": value, "path": "/"}]})
}

// Occupy a subscription's delivery queue with n not-yet-due deliveries so the
// queue-full guard in the drain has something to count.
async fn fill_queue(db: &Db, hook: &str, n: i64) {
    let t = openwarp_server::clock::now();
    let hook = hook.to_string();
    db.webhook_atomic(move |tx| {
        for i in 0..n {
            tx.exec("INSERT INTO webhook_deliveries(id,webhook_id,event_id,payload,version,status,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?,?)",
                &[json!(format!("fill-{hook}-{i}")), json!(hook), json!(format!("fill-event-{i}")), json!("{}"), json!(1), json!(t + 86400), json!(t), json!(t)])?;
        }
        Ok(())
    }).await.unwrap();
}

// Fill the outbox to capacity so the next append must refuse to enqueue.
async fn fill_outbox(db: &Db, n: i64) {
    let t = openwarp_server::clock::now();
    db.webhook_atomic(move |tx| {
        for i in 0..n {
            tx.exec("INSERT INTO webhook_outbox(id,payload,created_at) VALUES(?,?,?)",
                &[json!(format!("ob-{i}")), json!("{}"), json!(t)])?;
        }
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn full_queue_retains_target_then_drains_exactly_once_with_stable_event() {
    let (state, _) = fixture(&[HOOK_A]).await;
    fill_queue(state.db(), HOOK_A, 1000).await;

    let (status, body) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("FULLQ", "v"))).await;
    assert_eq!(status, 200, "deploy failed: {body}");

    // The business write committed but fan-out was deferred: the outbox row and
    // target survive, and no delivery exists for the event yet.
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 1);
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await, 1);
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id=?", &[json!(HOOK_A)]).await, 1000);

    let event_id = s(&state.db().one("SELECT id FROM webhook_outbox", &[]).await.unwrap().unwrap(), "id");
    let delivery_id = s(&state.db().one("SELECT delivery_id FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await.unwrap().unwrap(), "delivery_id");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await, 0,
        "a retained target must not be fanned out while the queue is full");

    // Free capacity and drain through the public maintenance entry point.
    state.db().exec("UPDATE webhook_deliveries SET status='delivered' WHERE webhook_id=? AND status IN ('pending','failed','processing')", &[json!(HOOK_A)]).await.unwrap();
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id=? AND status IN ('pending','failed','processing')", &[json!(HOOK_A)]).await, 0);

    process_webhooks(&state).await;

    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await, 0, "drain must consume the target");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 0, "drain must clear the orphaned outbox row");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await, 1, "the deferred event must fan out exactly once");
    let delivered = state.db().one("SELECT id,event_id,status,error_code FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await.unwrap().unwrap();
    assert_eq!(s(&delivered, "id"), delivery_id, "the drained delivery must reuse the target's delivery id");
    assert_eq!(s(&delivered, "event_id"), event_id, "the delivery must keep the stable event id");
    assert_eq!(s(&delivered, "status"), "dead_lettered", "the blocked destination must land in a terminal state, not keep retrying");
    assert_eq!(s(&delivered, "error_code"), "destination_blocked", "the private-destination guard must be what terminated the delivery");

    // Repeated maintenance must not duplicate the delivery.
    process_webhooks(&state).await;
    process_webhooks(&state).await;
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await, 1, "repeated drains must stay idempotent");
}

#[tokio::test]
async fn restart_between_commit_and_fanout_persists_target_and_recovers_once() {
    let file = std::env::temp_dir().join(format!("openwarp-obr-restart-{}-{}.db", std::process::id(), oc::random_token("fx")));
    let url = format!("sqlite://{}", file.display());
    let master = oc::random_key();

    let (event_id, delivery_id) = {
        let db = Db::open(&url).await.unwrap();
        let state = build_state(db, master);
        seed_base(state.db(), &master).await;
        add_hook(state.db(), HOOK_A).await;
        fill_queue(state.db(), HOOK_A, 1000).await;

        let (status, body) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("RESTART", "v"))).await;
        assert_eq!(status, 200, "deploy failed: {body}");

        let event_id = s(&state.db().one("SELECT id FROM webhook_outbox", &[]).await.unwrap().unwrap(), "id");
        let delivery_id = s(&state.db().one("SELECT delivery_id FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await.unwrap().unwrap(), "delivery_id");
        (event_id, delivery_id)
    }; // state and its connection drop here: a simulated process restart

    // A fresh process instance opens the same file and must see the committed,
    // still-undrained outbox row and target.
    let db2 = Db::open(&url).await.unwrap();
    let state2 = build_state(db2, master);
    assert_eq!(count(state2.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 1);
    assert_eq!(count(state2.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await, 1);
    assert_eq!(count(state2.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await, 0);

    // Recovery frees the queue and drains the persisted target exactly once.
    state2.db().exec("UPDATE webhook_deliveries SET status='delivered' WHERE webhook_id=? AND status IN ('pending','failed','processing')", &[json!(HOOK_A)]).await.unwrap();
    process_webhooks(&state2).await;
    assert_eq!(count(state2.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await, 1);
    let delivered = state2.db().one("SELECT id FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await.unwrap().unwrap();
    assert_eq!(s(&delivered, "id"), delivery_id, "recovery must reuse the persisted target's delivery id");

    process_webhooks(&state2).await;
    process_webhooks(&state2).await;
    assert_eq!(count(state2.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE event_id=?", &[json!(event_id)]).await, 1, "recovery must not duplicate the delivery");
    assert_eq!(count(state2.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await, 0);

    drop(state2);
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(file.with_extension("db-wal"));
    let _ = std::fs::remove_file(file.with_extension("db-shm"));
}

#[tokio::test]
async fn full_outbox_fails_deploy_without_business_or_audit_changes() {
    let (state, _) = fixture(&[HOOK_A]).await;
    fill_outbox(state.db(), 10000).await;

    let (status, body) = call(&state, "PUT", &format!("/api/envs/{ENV}/secrets"), Some(deploy_body("CAP", "v"))).await;
    assert!(status >= 400, "a full outbox must refuse the originating deploy; got {status}: {body}");
    assert!(body["error"].as_str().unwrap_or("").contains("capacity"), "the failure must surface the outbox capacity error; got {body}");

    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM secrets WHERE env_id=?", &[json!(ENV)]).await, 0, "the business write must roll back with the failed enqueue");
    assert_eq!(head_seq(state.db()).await, 0, "the audit head must not advance on a failed enqueue");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM audit WHERE org_id=? AND action='secret.deploy'", &[json!(ORG)]).await, 0, "no audit row may be appended on a failed enqueue");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox", &[]).await, 10000, "the pre-existing outbox rows must remain untouched");
}

#[tokio::test]
async fn full_subscription_targets_do_not_starve_an_available_hook() {
    let (state, _) = fixture(&[HOOK_A, HOOK_B]).await;
    fill_queue(state.db(), HOOK_A, 1000).await;

    // Seed a backlog of A targets older than B's single target. A naive drain
    // that pages by created_at and skips full queues in the loop would spend the
    // whole page on A and never reach B.
    let t = openwarp_server::clock::now();
    state.db().webhook_atomic(move |tx| {
        for i in 0..250 {
            let event = format!("a-event-{i}");
            tx.exec("INSERT INTO webhook_outbox(id,payload,created_at) VALUES(?,?,?)", &[json!(event), json!("{}"), json!(t)])?;
            tx.exec("INSERT INTO webhook_outbox_targets(event_id,webhook_id,version,delivery_id) VALUES(?,?,?,?)",
                &[json!(event), json!(HOOK_A), json!(1), json!(format!("a-del-{i}"))])?;
        }
        tx.exec("INSERT INTO webhook_outbox(id,payload,created_at) VALUES(?,?,?)", &[json!("b-event"), json!("{}"), json!(t + 1000)])?;
        tx.exec("INSERT INTO webhook_outbox_targets(event_id,webhook_id,version,delivery_id) VALUES(?,?,?,?)",
            &[json!("b-event"), json!(HOOK_B), json!(1), json!("b-del")])?;
        Ok(())
    }).await.unwrap();

    process_webhooks(&state).await;

    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id=? AND event_id=?", &[json!(HOOK_B), json!("b-event")]).await, 1,
        "the available hook must be drained even while the other subscription is full");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id=? AND event_id LIKE 'a-event-%'", &[json!(HOOK_A)]).await, 0,
        "the full subscription must not receive fan-out while its queue is full");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_A)]).await, 250,
        "the full subscription's targets must be retained, not dropped");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox_targets WHERE webhook_id=?", &[json!(HOOK_B)]).await, 0,
        "the available hook's target must be consumed");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox WHERE id LIKE 'a-event-%'", &[]).await, 250,
        "the retained targets' outbox rows must survive");
    assert_eq!(count(state.db(), "SELECT COUNT(*) AS n FROM webhook_outbox WHERE id='b-event'", &[]).await, 0,
        "the drained event's outbox row must be cleaned up");
}
