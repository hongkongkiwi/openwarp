use super::*;
use std::{future::Future, task::{Context, Poll, Waker}};

fn assert_waiting<F: Future>(future: std::pin::Pin<&mut F>) {
    // A no-op waker: the polled operation must stay pending without progress.
    let waker = Waker::noop();
    assert!(matches!(future.poll(&mut Context::from_waker(waker)), Poll::Pending), "operation crossed the held credential gate");
}

async fn state() -> (S, HeaderMap) {
    let db = Db::open_memory().await.unwrap();
    let (live, _) = broadcast::channel(16);
    let st = new_state(db, String::new(), "rotation-test".into(), String::new(), [1; 32], live, #[cfg(feature = "redis-cache")] None);
    st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('owner','owner@example.test','','','',?)", &[json!(now())]).await.unwrap();
    st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)", &[json!(oc::hash_token("rotation-session")), json!(now())]).await.unwrap();
    st.db.exec("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await.unwrap();
    let mut h = HeaderMap::new();
    h.insert("authorization", "Bearer rotation-session".parse().unwrap());
    (st, h)
}

#[tokio::test]
async fn rotation_snapshots_after_queued_credential_write() {
    let (st, h) = state().await;
    let gate = st.secret_health_credentials.lock().await;
    let rotation = rotate_master(State(st.clone()), h, Json(json!({"new_key":oc::b64(&[2; 32])})));
    let mut rotation = Box::pin(rotation);
    assert_waiting(rotation.as_mut());
    let encrypted = oc::encrypt_symmetric(&st.master(), b"credential-written-before-rotation");
    st.db.exec("INSERT INTO meta(k,v) VALUES('hibp_api_key:owner',?)", &[json!(encrypted)]).await.unwrap();
    drop(gate);
    let _ = rotation.await.unwrap();
    let row = st.db.one("SELECT v FROM meta WHERE k='hibp_api_key:owner'", &[]).await.unwrap().unwrap();
    assert_eq!(st.master(), [2; 32]);
    assert_eq!(oc::decrypt_symmetric(&st.master(), &db::s(&row, "v")).unwrap(), b"credential-written-before-rotation");
    let _ = rotate_master(State(st.clone()), {
        let mut h = HeaderMap::new(); h.insert("authorization", "Bearer rotation-session".parse().unwrap()); h
    }, Json(json!({"new_key":oc::b64(&[3; 32])}))).await.unwrap();
}

#[tokio::test]
async fn credential_operations_wait_for_rotation_and_use_its_current_key() {
    let (st, h) = state().await;
    let gate = st.secret_health_credentials.lock().await;
    let save = secret_health_save(State(st.clone()), h.clone(), Json(json!({"api_key":"0123456789abcdef0123456789abcdef"})));
    let clear = enzoic_save(State(st.clone()), h.clone(), Json(json!({"api_key":null,"api_secret":null})));
    let read = secret_health_settings(State(st.clone()), h.clone());
    let enzoic_read = enzoic_settings(State(st.clone()), h.clone());
    let email = secret_health_email(State(st.clone()), h.clone(), Json(json!({"email":"fixture@example.test","consent":true})));
    let password = enzoic_password(State(st.clone()), h.clone(), Json(json!({"prefix":"0123456789","consent":true})));
    let enzoic_save = enzoic_save(State(st.clone()), h.clone(), Json(json!({"api_key":"key","api_secret":"secret"})));
    let hibp_clear = secret_health_save(State(st.clone()), h, Json(json!({"api_key":null})));
    let mut save = Box::pin(save);
    let mut clear = Box::pin(clear);
    let mut read = Box::pin(read);
    let mut enzoic_read = Box::pin(enzoic_read);
    let mut email = Box::pin(email);
    let mut password = Box::pin(password);
    let mut enzoic_save = Box::pin(enzoic_save);
    let mut hibp_clear = Box::pin(hibp_clear);
    assert_waiting(save.as_mut()); assert_waiting(clear.as_mut());
    assert_waiting(read.as_mut()); assert_waiting(enzoic_read.as_mut());
    assert_waiting(email.as_mut()); assert_waiting(password.as_mut());
    assert_waiting(enzoic_save.as_mut()); assert_waiting(hibp_clear.as_mut());
    // Cancel relay futures before release so this test cannot contact providers.
    drop(email); drop(password); drop(enzoic_save); drop(hibp_clear);
    *st.master.write().unwrap() = [2; 32];
    drop(gate);
    let _ = save.await.unwrap(); let _ = clear.await.unwrap(); let _ = read.await.unwrap(); let _ = enzoic_read.await.unwrap();
    let row = st.db.one("SELECT v FROM meta WHERE k='hibp_api_key:owner'", &[]).await.unwrap().unwrap();
    assert_eq!(oc::decrypt_symmetric(&st.master(), &db::s(&row, "v")).unwrap(), b"0123456789abcdef0123456789abcdef");
}
