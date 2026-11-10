#[cfg(all(test, not(target_arch="wasm32")))]
mod master_publication_tests {
    use super::*;
    use std::task::Poll;
    use tower::ServiceExt;

    #[tokio::test]
    async fn http_environment_creation_waits_for_master_publication_gate() {
        let db=Db::open_memory().await.unwrap(); let old=oc::random_key(); let new=oc::random_key();
        let (live,_)=tokio::sync::broadcast::channel(8);
        let st=new_state(db,String::new(),"publication-test".into(),"https://example.invalid".into(),old,live,#[cfg(feature="redis-cache")] None);
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('publication-user','publication@test.invalid','','','',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES('publication-org','publication',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('publication-org','publication-user','owner')",&[]).await.unwrap();
        st.db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('publication-app','publication-org','publication',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'publication-user',?)",&[json!(oc::hash_token("publication-session")),json!(now())]).await.unwrap();
        let gate=st.key_lifecycle.write().await;
        // Model the committed-new-key / not-yet-published window without a live PostgreSQL service.
        let request=axum::http::Request::builder().method("POST").uri("/api/apps/publication-app/envs")
            .header("authorization","Bearer publication-session").header("content-type","application/json")
            .body(axum::body::Body::from(r#"{"name":"duringpublication"}"#)).unwrap();
        let mut request=request;
        request.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
        let pending=router(st.clone()).oneshot(request); tokio::pin!(pending);
        let blocked=std::future::poll_fn(|cx| {
            use std::future::Future;
            Poll::Ready(matches!(pending.as_mut().poll(cx),Poll::Pending))
        }).await;
        assert!(blocked,"HTTP mutation completed while master publication gate was held");
        let before=st.db.one("SELECT id FROM envs WHERE app_id='publication-app'",&[]).await.unwrap();
        assert!(before.is_none(),"environment was persisted before new master publication");
        *st.master.write().unwrap()=new;
        drop(gate);
        let response=pending.await.unwrap(); assert_eq!(response.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(response.into_body(),65536).await.unwrap(); let body:Value=serde_json::from_slice(&bytes).unwrap();
        let eid=body["id"].as_str().unwrap();
        let row=st.db.one("SELECT env_key_wrapped FROM envs WHERE id=?",&[json!(eid)]).await.unwrap().unwrap(); let wrapped=db::s(&row,"env_key_wrapped");
        assert_eq!(oc::decrypt_symmetric(&new,&wrapped).unwrap().len(),32,"new environment must use the published master");
        assert!(oc::decrypt_symmetric(&old,&wrapped).is_err(),"environment retained old-master wrapping");
        let mut request=axum::http::Request::builder().uri(format!("/api/envs/{eid}/secrets")).header("authorization","Bearer publication-session").body(axum::body::Body::empty()).unwrap();
        request.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
        assert_eq!(router(st).oneshot(request).await.unwrap().status(),StatusCode::OK,"created environment must remain readable");
    }

    #[tokio::test]
    async fn detached_blocking_publication_keeps_owned_gate_until_master_is_published() {
        let db=Db::open_memory().await.unwrap(); let old=oc::random_key(); let new=oc::random_key();
        let (live,_)=tokio::sync::broadcast::channel(8);
        let st=new_state(db,String::new(),"detached-publication".into(),"https://example.invalid".into(),old,live,#[cfg(feature="redis-cache")] None);
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('detached-user','detached@test.invalid','','','',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES('detached-org','detached',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('detached-org','detached-user','owner')",&[]).await.unwrap();
        st.db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('detached-app','detached-org','detached',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'detached-user',?)",&[json!(oc::hash_token("detached-session")),json!(now())]).await.unwrap();
        let permit=st.key_lifecycle.clone().write_owned().await;
        let (entered_tx,entered_rx)=tokio::sync::oneshot::channel();
        let (release_tx,release_rx)=std::sync::mpsc::channel();
        let (done_tx,done_rx)=tokio::sync::oneshot::channel(); let worker_state=st.clone();
        let worker=tokio::task::spawn_blocking(move || {
            let _permit=permit;
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("release detached publication");
            *worker_state.master.write().unwrap()=new;
            done_tx.send(()).unwrap();
        });
        entered_rx.await.unwrap();
        // Dropping the join handle models a cancelled request, not cancellation of blocking work.
        drop(worker);
        let mut request=axum::http::Request::builder().method("POST").uri("/api/apps/detached-app/envs")
            .header("authorization","Bearer detached-session").header("content-type","application/json")
            .body(axum::body::Body::from(r#"{"name":"afterdetached"}"#)).unwrap();
        request.extensions_mut().insert(PeerAddr("127.0.0.1".parse().unwrap()));
        let pending=router(st.clone()).oneshot(request); tokio::pin!(pending);
        let blocked=std::future::poll_fn(|cx| {
            use std::future::Future;
            Poll::Ready(matches!(pending.as_mut().poll(cx),Poll::Pending))
        }).await;
        release_tx.send(()).unwrap(); done_rx.await.unwrap();
        assert!(blocked,"detaching publication released the mutation gate before blocking work completed");
        let response=pending.await.unwrap(); assert_eq!(response.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(response.into_body(),65536).await.unwrap(); let body:Value=serde_json::from_slice(&bytes).unwrap();
        let row=st.db.one("SELECT env_key_wrapped FROM envs WHERE id=?",&[body["id"].clone()]).await.unwrap().unwrap();
        let wrapped=db::s(&row,"env_key_wrapped");
        assert_eq!(oc::decrypt_symmetric(&new,&wrapped).unwrap().len(),32);
        assert!(oc::decrypt_symmetric(&old,&wrapped).is_err(),"environment created under old master after request cancellation");
    }
}
