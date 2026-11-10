#[cfg(all(test, not(target_arch = "wasm32")))]
mod concurrency_tests {
    use super::*;
    use std::sync::Barrier;

    async fn fixture() -> (S, HeaderMap) {
        let db=Db::open_memory().await.unwrap();
        let (live,_)=tokio::sync::broadcast::channel(8);
        let st=new_state(db,String::new(),"webhook-unit".into(),"https://example.invalid".into(),oc::random_key(),live,#[cfg(feature="redis-cache")] None);
        st.db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('unit-owner','unit@test.invalid','','','',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO orgs(id,name,created_at) VALUES('unit-org','unit',?)",&[json!(now())]).await.unwrap();
        st.db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('unit-org','unit-owner','owner')",&[]).await.unwrap();
        st.db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'unit-owner',?)",&[json!(oc::hash_token("unit-session")),json!(now())]).await.unwrap();
        let mut h=HeaderMap::new(); h.insert("authorization","Bearer unit-session".parse().unwrap());
        let (_,enc)=generated(&st.master(),"unit-hook");
        st.db.exec("INSERT INTO webhook_subscriptions(id,org_id,app_id,name,url,events,enabled,secret_enc,version,created_at,updated_at) VALUES('unit-hook','unit-org','','unit','https://example.invalid','[]',1,?,1,?,?)",&[json!(enc),json!(now()),json!(now())]).await.unwrap();
        (st,h)
    }
    async fn delivery(st:&S,did:&str,wid:&str,status:&str,version:i64) {
        st.db.exec("INSERT INTO webhook_deliveries(id,webhook_id,event_id,payload,version,status,created_at,updated_at,next_attempt_at) VALUES(?,?,?,'{}',?,?,?, ?,?)",&[json!(did),json!(wid),json!(did),json!(version),json!(status),json!(now()),json!(now()),json!(now())]).await.unwrap();
    }

    #[tokio::test]
    async fn production_enqueue_serializes_last_slot_and_retry_cannot_overfill_queue() {
        let (st,h)=fixture().await;
        st.db.webhook_atomic(|tx| {
            for n in 0..999 {
                tx.exec("INSERT INTO webhook_deliveries(id,webhook_id,event_id,payload,version,status,created_at,updated_at,next_attempt_at) VALUES(?,'unit-hook',?,'{}',1,'pending',?,?,?)",&[json!(format!("seed-{n}")),json!(format!("seed-event-{n}")),json!(now()),json!(now()),json!(now()+3600)])?;
            }
            Ok(())
        }).await.unwrap();
        delivery(&st,"retry-candidate","unit-hook","dead_lettered",1).await;
        let barrier=Arc::new(Barrier::new(3)); let mut threads=Vec::new();
        for event in ["contender-a","contender-b"] {
            let st=st.clone(); let barrier=barrier.clone();
            threads.push(std::thread::spawn(move || {
                let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                runtime.block_on(async move {
                    let row=st.db.one("SELECT * FROM webhook_subscriptions WHERE id='unit-hook'",&[]).await.unwrap().unwrap();
                    barrier.wait(); enqueue(&st,&row,event,"{}").await
                })
            }));
        }
        barrier.wait(); let outcomes=threads.into_iter().map(|t|t.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|r|r.is_ok()).count(),1,"exactly one last-slot enqueue must win");
        assert_eq!(outcomes.iter().filter(|r|matches!(r,Err((StatusCode::SERVICE_UNAVAILABLE,_)))).count(),1);
        let retry=retry_delivery(State(st.clone()),h,Path("retry-candidate".into())).await;
        assert!(matches!(retry,Err((StatusCode::CONFLICT,_))),"retry admitted beyond capacity: {retry:?}");
        let row=st.db.one("SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id='unit-hook' AND status IN ('pending','failed','processing')",&[]).await.unwrap().unwrap();
        assert_eq!(db::n(&row,"n"),1000);
        let candidate=st.db.one("SELECT status FROM webhook_deliveries WHERE id='retry-candidate'",&[]).await.unwrap().unwrap();
        assert_eq!(db::s(&candidate,"status"),"dead_lettered");
    }

    #[tokio::test]
    async fn production_process_terminalizes_deleted_disabled_and_stale_version_work() {
        let (st,_)=fixture().await;
        st.db.exec("UPDATE webhook_subscriptions SET enabled=0,version=2 WHERE id='unit-hook'",&[]).await.unwrap();
        for (did,wid,version) in [("deleted-delivery","missing-hook",1),("disabled-delivery","unit-hook",2),("stale-delivery","unit-hook",1)] {
            delivery(&st,did,wid,"pending",version).await;
        }
        for (rid,wid,version) in [("deleted-receipt","missing-incoming",1),("stale-receipt","missing-incoming",2)] {
            st.db.exec("INSERT INTO webhook_receipts(id,webhook_id,message_id,body_hash,version,status,source_ip,created_at,updated_at,next_attempt_at) VALUES(?,?,?,'hash',?,'pending','127.0.0.1',?,?,?)",&[json!(rid),json!(wid),json!(rid),json!(version),json!(now()),json!(now()),json!(now())]).await.unwrap();
        }
        process(&st).await;
        for table in ["webhook_deliveries","webhook_receipts"] {
            let rows=st.db.query(&format!("SELECT status,attempts,claim_id,lease_until FROM {table}"),&[]).await.unwrap();
            assert!(!rows.is_empty());
            for row in rows { assert_eq!(db::s(&row,"status"),"cancelled"); assert_eq!(db::n(&row,"attempts"),1); assert_eq!(db::s(&row,"claim_id"),""); assert_eq!(db::n(&row,"lease_until"),0); }
        }
        process(&st).await;
        let row=st.db.one("SELECT SUM(attempts) AS n FROM webhook_deliveries",&[]).await.unwrap().unwrap(); assert_eq!(db::n(&row,"n"),3,"orphan work was claimed repeatedly");
    }

    #[tokio::test]
    async fn production_key_write_rejects_old_master_snapshot_after_fence_changes() {
        let (st,_)=fixture().await; let old=st.master(); let new=oc::random_key();
        let (_,ciphertext)=generated(&old,"unit-hook");
        key_write(&st,old,"unit-hook".into(),false,"UPDATE webhook_subscriptions SET secret_enc=? WHERE id='unit-hook'".into(),vec![json!(ciphertext)]).await.unwrap();
        // The old-key snapshot is captured before the transaction fence changes.
        let (_,stale_ciphertext)=generated(&old,"unit-hook");
        let new_hash=oc::hash_token(&Base64::encode_string(&new));
        st.db.webhook_atomic(move |tx| {tx.exec("UPDATE webhook_serialization SET master_hash=? WHERE id=1",&[json!(new_hash)])?;Ok(())}).await.unwrap();
        let before=st.db.one("SELECT secret_enc FROM webhook_subscriptions WHERE id='unit-hook'",&[]).await.unwrap().unwrap();
        let rejected=key_write(&st,old,"unit-hook".into(),false,"UPDATE webhook_subscriptions SET secret_enc=? WHERE id='unit-hook'".into(),vec![json!(stale_ciphertext)]).await;
        assert!(matches!(rejected,Err((StatusCode::CONFLICT,_))));
        let after=st.db.one("SELECT secret_enc FROM webhook_subscriptions WHERE id='unit-hook'",&[]).await.unwrap().unwrap(); assert_eq!(before,after,"stale key write changed ciphertext despite fence");
    }
}
