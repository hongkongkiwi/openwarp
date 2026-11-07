use super::*;

pub(super) async fn execute(st: &S, due: &Row) {
    if cfg!(target_arch="wasm32") { return; }
    let rid=db::s(due,"id"); let token=id(); let current=now();
    let claimed=st.db.rotation_batch("SELECT 1 AS blocked WHERE NOT EXISTS (SELECT id FROM rotation_schedules WHERE id=? AND enabled=1 AND next_run<=? AND execution_token='')", &[json!(rid),json!(current)], &[("UPDATE rotation_schedules SET execution_token=?,next_run=? WHERE id=?".into(),vec![json!(token),json!(current+db::n(due,"interval_secs").max(60)),json!(rid)])]).await;
    if !matches!(claimed,Ok(true)) { return; }
    let result=async {
        let r=st.db.one("SELECT * FROM rotation_schedules WHERE id=? AND execution_token=?", &[json!(rid),json!(token)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("rotation claim lost"))?;
        let eid=db::s(&r,"env_id");
        let mode=st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("environment missing"))?;
        if db::s(&mode,"mode")!="sse" { return Err(bad("static rotation requires SSE")); }
        let key=st.env_key(&eid).await?; let name=db::s(&r,"key_name"); let path=db::s(&r,"path");
        let target=st.db.one("SELECT secret_type FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid),json!(key_index(&key,&path,&name)),json!(oc::hash_token(&format!("{}:{}",path,name)))]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("rotation secret missing"))?;
        let stype=db::s(&target,"secret_type"); if stype=="sealed" { return Err(bad("sealed target")); }
        let raw=oc::decrypt_symmetric(&key,&db::s(&r,"config_enc")).map_err(|_| bad("rotation config unavailable"))?;
        let config: Value=serde_json::from_slice(&raw).map_err(|_| bad("rotation config invalid"))?;
        let (org,_)=st.env_org_app(&eid).await?;
        rotate(st,&r,&config,&key,&org,&stype).await
    }.await;
    // A timeout/cancelled task may leave remote work running. Only an operator may recover that claim.
    if !matches!(&result,Err((StatusCode::GATEWAY_TIMEOUT,_))) {
        let _=st.db.exec("UPDATE rotation_schedules SET execution_token='' WHERE id=? AND execution_token=?", &[json!(rid),json!(token)]).await;
    }
    if result.is_err() { if let Ok((org,app))=st.env_org_app(&db::s(due,"env_id")).await { st.audit(&org,&app,&db::s(due,"env_id"),"rotation-scheduler","rotation.failed_pending_retained",&rid).await; } }
}

pub(super) async fn rotate(st: &S, schedule: &Row, config: &Value, key: &[u8;32], org: &str, stype: &str) -> Result<(),(StatusCode,Json<Value>)> {
    let rid=db::s(schedule,"id"); let eid=db::s(schedule,"env_id"); let name=db::s(schedule,"key_name"); let path=db::s(schedule,"path");
    let connection=config["connection"].as_str().unwrap_or(""); let username=config["username"].as_str().unwrap_or("");
    crate::pglease::validate_static(connection,username).map_err(|e| bad(&e))?;
    let a=json!(["postgres-static-pending-v1",eid,rid]).to_string();
    let mut pending=db::s(schedule,"pending_enc");
    if pending.is_empty() {
        let candidate=oc::random_token("pg"); let enc=oc::encrypt_symmetric_aad(key,a.as_bytes(),candidate.as_bytes());
        st.db.exec("UPDATE rotation_schedules SET pending_enc=? WHERE id=? AND pending_enc=''", &[json!(enc),json!(rid)]).await.map_err(|e| bad(&e))?;
        pending=st.db.one("SELECT pending_enc FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"pending_enc")).filter(|p| !p.is_empty()).ok_or_else(|| bad("rotation schedule removed"))?;
    }
    let raw=oc::decrypt_symmetric_aad(key,a.as_bytes(),&pending).map_err(|_| bad("pending rotation password unavailable"))?;
    let password=String::from_utf8(raw).map_err(|_| bad("invalid pending rotation password"))?;
    crate::pglease::rotate_static(connection,username,&password).await.map_err(|e| if e=="static rotation outcome uncertain" { err(StatusCode::GATEWAY_TIMEOUT,"static rotation outcome uncertain; execution claim retained") } else { bad(&e) })?;
    // Retain the same password after uncertain remote or local outcomes. Retrying is idempotent.
    let input=SecretIn{key:name.clone(),value:password.clone(),path:path.clone(),comment:"scheduled PostgreSQL password rotation".into(),tags:String::new(),secret_type:stype.into()};
    upsert_secret(st,&eid,org,key,"rotation-scheduler",&input).await?;
    st.db.exec("UPDATE rotation_schedules SET pending_enc='' WHERE id=? AND pending_enc=?", &[json!(rid),json!(pending)]).await.map_err(|e| bad(&e))?;
    if let Ok((org,app))=st.env_org_app(&eid).await { st.audit(&org,&app,&eid,"rotation-scheduler","secret.rotate",&name).await; if let Some(e)=fire_rotation_hook(st,&org,&eid,&name,&password).await { st.audit(&org,&app,&eid,"rotation-scheduler","rotation_hook_failed",&e).await; } }
    let _=trigger_sync_internal(st,&eid).await; Ok(())
}
pub(super) async fn run(State(st): State<S>,h: HeaderMap,Path(rid): Path<String>) -> Res {
    let uid=st.token_user(&h).await?;
    let r=st.db.one("SELECT env_id FROM rotation_schedules WHERE id=?", &[json!(rid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("rotation schedule not found"))?;
    let eid=db::s(&r,"env_id"); st.check_scope(&h,&eid).await?; let (org,_)=st.require_env(&eid,&uid).await?; st.check_perm(&org,&uid,"rotations:write").await?;
    st.db.exec("UPDATE rotation_schedules SET next_run=?,enabled=1 WHERE id=?", &[json!(now()),json!(rid)]).await.map_err(|e| bad(&e))?;
    // Scheduling acknowledges no remote success; maintenance claims and performs the rotation.
    Ok(j(json!({"scheduled":true,"id":rid})))
}

#[cfg(all(test,not(target_arch="wasm32")))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn held_execution_blocks_claim_and_delete_without_pending() {
        let db=Db::open_memory().await.unwrap();
        db.exec("INSERT INTO rotation_schedules(id,env_id,key_name,path,interval_secs,next_run,created_at,execution_token) VALUES('held','env','KEY','/',60,0,0,'original')",&[]).await.unwrap();
        let blocked="SELECT id FROM rotation_schedules WHERE id=? AND (pending_enc<>'' OR execution_token<>'')";
        assert!(!db.rotation_batch(blocked,&[json!("held")],&[("DELETE FROM rotation_schedules WHERE id=?".into(),vec![json!("held")])]).await.unwrap());
        let predicate="SELECT 1 AS blocked WHERE NOT EXISTS (SELECT id FROM rotation_schedules WHERE id=? AND enabled=1 AND next_run<=? AND execution_token='')";
        assert!(!db.rotation_batch(predicate,&[json!("held"),json!(now())],&[("UPDATE rotation_schedules SET execution_token='replacement' WHERE id='held'".into(),vec![])]).await.unwrap());
        db.exec("UPDATE rotation_schedules SET next_run=0,enabled=1 WHERE id='held'",&[]).await.unwrap();
        assert_eq!(db::s(&db.one("SELECT execution_token FROM rotation_schedules WHERE id='held'",&[]).await.unwrap().unwrap(),"execution_token"),"original");
        assert_eq!(db.exec("UPDATE rotation_schedules SET execution_token='' WHERE id='held' AND execution_token='wrong'",&[]).await.unwrap(),0);
    }
    #[tokio::test]
    async fn lifecycle_barrier_blocks_environment_creation_until_root_switch() {
        use tower::ServiceExt;
        use std::future::Future;
        let db=Db::open_memory().await.unwrap(); let (live,_)=tokio::sync::broadcast::channel(1);
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES('owner','gate@test.invalid','','','',0,1)",&[]).await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',0)",&[]).await.unwrap();
        db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org','owner','owner')",&[]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','app',0)",&[]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'owner',?)",&[json!(oc::hash_token("owner")),json!(now())]).await.unwrap();
        let st=new_state(db,"sqlite::memory:".into(),"test".into(),String::new(),[7;32],live,#[cfg(feature="redis-cache")] None);
        let held=st.lifecycle.clone().write_owned().await;
        let request=axum::http::Request::builder().method("POST").uri("/api/apps/app/envs").header("authorization","Bearer owner").header("content-type","application/json").extension(PeerAddr(std::net::IpAddr::from([127,0,0,1]))).body(axum::body::Body::from(r#"{"name":"gated"}"#)).unwrap();
        let mut response=Box::pin(router(st.clone()).oneshot(request));
        assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(response.as_mut().poll(cx).is_pending())).await);
        assert!(st.db.one("SELECT id FROM envs WHERE name='gated'",&[]).await.unwrap().is_none());
        *st.master.write().unwrap()=[9;32]; drop(held);
        assert_eq!(response.await.unwrap().status(),StatusCode::OK);
        let row=st.db.one("SELECT env_key_wrapped FROM envs WHERE name='gated'",&[]).await.unwrap().unwrap();
        let wrapped=db::s(&row,"env_key_wrapped");
        assert!(oc::decrypt_symmetric(&[9;32],&wrapped).is_ok());
        assert!(oc::decrypt_symmetric(&[7;32],&wrapped).is_err());
    }
    #[tokio::test]
    async fn transit_gate_serializes_key_snapshot_access() {
        let db=Db::open_memory().await.unwrap(); let (live,_)=tokio::sync::broadcast::channel(1);
        let st=new_state(db,"sqlite::memory:".into(),"test".into(),String::new(),[7;32],live,#[cfg(feature="redis-cache")] None);
        let held=st.transit_gate.clone().lock_owned().await;
        assert!(st.transit_gate.try_lock().is_err());
        drop(held); assert!(st.transit_gate.try_lock().is_ok());
    }
}
