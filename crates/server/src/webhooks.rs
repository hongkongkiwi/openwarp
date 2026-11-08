use super::*;
use axum::body::Bytes;
use base64ct::{Base64, Encoding};
use hmac::Mac;
use sha2::{Digest, Sha256};
#[cfg(all(test,not(target_arch="wasm32")))]
include!("webhooks_concurrency_tests.rs");

pub(super) fn routes() -> Router<S> { Router::new()
    .route("/api/orgs/{oid}/webhooks", get(list_outgoing).post(create_outgoing))
    .route("/api/webhooks/{wid}", get(get_outgoing).patch(update_outgoing).delete(delete_outgoing))
    .route("/api/webhooks/{wid}/rotate", post(rotate_outgoing))
    .route("/api/webhooks/{wid}/test", post(test_outgoing))
    .route("/api/webhooks/{wid}/deliveries", get(deliveries))
    .route("/api/webhook-deliveries/{did}/retry", post(retry_delivery))
    .route("/api/webhook-deliveries/{did}/attempts", get(attempts))
    .route("/api/integrations/{iid}/webhooks", get(list_incoming).post(create_incoming))
    .route("/api/incoming-webhooks/{wid}", axum::routing::patch(update_incoming).delete(delete_incoming))
    .route("/api/incoming-webhooks/{wid}/rotate", post(rotate_incoming))
    .route("/api/incoming-webhooks/{wid}/reauthorize", post(reauthorize))
    .route("/api/incoming-webhooks/{wid}/receipts", get(receipts))
    .route("/hooks/integrations/{wid}", post(accept).layer(axum::extract::DefaultBodyLimit::max(65536)))
}
fn supported() -> Result<(), (StatusCode, Json<Value>)> { if cfg!(target_arch="wasm32") { Err(err(StatusCode::NOT_IMPLEMENTED,"webhook dispatch requires the native runtime")) } else { Ok(()) } }
fn generated(master: &[u8;32], wid: &str) -> (String,String) { let key=oc::random_key(); (format!("whsec_{}",Base64::encode_string(&key)),oc::encrypt_symmetric_aad(master,format!("webhook:{}",wid).as_bytes(),&key)) }
pub(super) fn master_fence(tx: &db::WebhookTx<'_>, master: &[u8;32]) -> Result<(),String> {
    let hash=oc::hash_token(&Base64::encode_string(master)); let row=tx.one("SELECT master_hash FROM webhook_serialization WHERE id=1",&[])?.ok_or("missing webhook serialization row")?;
    let stored=db::s(&row,"master_hash"); if !stored.is_empty() && stored!=hash {return Err("instance master key changed; restart with the current key".into());}
    if stored.is_empty() {tx.exec("UPDATE webhook_serialization SET master_hash=? WHERE id=1",&[json!(hash)])?;} Ok(())
}
// Generalized instance key epoch. The row is already locked by webhook_atomic
// (PG/MySQL FOR UPDATE, SQLite transaction), so this is the write-side fence,
// not a read-then-write check.
pub(super) const EPOCH_STALE: &str = "epoch_stale";
fn epoch_hash(master: &[u8;32]) -> String { oc::hash_token(&Base64::encode_string(master)) }
pub(super) fn epoch_lock(tx: &db::WebhookTx<'_>, master: &[u8;32]) -> Result<i64,String> {
    let hash=epoch_hash(master); let row=tx.one("SELECT epoch,master_hash FROM webhook_serialization WHERE id=1",&[])?.ok_or("missing webhook serialization row")?;
    let stored=db::s(&row,"master_hash");
    if !stored.is_empty() && stored!=hash {return Err(EPOCH_STALE.into());}
    if stored.is_empty() {tx.exec("UPDATE webhook_serialization SET master_hash=? WHERE id=1",&[json!(hash)])?;}
    Ok(db::n(&row,"epoch"))
}
pub(super) fn epoch_advance(tx: &db::WebhookTx<'_>, old: &[u8;32], new: &[u8;32]) -> Result<i64,String> {
    let old_hash=epoch_hash(old); let new_hash=epoch_hash(new);
    let row=tx.one("SELECT epoch,master_hash FROM webhook_serialization WHERE id=1",&[])?.ok_or("missing webhook serialization row")?;
    let stored=db::s(&row,"master_hash");
    if !stored.is_empty() && stored!=old_hash {return Err(EPOCH_STALE.into());}
    let next=db::n(&row,"epoch")+1;
    tx.exec("UPDATE webhook_serialization SET epoch=?,master_hash=? WHERE id=1",&[json!(next),json!(new_hash)])?;
    Ok(next)
}
pub(super) async fn epoch_current(db: &db::Db, master: &[u8;32]) -> Result<i64,String> {
    let hash=epoch_hash(master);
    let row=db.one("SELECT epoch,master_hash FROM webhook_serialization WHERE id=1",&[]).await?.ok_or("missing webhook serialization row")?;
    let stored=db::s(&row,"master_hash");
    if !stored.is_empty() && stored!=hash {return Err(EPOCH_STALE.into());}
    Ok(db::n(&row,"epoch"))
}
pub(super) fn epoch_stale() -> (StatusCode, Json<Value>) {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"instance key epoch changed; reload required","code":"epoch_stale"})))
}
// Management mutations commit the audit row, live event and outbox snapshot in
// the same transaction as the subscription change; drain only after commit.
async fn key_write_audited(st: &S, master: [u8;32], wid: String, incoming: bool, sql: String, params: Vec<Value>, event: AuditEvent) -> Result<(),(StatusCode,Json<Value>)> {
    st.db.webhook_atomic(move |tx| {master_fence(tx,&master)?; if tx.exec(&sql,&params)?!=1 {return Err("webhook changed during key operation".into());} cancel_tx(tx,&wid,incoming)?; event.append(tx)}).await.map_err(|e|err(StatusCode::CONFLICT,&e))?; st.drain_outbox().await; Ok(())
}
// Embedded concurrency unit test calls the legacy arity; keep its shim test-only.
#[cfg(all(test,not(target_arch="wasm32")))]
async fn key_write(st: &S, master: [u8;32], wid: String, incoming: bool, sql: String, params: Vec<Value>) -> Result<(),(StatusCode,Json<Value>)> {
    st.db.webhook_atomic(move |tx| {master_fence(tx,&master)?; if tx.exec(&sql,&params)?!=1 {return Err("webhook changed during key operation".into());} cancel_tx(tx,&wid,incoming)}).await.map_err(|e|err(StatusCode::CONFLICT,&e))
}
fn key(st: &AppState, row: &Row) -> Result<Vec<u8>, (StatusCode, Json<Value>)> { oc::decrypt_symmetric_aad(&st.master(),format!("webhook:{}",db::s(row,"id")).as_bytes(),&db::s(row,"secret_enc")).map_err(|_|err(StatusCode::SERVICE_UNAVAILABLE,"signing key unavailable")) }
fn visible(row: &Row) -> Value { let mut v=db::obj(row); if let Some(m)=v.as_object_mut() { for k in ["secret_enc","credential_hash","creator_id","source_ip"] { m.remove(k); } m.insert("enabled".into(),json!(db::n(row,"enabled")!=0)); if let Some(events)=m.get("events").and_then(Value::as_str).and_then(|s|serde_json::from_str::<Value>(s).ok()) { m.insert("events".into(),events); } } v }
fn page(q: &HashMap<String,String>) -> (i64,i64) { (q.get("limit").and_then(|v|v.parse().ok()).unwrap_or(25).clamp(1,100),q.get("offset").and_then(|v|v.parse().ok()).unwrap_or(0).clamp(0,100000)) }
fn name(body: &Value) -> Result<&str,(StatusCode,Json<Value>)> { let n=body["name"].as_str().unwrap_or("webhook"); if n.is_empty() || n.len()>128 { Err(bad("name must contain 1-128 bytes")) } else { Ok(n) } }
fn events(body: &Value) -> Result<String,(StatusCode,Json<Value>)> { let v=body.get("events").cloned().unwrap_or(json!(["*"])); let a=v.as_array().ok_or_else(||bad("events must be an array"))?; if a.is_empty() || a.len()>64 || a.iter().any(|x|x.as_str().map(|s|s.is_empty() || s.len()>128 || !s.bytes().all(|b|b.is_ascii_alphanumeric() || b"._*-".contains(&b))).unwrap_or(true)) { return Err(bad("invalid event filters")); } Ok(v.to_string()) }
fn public_ip(ip: std::net::IpAddr) -> bool { match ip {
    std::net::IpAddr::V4(v) => { let [a,b,_,_]=v.octets(); !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast() || a==0 || a>=240 || (a==100 && (64..=127).contains(&b)) || (a==192 && (b==0 || b==2 || b==168)) || (a==198 && (b==18 || b==19 || b==51)) || (a==203 && b==0)) },
    std::net::IpAddr::V6(v) => if let Some(v4)=v.to_ipv4_mapped() { public_ip(v4.into()) } else { let n=v.segments(); (n[0]&0xe000)==0x2000 && n[0]!=0x2002 && !(n[0]==0x2001 && (n[1]<0x0200 || n[1]==0x0db8)) && !(n[0]==0x3fff && (n[1]&0xf000)==0) }
} }
fn private_override() -> bool { crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").as_deref()==Ok("1") }
fn destination(raw: &str) -> Result<reqwest::Url,(StatusCode,Json<Value>)> { let u=reqwest::Url::parse(raw).map_err(|_|bad("invalid webhook URL"))?; if raw.len()>2048 || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() || u.host_str().is_none() || !(u.scheme()=="https" || (private_override() && u.scheme()=="http")) { return Err(bad("webhook URL must be HTTPS without credentials or fragment")); } let host=u.host_str().unwrap_or("").trim_matches(['[',']']); if !private_override() && (host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") || host.parse::<std::net::IpAddr>().map(|ip|!public_ip(ip)).unwrap_or(false)) { return Err(bad("private webhook destination prohibited")); } Ok(u) }
async fn outgoing_admin(st: &S,h: &HeaderMap,oid: &str) -> Result<String,(StatusCode,Json<Value>)> { let uid=st.token_user(h).await?; if !env_scope_of(st,h).await.is_empty() { return Err(err(StatusCode::FORBIDDEN,"unscoped credential required")); } transport_admin(st,h).await?; st.check_admin(oid,&uid).await?; Ok(uid) }
pub(super) async fn transport_admin(st: &S,h: &HeaderMap) -> Result<(),(StatusCode,Json<Value>)> { let hash=oc::hash_token(&bearer_token(h)); let scope=if let Some((_,s,_))=oauth_access(st,h).await { Some(s) } else { st.db.one("SELECT scopes FROM tokens WHERE token_hash=?",&[json!(hash)]).await.map_err(|e|bad(&e))?.map(|r|db::s(&r,"scopes")).filter(|s|!s.is_empty()) }; if scope.is_some_and(|s|!s.split_whitespace().any(|v|v=="org:admin" || v=="*")) { return Err(err(StatusCode::FORBIDDEN,"org:admin transport scope required")); } Ok(()) }
async fn out(st: &S,h: &HeaderMap,wid: &str) -> Result<Row,(StatusCode,Json<Value>)> { let r=st.db.one("SELECT * FROM webhook_subscriptions WHERE id=?",&[json!(wid)]).await.map_err(|e|bad(&e))?.ok_or_else(||err(StatusCode::NOT_FOUND,"webhook not found"))?; outgoing_admin(st,h,&db::s(&r,"org_id")).await?; Ok(r) }
async fn list_outgoing(State(st): State<S>,h: HeaderMap,Path(oid): Path<String>) -> Res { outgoing_admin(&st,&h,&oid).await?; let rows=st.db.query("SELECT * FROM webhook_subscriptions WHERE org_id=? ORDER BY created_at,id LIMIT 100",&[json!(oid)]).await.map_err(|e|bad(&e))?; Ok(j(json!(rows.iter().map(visible).collect::<Vec<_>>()))) }
async fn create_outgoing(State(st): State<S>,h: HeaderMap,Path(oid): Path<String>,Json(body): Json<Value>) -> Res { supported()?; let uid=outgoing_admin(&st,&h,&oid).await?; let url=body["url"].as_str().ok_or_else(||bad("url required"))?; destination(url)?; let app=body["app_id"].as_str().unwrap_or(""); if !app.is_empty() && st.db.one("SELECT id FROM apps WHERE id=? AND org_id=?",&[json!(app),json!(oid)]).await.map_err(|e|bad(&e))?.is_none() { return Err(bad("application does not belong to workspace")); }
    let count=st.db.one("SELECT COUNT(*) AS n FROM webhook_subscriptions WHERE org_id=?",&[json!(oid)]).await.map_err(|e|bad(&e))?.map(|r|db::n(&r,"n")).unwrap_or(0); if count>=100 { return Err(err(StatusCode::CONFLICT,"subscription limit reached")); }
    let wid=id(); let master=st.master(); let (secret,enc)=generated(&master,&wid); let event=AuditEvent::new([&oid,app,"",&uid,"webhook.create",&wid]); key_write_audited(&st,master,wid.clone(),false,"INSERT INTO webhook_subscriptions(id,org_id,app_id,name,url,events,enabled,secret_enc,version,created_at,updated_at) SELECT ?,?,?,?,?,?,?,?,1,?,? WHERE (SELECT COUNT(*) FROM webhook_subscriptions WHERE org_id=?)<100".into(),vec![json!(wid),json!(oid),json!(app),json!(name(&body)?),json!(url),json!(events(&body)?),json!(i64::from(body["enabled"].as_bool().unwrap_or(true))),json!(enc),json!(now()),json!(now()),json!(oid)],event).await?;
    let mut v=visible(&out(&st,&h,&wid).await?); v["secret"]=json!(secret); Ok(j(v)) }
async fn get_outgoing(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>) -> Res { Ok(j(visible(&out(&st,&h,&wid).await?))) }
async fn update_outgoing(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>,Json(body): Json<Value>) -> Res { let r=out(&st,&h,&wid).await?; let url=body["url"].as_str().map(str::to_string).unwrap_or_else(||db::s(&r,"url")); destination(&url)?; let n=if body.get("name").is_some() { name(&body)?.to_string() } else { db::s(&r,"name") }; let filters=if body.get("events").is_some() { events(&body)? } else { db::s(&r,"events") }; let app=body["app_id"].as_str().map(str::to_string).unwrap_or_else(||db::s(&r,"app_id")); if !app.is_empty() && st.db.one("SELECT id FROM apps WHERE id=? AND org_id=?",&[json!(app),json!(db::s(&r,"org_id"))]).await.map_err(|e|bad(&e))?.is_none() { return Err(bad("application does not belong to workspace")); }
    let actor=st.token_user(&h).await?; let event=AuditEvent::new([&db::s(&r,"org_id"),"","",&actor,"webhook.update",&wid]); mutate(&st,wid.clone(),false,"UPDATE webhook_subscriptions SET name=?,url=?,events=?,app_id=?,enabled=?,version=version+1,updated_at=? WHERE id=?".into(),vec![json!(n),json!(url),json!(filters),json!(app),json!(i64::from(body["enabled"].as_bool().unwrap_or(db::n(&r,"enabled")!=0))),json!(now()),json!(wid)],event).await?; Ok(j(visible(&out(&st,&h,&wid).await?))) }
fn cancel_tx(tx: &db::WebhookTx<'_>,wid: &str,incoming: bool) -> Result<(),String> {let table=if incoming {"webhook_receipts"} else {"webhook_deliveries"}; tx.exec(&format!("UPDATE {} SET status='cancelled',claim_id='',updated_at=?,error_code='subscription_changed' WHERE webhook_id=? AND status IN ('pending','failed','processing')",table),&[json!(now()),json!(wid)])?;Ok(())}
async fn mutate(st: &S,wid: String,incoming: bool,sql: String,params: Vec<Value>,event: AuditEvent) -> Result<(),(StatusCode,Json<Value>)> {
    st.db.webhook_atomic(move |tx| {if tx.exec(&sql,&params)?!=1 {return Err("webhook changed".into());} cancel_tx(tx,&wid,incoming)?; event.append(tx)}).await.map_err(|e|err(StatusCode::CONFLICT,&e))?; st.drain_outbox().await; Ok(())
}
async fn delete_outgoing(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>) -> Res { let r=out(&st,&h,&wid).await?; let actor=st.token_user(&h).await?; let event=AuditEvent::new([&db::s(&r,"org_id"),"","",&actor,"webhook.delete",&wid]); mutate(&st,wid.clone(),false,"DELETE FROM webhook_subscriptions WHERE id=?".into(),vec![json!(wid)],event).await?; Ok(j(json!({"deleted":wid}))) }
async fn rotate_outgoing(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>) -> Res { let r=out(&st,&h,&wid).await?; let master=st.master(); let (secret,enc)=generated(&master,&wid); let actor=st.token_user(&h).await?; let event=AuditEvent::new([&db::s(&r,"org_id"),"","",&actor,"webhook.rotate",&wid]); key_write_audited(&st,master,wid.clone(),false,"UPDATE webhook_subscriptions SET secret_enc=?,version=version+1,updated_at=? WHERE id=?".into(),vec![json!(enc),json!(now()),json!(wid)],event).await?; Ok(j(json!({"id":wid,"secret":secret}))) }
async fn deliveries(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>,Query(q): Query<HashMap<String,String>>) -> Res { out(&st,&h,&wid).await?; history(&st,"webhook_deliveries",&wid,&q).await }
async fn history(st: &S,table: &str,wid: &str,q: &HashMap<String,String>) -> Res { let (limit,offset)=page(q); let rows=st.db.query(&format!("SELECT id,{} AS {},status,attempts,http_status,duration_ms,updated_at,next_attempt_at,error_code,created_at FROM {} WHERE webhook_id=? ORDER BY created_at DESC,id LIMIT ? OFFSET ?",if table=="webhook_receipts" {"message_id"} else {"event_id"},if table=="webhook_receipts" {"message_id"} else {"event_id"},table),&[json!(wid),json!(limit),json!(offset)]).await.map_err(|e|bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn test_outgoing(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>) -> Res { supported()?; st.epoch_ok().await?; let r=out(&st,&h,&wid).await?; if db::n(&r,"enabled")==0 { return Err(bad("subscription disabled")); } let event=id(); enqueue(&st,&r,&event,&json!({"id":event,"type":"webhook.test","timestamp":now(),"workspace_id":db::s(&r,"org_id"),"app_id":db::s(&r,"app_id"),"env_id":"","actor_id":st.token_user(&h).await?}).to_string()).await?; Ok(j(json!({"event_id":event,"queued":true}))) }
async fn attempts(State(st): State<S>,h: HeaderMap,Path(did): Path<String>,Query(q): Query<HashMap<String,String>>) -> Res { let delivery=st.db.one("SELECT webhook_id FROM webhook_deliveries WHERE id=?",&[json!(did)]).await.map_err(|e|bad(&e))?.ok_or_else(||err(StatusCode::NOT_FOUND,"delivery not found"))?; out(&st,&h,&db::s(&delivery,"webhook_id")).await?; let (limit,offset)=page(&q); let rows=st.db.query("SELECT id,status,http_status,duration_ms,error_code,created_at,updated_at FROM webhook_attempts WHERE delivery_id=? ORDER BY created_at DESC,id LIMIT ? OFFSET ?",&[json!(did),json!(limit),json!(offset)]).await.map_err(|e|bad(&e))?; Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>()))) }
async fn retry_delivery(State(st): State<S>,h: HeaderMap,Path(did): Path<String>) -> Res { supported()?; let r=st.db.one("SELECT webhook_id FROM webhook_deliveries WHERE id=?",&[json!(did)]).await.map_err(|e|bad(&e))?.ok_or_else(||err(StatusCode::NOT_FOUND,"delivery not found"))?; let sub=out(&st,&h,&db::s(&r,"webhook_id")).await?; if db::n(&sub,"enabled")==0 { return Err(bad("subscription disabled")); } let retry_id=did.clone(); let retry_wid=db::s(&sub,"id"); let version=db::n(&sub,"version"); let changed=st.db.webhook_atomic(move |tx| {
    tx.exec("UPDATE webhook_deliveries SET status='pending',attempts=0,next_attempt_at=?,updated_at=?,version=?,claim_id='',lease_until=0,error_code='' WHERE id=? AND status IN ('failed','dead_lettered') AND EXISTS(SELECT 1 FROM webhook_subscriptions WHERE id=? AND enabled=1 AND version=?) AND (SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id=? AND id<>? AND status IN ('pending','failed','processing'))<1000",&[json!(now()),json!(now()),json!(version),json!(retry_id),json!(retry_wid),json!(version),json!(retry_wid),json!(retry_id)])
}).await.map_err(|e|bad(&e))?; if changed==0 { return Err(err(StatusCode::CONFLICT,"only failed or dead-lettered deliveries can be retried")); } Ok(j(json!({"id":did,"queued":true}))) }
async fn enqueue(st: &AppState,r: &Row,event: &str,payload: &str) -> Result<(),(StatusCode,Json<Value>)> {
    let wid=db::s(r,"id"); let version=db::n(r,"version"); let event=event.to_string(); let payload=payload.to_string();
    st.db.webhook_atomic(move |tx| {
        let changed=tx.exec("INSERT INTO webhook_deliveries(id,webhook_id,event_id,payload,version,status,created_at,updated_at,next_attempt_at) SELECT ?,?,?,?,?,'pending',?,?,? WHERE EXISTS(SELECT 1 FROM webhook_subscriptions WHERE id=? AND version=? AND enabled=1) AND (SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id=? AND status IN ('pending','processing','failed'))<1000",&[json!(id()),json!(wid),json!(event),json!(payload),json!(version),json!(now()),json!(now()),json!(now()),json!(wid),json!(version),json!(wid)])?;
        if changed!=1 {return Err("webhook changed or queue full".into());} Ok(())
    }).await.map_err(|e|err(StatusCode::SERVICE_UNAVAILABLE,&e))
}

async fn integration_access(st: &S,h: &HeaderMap,iid: &str) -> Result<(String,String,String),(StatusCode,Json<Value>)> { let uid=st.token_user(h).await?; let row=st.db.one("SELECT env_id FROM integrations WHERE id=?",&[json!(iid)]).await.map_err(|e|bad(&e))?.ok_or_else(||err(StatusCode::NOT_FOUND,"integration not found"))?; let eid=db::s(&row,"env_id"); st.check_scope(h,&eid).await?; let (oid,_)=st.require_env(&eid,&uid).await?; st.check_perm(&oid,&uid,"integrations:write").await?; Ok((uid,eid,oid)) }
async fn inc(st: &S,h: &HeaderMap,wid: &str) -> Result<Row,(StatusCode,Json<Value>)> { let row=st.db.one("SELECT * FROM incoming_webhooks WHERE id=?",&[json!(wid)]).await.map_err(|e|bad(&e))?.ok_or_else(||err(StatusCode::NOT_FOUND,"webhook not found"))?; integration_access(st,h,&db::s(&row,"integration_id")).await?; Ok(row) }
async fn list_incoming(State(st): State<S>,h: HeaderMap,Path(iid): Path<String>) -> Res { integration_access(&st,&h,&iid).await?; let rows=st.db.query("SELECT * FROM incoming_webhooks WHERE integration_id=? ORDER BY created_at,id LIMIT 100",&[json!(iid)]).await.map_err(|e|bad(&e))?; Ok(j(json!(rows.iter().map(visible).collect::<Vec<_>>()))) }
async fn create_incoming(State(st): State<S>,h: HeaderMap,peer: PeerAddr,Path(iid): Path<String>,Json(body): Json<Value>) -> Res { supported()?; let (uid,eid,oid)=integration_access(&st,&h,&iid).await?;
    if st.db.one("SELECT kind FROM integrations WHERE id=?",&[json!(iid)]).await.map_err(|e|bad(&e))?.is_some_and(|r|db::s(&r,"kind")=="ssh") {return Err(err(StatusCode::CONFLICT,"incoming SSH sync requires a cancellation-aware adapter"));} let mode=st.db.one("SELECT mode FROM envs WHERE id=?",&[json!(eid)]).await.map_err(|e|bad(&e))?.map(|r|db::s(&r,"mode")).unwrap_or_default(); if mode=="e2e" || mode=="delegated" { return Err(err(StatusCode::CONFLICT,"incoming sync hooks currently require a server-encrypted environment")); }
    let count=st.db.one("SELECT COUNT(*) AS n FROM incoming_webhooks WHERE integration_id=?",&[json!(iid)]).await.map_err(|e|bad(&e))?.map(|r|db::n(&r,"n")).unwrap_or(0); if count>=100 { return Err(err(StatusCode::CONFLICT,"incoming subscription limit reached")); }
    let wid=id(); let master=st.master(); let (secret,enc)=generated(&master,&wid); let token=if bearer_token(&h).is_empty() { cookie_val(&h,"ow_session") } else { bearer_token(&h) }; let url=format!("{}/hooks/integrations/{}",st.pub_url.trim_end_matches('/'),wid);
    let event=AuditEvent::new([&oid,"",&eid,&uid,"incoming_webhook.create",&wid]); key_write_audited(&st,master,wid.clone(),true,"INSERT INTO incoming_webhooks(id,integration_id,org_id,env_id,name,url,enabled,secret_enc,creator_id,credential_hash,source_ip,version,created_at,updated_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,1,?,? WHERE (SELECT COUNT(*) FROM incoming_webhooks WHERE integration_id=?)<100".into(),vec![json!(wid),json!(iid),json!(oid),json!(eid),json!(name(&body)?),json!(url),json!(i64::from(body["enabled"].as_bool().unwrap_or(true))),json!(enc),json!(uid),json!(oc::hash_token(&token)),json!(client_address(&h,peer)),json!(now()),json!(now()),json!(iid)],event).await?; let mut v=visible(&inc(&st,&h,&wid).await?); v["secret"]=json!(secret); Ok(j(v)) }
async fn update_incoming(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>,Json(body): Json<Value>) -> Res { let r=inc(&st,&h,&wid).await?; let n=if body.get("name").is_some() { name(&body)?.to_string() } else { db::s(&r,"name") }; let actor=st.token_user(&h).await?; let event=AuditEvent::new([&db::s(&r,"org_id"),"",&db::s(&r,"env_id"),&actor,"incoming_webhook.update",&wid]); mutate(&st,wid.clone(),true,"UPDATE incoming_webhooks SET name=?,enabled=?,version=version+1,updated_at=? WHERE id=?".into(),vec![json!(n),json!(i64::from(body["enabled"].as_bool().unwrap_or(db::n(&r,"enabled")!=0))),json!(now()),json!(wid)],event).await?; Ok(j(visible(&inc(&st,&h,&wid).await?))) }
async fn delete_incoming(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>) -> Res { let r=inc(&st,&h,&wid).await?; let actor=st.token_user(&h).await?; let event=AuditEvent::new([&db::s(&r,"org_id"),"",&db::s(&r,"env_id"),&actor,"incoming_webhook.delete",&wid]); mutate(&st,wid.clone(),true,"DELETE FROM incoming_webhooks WHERE id=?".into(),vec![json!(wid)],event).await?; Ok(j(json!({"deleted":wid}))) }
async fn rotate_incoming(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>) -> Res { let r=inc(&st,&h,&wid).await?; let master=st.master(); let (secret,enc)=generated(&master,&wid); let actor=st.token_user(&h).await?; let event=AuditEvent::new([&db::s(&r,"org_id"),"",&db::s(&r,"env_id"),&actor,"incoming_webhook.rotate",&wid]); key_write_audited(&st,master,wid.clone(),true,"UPDATE incoming_webhooks SET secret_enc=?,version=version+1,updated_at=? WHERE id=?".into(),vec![json!(enc),json!(now()),json!(wid)],event).await?; Ok(j(json!({"id":wid,"secret":secret}))) }
async fn reauthorize(State(st): State<S>,h: HeaderMap,peer: PeerAddr,Path(wid): Path<String>) -> Res {
    let row=inc(&st,&h,&wid).await?; let (uid,eid,oid)=integration_access(&st,&h,&db::s(&row,"integration_id")).await?;
    let ip=client_address(&h,peer); if !allowed_ip(&st,&oid,&ip).await {return Err(err(StatusCode::FORBIDDEN,"source IP prohibited"));}
    let token=if bearer_token(&h).is_empty() {cookie_val(&h,"ow_session")} else {bearer_token(&h)};
    let id=wid.clone(); let event=AuditEvent::new([&oid,"",&eid,&uid,"incoming_webhook.reauthorize",&wid]); st.db.webhook_atomic(move |tx| {
        if tx.exec("UPDATE incoming_webhooks SET creator_id=?,credential_hash=?,source_ip=?,version=version+1,updated_at=? WHERE id=?",&[json!(uid),json!(oc::hash_token(&token)),json!(ip),json!(now()),json!(id)])?!=1 {return Err("webhook removed".into());}
        tx.exec("UPDATE webhook_receipts SET status='cancelled',claim_id='',updated_at=?,error_code='reauthorized' WHERE webhook_id=? AND status IN ('pending','failed','processing')",&[json!(now()),json!(id)])?; event.append(tx)
    }).await.map_err(|e|bad(&e))?;
    st.drain_outbox().await; Ok(j(visible(&inc(&st,&h,&wid).await?)))
}
async fn receipts(State(st): State<S>,h: HeaderMap,Path(wid): Path<String>,Query(q): Query<HashMap<String,String>>) -> Res { inc(&st,&h,&wid).await?; history(&st,"webhook_receipts",&wid,&q).await }
fn client_address(h: &HeaderMap,peer: PeerAddr) -> String { let ip=peer.0.to_string(); let trust=crate::envcfg::var("OPENWARP_TRUST_PROXY").as_deref()==Ok("1") && crate::envcfg::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_|"127.0.0.1/32,::1".into()).split(',').any(|c|ip_in_cidr(&ip,c)); if trust { if let Some(v)=h.get("x-forwarded-for").and_then(|v|v.to_str().ok()).and_then(|v|v.split(',').next()) { return v.trim().to_string(); } } ip }
async fn allowed_ip(st: &S,oid: &str,ip: &str) -> bool { match st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?",&[json!(oid)]).await { Ok(Some(r)) => { let list=db::s(&r,"ip_allowlist"); list.trim().is_empty() || list.split(',').any(|c|ip_in_cidr(ip,c)) }, _=>false } }
async fn creator_valid(st: &S,r: &Row) -> Result<(),(StatusCode,Json<Value>)> { let uid=db::s(r,"creator_id"); let hash=db::s(r,"credential_hash"); if !st.principal_active(&uid).await { return Err(err(StatusCode::FORBIDDEN,"creator inactive")); }
    let credential=st.db.one("SELECT user_id FROM sessions WHERE token_hash=? AND created_at>?",&[json!(hash),json!(now()-7*86400)]).await.map_err(|e|bad(&e))?.map(|v|db::s(&v,"user_id")==uid).unwrap_or(false)
        || st.db.one("SELECT user_id FROM oauth_tokens WHERE token_hash=? AND kind='access' AND expires_at>?",&[json!(hash),json!(now())]).await.map_err(|e|bad(&e))?.map(|v|db::s(&v,"user_id")==uid).unwrap_or(false)
        || st.db.one("SELECT created_by FROM tokens WHERE token_hash=? AND (expires_at=0 OR expires_at>?) AND (kind<>'machine' OR created_at>?)",&[json!(hash),json!(now()),json!(now()-3600)]).await.map_err(|e|bad(&e))?.map(|v|db::s(&v,"created_by")==uid).unwrap_or(false);
    if !credential { return Err(err(StatusCode::FORBIDDEN,"creator credential revoked or expired")); }
    let eid=db::s(r,"env_id"); st.require_env_running(&eid).await?; let (oid,_)=st.require_env(&eid,&uid).await?; st.check_perm(&oid,&uid,"integrations:write").await?;
    if let Some(token)=st.db.one("SELECT env_id,scopes FROM tokens WHERE token_hash=?",&[json!(hash)]).await.map_err(|e|bad(&e))? { let env=db::s(&token,"env_id"); let scopes=db::s(&token,"scopes"); if (!env.is_empty() && env!=eid) || (!scopes.is_empty() && !scopes.split_whitespace().any(|s|s=="*" || s=="secrets:write")) { return Err(err(StatusCode::FORBIDDEN,"creator credential scope changed")); } }
    if let Some(token)=st.db.one("SELECT scope FROM oauth_tokens WHERE token_hash=?",&[json!(hash)]).await.map_err(|e|bad(&e))? { if !db::s(&token,"scope").split_whitespace().any(|s|s=="*" || s=="secrets:write") { return Err(err(StatusCode::FORBIDDEN,"creator credential scope changed")); } }
    let mode=st.db.one("SELECT mode FROM envs WHERE id=?",&[json!(eid)]).await.map_err(|e|bad(&e))?.map(|r|db::s(&r,"mode")).unwrap_or_default(); if mode=="e2e" || mode=="delegated" { return Err(err(StatusCode::FORBIDDEN,"environment no longer supports server sync")); }
    if !allowed_ip(st,&oid,&db::s(r,"source_ip")).await { return Err(err(StatusCode::FORBIDDEN,"creator source IP no longer allowed")); }
    let integration=st.db.one("SELECT env_id,kind FROM integrations WHERE id=?",&[json!(db::s(r,"integration_id"))]).await.map_err(|e|bad(&e))?; if integration.map(|v|db::s(&v,"env_id")==eid && db::s(&v,"kind")!="ssh")!=Some(true) { return Err(err(StatusCode::FORBIDDEN,"integration removed")); } Ok(()) }
async fn accept(State(st): State<S>,h: HeaderMap,peer: PeerAddr,Path(wid): Path<String>,body: Bytes) -> Response { if let Err(e)=st.epoch_ok().await { return e.into_response(); } match accept_inner(&st,&h,peer,&wid,&body).await { Ok((status,v))=>(status,Json(v)).into_response(), Err(e)=>e.into_response() } }
async fn accept_inner(st: &S,h: &HeaderMap,peer: PeerAddr,wid: &str,body: &[u8]) -> Result<(StatusCode,Value),(StatusCode,Json<Value>)> { supported()?;
    let source=client_address(h,peer); let ratekey=format!("incoming_source:{}",source);
    let budget=st.db.webhook_atomic(move |tx| {
        let prior=tx.one("SELECT count,window_start FROM rate_limits WHERE key=?",&[json!(ratekey)])?;
        let count=prior.as_ref().filter(|r|db::n(r,"window_start")>now()-60).map(|r|db::n(r,"count")+1).unwrap_or(1);
        if prior.is_some() {tx.exec("UPDATE rate_limits SET count=?,window_start=CASE WHEN window_start<=? THEN ? ELSE window_start END WHERE key=?",&[json!(count),json!(now()-60),json!(now()),json!(ratekey)])?;}
        else {tx.exec("INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,?)",&[json!(ratekey),json!(now()),json!(count)])?;} Ok(count)
    }).await.map_err(|_|err(StatusCode::SERVICE_UNAVAILABLE,"source limiter unavailable"))?;
    if budget>180 {return Err(err(StatusCode::TOO_MANY_REQUESTS,"source request budget exceeded"));} let r=st.db.one("SELECT * FROM incoming_webhooks WHERE id=?",&[json!(wid)]).await.map_err(|e|bad(&e))?.ok_or_else(||err(StatusCode::NOT_FOUND,"webhook not found"))?; if db::n(&r,"enabled")==0 { return Err(err(StatusCode::FORBIDDEN,"webhook disabled")); }
    let header=|k|h.get(k).and_then(|v|v.to_str().ok()).unwrap_or(""); let mid=header("webhook-id"); let ts=header("webhook-timestamp"); let timestamp=ts.parse::<i64>().map_err(|_|err(StatusCode::UNAUTHORIZED,"invalid signature"))?;
    if mid.is_empty() || mid.len()>128 || !mid.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'_' || b==b'-') || timestamp.abs_diff(now())>300 { return Err(err(StatusCode::UNAUTHORIZED,"invalid signature")); }
    let material=key(st,&r)?; let mut mac=hmac::Hmac::<Sha256>::new_from_slice(&material).map_err(|_|bad("invalid key"))?; mac.update(format!("{}.{}.",mid,ts).as_bytes()); mac.update(body);
    if !header("webhook-signature").split_whitespace().take(8).any(|sig|sig.strip_prefix("v1,").and_then(|s|Base64::decode_vec(s).ok()).map(|sig|mac.clone().verify_slice(&sig).is_ok()).unwrap_or(false)) { return Err(err(StatusCode::UNAUTHORIZED,"invalid signature")); }
    creator_valid(st,&r).await?; let ip=client_address(h,peer); if !allowed_ip(st,&db::s(&r,"org_id"),&ip).await { return Err(err(StatusCode::FORBIDDEN,"source IP prohibited")); }
    let hash=Base64::encode_string(&Sha256::digest(body));
    if let Some(old)=st.db.one("SELECT body_hash FROM webhook_receipts WHERE webhook_id=? AND message_id=?",&[json!(wid),json!(mid)]).await.map_err(|e|bad(&e))? { if db::s(&old,"body_hash")!=hash { return Err(err(StatusCode::CONFLICT,"message ID reused with different bytes")); } return Ok((StatusCode::OK,json!({"duplicate":true}))); }
    let wid=wid.to_string(); let mid=mid.to_string(); let version=db::n(&r,"version");
    let outcome=st.db.webhook_atomic(move |tx| {
        if let Some(old)=tx.one("SELECT body_hash FROM webhook_receipts WHERE webhook_id=? AND message_id=?",&[json!(wid),json!(mid)])? {return if db::s(&old,"body_hash")==hash {Ok((200,json!({"duplicate":true})))} else {Ok((409,json!({"error":"message ID reused with different bytes"})))};}
        if tx.one("SELECT id FROM incoming_webhooks WHERE id=? AND enabled=1 AND version=?",&[json!(wid),json!(version)])?.is_none() {return Ok((403,json!({"error":"webhook changed"})));}
        let count=tx.one("SELECT COUNT(*) AS n FROM webhook_receipts WHERE webhook_id=? AND status IN ('pending','processing','failed')",&[json!(wid)])?.map(|r|db::n(&r,"n")).unwrap_or(0); if count>=1000 {return Ok((503,json!({"error":"incoming queue full"})));}
        let ratekey=format!("incoming:{}",wid); let prior=tx.one("SELECT count,window_start FROM rate_limits WHERE key=?",&[json!(ratekey)])?;
        if prior.is_some_and(|r|db::n(&r,"window_start")>now()-60 && db::n(&r,"count")>=60) {return Ok((429,json!({"error":"incoming webhook rate exceeded"})));}
        if tx.exec("UPDATE rate_limits SET count=CASE WHEN window_start<=? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<=? THEN ? ELSE window_start END WHERE key=?",&[json!(now()-60),json!(now()-60),json!(now()),json!(ratekey)])?==0 {
            tx.exec("INSERT INTO rate_limits(key,window_start,count) VALUES(?,?,1)",&[json!(ratekey),json!(now())])?;
        }
        let rid=id();tx.exec("INSERT INTO webhook_receipts(id,webhook_id,message_id,body_hash,version,status,source_ip,created_at,updated_at,next_attempt_at) VALUES(?,?,?,?,?,'pending',?,?,?,?)",&[json!(rid),json!(wid),json!(mid),json!(hash),json!(version),json!(ip),json!(now()),json!(now()),json!(now())])?;
        Ok((202,json!({"id":rid,"queued":true})))
    }).await.map_err(|e|err(StatusCode::SERVICE_UNAVAILABLE,&e))?;
    Ok((StatusCode::from_u16(outcome.0).map_err(|_|bad("invalid admission status"))?,outcome.1)) }

#[cfg(not(target_arch="wasm32"))]
async fn send(st: &S,sub: &Row,delivery: &Row) -> (bool,i64,String,i64) { let result=async {
    let url=destination(&db::s(sub,"url")).map_err(|_|"destination_blocked")?; let host=url.host_str().ok_or("destination_blocked")?.trim_matches(['[',']']); let port=url.port_or_known_default().ok_or("destination_blocked")?;
    let addresses=tokio::time::timeout(std::time::Duration::from_secs(5),tokio::net::lookup_host((host,port))).await.map_err(|_|"dns_timeout")?.map_err(|_|"dns_failed")?.collect::<Vec<_>>();
    if addresses.is_empty() || (!private_override() && addresses.iter().any(|v|!public_ip(v.ip()))) { return Err("destination_blocked"); }
    let client=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(10)).resolve_to_addrs(host,&addresses).build().map_err(|_|"transport_failed")?;
    let material=key(st,sub).map_err(|_|"signing_key_unavailable")?; let ts=now(); let event=db::s(delivery,"event_id"); let payload=db::s(delivery,"payload"); let mut mac=hmac::Hmac::<Sha256>::new_from_slice(&material).map_err(|_|"signing_key_unavailable")?; mac.update(format!("{}.{}.",event,ts).as_bytes()); mac.update(payload.as_bytes());
    let response=client.post(url.clone()).header("content-type","application/json").header("webhook-id",event).header("webhook-timestamp",ts.to_string()).header("webhook-signature",format!("v1,{}",Base64::encode_string(&mac.finalize().into_bytes()))).body(payload).send().await.map_err(|_|"transport_failed")?;
    let status=i64::from(response.status().as_u16()); let retry=if status==429 || status==503 { response.headers().get("retry-after").and_then(|v|v.to_str().ok()).and_then(|v|v.parse::<i64>().ok()).unwrap_or(0).clamp(0,3600) } else {0};
    Ok::<_,&str>((response.status().is_success(),status,if response.status().is_success(){""} else {"http_error"}.to_string(),retry))
    }; result.await.unwrap_or_else(|e|(false,0,e.into(),0)) }
#[cfg(not(target_arch="wasm32"))]
pub(super) async fn process(st: &S) {
    st.drain_outbox().await;
    let _=st.db.exec("DELETE FROM webhook_attempts WHERE created_at<?",&[json!(now()-7*86400)]).await;
    let _=st.db.exec("UPDATE webhook_attempts SET status='lease_expired',error_code='lease_expired',updated_at=? WHERE status='processing' AND created_at<?",&[json!(now()),json!(now()-120)]).await;
    for incoming in [false,true] {
    let table=if incoming {"webhook_receipts"} else {"webhook_deliveries"}; let subs=if incoming {"incoming_webhooks"} else {"webhook_subscriptions"};
    let _=st.db.exec(&format!("DELETE FROM {} WHERE created_at<? AND status IN ('delivered','dead_lettered','cancelled')",table),&[json!(now()-7*86400)]).await;
    let rows=st.db.query(&format!("SELECT * FROM {} WHERE ((status IN ('pending','failed') AND next_attempt_at<=?) OR (status='processing' AND lease_until<?)) ORDER BY created_at LIMIT 10",table),&[json!(now()),json!(now())]).await.unwrap_or_default();
    for mut row in rows { let did=db::s(&row,"id"); let claim=id(); let changed=st.db.exec(&format!("UPDATE {} SET status='processing',claim_id=?,lease_until=?,attempts=attempts+1,updated_at=? WHERE id=? AND ((status IN ('pending','failed') AND next_attempt_at<=?) OR (status='processing' AND lease_until<?))",table),&[json!(claim),json!(now()+120),json!(now()),json!(did),json!(now()),json!(now())]).await.unwrap_or(0); if changed==0 {continue;}
        let attempts=db::n(&row,"attempts")+1; row.insert("attempts".into(),json!(attempts)); let sub=st.db.one(&format!("SELECT * FROM {} WHERE id=? AND enabled=1 AND version=?",subs),&[json!(db::s(&row,"webhook_id")),json!(db::n(&row,"version"))]).await.ok().flatten();
        let attempt_id=id();
        if !incoming && st.db.exec("INSERT INTO webhook_attempts(id,delivery_id,claim_id,status,created_at,updated_at) VALUES(?,?,?,'processing',?,?)",&[json!(attempt_id),json!(did),json!(claim),json!(now()),json!(now())]).await.is_err() { continue; }
        let start=std::time::Instant::now(); let (ok,status,code,retry)=if let Some(sub)=sub { if incoming {
            let authorization=creator_valid(st,&sub).await.is_ok() && allowed_ip(st,&db::s(&sub,"org_id"),&db::s(&row,"source_ip")).await;
            if !authorization {(false,0,"authorization_revoked".into(),0)} else { match tokio::time::timeout(std::time::Duration::from_secs(90),sync_one_for_webhook(st,&db::s(&sub,"integration_id"),&db::s(&sub,"creator_id"))).await { Ok(Ok(_))=>(true,0,String::new(),0),Ok(Err(_))=>(false,0,"integration_sync_failed".into(),0),Err(_)=>(false,0,"integration_sync_timeout".into(),0) } }
        } else { let app=db::s(&sub,"app_id"); let running=if app.is_empty() {st.require_org_running(&db::s(&sub,"org_id")).await} else {st.require_app_running(&app).await}; if running.is_err() {(false,0,"emergency_lockdown".into(),0)} else {send(st,&sub,&row).await} } } else {(false,0,"subscription_changed".into(),0)};
        let terminal=attempts>=8 || ["authorization_revoked","subscription_changed","destination_blocked"].contains(&code.as_str()); let state=if ok {"delivered"} else if terminal {"dead_lettered"} else {"failed"}; let delay=(5_i64*2_i64.pow(attempts.min(10) as u32)).min(3600)+i64::from(oc::random_key()[0]%16); let next=now()+delay.max(retry);
        if !incoming { let _=st.db.exec("UPDATE webhook_attempts SET status=?,http_status=?,duration_ms=?,error_code=?,updated_at=? WHERE id=? AND claim_id=?",&[json!(if ok {"delivered"} else {"failed"}),json!(status),json!(start.elapsed().as_millis() as i64),json!(code),json!(now()),json!(attempt_id),json!(claim)]).await; }
        let _=st.db.exec(&format!("UPDATE {} SET status=CASE WHEN EXISTS(SELECT 1 FROM {} s WHERE s.id={}.webhook_id AND s.version={}.version AND s.enabled=1) THEN ? ELSE 'cancelled' END,http_status=?,duration_ms=?,error_code=?,next_attempt_at=?,updated_at=?,claim_id='',lease_until=0 WHERE id=? AND claim_id=? AND lease_until>=?",table,subs,table,table),&[json!(state),json!(status),json!(start.elapsed().as_millis() as i64),json!(code),json!(next),json!(now()),json!(did),json!(claim),json!(now())]).await;
    }
} }
