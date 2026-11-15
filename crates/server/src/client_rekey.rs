use super::*;
use std::collections::BTreeSet;

fn failure(e: String) -> (StatusCode, Json<Value>) {
    if let Some(e)=e.strip_prefix("stale:") { err(StatusCode::CONFLICT,e) }
    else if let Some(e)=e.strip_prefix("denied:") { err(StatusCode::FORBIDDEN,e) }
    else { bad(&e) }
}
fn env(tx: &db::WebhookTx<'_>, eid: &str) -> Result<Row,String> {
    tx.one("SELECT e.*,a.org_id AS org_id,a.emergency_locked AS app_locked,o.emergency_locked AS org_locked FROM envs e JOIN apps a ON a.id=e.app_id JOIN orgs o ON o.id=a.org_id WHERE e.id=?", &[json!(eid)])?.ok_or_else(||"environment not found".into())
}
fn permissions(tx: &db::WebhookTx<'_>, org: &str, role: &str) -> Result<Vec<String>,String> {
    Ok(match role { "owner"|"admin"=>vec!["*".into()], "developer"=>DEVELOPER_PERMS.iter().map(|s|s.to_string()).collect(), _=>tx.one("SELECT permissions FROM roles WHERE org_id=? AND name=?", &[json!(org),json!(role)])?.and_then(|r|serde_json::from_str(&db::s(&r,"permissions")).ok()).unwrap_or_default() })
}
fn member(tx: &db::WebhookTx<'_>, e: &Row, uid: &str, action: &str) -> Result<Option<String>,String> {
    let Some(m)=tx.one("SELECT m.role,m.locked,u.active,u.email_verified,u.pubkey FROM org_members m JOIN users u ON u.id=m.user_id WHERE m.org_id=? AND m.user_id=?", &[json!(db::s(e,"org_id")),json!(uid)])? else { return Ok(None) };
    if db::n(&m,"locked")!=0 || db::n(&m,"active")==0 || db::n(&m,"email_verified")==0 || db::s(&m,"pubkey").is_empty() { return Ok(None); }
    let role=db::s(&m,"role"); let p=permissions(tx,&db::s(e,"org_id"),&role)?;
    if !p.iter().any(|p|p=="*" || p==action) { return Ok(None); }
    if db::n(e,"restricted")==1 && role!="owner" && role!="admin" &&
        tx.one("SELECT user_id FROM env_members WHERE env_id=? AND user_id=?", &[json!(db::s(e,"id")),json!(uid)])?.is_none() &&
        tx.one("SELECT user_id FROM app_members WHERE app_id=? AND user_id=?", &[json!(db::s(e,"app_id")),json!(uid)])?.is_none() &&
        tx.one("SELECT g.team_id FROM team_env_grants g JOIN team_members m ON m.team_id=g.team_id WHERE g.env_id=? AND m.user_id=?", &[json!(db::s(e,"id")),json!(uid)])?.is_none() { return Ok(None); }
    Ok(Some(role))
}
fn authorize(tx: &db::WebhookTx<'_>, e: &Row, uid: &str, credential: &(String,String), write: bool, holder: bool) -> Result<String,String> {
    if !matches!(db::s(e,"mode").as_str(),"e2e"|"delegated") { return Err("client-encrypted environment required".into()); }
    if db::n(e,"app_locked")!=0 || db::n(e,"org_locked")!=0 { return Err("denied:emergency lockdown".into()); }
    let (hash,audience)=credential;
    if tx.one("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND created_at>=?", &[json!(hash),json!(uid),json!(now()-7*86400)])?.is_none() {
        let oauth=tx.one("SELECT scope,resource FROM oauth_tokens WHERE token_hash=? AND user_id=? AND kind='access' AND expires_at>?", &[json!(hash),json!(uid),json!(now())])?.ok_or("denied:account session or live user OAuth access token required")?;
        let required=if write {"secrets:write"} else {"secrets:read"};
        if db::s(&oauth,"resource")!=*audience || !scope_has(&db::s(&oauth,"scope"),required) { return Err("denied:OAuth audience or scope denied".into()); }
    }
    let role=member(tx,e,uid,if write {"secrets:write"} else {"secrets:read"})?.ok_or("denied:current eligible membership required")?;
    if tx.one("SELECT role FROM path_policies WHERE env_id=? AND role=?", &[json!(db::s(e,"id")),json!(role)])?.is_some() && role!="owner" { return Err("denied:path-restricted accounts cannot rotate opaque paths".into()); }
    if write && db::n(e,"require_approval")==1 && role!="owner" && role!="admin" { return Err("denied:approved proposal required".into()); }
    if holder && tx.one("SELECT user_id FROM env_keys WHERE env_id=? AND user_id=?", &[json!(db::s(e,"id")),json!(uid)])?.is_none() { return Err("denied:current key holder required".into()); }
    Ok(role)
}
fn grants(tx: &db::WebhookTx<'_>, e: &Row) -> Result<Vec<Value>,String> {
    let mut out=Vec::new();
    for r in tx.query("SELECT k.user_id,u.email,u.pubkey,k.wrapped_key FROM env_keys k JOIN users u ON u.id=k.user_id WHERE k.env_id=? ORDER BY k.user_id", &[json!(db::s(e,"id"))])? {
        if member(tx,e,&db::s(&r,"user_id"),"secrets:read")?.is_some() { out.push(db::obj(&r)); }
    }
    Ok(out)
}
fn secrets(tx: &db::WebhookTx<'_>, eid: &str) -> Result<Vec<Row>,String> { tx.query("SELECT id,path,path_enc,key_hash,key_enc,value_enc,version,updated_at FROM secrets WHERE env_id=? AND deleted=0 AND e2e=1 ORDER BY id", &[json!(eid)]) }
fn snapshot(tx: &db::WebhookTx<'_>, e: &Row) -> Result<Value,String> {
    let runner=tx.one("SELECT id,pubkey FROM runners WHERE id=?", &[json!(db::s(e,"runner_id"))])?.map(|r|json!({"id":db::s(&r,"id"),"public_key":db::s(&r,"pubkey"),"rekey_authorized":db::n(e,"runner_rekey_authorized")==1})).unwrap_or(Value::Null);
    let recipients=grants(tx,e)?;
    let rows=secrets(tx,&db::s(e,"id"))?.iter().map(db::obj).collect::<Vec<_>>();
    let state=json!({"env":db::obj(e),"secrets":rows,"grants":recipients,"runner":runner});
    Ok(json!({"mode":db::s(e,"mode"),"key_generation":db::n(e,"key_generation"),"membership_version":db::n(e,"membership_version"),"snapshot_token":oc::hash_token(&state.to_string()),"rekey_required":db::n(e,"rekey_pending")==1,"runner":runner}))
}
async fn preflight(st: &S,h: &HeaderMap,eid: &str,write: bool) -> Result<(String,String,String),(StatusCode,Json<Value>)> {
    let uid=st.token_user(h).await?; st.check_scope(h,eid).await?; let (org,app)=st.require_env(eid,&uid).await?;
    st.check_perm(&org,&uid,if write {"secrets:write"} else {"secrets:read"}).await?;
    if write { require_approval_for_write(st,eid,&org,&uid).await?; }
    Ok((uid,org,app))
}
pub(super) async fn meta(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>) -> Res {
    let (uid,_,_)=preflight(&st,&h,&eid,false).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let result=st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,false,true)?; snapshot(tx,&e) }).await.map_err(failure)?;
    Ok(j(result))
}
pub(super) async fn get(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>) -> Res {
    let (uid,_,_)=preflight(&st,&h,&eid,false).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let result=st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,false,true)?;
        let wrap=tx.one("SELECT wrapped_key FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid),json!(uid)])?.ok_or("denied:no wrapped key")?;
        Ok(json!({"wrapped_key":db::s(&wrap,"wrapped_key"),"key_generation":db::n(&e,"key_generation"),"secrets":secrets(tx,&eid)?.iter().map(db::obj).collect::<Vec<_>>()})) }).await.map_err(failure)?;
    Ok(j(result))
}
pub(super) async fn list_grants(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>) -> Res {
    let (uid,_,_)=preflight(&st,&h,&eid,false).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let result=st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,false,true)?;
        Ok(grants(tx,&e)?.into_iter().map(|mut g| { g.as_object_mut().unwrap().remove("wrapped_key"); g }).collect::<Vec<_>>()) }).await.map_err(failure)?;
    Ok(j(json!(result)))
}
pub(super) async fn rekey(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>,Json(body): Json<Value>) -> Res {
    let (uid,org,app)=preflight(&st,&h,&eid,true).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let generation=body["expected_generation"].as_i64().filter(|n|*n>=1).ok_or_else(||bad("expected_generation required"))?;
    let membership=body["membership_version"].as_i64().filter(|n|*n>=0).ok_or_else(||bad("membership_version required"))?;
    let token=body["snapshot_token"].as_str().filter(|s|!s.is_empty()).ok_or_else(||bad("snapshot_token required"))?.to_string();
    let incoming=body["secrets"].as_array().ok_or_else(||bad("secrets array required"))?.clone();
    let wrapped=body["grants"].as_array().ok_or_else(||bad("grants array required"))?.clone();
    require_step_up(&st,&h,&uid,StepUpRisk::TwoFactor).await?;
    let result=st.db.webhook_atomic(move |tx| {
        let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,true,true)?;
        if db::n(&e,"key_generation")!=generation || db::n(&e,"membership_version")!=membership || snapshot(tx,&e)?["snapshot_token"]!=token { return Err("stale:environment snapshot changed; refresh and retry".into()); }
        let current=secrets(tx,&eid)?; let mut seen=BTreeSet::new();
        for s in &incoming {
            let sid=s["id"].as_str().unwrap_or("");
            let Some(old)=current.iter().find(|r|db::s(r,"id")==sid) else { return Err("payload must cover exactly current secret records".into()) };
            if !seen.insert(sid.to_string()) || s["version"].as_i64()!=Some(db::n(old,"version")) || s["key_hash"].as_str()!=Some(db::s(old,"key_hash").as_str()) { return Err("duplicate or changed secret identity/version".into()); }
            for f in ["key_enc","value_enc","path_enc"] { if s[f].as_str().unwrap_or("").is_empty() { return Err(format!("{} required",f)); } }
        }
        if seen.len()!=current.len() { return Err("payload must cover every current secret".into()); }
        let remove=body["remove_user"].as_str().unwrap_or(""); let mut expected: BTreeSet<String>=grants(tx,&e)?.iter().map(|g|g["user_id"].as_str().unwrap().to_string()).collect();
        if !remove.is_empty() && (remove==uid || !expected.remove(remove)) { return Err("invalid remove_user".into()); }
        let mut received=BTreeSet::new();
        for g in &wrapped { let user=g["user_id"].as_str().unwrap_or(""); if !received.insert(user.to_string()) || g["wrapped_key"].as_str().unwrap_or("").is_empty() { return Err("invalid or duplicate key grant".into()); } }
        if received!=expected || !received.contains(&uid) { return Err("all current eligible holders except explicit remove_user need new wraps, including caller".into()); }
        let runner_wrap=body["runner_wrapped_key"].as_str().unwrap_or(""); let delegated=db::s(&e,"mode")=="delegated"; let allowed=delegated && db::n(&e,"runner_rekey_authorized")==1;
        if allowed && runner_wrap.is_empty() { return Err("runner_wrapped_key required by explicit runner policy".into()); }
        if !allowed && !runner_wrap.is_empty() { return Err("runner wrapping is not authorized".into()); }
        for s in &incoming { let sid=s["id"].as_str().unwrap(); let version=s["version"].as_i64().unwrap()+1;
            tx.exec("UPDATE secrets SET key_enc=?,value_enc=?,path='',path_enc=?,key_index=?,version=?,updated_at=?,updated_by=? WHERE id=? AND env_id=?", &[s["key_enc"].clone(),s["value_enc"].clone(),s["path_enc"].clone(),s["key_hash"].clone(),json!(version),json!(now()),json!(uid),json!(sid),json!(eid)])?;
            // Previous history cannot be decrypted with the replacement client key.
            tx.exec("DELETE FROM secret_versions WHERE secret_id=?", &[json!(sid)])?;
            tx.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,path,tags,created_at,created_by) VALUES(?,?,?,?,?,'','',?,?)", &[json!(id()),json!(sid),json!(version),s["key_enc"].clone(),s["value_enc"].clone(),json!(now()),json!(uid)])?;
        }
        tx.exec("DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE env_id=? AND deleted=1)", &[json!(eid)])?;
        tx.exec("DELETE FROM overrides WHERE secret_id IN (SELECT id FROM secrets WHERE env_id=? AND deleted=1)", &[json!(eid)])?;
        tx.exec("DELETE FROM secrets WHERE env_id=? AND deleted=1", &[json!(eid)])?;
        tx.exec("DELETE FROM env_keys WHERE env_id=?", &[json!(eid)])?;
        for g in &wrapped { tx.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(eid),g["user_id"].clone(),g["wrapped_key"].clone()])?; }
        tx.exec("DELETE FROM runner_env_keys WHERE env_id=?", &[json!(eid)])?;
        if allowed { tx.exec("INSERT INTO runner_env_keys(runner_id,env_id,wrapped_key) VALUES(?,?,?)", &[json!(db::s(&e,"runner_id")),json!(eid),json!(runner_wrap)])?; }
        tx.exec("UPDATE sync_jobs SET status='failed',detail='environment key rotated',claim_id='' WHERE env_id=? AND status IN ('pending','claimed')", &[json!(eid)])?;
        tx.exec("UPDATE envs SET key_generation=key_generation+1,membership_version=membership_version+?,rekey_pending=0 WHERE id=?", &[json!(i64::from(!remove.is_empty())),json!(eid)])?;
        tx.exec("DELETE FROM meta WHERE k=?", &[json!(format!("rekey_required:{}",eid))])?;
        AuditEvent::new([&org,&app,&eid,&uid,"e2e.rekey",&format!("{} secrets, {} grants",incoming.len(),wrapped.len())]).append(tx)?;
        Ok(json!({"rekeyed":incoming.len(),"grants":wrapped.len(),"key_generation":generation+1}))
    }).await.map_err(failure)?;
    st.drain_outbox().await; Ok(j(result))
}
pub(super) async fn grant(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>,Json(body): Json<Value>) -> Res {
    let (uid,org,app)=preflight(&st,&h,&eid,true).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let email=body["email"].as_str().unwrap_or("").to_lowercase(); let wrap=body["wrapped_key"].as_str().unwrap_or("").to_string();
    if email.is_empty() || wrap.is_empty() { return Err(bad("email and wrapped_key required")); }
    let generation=body["expected_generation"].as_i64().filter(|n|*n>=1).ok_or_else(||bad("expected_generation required"))?;
    require_step_up(&st,&h,&uid,StepUpRisk::TwoFactor).await?;
    st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,true,true)?; ready(&e)?;
        if db::n(&e,"key_generation")!=generation { return Err("stale:key generation changed".into()); }
        let target=tx.one("SELECT id FROM users WHERE email=?", &[json!(email)])?.ok_or("user not found")?; let target=db::s(&target,"id");
        if member(tx,&e,&target,"secrets:read")?.is_none() { return Err("denied:recipient must be an eligible current member".into()); }
        tx.exec("DELETE FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid),json!(target)])?;
        tx.exec("INSERT INTO env_keys(env_id,user_id,wrapped_key) VALUES(?,?,?)", &[json!(eid),json!(target),json!(wrap)])?;
        tx.exec("UPDATE envs SET membership_version=membership_version+1 WHERE id=?", &[json!(eid)])?;
        AuditEvent::new([&org,&app,&eid,&uid,"e2e.grant",&target]).append(tx)
    }).await.map_err(failure)?; st.drain_outbox().await; Ok(j(json!({"ok":true})))
}
pub(super) async fn revoke(State(st): State<S>,h: HeaderMap,Path((eid,target)): Path<(String,String)>) -> Res {
    let (uid,org,app)=preflight(&st,&h,&eid,true).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    if uid==target { return Err(bad("cannot revoke own last completing holder")); }
    require_step_up(&st,&h,&uid,StepUpRisk::TwoFactor).await?;
    let removed=target.clone(); st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,true,true)?;
        if tx.exec("DELETE FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid),json!(target)])?!=1 { return Err("no key grant for that user".into()); }
        tx.exec("UPDATE envs SET membership_version=membership_version+1,rekey_pending=1 WHERE id=?", &[json!(eid)])?;
        AuditEvent::new([&org,&app,&eid,&uid,"e2e.revoke",&target]).append(tx)
    }).await.map_err(failure)?; st.drain_outbox().await; Ok(j(json!({"revoked":removed,"rekey_required":true})))
}
pub(super) async fn policy(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>,Json(body): Json<Value>) -> Res {
    let (uid,org,app)=preflight(&st,&h,&eid,true).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let allow=body["runner_rekey_authorized"].as_bool().ok_or_else(||bad("runner_rekey_authorized boolean required"))?;
    require_step_up(&st,&h,&uid,StepUpRisk::TwoFactor).await?;
    st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; let role=authorize(tx,&e,&uid,&hash,true,false)?;
        if role!="owner" && role!="admin" { return Err("denied:owner or admin required".into()); }
        if db::s(&e,"mode")!="delegated" { return Err("delegated environment required".into()); }
        if (db::n(&e,"runner_rekey_authorized")==1)!=allow {
            tx.exec("UPDATE envs SET runner_rekey_authorized=?,membership_version=membership_version+1 WHERE id=?", &[json!(i64::from(allow)),json!(eid)])?;
            AuditEvent::new([&org,&app,&eid,&uid,"e2e.policy",if allow {"runner rekey authorized"} else {"runner rekey unauthorized"}]).append(tx)?;
        } Ok(())
    }).await.map_err(failure)?; st.drain_outbox().await; Ok(j(json!({"runner_rekey_authorized":allow})))
}
pub(super) async fn lifecycle(st: &S,eid: &str,sid: &str,statements: &[(String,Vec<Value>)],fields: [&str;6],generation: i64) -> Result<(),(StatusCode,Json<Value>)> { let eid=eid.to_string(); let sid=sid.to_string(); let sql=statements.to_vec(); let event=AuditEvent::new(fields); let action=fields[4].to_string(); let uid=fields[3].to_string();
    st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; ready(&e)?;
        if db::n(&e,"key_generation")!=generation { return Err("stale:key generation changed".into()); }
        if db::n(&e,"app_locked")!=0 || db::n(&e,"org_locked")!=0 { return Err("denied:emergency lockdown".into()); }
        let permission=if action=="secret.delete" || action=="secret.destroy" {"secrets:delete"} else {"secrets:write"};
        if member(tx,&e,&uid,permission)?.is_none() || tx.one("SELECT user_id FROM env_keys WHERE env_id=? AND user_id=?", &[json!(eid),json!(uid)])?.is_none() { return Err("denied:current member holder required".into()); }
        if tx.one("SELECT id FROM secrets WHERE id=? AND env_id=?", &[json!(sid),json!(eid)])?.is_none() { return Err("stale:secret removed during rekey".into()); }
        for (index,(statement,params)) in sql.into_iter().enumerate() { let affected=tx.exec(&statement,&params)?; if index==0 && matches!(action.as_str(),"secret.delete"|"secret.restore"|"secret.undelete") && affected!=1 { return Err("stale:secret changed".into()); } } event.append(tx)
    }).await.map_err(failure)?; st.drain_outbox().await; Ok(())
}
pub(super) async fn enqueue(st: &S,eid: &str,iid: &str,kind: &str) -> Result<(),(StatusCode,Json<Value>)> {
    let eid=eid.to_string(); let iid=iid.to_string(); let kind=kind.to_string();
    st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; ready(&e)?;
        if db::n(&e,"app_locked")!=0 || db::n(&e,"org_locked")!=0 { return Err("denied:emergency lockdown".into()); }
        let rid=db::s(&e,"runner_id");
        if tx.one("SELECT runner_id FROM runner_env_keys WHERE env_id=? AND runner_id=?", &[json!(eid),json!(rid)])?.is_none() { return Err("stale:runner has no current key grant".into()); }
        if tx.one("SELECT id FROM sync_jobs WHERE integration_id=? AND status IN ('pending','claimed') AND kind=?", &[json!(iid),json!(kind)])?.is_none() {
            tx.exec("INSERT INTO sync_jobs(id,env_id,integration_id,runner_id,kind,created_at) VALUES(?,?,?,?,?,?)", &[json!(id()),json!(eid),json!(iid),json!(rid),json!(kind),json!(now())])?;
        } Ok(())
    }).await.map_err(failure)
}
pub(super) async fn runner_payloads(st: &S,rid: String,hash: String) -> Res {
    let jobs=st.db.webhook_atomic(move |tx| {
        if tx.one("SELECT id FROM runners WHERE id=? AND token_hash=?", &[json!(rid),json!(hash)])?.is_none() { return Err("denied:runner credential revoked".into()); }
        let rows=tx.query("SELECT j.* FROM sync_jobs j JOIN envs e ON e.id=j.env_id JOIN apps a ON a.id=e.app_id JOIN orgs o ON o.id=a.org_id JOIN runner_env_keys k ON k.env_id=e.id AND k.runner_id=j.runner_id WHERE j.runner_id=? AND e.runner_id=j.runner_id AND e.rekey_pending=0 AND a.emergency_locked=0 AND o.emergency_locked=0 AND (j.status='pending' OR (j.status='claimed' AND j.claimed_at<?)) ORDER BY j.created_at LIMIT 10", &[json!(rid),json!(now()-600)])?;
        let mut jobs=Vec::new();
        for job in rows { let eid=db::s(&job,"env_id"); let iid=db::s(&job,"integration_id");
            let e=env(tx,&eid)?;
            if db::s(&e,"runner_id")!=rid || db::n(&e,"rekey_pending")!=0 || db::n(&e,"app_locked")!=0 || db::n(&e,"org_locked")!=0 { continue; }
            let Some(wrap)=tx.one("SELECT wrapped_key FROM runner_env_keys WHERE env_id=? AND runner_id=?", &[json!(eid),json!(rid)])? else { continue };
            let Some(integ)=tx.one("SELECT kind,config_enc FROM integrations WHERE id=? AND env_id=?", &[json!(iid),json!(eid)])? else { continue };
            let rows=tx.query("SELECT id,key_enc,value_enc,key_hash,path,path_enc,tags,tags_enc,secret_type,version FROM secrets WHERE env_id=? AND deleted=0 AND secret_type NOT IN ('sealed','wallet_private_key','wallet_recovery_phrase')", &[json!(eid)])?;
            let prev=tx.query("SELECT remote_name,value_hash FROM integration_sync_state WHERE integration_id=?", &[json!(iid)])?;
            let jid=db::s(&job,"id"); let claim=oc::random_token("job");
            tx.exec("UPDATE sync_jobs SET status='claimed',claimed_at=?,claim_id=? WHERE id=?", &[json!(now()),json!(claim),json!(jid)])?;
            jobs.push(json!({"id":jid,"claim":claim,"env_id":eid,"integration_id":iid,"job_kind":db::s(&job,"kind"),"environment":db::s(&e,"name"),"key_generation":db::n(&e,"key_generation"),"kind":db::s(&integ,"kind"),"config_enc":db::s(&integ,"config_enc"),"wrapped_key":db::s(&wrap,"wrapped_key"),"secrets":rows.iter().map(db::obj).collect::<Vec<_>>(),"previous":prev.iter().map(|r|db::s(r,"remote_name")).collect::<Vec<_>>(),"previous_hashes":prev.iter().map(|r|(db::s(r,"remote_name"),json!(db::s(r,"value_hash")))).collect::<serde_json::Map<String,Value>>() }));
        } Ok(jobs)
    }).await.map_err(failure)?;
    Ok(j(json!({"jobs":jobs})))
}
fn ready(e: &Row) -> Result<(),String> { if db::n(e,"rekey_pending")!=0 { Err("stale:client key rotation pending".into()) } else { Ok(()) } }
pub(super) async fn require_ready(st: &S,eid: &str) -> Result<(),(StatusCode,Json<Value>)> {
    let row=st.db.one("SELECT rekey_pending FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e|bad(&e))?.ok_or_else(||bad("environment not found"))?;
    ready(&row).map_err(failure)
}
pub(super) async fn put(State(st): State<S>,h: HeaderMap,Path(eid): Path<String>,Json(body): Json<Value>) -> Res {
    let (uid,org,app)=preflight(&st,&h,&eid,true).await?; let hash=(oc::hash_token(&secret_health_token(&h)),issuer(&st,&h));
    let generation=body["expected_generation"].as_i64().filter(|n|*n>=1).ok_or_else(||bad("expected_generation required"))?;
    let inputs=body["secrets"].as_array().cloned().ok_or_else(||bad("secrets required"))?;
    require_step_up(&st,&h,&uid,StepUpRisk::TwoFactor).await?;
    let count=st.db.webhook_atomic(move |tx| { let e=env(tx,&eid)?; authorize(tx,&e,&uid,&hash,true,true)?; ready(&e)?;
        if db::n(&e,"key_generation")!=generation { return Err("stale:key generation changed".into()); }
        let mut count=0;
        for s in &inputs { let kh=s["key_hash"].as_str().unwrap_or(""); let ke=s["key_enc"].as_str().unwrap_or(""); if kh.is_empty() || ke.is_empty() { continue; }
            let ve=s["value_enc"].as_str().unwrap_or(""); let pe=s["path_enc"].as_str().unwrap_or(""); let path=if pe.is_empty() {s["path"].as_str().unwrap_or("/")} else {""};
            let old=tx.one("SELECT id,version FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?) AND deleted=0", &[json!(eid),json!(kh),json!(kh)])?;
            let (sid,version)=if let Some(old)=old { let sid=db::s(&old,"id"); let version=db::n(&old,"version")+1;
                tx.exec("UPDATE secrets SET key_enc=?,value_enc=?,path=?,path_enc=?,key_index=?,version=?,updated_at=?,updated_by=? WHERE id=?", &[json!(ke),json!(ve),json!(path),json!(pe),json!(kh),json!(version),json!(now()),json!(uid),json!(sid)])?; (sid,version)
            } else { let sid=id(); tx.exec("INSERT INTO secrets(id,env_id,path,path_enc,key_enc,key_hash,key_index,value_enc,e2e,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,1,1,?,?)", &[json!(sid),json!(eid),json!(path),json!(pe),json!(ke),json!(kh),json!(kh),json!(ve),json!(now()),json!(uid)])?; (sid,1) };
            tx.exec("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,'',?,?)", &[json!(id()),json!(sid),json!(version),json!(ke),json!(ve),json!(path),json!(now()),json!(uid)])?; count+=1;
        }
        AuditEvent::new([&org,&app,&eid,&uid,"secret.e2e_deploy",&format!("{} secrets",count)]).append(tx)?; Ok(count)
    }).await.map_err(failure)?; st.drain_outbox().await; Ok(j(json!({"deployed":count})))
}
