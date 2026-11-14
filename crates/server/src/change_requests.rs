use super::*;
type Statement = (String, Vec<Value>, Option<u64>);
type Payloads = Vec<(String,[u8;32],Vec<Value>)>;
fn conflict() -> (StatusCode, Json<Value>) { err(StatusCode::CONFLICT,"change request revision, state or target changed") }
fn tx_error(e: String) -> (StatusCode, Json<Value>) { if e.contains("unavailable on Workers") { err(StatusCode::NOT_IMPLEMENTED,"atomic change requests unavailable on Workers") } else { conflict() } }
fn aad(pid: &str, eid: &str, revision: i64) -> Vec<u8> { json!(["openwarp:change-request:v1",pid,eid,revision]).to_string().into_bytes() }
async fn environment(st: &S, h: &HeaderMap, uid: &str, org: &str, eid: &str) -> Result<[u8;32], (StatusCode, Json<Value>)> {
    st.check_scope(h,eid).await?; let (actual,app) = st.require_env(eid,uid).await?;
    if actual!=org { return Err(err(StatusCode::FORBIDDEN,"environment outside workspace")); }
    // Lockdown is enforced here too: these routes are outside the central mapper.
    st.require_org_running(&actual).await?; st.require_app_running(&app).await?;
    let row = st.db.one("SELECT mode FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.ok_or_else(conflict)?;
    if db::s(&row,"mode")!="sse" { return Err(err(StatusCode::CONFLICT,"change requests require server-readable SSE environments")); }
    st.env_key(eid).await
}
async fn snapshot(st: &S, h: &HeaderMap, uid: &str, org: &str, pid: &str, revision: i64, body: &Value) -> Result<Vec<Statement>, (StatusCode, Json<Value>)> {
    let title = body["title"].as_str().ok_or_else(|| bad("title required"))?;
    if title.is_empty() || title.len()>200 { return Err(bad("title must be 1-200 bytes")); }
    let changes = body["changes"].as_array().ok_or_else(|| bad("changes required"))?;
    if changes.is_empty() || changes.len()>20 { return Err(bad("provide 1-20 environments")); }
    let mut seen_envs = std::collections::HashSet::new(); let mut total = 0; let mut statements = Vec::new();
    for change in changes {
        let eid = change["env_id"].as_str().ok_or_else(|| bad("env_id required"))?;
        if !seen_envs.insert(eid) { return Err(bad("duplicate environment")); }
        let key = environment(st,h,uid,org,eid).await?;
        let mut items = Vec::new(); let mut seen = std::collections::HashSet::new();
        for field in ["secrets","deletes"] {
            let empty = Vec::new(); let inputs = match change.get(field) { Some(v)=>v.as_array().ok_or_else(|| bad("operations must be arrays"))?, None=>&empty };
            total += inputs.len(); if total>500 { return Err(bad("maximum 500 operations")); }
            for input in inputs {
                let name = input["key"].as_str().ok_or_else(|| bad("key required"))?.trim().to_uppercase();
                let path = input.get("path").map(|v| v.as_str().ok_or_else(|| bad("invalid path"))).transpose()?.unwrap_or("/");
                if !valid_secret_key(&name) || !valid_path(path) { return Err(bad("invalid secret key or path")); }
                if !seen.insert((name.clone(),path.to_string())) { return Err(bad("duplicate logical secret")); }
                let index = key_index(&key,path,&name); let legacy = oc::hash_token(&format!("{}:{}",path,name));
                let rows = st.db.query("SELECT * FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?)", &[json!(eid),json!(index),json!(legacy)]).await.map_err(|e| bad(&e))?;
                let active: Vec<_> = rows.iter().filter(|r| db::n(r,"deleted")==0).collect();
                if active.len()>1 { return Err(conflict()); }
                let before = active.first().map(|r| db::obj(r)).unwrap_or(Value::Null);
                let after = if field=="deletes" { Value::Null } else {
                    let mut s: SecretIn = serde_json::from_value(input.clone()).map_err(|_| bad("invalid secret input"))?;
                    s.key = name.clone(); s.path = path.to_string(); if s.secret_type.is_empty() { s.secret_type="secret".into(); }
                    if !matches!(s.secret_type.as_str(),"secret"|"sealed"|"ssh_key"|"config"|"wallet_private_key"|"wallet_recovery_phrase") { return Err(bad("invalid secret type")); }
                    if wallet_type(before["secret_type"].as_str().unwrap_or("")) && before["secret_type"]!=s.secret_type { return Err(bad("wallet secrets cannot change type; delete and recreate")); }
                    if s.secret_type=="ssh_key" && ssh_keys::public_key_error(&name,&s.value).is_some() { return Err(bad("invalid SSH public key")); }
                    if before["secret_type"]=="sealed" && s.secret_type!="sealed" { return Err(bad("sealed secrets cannot change type; delete and recreate")); }
                    json!({"key":name,"path":path,"value":s.value,"comment":s.comment,"tags":s.tags,"type":s.secret_type})
                };
                items.push(json!({"key":name,"path":path,"index":index,"legacy":legacy,"rows":rows.iter().map(db::obj).collect::<Vec<_>>(),"before":before,"after":after}));
            }
        }
        let encrypted = oc::encrypt_symmetric_aad(&key,&aad(pid,eid,revision),&serde_json::to_vec(&items).map_err(|e| bad(&e.to_string()))?);
        statements.push(("INSERT INTO change_request_envs(request_id,env_id,payload_enc) VALUES(?,?,?)".into(),vec![json!(pid),json!(eid),json!(encrypted)],Some(1)));
    }
    if total==0 { return Err(bad("at least one operation required")); }
    Ok(statements)
}
async fn request(st: &S, pid: &str) -> Result<Row, (StatusCode, Json<Value>)> {
    let row = st.db.one("SELECT * FROM change_requests WHERE id=?", &[json!(pid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"change request not found"))?;
    st.require_feature(&db::s(&row,"org_id"), "change-requests").await?;
    Ok(row)
}
async fn payloads(st: &S, row: &Row, h: &HeaderMap, uid: &str) -> Result<Payloads, (StatusCode, Json<Value>)> {
    let pid = db::s(row,"id"); let org = db::s(row,"org_id");
    let rows = st.db.query("SELECT env_id,payload_enc FROM change_request_envs WHERE request_id=? ORDER BY env_id", &[json!(pid)]).await.map_err(|e| bad(&e))?;
    let mut result = Vec::new();
    for r in rows {
        let eid = db::s(&r,"env_id"); let key = environment(st,h,uid,&org,&eid).await?;
        let raw = oc::decrypt_symmetric_aad(&key,&aad(&pid,&eid,db::n(row,"revision")),&db::s(&r,"payload_enc")).map_err(|_| conflict())?;
        let items: Vec<Value> = serde_json::from_slice(&raw).map_err(|_| conflict())?;
        result.push((eid,key,items));
    }
    Ok(result)
}
pub(super) async fn create(State(st): State<S>, h: HeaderMap, Path(org): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; st.check_perm(&org,&uid,"proposals:write").await?;
    st.require_feature(&org,"change-requests").await?;
    let pid = id(); let mut statements = snapshot(&st,&h,&uid,&org,&pid,1,&body).await?;
    statements.insert(0,("INSERT INTO change_requests(id,org_id,title,author,revision,status,created_at) VALUES(?,?,?,?,1,'pending',?)".into(),vec![json!(pid),json!(org),body["title"].clone(),json!(uid),json!(now())],Some(1)));
    let (pairs,checked)=crate::checked_pairs(statements,false);
    st.audited_batch(&pairs,&checked,[&org,"","",&uid,"change_request.create",&pid]).await.map_err(tx_error)?;
    Ok(j(json!({"id":pid,"revision":1,"status":"pending"})))
}
pub(super) async fn edit(State(st): State<S>, h: HeaderMap, Path(pid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let row = request(&st,&pid).await?; let org = db::s(&row,"org_id");
    st.check_perm(&org,&uid,"proposals:write").await?;
    if db::s(&row,"author")!=uid { return Err(err(StatusCode::FORBIDDEN,"only author may edit")); }
    let revision = body["revision"].as_i64().ok_or_else(|| bad("revision required"))?;
    if revision!=db::n(&row,"revision") || !matches!(db::s(&row,"status").as_str(),"pending"|"approved") { return Err(conflict()); }
    payloads(&st,&row,&h,&uid).await?;
    let next = revision.checked_add(1).ok_or_else(conflict)?;
    let mut statements = snapshot(&st,&h,&uid,&org,&pid,next,&body).await?;
    statements.insert(0,("DELETE FROM change_request_envs WHERE request_id=?".into(),vec![json!(pid)],None));
    statements.insert(0,("UPDATE change_requests SET title=?,revision=?,status='pending',approved_by='' WHERE id=? AND author=? AND revision=? AND (status='pending' OR status='approved')".into(),vec![body["title"].clone(),json!(next),json!(pid),json!(uid),json!(revision)],Some(1)));
    let (pairs,checked)=crate::checked_pairs(statements,false);
    st.audited_batch(&pairs,&checked,[&org,"","",&uid,"change_request.edit",&pid]).await.map_err(tx_error)?;
    Ok(j(json!({"id":pid,"revision":next,"status":"pending"})))
}
pub(super) async fn list(State(st): State<S>, h: HeaderMap, Path(org): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.require_org(&org,&uid).await?;
    st.require_feature(&org,"change-requests").await?;
    let rows = st.db.query("SELECT * FROM change_requests WHERE org_id=? ORDER BY created_at,id", &[json!(org)]).await.map_err(|e| bad(&e))?;
    let mut result = Vec::new();
    for row in rows { if payloads(&st,&row,&h,&uid).await.is_ok() { result.push(db::obj(&row)); } }
    Ok(j(json!(result)))
}
pub(super) async fn detail(State(st): State<S>, h: HeaderMap, Path(pid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; let row = request(&st,&pid).await?; st.check_perm(&db::s(&row,"org_id"),&uid,"secrets:read").await?;
    let payloads = payloads(&st,&row,&h,&uid).await?; let mut changes = Vec::new();
    for (eid,key,items) in payloads {
        let mut reviewed = Vec::new();
        for item in items {
            let mut before = if item["before"].is_null() { Value::Null } else {
                let raw: Row = serde_json::from_value(item["before"].clone()).map_err(|_| conflict())?;
                st.decrypt_secret(&key,&raw,None).await
            };
            let mut after = item["after"].clone();
            let name = item["key"].as_str().ok_or_else(conflict)?; let path = item["path"].as_str().ok_or_else(conflict)?;
            let sid = if item["before"].is_null() { "" } else { item["before"]["id"].as_str().ok_or_else(conflict)? };
            let index = key_index(&key,path,name); let legacy = oc::hash_token(&format!("{}:{}",path,name));
            let current_wallet = st.db.one("SELECT id FROM secrets WHERE env_id=? AND secret_type IN ('wallet_private_key','wallet_recovery_phrase') AND (id=? OR key_index=? OR key_hash=?) LIMIT 1", &[json!(&eid),json!(sid),json!(index),json!(legacy)]).await.map_err(|e| bad(&e))?.is_some();
            if current_wallet || after["type"]=="sealed" || before["type"]=="sealed" || wallet_type(after["type"].as_str().unwrap_or("")) || wallet_type(before["type"].as_str().unwrap_or("")) {
                if after.is_object() { after["value"]=Value::Null; }
                if before.is_object() { before["value"]=Value::Null; }
            }
            reviewed.push(json!({"key":item["key"],"path":item["path"],"before":before,"after":after}));
        }
        changes.push(json!({"env_id":eid,"items":reviewed}));
    }
    let mut result = db::obj(&row); result["changes"]=json!(changes); Ok(j(result))
}
fn row_guard(raw: &Value) -> Result<Statement, (StatusCode, Json<Value>)> {
    let row: Row = serde_json::from_value(raw.clone()).map_err(|_| conflict())?;
    let columns = ["id","env_id","path","key_enc","key_hash","value_enc","comment_enc","tags","secret_type","version","deleted","deleted_at","updated_at","updated_by","e2e","value_fp","path_enc","tags_enc","key_index"];
    let mut conditions = Vec::new(); let mut params = Vec::new();
    for column in columns {
        let value = row.get(column).ok_or_else(conflict)?;
        if value.is_null() { conditions.push(format!("{} IS NULL",column)); } else { conditions.push(format!("{}=?",column)); params.push(value.clone()); }
    }
    Ok((format!("UPDATE secrets SET version=version WHERE {}",conditions.join(" AND ")),params,Some(1)))
}
async fn writes(st: &S, eid: &str, org: &str, uid: &str, key: &[u8;32], limit: i64, item: &Value) -> Result<Vec<Statement>, (StatusCode, Json<Value>)> {
    let before = &item["before"]; let after = &item["after"]; let mut result = Vec::new();
    if after.is_null() {
        if !before.is_null() { result.push(("UPDATE secrets SET deleted=1,deleted_at=?,updated_at=?,updated_by=? WHERE id=? AND env_id=?".into(),vec![json!(now()),json!(now()),json!(uid),before["id"].clone(),json!(eid)],Some(1))); }
        return Ok(result);
    }
    let s: SecretIn = serde_json::from_value(after.clone()).map_err(|_| conflict())?;
    let sid = before["id"].as_str().map(str::to_string).unwrap_or_else(id);
    let version = if before.is_null() { 1 } else { before["version"].as_i64().ok_or_else(conflict)?.checked_add(1).ok_or_else(conflict)? };
    let key_enc = oc::encrypt_symmetric_aad(key,&secret_aad(eid,&sid,"key"),s.key.as_bytes());
    let value_enc = oc::encrypt_symmetric_aad(key,&secret_aad_v(eid,&sid,"value",version),s.value.as_bytes());
    let comment_enc = oc::encrypt_symmetric_aad(key,&secret_aad_v(eid,&sid,"comment",version),s.comment.as_bytes());
    let path_enc = oc::encrypt_symmetric_aad(key,&secret_aad(eid,&sid,"path"),s.path.as_bytes());
    let tags_enc = oc::encrypt_symmetric_aad(key,&secret_aad(eid,&sid,"tags"),s.tags.as_bytes());
    let index = key_index(key,&s.path,&s.key);
    let fp = if s.secret_type=="secret" && !s.value.is_empty() { value_fingerprint(&st.master(),org,&s.value) } else { String::new() };
    if before.is_null() {
        result.push(("INSERT INTO secrets(id,env_id,path,path_enc,key_enc,key_hash,key_index,value_enc,value_fp,comment_enc,tags,tags_enc,secret_type,version,updated_at,updated_by) VALUES(?,?,'',?,?,?,?,?,?,?,'',?,?,?,?,?)".into(),vec![json!(sid),json!(eid),json!(path_enc),json!(key_enc),json!(index),json!(index),json!(value_enc),json!(fp),json!(comment_enc),json!(tags_enc),json!(s.secret_type),json!(version),json!(now()),json!(uid)],Some(1)));
    } else {
        result.push(("UPDATE secrets SET value_enc=?,value_fp=?,comment_enc=?,path='',path_enc=?,tags='',tags_enc=?,key_hash=?,key_index=?,secret_type=?,version=?,updated_at=?,updated_by=? WHERE id=? AND env_id=?".into(),vec![json!(value_enc),json!(fp),json!(comment_enc),json!(path_enc),json!(tags_enc),json!(index),json!(index),json!(s.secret_type),json!(version),json!(now()),json!(uid),json!(sid),json!(eid)],Some(1)));
    }
    result.push(("INSERT INTO secret_versions(id,secret_id,version,key_enc,value_enc,comment_enc,secret_type,path,tags,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)".into(),vec![json!(id()),json!(sid),json!(version),json!(key_enc),json!(value_enc),json!(comment_enc),json!(s.secret_type),json!(s.path),json!(s.tags),json!(now()),json!(uid)],Some(1)));
    // The limit is read once per environment and guarded by the apply transaction,
    // so every item in one apply prunes under the same committed policy.
    if limit > 0 && version > limit { result.push(("DELETE FROM secret_versions WHERE secret_id=? AND version<=?".into(),vec![json!(sid),json!(version-limit)],None)); }
    Ok(result)
}
pub(super) async fn action(State(st): State<S>, h: HeaderMap, Path((pid,action)): Path<(String,String)>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h).await?; let row = request(&st,&pid).await?; let org = db::s(&row,"org_id"); st.check_admin(&org,&uid).await?;
    if matches!(action.as_str(),"approve"|"apply") && db::s(&row,"author")==uid { return Err(err(StatusCode::FORBIDDEN,"author cannot approve or apply")); }
    let revision = body["revision"].as_i64().ok_or_else(|| bad("revision required"))?;
    if revision!=db::n(&row,"revision") { return Err(conflict()); }
    let status = db::s(&row,"status");
    let next = match action.as_str() { "approve" if status=="pending"=>"approved", "apply" if status=="approved"=>"applied", "reject" if status=="pending" || status=="approved"=>"rejected", "approve"|"apply"|"reject"=>return Err(conflict()), _=>return Err(bad("invalid change request action")) };
    if action=="approve" { st.check_perm(&org,&uid,"secrets:read").await?; }
    let payloads = payloads(&st,&row,&h,&uid).await?;
    let mut statements = vec![("UPDATE change_requests SET status=?,approved_by=? WHERE id=? AND revision=? AND status=?".into(),vec![json!(next),json!(if action=="approve" { uid.clone() } else { db::s(&row,"approved_by") }),json!(pid),json!(revision),json!(status)],Some(1))];
    let mut mutations = Vec::new();
    if action=="apply" {
        for (eid,key,items) in &payloads {
            let env = st.db.one("SELECT env_key_wrapped,max_versions FROM envs WHERE id=?", &[json!(eid)]).await.map_err(|e| bad(&e))?.ok_or_else(conflict)?;
            let wrapped = db::s(&env,"env_key_wrapped"); let limit = db::n(&env,"max_versions");
            if st.env_key(eid).await? != *key { return Err(conflict()); }
            // Retention is part of the guarded snapshot: a policy edited after this read
            // makes the apply conflict instead of pruning under a stale limit.
            statements.push(("UPDATE envs SET mode=mode WHERE id=? AND mode='sse' AND env_key_wrapped=? AND max_versions=?".into(),vec![json!(eid),json!(wrapped),json!(limit)],Some(1)));
            for item in items {
                st.check_perm(&org,&uid,if item["after"].is_null() { "secrets:delete" } else { "secrets:write" }).await?;
                let rows = item["rows"].as_array().ok_or_else(conflict)?;
                // The table lock makes both cardinality and raw-row guards stable until commit.
                statements.push(("UPDATE change_requests SET revision=revision WHERE id=? AND revision=? AND (SELECT COUNT(*) FROM secrets WHERE env_id=? AND (key_index=? OR key_hash=?))=?".into(),vec![json!(pid),json!(revision),json!(eid),item["index"].clone(),item["legacy"].clone(),json!(rows.len() as i64)],Some(1)));
                for raw in rows { statements.push(row_guard(raw)?); }
                mutations.extend(writes(&st,eid,&org,&uid,key,limit,item).await?);
            }
        }
        statements.extend(mutations);
    }
    require_step_up(&st,&h,&uid,StepUpRisk::TwoFactor).await?;
    if action=="apply" {
        // Apply keeps checked_batch's original semantics exactly: per-statement
        // expected counts (retention pruning deletes many rows) plus the
        // secret-table lock; its audit stays observational because audited_batch
        // cannot express the lock. Known composition gap, disclosed in the PR.
        st.db.checked_batch(&statements,true).await.map_err(tx_error)?;
        st.audit(&org,"","",&uid,&format!("change_request.{}",action),&format!("{} revision={}",pid,revision)).await;
    } else {
        let (pairs,checked)=crate::checked_pairs(statements,false);
        st.audited_batch(&pairs,&checked,[&org,"","",&uid,&format!("change_request.{}",action),&format!("{} revision={}",pid,revision)]).await.map_err(tx_error)?;
    }
    let mut sync_errors = serde_json::Map::new();
    if action=="apply" { for (eid,_,_) in &payloads { sync_errors.insert(eid.clone(),json!(trigger_sync(&st,eid,&uid).await)); } }
    Ok(j(json!({"id":pid,"revision":revision,"status":next,"sync_errors":sync_errors})))
}
