use super::*;
type Failure = (StatusCode, Json<Value>);

pub(super) async fn creation_open(st: &S) -> Result<bool, Failure> {
    if let Ok(v) = crate::envcfg::var("OPENWARP_WORKSPACE_CREATION") { return Ok(!matches!(v.trim().to_ascii_lowercase().as_str(), "closed" | "invite" | "invite_only" | "disabled" | "0" | "false")); }
    Ok(st.db.one("SELECT v FROM meta WHERE k='workspace_creation_open'", &[]).await.map_err(|e| bad(&e))?.map(|r| db::s(&r,"v") != "0").unwrap_or(true))
}
pub(super) fn policy_lock() -> (String, Vec<Value>) { ("UPDATE meta SET v=v WHERE k='workspace_policy_lock'".into(), vec![]) }
pub(super) fn creation_guard() -> (String, Vec<Value>) {
    ("UPDATE meta SET v=v WHERE k='workspace_creation_open' AND v<>'0'".into(), vec![])
}
pub(super) async fn default_workspace(st: &S, uid: &str, email: &str) -> Result<Option<String>, Failure> {
    if !creation_open(st).await? { return Ok(None); }
    let oid = id(); let mut stmts = vec![policy_lock()];
    if crate::envcfg::var("OPENWARP_WORKSPACE_CREATION").is_err() { stmts.push(creation_guard()); }
    let checked: Vec<usize> = (0..stmts.len()).collect();
    stmts.push(("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)".into(), vec![json!(&oid),json!(format!("{}'s organisation",email)),json!(now())]));
    stmts.push(("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,'owner')".into(), vec![json!(&oid),json!(uid)]));
    user_guarded_batch(st, &[uid], &stmts, &checked).await?; Ok(Some(oid))
}
pub(super) async fn set_creation(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = human(&st,&h).await?;
    if instance_owner(&st).await.as_deref() != Some(uid.as_str()) { return Err(err(StatusCode::FORBIDDEN,"only the instance owner can change workspace creation")); }
    if crate::envcfg::var("OPENWARP_WORKSPACE_CREATION").is_ok() { return Err(err(StatusCode::CONFLICT,"OPENWARP_WORKSPACE_CREATION controls workspace creation on this instance")); }
    let open = body["open"].as_bool().ok_or_else(|| bad("open must be a boolean"))?;
    let mut stmts = vec![policy_lock()]; let mut checked = vec![0];
    if !open { stmts.push(("UPDATE meta SET v=v WHERE k='workspace_policy_lock' AND EXISTS (SELECT 1 FROM orgs)".into(),vec![])); checked.push(1); }
    // The lock row serializes policy writes with creation and last-workspace deletion.
    stmts.push(("DELETE FROM meta WHERE k='workspace_creation_open'".into(),vec![]));
    stmts.push(("INSERT INTO meta(k,v) VALUES('workspace_creation_open',?)".into(),vec![json!(if open { "1" } else { "0" })]));
    st.db.batch_checked(&stmts,&checked).await.map_err(|e| if e.contains("version conflict") { err(StatusCode::CONFLICT,"create a workspace before disabling workspace creation") } else { bad(&e) })?;
    st.audit("","","",&uid,"instance.workspace_creation",if open { "open" } else { "invitation_only" }).await;
    Ok(j(json!({"workspace_creation_open":open})))
}
pub(super) async fn human(st: &S, h: &HeaderMap) -> Result<String, Failure> {
    let uid = st.token_user(h).await?; let bearer = bearer_token(h); let token = if bearer.is_empty() { cookie_val(h,"ow_session") } else { bearer };
    if st.db.one("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=?", &[json!(oc::hash_token(&token)),json!(&uid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(err(StatusCode::FORBIDDEN,"an account session is required")); } Ok(uid)
}
pub(super) async fn grant(st: &S, org: &str, uid: &str, role: &str) -> Result<(), Failure> {
    st.check_admin(org,uid).await?;
    if !["owner","admin","developer"].contains(&role) && st.db.one("SELECT id FROM roles WHERE org_id=? AND name=?", &[json!(org),json!(role)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad("unknown role for this organisation")); }
    if st.role_privileged(org,role).await && st.require_org(org,uid).await? != "owner" { return Err(err(StatusCode::FORBIDDEN,"only an owner can grant a role with admin rights")); } Ok(())
}
pub(super) async fn valid_invite(st: &S, token: &str, h: &HeaderMap, addr: std::net::IpAddr) -> Result<Row, Failure> {
    let row = st.db.one("SELECT * FROM invites WHERE token_hash=? AND accepted=0 AND expires_at>?", &[json!(oc::hash_token(token.trim())),json!(now())]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("invite is invalid or expired"))?;
    let org = db::s(&row,"org_id"); let inviter = db::s(&row,"invited_by");
    if !inviter.is_empty() {
        if !st.principal_active(&inviter).await { return Err(err(StatusCode::FORBIDDEN,"inviter is no longer active")); }
        grant(st,&org,&inviter,&db::s(&row,"role")).await?;
    }
    let o = st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?", &[json!(&org)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("workspace not found"))?;
    let proxy = crate::envcfg::var("OPENWARP_TRUST_PROXY").as_deref()==Ok("1") && crate::envcfg::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1/32,::1".into()).split(',').any(|c| ip_in_cidr(&addr.to_string(),c));
    let ip = if proxy { h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(|v| v.split(',').next().unwrap_or("").trim().to_string()).unwrap_or_else(|| addr.to_string()) } else { addr.to_string() };
    let list = db::s(&o,"ip_allowlist"); if !list.trim().is_empty() && !list.split(',').any(|c| ip_in_cidr(&ip,c)) { return Err(err(StatusCode::FORBIDDEN,"source IP not in organisation allowlist")); } Ok(row)
}
pub(super) async fn metadata(State(st): State<S>, PeerAddr(addr): PeerAddr, h: HeaderMap, Query(q): Query<HashMap<String,String>>) -> Res {
    let token = q.get("token").ok_or_else(|| bad("token required"))?; let row = valid_invite(&st,token,&h,addr).await?;
    let org = db::s(&row,"org_id"); let o = st.db.one("SELECT name FROM orgs WHERE id=?", &[json!(&org)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("workspace not found"))?;
    let existing = st.db.one("SELECT id FROM users WHERE email=?", &[json!(db::s(&row,"email"))]).await.map_err(|e| bad(&e))?.is_some();
    Ok(j(json!({"org_id":org,"org_name":db::s(&o,"name"),"email":db::s(&row,"email"),"role":db::s(&row,"role"),"expires_at":db::n(&row,"expires_at"),"existing_account":existing})))
}
pub(super) fn share(st: &S, iid: &str, token: &str, expires: i64) -> Value { json!({"ok":true,"id":iid,"invite_token":token,"expires_at":expires,"invite_url":format!("{}/#invite={}",st.pub_url.trim_end_matches('/'),token)}) }
pub(super) async fn consume(st: &S, row: &Row, token: &str) -> Result<(String, Vec<Value>), Failure> {
    let org = db::s(row,"org_id"); let role = db::s(row,"role");
    let roles = st.db.query("SELECT id,name,permissions FROM roles WHERE org_id=?", &[json!(&org)]).await.map_err(|e| bad(&e))?;
    // Custom role permissions are immutable; resolve JSON here rather than using backend-specific JSON SQL.
    let privileged = ["owner","admin"].contains(&role.as_str()) || roles.iter().any(|r| db::s(r,"name")==role && serde_json::from_str::<Vec<String>>(&db::s(r,"permissions")).unwrap_or_default().iter().any(|p| p=="*" || p=="org:admin"));
    let mut allowed = vec!["'owner'".to_string()];
    let mut custom = Vec::new();
    if !privileged {
        allowed.push("'admin'".into());
        for r in &roles {
            if serde_json::from_str::<Vec<String>>(&db::s(r,"permissions")).unwrap_or_default().iter().any(|p| p=="*" || p=="org:admin") { custom.push(json!(db::s(r,"id"))); }
        }
    }
    let mut authority = format!("p.role IN ({})",allowed.join(","));
    if !custom.is_empty() { authority.push_str(&format!(" OR EXISTS (SELECT 1 FROM roles r WHERE r.org_id=p.org_id AND r.name=p.role AND r.id IN ({}))",vec!["?";custom.len()].join(","))); }
    let sql = format!("UPDATE invites SET accepted=1 WHERE token_hash=? AND org_id=? AND role=? AND invited_by=? AND accepted=0 AND expires_at>? AND EXISTS (SELECT 1 FROM orgs WHERE id=?) AND (invited_by='' OR EXISTS (SELECT 1 FROM org_members p JOIN users u ON u.id=p.user_id WHERE p.org_id=invites.org_id AND p.user_id=invites.invited_by AND u.active=1 AND u.email_verified=1 AND ({})) OR EXISTS (SELECT 1 FROM identities p WHERE p.org_id=invites.org_id AND p.id=invites.invited_by AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=p.id) AND ({})))",authority,authority);
    let mut args = vec![json!(oc::hash_token(token.trim())),json!(&org),json!(&role),json!(db::s(row,"invited_by")),json!(now()),json!(&org)]; args.extend(custom.clone()); args.extend(custom);
    Ok((sql,args))
}
pub(super) async fn invite_batch(st: &S, row: &Row, users: &[&str], statements: &[(String, Vec<Value>)], checked: &[usize]) -> Result<(), Failure> {
    let inviter = db::s(row,"invited_by"); let mut users = users.to_vec();
    if !inviter.is_empty() && st.db.one("SELECT id FROM users WHERE id=?", &[json!(&inviter)]).await.map_err(|e| bad(&e))?.is_some() { users.push(&inviter); }
    // The leading org-row guard row-locks the workspace against emergency
    // transitions and enforces the running check atomically with acceptance.
    let org = db::s(row,"org_id");
    let mut guarded = vec![("UPDATE orgs SET name=name WHERE id=? AND emergency_locked=0 AND NOT EXISTS (SELECT 1 FROM apps WHERE org_id=? AND emergency_locked<>0)".into(), vec![json!(&org), json!(&org)])];
    let shifted = std::iter::once(0usize).chain(checked.iter().map(|i| i + 1)).collect::<Vec<_>>();
    guarded.extend_from_slice(statements);
    user_guarded_batch(st,&users,&guarded,&shifted).await.map_err(invite_error)
}
/// invite_batch with a master epoch fence and transactional audit: the v2
/// acceptance writes a master-encrypted auth key, so a replica holding a stale
/// key must fail closed inside the consuming transaction, not at entry.
pub(super) async fn invite_batch_master(st: &S, row: &Row, users: &[&str], statements: &[(String, Vec<Value>)], checked: &[usize], fields: [&str; 6], master: [u8; 32]) -> Result<(), Failure> {
    let inviter = db::s(row,"invited_by"); let mut users = users.to_vec();
    if !inviter.is_empty() && st.db.one("SELECT id FROM users WHERE id=?", &[json!(&inviter)]).await.map_err(|e| bad(&e))?.is_some() { users.push(&inviter); }
    let org = db::s(row,"org_id");
    let mut guarded = vec![("UPDATE orgs SET name=name WHERE id=? AND emergency_locked=0 AND NOT EXISTS (SELECT 1 FROM apps WHERE org_id=? AND emergency_locked<>0)".into(), vec![json!(&org), json!(&org)])];
    let shifted = std::iter::once(0usize).chain(checked.iter().map(|i| i + 1)).collect::<Vec<_>>();
    guarded.extend_from_slice(statements);
    user_guarded_commit_master(st,&users,&guarded,&shifted,fields,master).await
        .map_err(|e| if e.1.get("error").and_then(|v| v.as_str())==Some("epoch_stale") { (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"instance key epoch changed; reload required","code":"epoch_stale"}))) } else { invite_error(e) })
}
pub(super) async fn existing(st: &S, row: &Row, token: &str, h: &HeaderMap) -> Result<Option<(HeaderMap,Json<Value>)>, Failure> {
    let user = st.db.one("SELECT id FROM users WHERE email=?", &[json!(db::s(row,"email"))]).await.map_err(|e| bad(&e))?;
    if let Some(user) = user {
        let uid = human(st,h).await?;
        if uid != db::s(&user,"id") { return Err(err(StatusCode::FORBIDDEN,"invitation belongs to a different account")); }
        let org = db::s(row,"org_id"); let role = db::s(row,"role");
        st.require_org_running(&org).await?;
        invite_batch(st,row,&[&uid],&[
            consume(st,row,token).await?,
            ("UPDATE users SET active=active WHERE id=? AND active=1 AND email_verified=1".into(),vec![json!(&uid)]),
            ("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)".into(),vec![json!(&org),json!(&uid),json!(&role)]),
        ],&[0,1,2]).await?;
        st.audit(&org,"","",&uid,"member.accept_invite",&db::s(row,"email")).await;
        return Ok(Some((HeaderMap::new(),j(json!({"user_id":uid,"org_id":org,"role":role})))));
    }
    if st.token_user(h).await.is_ok() { return Err(err(StatusCode::FORBIDDEN,"sign out before accepting an invitation for a new account")); }
    Ok(None)
}
pub(super) fn invite_error(e: Failure) -> Failure { if e.0==StatusCode::CONFLICT { bad("invite is invalid, expired, already used, or membership changed") } else { e } }
pub(super) async fn list(State(st): State<S>, h: HeaderMap, Path(oid): Path<String>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let legacy = st.db.query("SELECT token_hash FROM invites WHERE org_id=? AND id IS NULL", &[json!(&oid)]).await.map_err(|e| bad(&e))?;
    for row in legacy { st.db.exec("UPDATE invites SET id=? WHERE token_hash=? AND id IS NULL", &[json!(id()),json!(db::s(&row,"token_hash"))]).await.map_err(|e| bad(&e))?; }
    let rows = st.db.query("SELECT id,email,role,invited_by,created_at,expires_at FROM invites WHERE org_id=? AND accepted=0 AND expires_at>?", &[json!(&oid),json!(now())]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>())))
}
pub(super) async fn revoke(State(st): State<S>, h: HeaderMap, Path((oid,iid)): Path<(String,String)>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let row = st.db.one("SELECT role FROM invites WHERE org_id=? AND id=? AND accepted=0", &[json!(&oid),json!(&iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"invitation not found"))?;
    grant(&st,&oid,&uid,&db::s(&row,"role")).await?;
    st.db.exec("DELETE FROM invites WHERE org_id=? AND id=? AND accepted=0", &[json!(&oid),json!(&iid)]).await.map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"invite.revoke",&iid).await; Ok(j(json!({"ok":true})))
}
pub(super) async fn resend(State(st): State<S>, h: HeaderMap, Path((oid,iid)): Path<(String,String)>) -> Res {
    let uid = st.token_user(&h).await?; st.check_admin(&oid,&uid).await?;
    let row = st.db.one("SELECT role FROM invites WHERE org_id=? AND id=? AND accepted=0", &[json!(&oid),json!(&iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::NOT_FOUND,"invitation not found"))?;
    grant(&st,&oid,&uid,&db::s(&row,"role")).await?;
    let token = oc::random_token("inv"); let expires = now()+7*86400;
    st.db.batch_checked(&[("UPDATE invites SET token_hash=?,expires_at=?,invited_by=? WHERE org_id=? AND id=? AND accepted=0".into(),vec![json!(oc::hash_token(&token)),json!(expires),json!(&uid),json!(&oid),json!(&iid)])],&[0]).await.map_err(|e| bad(&e))?;
    st.audit(&oid,"","",&uid,"invite.resend",&iid).await; Ok(j(share(&st,&iid,&token,expires)))
}
