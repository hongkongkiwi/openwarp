use super::*;

fn denied() -> (StatusCode, Json<Value>) { err(StatusCode::UNAUTHORIZED, "invalid workload proof") }
fn text<'a>(v: &'a Value, k: &str) -> &'a str { v.get(k).and_then(Value::as_str).unwrap_or("") }
fn bounded(s: &str) -> bool { !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control) }
fn public_key(k: &Value, alg: jsonwebtoken::Algorithm) -> Result<jsonwebtoken::DecodingKey, String> {
    use jsonwebtoken::Algorithm::*;
    if !k.is_object() || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].iter().any(|f| k.get(*f).is_some()) { return Err("public asymmetric keys only".into()); }
    if k.get("use").is_some() && text(k, "use") != "sig" { return Err("JWK must be for signatures".into()); }
    if let Some(ops) = k.get("key_ops") {
        let ops = ops.as_array().ok_or("invalid key_ops")?;
        if ops.len() != 1 || ops[0].as_str() != Some("verify") { return Err("JWK key_ops must be verify only".into()); }
    }
    jwk_signing_algorithm(k, alg)?;
    match alg {
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 if text(k, "kty") == "RSA" => (),
        ES256 if text(k, "kty") == "EC" && text(k, "crv") == "P-256" => (),
        ES384 if text(k, "kty") == "EC" && text(k, "crv") == "P-384" => (),
        _ => return Err("JWK algorithm and key type disagree".into()),
    }
    jwk_decoding_key(k, alg)
}
fn validate_jwks(v: &Value) -> Result<(), String> {
    let keys = v.get("keys").and_then(Value::as_array).ok_or("inline JWKS required")?;
    if keys.is_empty() || keys.len() > 16 || v.to_string().len() > 65536 { return Err("invalid JWKS size".into()); }
    let mut kids = std::collections::HashSet::new();
    for k in keys {
        if !kids.insert(text(k, "kid")) { return Err("duplicate JWK kid".into()); }
        let alg = match text(k, "alg") {
            "" => match (text(k, "kty"), text(k, "crv")) { ("RSA", _) => jsonwebtoken::Algorithm::RS256, ("EC", "P-256") => jsonwebtoken::Algorithm::ES256, ("EC", "P-384") => jsonwebtoken::Algorithm::ES384, _ => return Err("unsupported JWK".into()) },
            s => serde_json::from_value(json!(s)).map_err(|_| "invalid JWK algorithm")?,
        };
        public_key(k, alg)?;
    }
    Ok(())
}
async fn authority(st: &S, h: &HeaderMap, oid: &str, iid: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let uid = st.token_user(h).await?; let role = st.require_org(oid, &uid).await?; st.check_admin(oid, &uid).await?;
    st.require_org_running(oid).await?;
    st.require_feature(oid, "workload-identity").await?;
    let identity = st.db.one("SELECT role FROM identities WHERE id=? AND org_id=?", &[json!(iid), json!(oid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| err(StatusCode::FORBIDDEN, "identity does not belong to workspace"))?;
    if st.role_privileged(oid, &db::s(&identity, "role")).await && role != "owner" { return Err(err(StatusCode::FORBIDDEN, "only owner may configure privileged identities")); }
    Ok(uid)
}
pub(super) async fn create(State(st): State<S>, h: HeaderMap, Path((oid, iid)): Path<(String, String)>, Json(body): Json<Value>) -> Res {
    let uid = authority(&st, &h, &oid, &iid).await?;
    let eid = text(&body, "env_id"); if !bounded(eid) { return Err(bad("single env_id required")); }
    st.check_scope(&h, eid).await?; let (org, _) = st.require_env(eid, &uid).await?;
    if org != oid { return Err(err(StatusCode::FORBIDDEN, "environment does not belong to workspace")); }
    for f in ["issuer", "audience", "subject"] { if !bounded(text(&body, f)) { return Err(bad("issuer, audience and subject required and bounded")); } }
    let ttl = body.get("ttl").and_then(Value::as_i64).unwrap_or(300); if !(30..=900).contains(&ttl) { return Err(bad("ttl must be 30-900 seconds")); }
    let scopes = body.get("scopes").and_then(Value::as_array).ok_or_else(|| bad("scopes required"))?;
    if scopes.is_empty() || scopes.len() > 2 || scopes.iter().any(|s| !matches!(s.as_str(), Some("secrets:read" | "secrets:write"))) { return Err(bad("only explicit secret read/write scopes supported")); }
    let bound = body.get("bound_claims").cloned().unwrap_or(json!({}));
    let claims = bound.as_object().ok_or_else(|| bad("bound_claims must be an object"))?;
    if bound.to_string().len() > 16384 || claims.len() > 32 { return Err(bad("too many bound claims")); }
    for (k, v) in claims {
        if !bounded(k) || ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"].contains(&k.as_str()) { return Err(bad("reserved or invalid bound claim")); }
        let valid = match v { Value::String(s) => bounded(s), Value::Array(a) => !a.is_empty() && a.len() <= 32 && a.iter().all(|v| v.as_str().is_some_and(bounded)), _ => false };
        if !valid { return Err(bad("bound claims must be strings or string arrays")); }
    }
    let jwks = body.get("jwks").ok_or_else(|| bad("inline JWKS required"))?; validate_jwks(jwks).map_err(|e| bad(&e))?;
    let tid = id(); let scopes = scopes.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ");
    st.db.exec("INSERT INTO workload_trusts(id,org_id,identity_id,env_id,issuer,audience,subject,jwks,scopes,ttl,bound_claims,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", &[json!(tid), json!(oid), json!(iid), json!(eid), body["issuer"].clone(), body["audience"].clone(), body["subject"].clone(), json!(jwks.to_string()), json!(scopes), json!(ttl), json!(bound.to_string()), json!(now())]).await.map_err(|e| bad(&e))?;
    st.audit(&oid, "", eid, &uid, "workload.trust.create", &tid).await;
    Ok(j(json!({"id":tid,"env_id":eid,"ttl":ttl})))
}
pub(super) async fn list(State(st): State<S>, h: HeaderMap, Path((oid, iid)): Path<(String, String)>) -> Res {
    authority(&st, &h, &oid, &iid).await?;
    let rows = st.db.query("SELECT id,env_id,issuer,audience,subject,scopes,ttl,revoked,created_at FROM workload_trusts WHERE org_id=? AND identity_id=?", &[json!(oid), json!(iid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!(rows.iter().map(db::obj).collect::<Vec<_>>())))
}
pub(super) async fn revoke(State(st): State<S>, h: HeaderMap, Path((oid, iid, tid)): Path<(String, String, String)>) -> Res {
    let uid = authority(&st, &h, &oid, &iid).await?;
    let n = st.db.exec("UPDATE workload_trusts SET revoked=1 WHERE id=? AND org_id=? AND identity_id=?", &[json!(tid), json!(oid), json!(iid)]).await.map_err(|e| bad(&e))?;
    if n == 0 { return Err(err(StatusCode::NOT_FOUND, "trust not found")); }
    // Live policy checks deny existing tokens even if cleanup fails.
    st.db.exec("DELETE FROM tokens WHERE trust_id=?", &[json!(tid)]).await.map_err(|e| bad(&e))?;
    st.audit(&oid, "", "", &uid, "workload.trust.revoke", &tid).await;
    Ok(j(json!({"revoked":tid})))
}
fn verify(jwt: &str, trust: &Row) -> Result<Value, String> {
    if jwt.len() > 32768 { return Err("proof too large".into()); }
    let raw_header = jwt.split('.').next().and_then(b64url_json).ok_or("invalid header")?;
    if ["jku", "x5u", "jwk", "crit"].iter().any(|f| raw_header.get(*f).is_some()) { return Err("unsupported header".into()); }
    let header = jsonwebtoken::decode_header(jwt).map_err(|e| e.to_string())?;
    let jwks: Value = serde_json::from_str(&db::s(trust, "jwks")).map_err(|e| e.to_string())?;
    let keys = jwks["keys"].as_array().ok_or("invalid keys")?;
    let key = match header.kid { Some(kid) => keys.iter().find(|k| text(k, "kid") == kid).ok_or("unknown kid")?, None if keys.len() == 1 => &keys[0], _ => return Err("kid required".into()) };
    let decoding = public_key(key, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg); validation.leeway = 0; validation.validate_nbf = true;
    validation.set_issuer(&[db::s(trust, "issuer")]); validation.set_audience(&[db::s(trust, "audience")]);
    validation.set_required_spec_claims(&["iss", "aud", "sub", "exp", "iat", "jti"]);
    let c = jsonwebtoken::decode::<Value>(jwt, &decoding, &validation).map_err(|e| e.to_string())?.claims;
    let t = now(); let exp = c["exp"].as_i64().ok_or("exp required")?; let iat = c["iat"].as_i64().ok_or("iat required")?;
    if exp <= t || iat > t + 30 || iat < t - 900 || exp <= iat || exp - iat > 3600 || text(&c, "sub") != db::s(trust, "subject") || !bounded(text(&c, "jti")) { return Err("invalid claims".into()); }
    if let Some(nbf) = c.get("nbf") { if nbf.as_i64().is_none_or(|n| n > t) { return Err("invalid nbf".into()); } }
    let bound: Value = serde_json::from_str(&db::s(trust, "bound_claims")).map_err(|e| e.to_string())?;
    for (k, v) in bound.as_object().ok_or("invalid bound claims")? { if c.get(k) != Some(v) { return Err("bound claim mismatch".into()); } }
    Ok(c)
}
fn client_ip(h: &HeaderMap, peer: PeerAddr) -> String {
    let peer = peer.0.to_string();
    let proxy = crate::envcfg::var("OPENWARP_TRUST_PROXY").is_ok_and(|v| v == "1") && crate::envcfg::var("OPENWARP_TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1/32,::1".into()).split(',').any(|c| ip_in_cidr(&peer, c));
    if proxy { if let Some(ip) = h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next()).and_then(|v| v.trim().parse::<std::net::IpAddr>().ok()) { return ip.to_string(); } }
    peer
}
async fn rate(st: &S, key: &str, max: i64) -> bool {
    st.db.rate_increment(key, now(), 60).await.is_ok_and(|count| count > 0 && count <= max)
}
pub(super) async fn login(State(st): State<S>, h: HeaderMap, peer: PeerAddr, Json(body): Json<Value>) -> Res {
    let tid = text(&body, "trust_id"); let jwt = text(&body, "jwt"); let ip = client_ip(&h, peer);
    if !bounded(tid) || jwt.is_empty() || jwt.len() > 32768 { return Err(denied()); }
    if !rate(&st, &format!("workload:peer:{}", ip), 120).await || !rate(&st, &format!("workload:trust:{}:{}", ip, oc::hash_token(tid)), 60).await { return Err(err(StatusCode::TOO_MANY_REQUESTS, "workload exchange rate exceeded")); }
    let trust = st.db.one("SELECT w.* FROM workload_trusts w JOIN identities i ON i.id=w.identity_id AND i.org_id=w.org_id WHERE w.id=? AND w.revoked=0", &[json!(tid)]).await.map_err(|_| denied())?.ok_or_else(denied)?;
    let oid = db::s(&trust, "org_id"); let iid = db::s(&trust, "identity_id"); let eid = db::s(&trust, "env_id");
    // A grant removed after a trust was created stops the exchange as well.
    st.require_feature(&oid, "workload-identity").await.map_err(|_| denied())?;
    let org = st.db.one("SELECT ip_allowlist FROM orgs WHERE id=?", &[json!(oid)]).await.map_err(|_| denied())?.ok_or_else(denied)?;
    let list = db::s(&org, "ip_allowlist"); if !list.trim().is_empty() && !list.split(',').any(|c| ip_in_cidr(&ip, c)) { return Err(err(StatusCode::FORBIDDEN, "source IP not in organisation allowlist")); }
    // Lockdown denials stay 403 and distinct from a generic proof failure; check
    // them before spending work on the proof.
    let (trust_org, app) = st.env_org_app(&eid).await.map_err(|_| denied())?; if trust_org != oid { return Err(denied()); }
    st.require_org_running(&oid).await?; st.require_app_running(&app).await?;
    let c = verify(jwt, &trust).map_err(|_| denied())?;
    st.require_env(&eid, &iid).await.map_err(|_| denied())?;
    let ttl = db::n(&trust, "ttl").min(c["exp"].as_i64().ok_or_else(denied)? - now()); if ttl <= 0 { return Err(denied()); }
    let token = oc::random_token("oww");
    let replay = oc::hash_token(&json!([db::s(&trust,"issuer"),c["jti"]]).to_string());
    let statements = vec![
        ("DELETE FROM workload_replay WHERE expires_at<=?".into(), vec![json!(now())], None),
        ("UPDATE workload_trusts SET revoked=revoked WHERE id=? AND revoked=0".into(), vec![json!(tid)], Some(1)),
        ("UPDATE identities SET role=role WHERE id=? AND org_id=?".into(), vec![json!(iid),json!(oid)], Some(1)),
        ("INSERT INTO workload_replay(key,expires_at) VALUES(?,?)".into(), vec![json!(replay),c["exp"].clone()], Some(1)),
        ("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,kind,expires_at,scopes,created_at,created_by,trust_id) VALUES(?,?,?,?,?,?,'workload',?,?,?,?,?)".into(), vec![json!(id()),json!(oid),json!(app),json!(eid),json!("workload"),json!(oc::hash_token(&token)),json!(now()+ttl),json!(db::s(&trust,"scopes")),json!(now()),json!(iid),json!(tid)], Some(1)),
    ];
    st.db.checked_batch(&statements, false).await.map_err(|e| if e.contains("unavailable on Workers") { err(StatusCode::NOT_IMPLEMENTED, "atomic workload exchange unavailable on Workers") } else { denied() })?;
    Ok(j(json!({"accessToken":token,"expiresIn":ttl,"tokenType":"Bearer","identity_id":iid})))
}
pub(super) async fn live(st: &AppState, token: &Row) -> bool {
    let tid = db::s(token, "trust_id");
    st.db.one("SELECT w.env_id,w.org_id,w.identity_id,w.scopes FROM workload_trusts w JOIN identities i ON i.id=w.identity_id AND i.org_id=w.org_id JOIN envs e ON e.id=w.env_id JOIN apps a ON a.id=e.app_id AND a.org_id=w.org_id JOIN orgs o ON o.id=w.org_id WHERE w.id=? AND w.revoked=0", &[json!(tid)]).await.ok().flatten().is_some_and(|w| ["env_id","org_id","scopes"].iter().all(|f| db::s(&w,f)==db::s(token,f)) && db::s(&w,"identity_id")==db::s(token,"created_by"))
}
pub(super) async fn restrict(st: &S, h: &HeaderMap, path: &str, method: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let token = bearer_token(h); if token.is_empty() { return Ok(()); }
    let row = st.db.one("SELECT * FROM tokens WHERE token_hash=? AND kind='workload'", &[json!(oc::hash_token(&token))]).await.map_err(|_| denied())?;
    let Some(row) = row else { return Ok(()); };
    if db::n(&row,"expires_at") <= now() || !live(st, &row).await { return Err(denied()); }
    let eid = db::s(&row,"env_id");
    let prefix = format!("/api/envs/{}/",eid); let tail = path.strip_prefix(&prefix).unwrap_or("");
    let action = match (method,tail) {
        ("GET", "secrets" | "export" | "meta" | "e2e/secrets" | "e2e/meta") => "secrets:read",
        ("PUT", "secrets") | ("POST", "import") => "secrets:write",
        _ => return Err(err(StatusCode::FORBIDDEN, "workload token endpoint denied")),
    };
    if !db::s(&row,"scopes").split_whitespace().any(|s| s==action) { return Err(err(StatusCode::FORBIDDEN,"workload token lacks action scope")); }
    st.require_env(&eid, &db::s(&row,"created_by")).await?;
    Ok(())
}
