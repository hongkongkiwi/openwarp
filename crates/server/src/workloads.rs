use super::*;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

pub(super) async fn manage(State(st): State<S>, h: HeaderMap, Path((oid,iid)): Path<(String,String)>, method: axum::http::Method, body: Option<Json<Value>>) -> Res {
    let uid = st.token_user(&h).await?;
    if st.require_org(&oid,&uid).await? != "owner" { return Err(err(StatusCode::FORBIDDEN,"workspace owner required")); }
    if st.db.one("SELECT id FROM identities WHERE id=? AND org_id=?", &[json!(iid),json!(oid)]).await.map_err(|e| bad(&e))?.is_none() { return Err(bad("identity not found")); }
    if method == axum::http::Method::GET {
        let r = st.db.one("SELECT issuer,jwks_url,audience,subject,max_ttl_secs FROM workload_bindings WHERE identity_id=? AND org_id=?", &[json!(iid),json!(oid)]).await.map_err(|e| bad(&e))?;
        return Ok(j(r.map(|r| db::obj(&r)).unwrap_or(Value::Null)));
    }
    if method == axum::http::Method::DELETE {
        st.db.exec("DELETE FROM workload_bindings WHERE identity_id=? AND org_id=?", &[json!(iid),json!(oid)]).await.map_err(|e| bad(&e))?;
    } else {
        let Json(b) = body.ok_or_else(|| bad("trust binding required"))?;
        let field = |k: &str| b[k].as_str().filter(|s| !s.is_empty() && s.len()<=2048).ok_or_else(|| bad("issuer, jwks_url, audience and subject required"));
        let issuer = field("issuer")?; let url = field("jwks_url")?; let audience = field("audience")?; let subject = field("subject")?;
        destination(url)?; destination(issuer)?;
        let ttl = b.get("max_ttl_secs").map(|v| v.as_i64().unwrap_or(0)).unwrap_or(300);
        if !(1..=300).contains(&ttl) { return Err(bad("max_ttl_secs must be 1-300")); }
        let sql = "INSERT INTO workload_bindings(identity_id,org_id,revision,issuer,jwks_url,audience,subject,max_ttl_secs) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(identity_id) DO UPDATE SET org_id=excluded.org_id,revision=excluded.revision,issuer=excluded.issuer,jwks_url=excluded.jwks_url,audience=excluded.audience,subject=excluded.subject,max_ttl_secs=excluded.max_ttl_secs";
        #[cfg(not(target_arch = "wasm32"))]
        let sql = if st.db.backend() == db::Backend::Mysql { "INSERT INTO workload_bindings(identity_id,org_id,revision,issuer,jwks_url,audience,subject,max_ttl_secs) VALUES(?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE org_id=VALUES(org_id),revision=VALUES(revision),issuer=VALUES(issuer),jwks_url=VALUES(jwks_url),audience=VALUES(audience),subject=VALUES(subject),max_ttl_secs=VALUES(max_ttl_secs)" } else { sql };
        st.db.exec(sql, &[json!(iid),json!(oid),json!(id()),json!(issuer),json!(url),json!(audience),json!(subject),json!(ttl)]).await.map_err(|e| bad(&e))?;
    }
    st.db.exec("DELETE FROM tokens WHERE created_by=? AND workload_revision<>''", &[json!(iid)]).await.map_err(|e| bad(&e))?;
    Ok(j(json!({"ok":true})))
}
fn destination(raw: &str) -> Result<reqwest::Url, (StatusCode, Json<Value>)> {
    let u = reqwest::Url::parse(raw).map_err(|_| bad("invalid workload trust URL"))?;
    let private = crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").ok().as_deref()==Some("1");
    if u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() || (u.scheme()!="https" && !(private && u.scheme()=="http")) { return Err(bad("workload trust URL requires HTTPS (private HTTP requires operator override)")); }
    Ok(u)
}
#[cfg(not(target_arch = "wasm32"))]
fn public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => { let o = v.octets(); !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast() || o[0]==0 || o[0]>=240 || (o[0]==100 && (64..=127).contains(&o[1])) || (o[0]==192 && o[1]==0) || (o[0]==198 && (o[1]==18 || o[1]==19))) },
        std::net::IpAddr::V6(v) => { let o=v.octets(); if let Some(v4)=v.to_ipv4_mapped() { public(v4.into()) } else { o[0]&0xe0==0x20 && !(o[0]==0x20 && (o[1]==0x02 || (o[1]==0x01 && (o[2]<2 || (o[2]==0x0d && o[3]==0xb8))))) } }
    }
}
#[cfg(not(target_arch = "wasm32"))]
async fn fetch(raw: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let url = destination(raw)?; let host = url.host_str().ok_or_else(|| bad("missing JWKS host"))?; let port=url.port_or_known_default().ok_or_else(|| bad("missing JWKS port"))?;
    let allow = crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").ok().as_deref()==Some("1");
    let addrs: Vec<_> = tokio::net::lookup_host((host,port)).await.map_err(|_| bad("JWKS resolution failed"))?.filter(|a| allow || public(a.ip())).collect();
    if addrs.is_empty() { return Err(bad("JWKS destination denied")); }
    let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(15)).resolve_to_addrs(host,&addrs).build().map_err(|_| bad("JWKS client unavailable"))?;
    let mut r=client.get(url).send().await.map_err(|_| bad("JWKS fetch failed"))?;
    if !r.status().is_success() || r.content_length().is_some_and(|n| n>262144) { return Err(bad("JWKS response rejected")); }
    let mut bytes=Vec::new(); while let Some(chunk)=r.chunk().await.map_err(|_| bad("JWKS fetch failed"))? { if bytes.len()+chunk.len()>262144 { return Err(bad("JWKS exceeds 256 KiB")); } bytes.extend_from_slice(&chunk); }
    serde_json::from_slice(&bytes).map_err(|_| bad("invalid JWKS JSON"))
}
#[cfg(not(target_arch = "wasm32"))]
async fn bounded_fetch(raw: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    tokio::time::timeout(std::time::Duration::from_secs(15),fetch(raw)).await.map_err(|_| bad("JWKS deadline exceeded"))?
}
#[cfg(target_arch = "wasm32")]
async fn bounded_fetch(_raw: &str) -> Result<Value, (StatusCode, Json<Value>)> { Err(err(StatusCode::NOT_IMPLEMENTED,"bounded workload JWKS fetch is unavailable on Workers")) }

pub(super) async fn login(State(st): State<S>, Json(b): Json<Value>) -> Res {
    let iid=b["identity_id"].as_str().filter(|s| s.len()<=256).ok_or_else(|| bad("identity_id required"))?;
    let jwt=b["jwt"].as_str().filter(|s| !s.is_empty() && s.len()<=16384).ok_or_else(|| bad("JWT required (maximum 16 KiB)"))?;
    let rate=format!("workload:{}",iid); if !st.rate_ok(&rate,60,60).await { return Err(err(StatusCode::TOO_MANY_REQUESTS,"workload exchange rate exceeded")); } st.rate_fail(&rate,60).await;
    let binding=st.db.one("SELECT w.* FROM workload_bindings w JOIN identities i ON i.id=w.identity_id AND i.org_id=w.org_id WHERE w.identity_id=?", &[json!(iid)]).await.map_err(|e| bad(&e))?.ok_or_else(|| bad("workload trust not configured"))?;
    let header=jsonwebtoken::decode_header(jwt).map_err(|_| bad("invalid JWT header"))?;
    if !matches!(header.alg, Algorithm::RS256|Algorithm::RS384|Algorithm::RS512|Algorithm::PS256|Algorithm::PS384|Algorithm::PS512|Algorithm::ES256|Algorithm::ES384|Algorithm::EdDSA) { return Err(bad("asymmetric JWT signature required")); }
    let kid=header.kid.as_deref().ok_or_else(|| bad("JWT kid required"))?;
    let jwks=bounded_fetch(&db::s(&binding,"jwks_url")).await?;
    let keys=jwks["keys"].as_array().filter(|k| !k.is_empty() && k.len()<=32).ok_or_else(|| bad("JWKS must contain 1-32 keys"))?;
    let candidates: Vec<_>=keys.iter().filter(|k| k["kid"].as_str()==Some(kid)).collect();
    if candidates.len()!=1 { return Err(bad("JWT signing key ambiguous or missing")); } let k=candidates[0];
    let alg=serde_json::to_value(header.alg).map_err(|_| bad("invalid algorithm"))?;
    let kty=match header.alg { Algorithm::ES256|Algorithm::ES384=>"EC",Algorithm::EdDSA=>"OKP",_=>"RSA" };
    if k["kty"]!=kty || k.get("alg").is_some_and(|v| v!=&alg) || k.get("use").is_some_and(|v| v!="sig") || ["d","p","q","dp","dq","qi","oth","k"].iter().any(|f| k.get(*f).is_some()) { return Err(bad("JWKS key is not a public signing key for this algorithm")); }
    if let Some(ops)=k.get("key_ops") { let ops=ops.as_array().ok_or_else(|| bad("invalid JWK operations"))?; if ops.is_empty() || ops.iter().any(|v| v!="verify") { return Err(bad("JWK must permit verification only")); } }
    let jwk: jsonwebtoken::jwk::Jwk=serde_json::from_value(k.clone()).map_err(|_| bad("invalid public JWK"))?;
    let key=DecodingKey::from_jwk(&jwk).map_err(|_| bad("unsupported public JWK"))?;
    let mut validation=Validation::new(header.alg); validation.leeway=0; validation.validate_nbf=true; validation.set_required_spec_claims(&["exp","iat","iss","sub","aud"]); validation.set_issuer(&[db::s(&binding,"issuer")]); validation.set_audience(&[db::s(&binding,"audience")]);
    let claims=jsonwebtoken::decode::<Value>(jwt,&key,&validation).map_err(|_| bad("JWT verification failed"))?.claims;
    let current=now(); let exp=claims["exp"].as_i64().ok_or_else(|| bad("integer exp required"))?; let iat=claims["iat"].as_i64().ok_or_else(|| bad("integer iat required"))?;
    let audience=db::s(&binding,"audience"); let aud=&claims["aud"];
    let sole=aud.as_str()==Some(audience.as_str()) || aud.as_array().is_some_and(|a| a.len()==1 && a[0].as_str()==Some(audience.as_str()));
    if !sole || claims["iss"]!=db::s(&binding,"issuer") || claims["sub"]!=db::s(&binding,"subject") || exp<=current || iat>current+30 || exp<=iat || exp-iat>3600 || claims.get("nbf").is_some_and(|v| v.as_i64().is_none_or(|n| n>current)) { return Err(bad("JWT claims rejected")); }
    let _=st.db.exec("DELETE FROM workload_assertions WHERE expires_at<=?", &[json!(current)]).await;
    st.db.exec("INSERT INTO workload_assertions(digest,expires_at) VALUES(?,?)", &[json!(oc::hash_token(jwt.rsplit_once('.').ok_or_else(|| bad("invalid signed JWT"))?.0)),json!(exp)]).await.map_err(|_| err(StatusCode::CONFLICT,"assertion already consumed or replay storage unavailable"))?;
    let current=now(); let ttl=(exp-current).min(db::n(&binding,"max_ttl_secs")).min(300); if ttl<=0 { return Err(bad("assertion expired")); }
    let token=oc::random_token("owm"); let revision=db::s(&binding,"revision");
    let inserted=st.db.exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,kind,created_at,created_by,expires_at,workload_revision) SELECT ?,i.org_id,'','','workload',?,'machine',?,i.id,?,w.revision FROM identities i JOIN workload_bindings w ON w.identity_id=i.id AND w.org_id=i.org_id WHERE i.id=? AND w.revision=?", &[json!(id()),json!(oc::hash_token(&token)),json!(current),json!(current+ttl),json!(iid),json!(revision)]).await.map_err(|e| bad(&e))?;
    if inserted!=1 { return Err(bad("workload trust changed during exchange")); }
    Ok(j(json!({"accessToken":token,"expiresIn":ttl,"identity_id":iid,"tokenType":"Bearer"})))
}
