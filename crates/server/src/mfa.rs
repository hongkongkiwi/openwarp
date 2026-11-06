//! Second factors for an account: TOTP, WebAuthn passkeys and emailed codes.
//! Every factor is optional, but at least one enabled factor makes the second
//! step mandatory on every sign-in path, including social and OIDC.
use super::*;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;

const CHALLENGE_TTL: i64 = 300;
const CODE_TTL: i64 = 600;
const MAX_CODE_ATTEMPTS: i64 = 5;

pub fn email_available() -> bool {
    std::env::var("OPENWARP_EMAIL_WEBHOOK").map(|v| !v.trim().is_empty()).unwrap_or(false)
}
pub fn totp_enabled(st: &S, uid: &str) -> bool { meta_get(st, &format!("totp_enabled:{}", uid)) == "1" }
pub fn email_enabled(st: &S, uid: &str) -> bool { meta_get(st, &format!("email_mfa_enabled:{}", uid)) == "1" }
pub fn passkey_count(st: &S, uid: &str) -> i64 {
    st.db.one("SELECT COUNT(*) AS n FROM passkeys WHERE user_id=?", &[json!(uid)]).ok().flatten().map(|r| db::n(&r, "n")).unwrap_or(0)
}
pub fn methods(st: &S, uid: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    if totp_enabled(st, uid) { out.push("totp"); }
    if passkey_count(st, uid) > 0 { out.push("passkey"); }
    if email_enabled(st, uid) { out.push("email"); }
    out
}
pub fn required(st: &S, uid: &str) -> bool { !methods(st, uid).is_empty() }
pub fn recovery_count(st: &S, uid: &str) -> usize {
    meta_get(st, &format!("totp_recovery:{}", uid)).split(',').filter(|s| !s.is_empty()).count()
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn issue_recovery_codes(st: &S, uid: &str) -> Vec<String> {
    let codes: Vec<String> = (0..8).map(|_| oc::random_token("rc")).collect();
    let hashed: Vec<String> = codes.iter().map(|c| oc::hash_token(c)).collect();
    meta_set(st, &format!("totp_recovery:{}", uid), &hashed.join(","));
    codes
}
fn ensure_recovery_codes(st: &S, uid: &str) -> Option<Vec<String>> {
    if recovery_count(st, uid) == 0 { Some(issue_recovery_codes(st, uid)) } else { None }
}

/// Activate a pending TOTP secret. The setup code stays usable for the first
/// sign-in; replay protection starts at the first login that consumes a code.
pub fn confirm_totp(st: &S, uid: &str, code: &str) -> bool {
    let pending = meta_get(st, &format!("totp_pending:{}", uid));
    let stored = meta_get(st, &format!("totp_secret:{}", uid));
    let enc = if pending.is_empty() { stored } else { pending };
    let Ok(secret) = oc::decrypt_symmetric(&st.master, &enc) else { return false };
    let counter = (now() / 30) as u64;
    for c in [counter.wrapping_sub(1), counter, counter + 1] {
        if ct_eq(&totp_code(&secret, c), code) {
            // Promote only after proof. A failed or abandoned re-enrolment keeps
            // the previous secret active, so the account never silently loses
            // its only factor.
            meta_set(st, &format!("totp_secret:{}", uid), &enc);
            meta_set(st, &format!("totp_enabled:{}", uid), "1");
            meta_set(st, &format!("totp_pending:{}", uid), "");
            meta_set(st, &format!("totp_last:{}", uid), "0");
            return true;
        }
    }
    false
}

fn totp_ok(st: &S, uid: &str, code: &str) -> bool {
    if !totp_enabled(st, uid) || code.is_empty() { return false; }
    let Ok(secret) = oc::decrypt_symmetric(&st.master, &meta_get(st, &format!("totp_secret:{}", uid))) else { return false };
    let counter = (now() / 30) as u64;
    for c in [counter.wrapping_sub(1), counter, counter + 1] {
        if ct_eq(&totp_code(&secret, c), code) {
            let last = meta_get(st, &format!("totp_last:{}", uid)).parse::<u64>().unwrap_or(0);
            if c <= last { return false; }
            meta_set(st, &format!("totp_last:{}", uid), &c.to_string());
            return true;
        }
    }
    false
}
fn recovery_ok(st: &S, uid: &str, code: &str) -> bool {
    if code.is_empty() { return false; }
    let stored = meta_get(st, &format!("totp_recovery:{}", uid));
    if stored.is_empty() { return false; }
    let hash = oc::hash_token(code);
    let mut list: Vec<String> = stored.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
    match list.iter().position(|x| ct_eq(x, &hash)) {
        Some(pos) => { list.remove(pos); meta_set(st, &format!("totp_recovery:{}", uid), &list.join(",")); true }
        None => false,
    }
}

fn six_digits() -> String {
    let mut b = [0u8; 4];
    loop {
        OsRng.fill_bytes(&mut b);
        let n = u32::from_be_bytes(b);
        // Reject the short tail so every six-digit code is equally likely.
        if n < u32::MAX - (u32::MAX % 1_000_000) { return format!("{:06}", n % 1_000_000); }
    }
}
// A six-digit code has only a million possible hashes, so bind it to the
// master key: a stolen database alone cannot recover a live code offline.
fn code_hash(st: &S, code: &str) -> String { hmac_hex(&st.master, format!("openwarp-email-code:{}", code).as_bytes()) }
fn store_email_code(st: &S, uid: &str, purpose: &str, code: &str) {
    let current = now();
    let _ = st.db.exec("DELETE FROM email_codes WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]);
    let _ = st.db.exec("INSERT INTO email_codes(user_id,purpose,code_hash,created_at,expires_at,attempts) VALUES(?,?,?,?,?,0)",
        &[json!(uid), json!(purpose), json!(code_hash(st, code)), json!(current), json!(current + CODE_TTL)]);
}
fn email_code_ok(st: &S, uid: &str, code: &str, purpose: &str) -> bool {
    if code.is_empty() { return false; }
    let row = match st.db.one("SELECT code_hash,expires_at,attempts FROM email_codes WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]) {
        Ok(Some(r)) => r, _ => return false };
    let attempts = db::n(&row, "attempts");
    if db::n(&row, "expires_at") < now() || attempts >= MAX_CODE_ATTEMPTS {
        let _ = st.db.exec("DELETE FROM email_codes WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]);
        return false;
    }
    if ct_eq(&db::s(&row, "code_hash"), &code_hash(st, code)) {
        let _ = st.db.exec("DELETE FROM email_codes WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]);
        return true;
    }
    if attempts + 1 >= MAX_CODE_ATTEMPTS {
        let _ = st.db.exec("DELETE FROM email_codes WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]);
    } else {
        let _ = st.db.exec("UPDATE email_codes SET attempts=attempts+1 WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]);
    }
    false
}
async fn send_code(st: &S, uid: &str, purpose: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if !email_available() { return Err(err(StatusCode::SERVICE_UNAVAILABLE, "email delivery is not configured on this instance")); }
    let email = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "email")).unwrap_or_default();
    if email.is_empty() { return Err(bad("account has no email address")); }
    let code = six_digits();
    store_email_code(st, uid, purpose, &code);
    let subject = if purpose == "enroll" { "Confirm email codes for OpenWarp" } else { "Your OpenWarp sign-in code" };
    let text = format!("Your OpenWarp code is {}.\n\nIt expires in 10 minutes and can be used once. If you did not request it, ignore this message.", code);
    // A code the user never received must not stay valid; remove it when the
    // relay rejects the message.
    if let Err((status, Json(v))) = send_email_result(&email, subject, &text).await {
        let _ = st.db.exec("DELETE FROM email_codes WHERE user_id=? AND purpose=?", &[json!(uid), json!(purpose)]);
        let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("the email could not be sent; try again");
        return Err(err(status, msg));
    }
    Ok(())
}

/// True when any enabled factor accepted the code. Recovery codes and emailed
/// codes are consumed; TOTP counters advance so a code cannot be replayed.
pub fn second_factor_ok(st: &S, uid: &str, code: &str) -> bool {
    if !required(st, uid) { return true; }
    if code.is_empty() { return false; }
    if totp_ok(st, uid, code) { return true; }
    if recovery_ok(st, uid, code) { return true; }
    if email_enabled(st, uid) && email_code_ok(st, uid, code, "login") { return true; }
    false
}

pub fn new_challenge(st: &S, uid: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let _ = st.db.exec("DELETE FROM mfa_challenges WHERE created_at<?", &[json!(now() - 3600)]);
    let token = oc::random_token("mfa");
    st.db.exec("INSERT INTO mfa_challenges(token,user_id,created_at) VALUES(?,?,?)",
        &[json!(oc::hash_token(&token)), json!(uid), json!(now())]).map_err(|e| bad(&e))?;
    Ok(token)
}
pub fn challenge_user(st: &S, token: &str) -> Option<String> {
    if token.is_empty() { return None; }
    let row = st.db.one("SELECT user_id,created_at FROM mfa_challenges WHERE token=?", &[json!(oc::hash_token(token))]).ok().flatten()?;
    if db::n(&row, "created_at") + CHALLENGE_TTL < now() { return None; }
    Some(db::s(&row, "user_id"))
}
pub fn consume_challenge(st: &S, token: &str) {
    let _ = st.db.exec("DELETE FROM mfa_challenges WHERE token=?", &[json!(oc::hash_token(token))]);
}

fn password_known(st: &S, uid: &str) -> bool { meta_get(st, &format!("password_known:{}", uid)) == "1" }
pub fn note_password_login(st: &S, uid: &str) { meta_set(st, &format!("password_known:{}", uid), "1"); }

/// Adding a factor to an account that already has one is a takeover primitive
/// for a stolen session, so ask for the password when the user knows it.
pub fn reauth_add(st: &S, uid: &str, body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    if !password_known(st, uid) || !required(st, uid) { return Ok(()); }
    check_password(st, uid, body)
}
/// Removing a factor weakens the account, so the password is required whenever
/// this user has one. Accounts created through social sign-in never do.
pub fn reauth_remove(st: &S, uid: &str, body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    if !password_known(st, uid) { return Ok(()); }
    check_password(st, uid, body)
}
fn check_password(st: &S, uid: &str, body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let row = st.db.one("SELECT pass_hash FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.ok_or_else(|| bad("no user"))?;
    if password.is_empty() || !oc::verify_password(password, &db::s(&row, "pass_hash")) {
        return Err(err(StatusCode::UNAUTHORIZED, "current password required to change two-factor settings"));
    }
    Ok(())
}

fn loopback_host(host: &str) -> bool {
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(name.trim_start_matches('[').trim_end_matches(']'), "localhost" | "127.0.0.1" | "::1")
}
fn public_origin(st: &S, h: &HeaderMap) -> Option<String> {
    // WebAuthn's origin and RP ID decide whether a credential may sign in, so
    // production pins them. Only a loopback Host is trusted for local dev.
    let raw = std::env::var("OPENWARP_RP_ORIGIN").ok().filter(|v| !v.trim().is_empty())
        .or_else(|| Some(st.pub_url.clone()).filter(|v| !v.is_empty()))
        .or_else(|| h.get("host").and_then(|v| v.to_str().ok()).filter(|host| loopback_host(host)).map(|host| format!("http://{}", host)))?;
    let url = Url::parse(raw.trim()).ok()?;
    let mut origin = format!("{}://{}", url.scheme(), url.host_str()?);
    if let Some(port) = url.port() { origin.push_str(&format!(":{}", port)); }
    Some(origin)
}
fn webauthn(st: &S, h: &HeaderMap) -> Result<Webauthn, (StatusCode, Json<Value>)> {
    let origin = public_origin(st, h).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "passkeys need OPENWARP_PUBLIC_URL or a Host header"))?;
    let url = Url::parse(&origin).map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "the public origin is not a valid URL"))?;
    let rp_id = std::env::var("OPENWARP_RP_ID").ok().map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty())
        .or_else(|| url.host_str().map(str::to_string)).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "the public origin has no host"))?;
    WebauthnBuilder::new(&rp_id, &url)
        .and_then(|b| b.rp_name("OpenWarp").build())
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, &format!("passkeys are not available for this origin: {}", e)))
}
fn user_handle(uid: &str) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"openwarp-webauthn-user:");
    h.update(uid.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
fn passkeys(st: &S, uid: &str) -> Vec<Passkey> {
    st.db.query("SELECT credential_json FROM passkeys WHERE user_id=? ORDER BY created_at", &[json!(uid)]).unwrap_or_default()
        .iter().filter_map(|r| serde_json::from_str::<Passkey>(&db::s(r, "credential_json")).ok()).collect()
}

pub async fn status(State(st): State<S>, h: HeaderMap) -> Res {
    let uid = st.token_user(&h)?;
    let rows = st.db.query("SELECT id,name,created_at,last_used_at FROM passkeys WHERE user_id=? ORDER BY created_at", &[json!(uid)]).map_err(|e| bad(&e))?;
    Ok(j(json!({
        "methods": methods(&st, &uid),
        "required": required(&st, &uid),
        "totp": totp_enabled(&st, &uid),
        "email": email_enabled(&st, &uid),
        "email_available": email_available(),
        "recovery_codes": recovery_count(&st, &uid),
        "passkeys": rows.iter().map(db::obj).collect::<Vec<_>>(),
    }))) }

pub async fn recovery_regenerate(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    reauth_remove(&st, &uid, &body)?;
    let codes = issue_recovery_codes(&st, &uid);
    st.audit("", "", "", &uid, "auth.recovery_codes_regenerated", "");
    Ok(j(json!({"recovery_codes": codes}))) }

pub async fn totp_disable(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    reauth_remove(&st, &uid, &body)?;
    if !totp_enabled(&st, &uid) { return Err(bad("TOTP is not enabled")); }
    meta_set(&st, &format!("totp_enabled:{}", uid), "0");
    meta_set(&st, &format!("totp_secret:{}", uid), "");
    meta_set(&st, &format!("totp_pending:{}", uid), "");
    meta_set(&st, &format!("totp_last:{}", uid), "0");
    if methods(&st, &uid).is_empty() { meta_set(&st, &format!("totp_recovery:{}", uid), ""); }
    st.audit("", "", "", &uid, "auth.totp_disabled", "");
    Ok(j(json!({"totp": false}))) }

pub async fn email_enroll_start(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    reauth_add(&st, &uid, &body)?;
    let key = format!("email-enroll:{}", uid);
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many codes requested; try again later")); }
    st.rate_fail(&key, 900);
    send_code(&st, &uid, "enroll").await?;
    st.audit("", "", "", &uid, "auth.email_code_requested", "");
    Ok(j(json!({"sent": true}))) }
pub async fn email_enroll_verify(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    let key = format!("email-enroll-verify:{}", uid);
    if !st.rate_ok(&key, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed code attempts; try again later")); }
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    if !email_code_ok(&st, &uid, code, "enroll") {
        st.rate_fail(&key, 900);
        return Err(err(StatusCode::UNAUTHORIZED, "invalid or expired email code"));
    }
    st.rate_clear(&key);
    meta_set(&st, &format!("email_mfa_enabled:{}", uid), "1");
    let codes = ensure_recovery_codes(&st, &uid);
    st.audit("", "", "", &uid, "auth.email_code_enabled", "");
    Ok(j(json!({"email": true, "recovery_codes": codes}))) }
pub async fn email_disable(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    reauth_remove(&st, &uid, &body)?;
    if !email_enabled(&st, &uid) { return Err(bad("email codes are not enabled")); }
    meta_set(&st, &format!("email_mfa_enabled:{}", uid), "0");
    let _ = st.db.exec("DELETE FROM email_codes WHERE user_id=?", &[json!(uid)]);
    if methods(&st, &uid).is_empty() { meta_set(&st, &format!("totp_recovery:{}", uid), ""); }
    st.audit("", "", "", &uid, "auth.email_code_disabled", "");
    Ok(j(json!({"email": false}))) }

pub async fn passkey_register_start(State(st): State<S>, h: HeaderMap, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    reauth_add(&st, &uid, &body)?;
    let wa = webauthn(&st, &h)?;
    let email = st.db.one("SELECT email FROM users WHERE id=?", &[json!(uid)]).map_err(|e| bad(&e))?.map(|r| db::s(&r, "email")).unwrap_or_default();
    let existing: Vec<CredentialID> = passkeys(&st, &uid).iter().map(|p| p.cred_id().clone()).collect();
    let (options, state) = wa.start_passkey_registration(user_handle(&uid), &email, &email, if existing.is_empty() { None } else { Some(existing) })
        .map_err(|e| bad(&format!("passkey registration could not start: {}", e)))?;
    let state_json = serde_json::to_string(&state).map_err(|e| bad(&e.to_string()))?;
    let sid = oc::random_token("pk");
    let _ = st.db.exec("DELETE FROM passkey_registrations WHERE user_id=? OR created_at<?", &[json!(uid), json!(now() - CHALLENGE_TTL)]);
    st.db.exec("INSERT INTO passkey_registrations(id,user_id,state_json,created_at) VALUES(?,?,?,?)",
        &[json!(oc::hash_token(&sid)), json!(uid), json!(state_json), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"state_id": sid, "options": options}))) }

#[derive(Deserialize)]
pub struct PasskeyRegisterReq { state_id: String, credential: RegisterPublicKeyCredential, #[serde(default)] name: String }
pub async fn passkey_register_finish(State(st): State<S>, h: HeaderMap, Json(r): Json<PasskeyRegisterReq>) -> Res {
    let uid = st.token_user(&h)?;
    let wa = webauthn(&st, &h)?;
    let state_key = oc::hash_token(&r.state_id);
    let row = st.db.one("SELECT user_id,state_json,created_at FROM passkey_registrations WHERE id=?", &[json!(state_key)]).map_err(|e| bad(&e))?
        .ok_or_else(|| bad("passkey registration expired; start again"))?;
    let _ = st.db.exec("DELETE FROM passkey_registrations WHERE id=?", &[json!(state_key)]);
    if db::s(&row, "user_id") != uid || db::n(&row, "created_at") + CHALLENGE_TTL < now() {
        return Err(bad("passkey registration expired; start again")); }
    let state: PasskeyRegistration = serde_json::from_str(&db::s(&row, "state_json")).map_err(|_| bad("passkey registration expired; start again"))?;
    let passkey = wa.finish_passkey_registration(&r.credential, &state).map_err(|e| bad(&format!("passkey registration was rejected: {}", e)))?;
    let credential_id = b64url(passkey.cred_id());
    let name: String = r.name.trim().chars().take(100).collect();
    let name = if name.is_empty() { "passkey".to_string() } else { name };
    let pid = id();
    let credential_json = serde_json::to_string(&passkey).map_err(|e| bad(&e.to_string()))?;
    if st.db.one("SELECT user_id FROM passkeys WHERE credential_id=?", &[json!(&credential_id)]).map_err(|e| bad(&e))?.is_some() {
        return Err(err(StatusCode::CONFLICT, "this passkey is already registered to an account")); }
    st.db.exec("INSERT INTO passkeys(id,user_id,name,credential_id,credential_json,sign_count,created_at) VALUES(?,?,?,?,?,0,?)",
        &[json!(pid), json!(uid), json!(name), json!(credential_id), json!(credential_json), json!(now())]).map_err(|_| err(StatusCode::CONFLICT, "this passkey is already registered to an account"))?;
    let codes = ensure_recovery_codes(&st, &uid);
    st.audit("", "", "", &uid, "auth.passkey_added", &name);
    Ok(j(json!({"id": pid, "name": name, "recovery_codes": codes}))) }

pub async fn passkey_delete(State(st): State<S>, h: HeaderMap, Path(pid): Path<String>, Json(body): Json<Value>) -> Res {
    let uid = st.token_user(&h)?;
    reauth_remove(&st, &uid, &body)?;
    let deleted = st.db.exec("DELETE FROM passkeys WHERE id=? AND user_id=?", &[json!(pid), json!(uid)]).map_err(|e| bad(&e))?;
    if deleted == 0 { return Err(err(StatusCode::NOT_FOUND, "passkey not found")); }
    if methods(&st, &uid).is_empty() { meta_set(&st, &format!("totp_recovery:{}", uid), ""); }
    st.audit("", "", "", &uid, "auth.passkey_removed", &pid);
    Ok(j(json!({"deleted": pid}))) }

#[derive(Deserialize)]
pub struct MfaTokenReq { mfa_token: String }
pub async fn mfa_options(State(st): State<S>, Json(r): Json<MfaTokenReq>) -> Res {
    let uid = challenge_user(&st, &r.mfa_token).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "MFA challenge expired or invalid"))?;
    Ok(j(json!({
        "methods": methods(&st, &uid),
        "email_available": email_available() && email_enabled(&st, &uid),
        "recovery_codes": recovery_count(&st, &uid),
    }))) }
/// Send a login code after the caller has proved the account password (the
/// challenge token is that proof). Callers own the rate limit.
pub async fn send_login_code(st: &S, uid: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if !email_enabled(st, uid) { return Err(bad("email codes are not enabled for this account")); }
    send_code(st, uid, "login").await
}
pub async fn email_login_send(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, Json(r): Json<MfaTokenReq>) -> Res {
    let uid = challenge_user(&st, &r.mfa_token).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "MFA challenge expired or invalid"))?;
    let key = format!("email-mfa:{}:{}", addr.ip(), uid);
    if !st.rate_ok(&key, 3, 600) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many codes requested; try again later")); }
    st.rate_fail(&key, 600);
    send_login_code(&st, &uid).await?;
    st.audit("", "", "", &uid, "auth.mfa_email_sent", "");
    Ok(j(json!({"sent": true}))) }
pub async fn passkey_login_start(State(st): State<S>, h: HeaderMap, Json(r): Json<MfaTokenReq>) -> Res {
    let uid = challenge_user(&st, &r.mfa_token).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "MFA challenge expired or invalid"))?;
    let wa = webauthn(&st, &h)?;
    let keys = passkeys(&st, &uid);
    if keys.is_empty() { return Err(bad("this account has no passkey")); }
    let (options, state) = wa.start_passkey_authentication(&keys).map_err(|e| bad(&format!("passkey sign-in could not start: {}", e)))?;
    let state_json = serde_json::to_string(&state).map_err(|e| bad(&e.to_string()))?;
    let key = oc::hash_token(&r.mfa_token);
    let _ = st.db.exec("DELETE FROM mfa_passkey_states WHERE mfa_token=? OR created_at<?", &[json!(&key), json!(now() - CHALLENGE_TTL)]);
    st.db.exec("INSERT INTO mfa_passkey_states(mfa_token,user_id,state_json,created_at) VALUES(?,?,?,?)",
        &[json!(key), json!(uid), json!(state_json), json!(now())]).map_err(|e| bad(&e))?;
    Ok(j(json!({"options": options}))) }

#[derive(Deserialize)]
pub struct PasskeyLoginReq { mfa_token: String, credential: PublicKeyCredential }
pub async fn passkey_login_finish(State(st): State<S>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>, h: HeaderMap, Json(r): Json<PasskeyLoginReq>)
    -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    let uid = challenge_user(&st, &r.mfa_token).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "MFA challenge expired or invalid"))?;
    let rl = format!("mfa:{}:{}", addr.ip(), uid);
    if !st.rate_ok(&rl, 5, 900) { return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many failed two-factor attempts; try again later")); }
    let key = oc::hash_token(&r.mfa_token);
    let row = st.db.one("SELECT user_id,state_json,created_at FROM mfa_passkey_states WHERE mfa_token=?", &[json!(&key)]).map_err(|e| bad(&e))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "passkey sign-in expired; start again"))?;
    let _ = st.db.exec("DELETE FROM mfa_passkey_states WHERE mfa_token=?", &[json!(&key)]);
    if db::s(&row, "user_id") != uid || db::n(&row, "created_at") + CHALLENGE_TTL < now() {
        return Err(err(StatusCode::UNAUTHORIZED, "passkey sign-in expired; start again")); }
    let state: PasskeyAuthentication = serde_json::from_str(&db::s(&row, "state_json")).map_err(|_| bad("passkey sign-in failed"))?;
    let wa = webauthn(&st, &h)?;
    let result = wa.finish_passkey_authentication(&r.credential, &state).map_err(|e| { st.rate_fail(&rl, 900); bad(&format!("passkey sign-in was rejected: {}", e)) })?;
    let rows = st.db.query("SELECT id,credential_json,sign_count FROM passkeys WHERE user_id=?", &[json!(&uid)]).map_err(|e| bad(&e))?;
    let mut matched = false;
    for row in &rows {
        let Ok(mut passkey) = serde_json::from_str::<Passkey>(&db::s(row, "credential_json")) else { continue };
        if passkey.cred_id() != result.cred_id() { continue; }
        let stored = db::n(row, "sign_count");
        if result.counter() > 0 && stored > 0 && i64::from(result.counter()) <= stored {
            st.rate_fail(&rl, 900);
            return Err(err(StatusCode::UNAUTHORIZED, "passkey signature counter did not advance; the credential may be cloned"));
        }
        if passkey.update_credential(&result).is_none() {
            st.rate_fail(&rl, 900);
            return Err(err(StatusCode::UNAUTHORIZED, "passkey does not belong to this account"));
        }
        let updated = serde_json::to_string(&passkey).map_err(|e| bad(&e.to_string()))?;
        // The session may only follow a durable counter update; otherwise the
        // next assertion could replay the same counter.
        st.db.exec("UPDATE passkeys SET credential_json=?,sign_count=?,last_used_at=? WHERE id=?",
            &[json!(updated), json!(i64::from(result.counter())), json!(now()), json!(db::s(row, "id"))])
            .map_err(|e| bad(&format!("passkey state could not be saved: {}", e)))?;
        matched = true;
        break;
    }
    if !matched { st.rate_fail(&rl, 900); return Err(err(StatusCode::UNAUTHORIZED, "passkey does not belong to this account")); }
    st.rate_clear(&rl);
    consume_challenge(&st, &r.mfa_token);
    st.audit("", "", "", &uid, "auth.mfa_passkey", "");
    let session = make_session(&st, &uid)?;
    let mut hdr = HeaderMap::new();
    hdr.insert(axum::http::header::SET_COOKIE, session_cookie(&session).parse().unwrap());
    Ok((hdr, j(json!({"token": session, "user_id": uid})))) }
