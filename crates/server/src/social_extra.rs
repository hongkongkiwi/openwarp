use serde_json::{json, Value};

fn env_nonempty(key: &str) -> String { crate::envcfg::var(key).ok().map(|v| v.trim().to_string()).unwrap_or_default() }
fn env_or(key: &str, default: &str) -> String { let value = env_nonempty(key); if value.is_empty() { default.to_string() } else { value } }

pub fn credentials(provider: &str) -> Option<(String, String)> {
    let (id, secret) = match provider {
        "discord" => ("OPENWARP_DISCORD_CLIENT_ID", "OPENWARP_DISCORD_CLIENT_SECRET"),
        "linkedin" => ("OPENWARP_LINKEDIN_CLIENT_ID", "OPENWARP_LINKEDIN_CLIENT_SECRET"),
        "workos" => ("OPENWARP_WORKOS_CLIENT_ID", "OPENWARP_WORKOS_CLIENT_SECRET"),
        _ => return None };
    let id = env_nonempty(id); let secret = env_nonempty(secret);
    if id.is_empty() || secret.is_empty() { None } else { Some((id, secret)) } }

pub fn issuer(provider: &str) -> Option<String> {
    if provider == "linkedin" { Some(env_or("OPENWARP_LINKEDIN_ISSUER", "https://www.linkedin.com/oauth")) } else { None } }

pub fn scope(provider: &str) -> Option<&'static str> {
    match provider { "discord" => Some("identify email"), "linkedin" => Some("openid profile email"), "workos" => Some(""), _ => None } }

fn api(provider: &str) -> Option<String> {
    match provider {
        "discord" => Some(env_or("OPENWARP_DISCORD_API", "https://discord.com")),
        "workos" => Some(env_or("OPENWARP_WORKOS_API", "https://api.workos.com")),
        _ => None } }

fn endpoint(provider: &str, path: &str) -> Result<String, String> {
    let base = api(provider).ok_or("unsupported provider")?;
    let endpoint = format!("{}{}", base.trim_end_matches('/'), path);
    if !crate::app::issuer_url_ok(&endpoint) || !crate::app::egress_allowed(&endpoint) {
        return Err("provider endpoint is refused by URL or egress policy".into()); }
    Ok(endpoint) }

pub fn authorize_url(provider: &str, client_id: &str, redirect: &str, state: &str) -> Result<Option<String>, String> {
    let path = match provider { "discord" => "/api/oauth2/authorize", "workos" => "/user_management/authorize", _ => return Ok(None) };
    let mut url = crate::http::Url::parse(&endpoint(provider, path)?).map_err(|_| "invalid provider authorization endpoint")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code").append_pair("client_id", client_id).append_pair("redirect_uri", redirect).append_pair("state", state);
        if provider == "discord" { query.append_pair("scope", "identify email"); }
        else {
            let connection = env_nonempty("OPENWARP_WORKOS_CONNECTION_ID");
            if connection.is_empty() { query.append_pair("provider", &env_or("OPENWARP_WORKOS_PROVIDER", "authkit")); }
            else { query.append_pair("connection_id", &connection); }
        }
    }
    Ok(Some(url.to_string())) }

async fn response_json(response: crate::http::Response) -> Result<Value, String> {
    if !response.status().is_success() { return Err("provider request failed".into()); }
    let bytes = crate::http::read_bounded(response, 1024 * 1024).await?;
    if bytes.len() > 1024 * 1024 { return Err("provider response is too large".into()); }
    serde_json::from_slice(&bytes).map_err(|_| "provider response is invalid JSON".into()) }

fn profile(user: &Value, verified_field: &str) -> Result<(String, String), String> {
    if user.get(verified_field).and_then(Value::as_bool) != Some(true) { return Err("provider email is not verified".into()); }
    let subject = user.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("provider response has no subject")?;
    let email = user.get("email").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
    if email.is_empty() { return Err("provider response has no email".into()); }
    Ok((subject.to_string(), email)) }

pub async fn identity(provider: &str, client_id: &str, secret: &str, redirect: &str, code: &str) -> Result<Option<(String, String)>, String> {
    match provider {
        "discord" => {
            let token_ep = endpoint(provider, "/api/oauth2/token")?;
            let user_ep = endpoint(provider, "/api/users/@me")?;
            let request = crate::app::http_client().post(&token_ep)
                .form(&[("client_id", client_id), ("client_secret", secret), ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect)]);
            let bytes = crate::http::provider_post_bounded(request, 1024 * 1024).await?;
            let token: Value = serde_json::from_slice(&bytes).map_err(|_| "provider response is invalid JSON")?;
            let access_token = token.get("access_token").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("provider response has no access token")?;
            let response = crate::app::http_client().get(&user_ep).bearer_auth(access_token).send().await.map_err(|_| "provider profile request failed")?;
            Ok(Some(profile(&response_json(response).await?, "verified")?)) }
        "workos" => {
            let endpoint = endpoint(provider, "/user_management/authenticate")?;
            let request = crate::app::http_client().post(&endpoint)
                .json(&json!({"client_id": client_id, "client_secret": secret, "grant_type": "authorization_code", "code": code}));
            let bytes = crate::http::provider_post_bounded(request, 1024 * 1024).await?;
            let token: Value = serde_json::from_slice(&bytes).map_err(|_| "provider response is invalid JSON")?;
            let user = token.get("user").ok_or("provider response has no user")?;
            Ok(Some(profile(user, "email_verified")?)) }
        _ => Ok(None) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_requires_verified_email_and_subject() {
        assert_eq!(profile(&json!({"id":"123", "email":" User@Example.com ", "verified":true}), "verified").unwrap(), ("123".into(), "user@example.com".into()));
        for value in [json!(false), json!(null), json!("true")] {
            assert!(profile(&json!({"id":"123", "email":"user@example.com", "email_verified":value}), "email_verified").is_err());
        }
        assert!(profile(&json!({"id":"", "email":"user@example.com", "email_verified":true}), "email_verified").is_err());
        assert!(profile(&json!({"id":"123", "email":" ", "email_verified":true}), "email_verified").is_err());
    }

    #[test]
    fn unknown_provider_is_not_claimed() {
        assert!(credentials("google").is_none());
        assert!(issuer("google").is_none());
        assert!(scope("google").is_none());
        assert!(authorize_url("google", "id", "redirect", "state").unwrap().is_none());
    }
}
