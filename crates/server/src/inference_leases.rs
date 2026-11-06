//! Dynamic leases for inference providers that document both minting a child
//! credential and deleting it afterwards. Each function returns only the child
//! secret and the identifier its revoke call needs.
use serde_json::{json, Value};

fn cfg<'a>(c: &'a Value, k: &str) -> &'a str { c.get(k).and_then(|v| v.as_str()).unwrap_or("") }
#[cfg(not(target_arch = "wasm32"))]
fn http_client() -> crate::http::Client { crate::http::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| crate::http::Client::builder().build().expect("http client")) }
#[cfg(target_arch = "wasm32")]
fn http_client() -> crate::http::Client { crate::http::Client::new() }
async fn req(r: crate::http::RequestBuilder) -> Result<String, String> {
    let resp = r.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if status.is_success() { Ok(text) } else { Err(format!("HTTP {}: {}", status, text.chars().take(400).collect::<String>())) }
}
fn key_ref_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}
/// Same host rule as `integrations::lease_base`: production refuses loopback and literal IPs.
fn lease_base(config: &Value, default: &str) -> Result<String, String> {
    let raw = { let b = cfg(config, "base_url"); if b.is_empty() { default } else { b } };
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid base_url: {}", e))?;
    if url.scheme() != "https" && url.scheme() != "http" { return Err("base_url must be an http(s) URL".into()); }
    let host = url.host_str().ok_or("base_url has no host")?;
    let production = crate::envcfg::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) || config.get("require_public_host").and_then(|v| v.as_bool()).unwrap_or(false);
    let private_ok = crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false);
    if production && !private_ok && (host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok()) {
        return Err("base_url must name a public host; loopback and IP hosts are refused".into());
    }
    Ok(raw.trim_end_matches('/').to_string())
}
fn stamp_at(secs: i64) -> String {
    let days = secs.div_euclid(86400); let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}
fn expires_at(ttl_secs: i64) -> String {
    let now = crate::clock::now();
    stamp_at(now + ttl_secs.clamp(60, 30 * 86400))
}
fn civil(z: i64) -> (i64, u32, u32) { let z = z + 719468; let era = z.div_euclid(146097); let doe = z.rem_euclid(146097); let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; let y = yoe + era * 400; let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); let mp = (5 * doy + 2) / 153; let d = (doy - (153 * mp + 2) / 5 + 1) as u32; let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; (if m <= 2 { y + 1 } else { y }, m, d) }

/// Issue a Fireworks API key. `POST /v1/accounts/{account}/users/{user}/apiKeys`
pub async fn fireworks_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
    let api_key = cfg(config, "api_key");
    let account_id = cfg(config, "account_id");
    let user_id = cfg(config, "user_id");
    if api_key.is_empty() || !key_ref_ok(account_id) || !key_ref_ok(user_id) {
        return Err("fireworks lease requires config.api_key, account_id and user_id".into());
    }
    let display = if name.is_empty() { "openwarp" } else { name };
    if display.len() > 256 { return Err("fireworks key name must be 1 to 256 characters".into()); }
    let api_key_body = json!({"displayName": display, "expireTime": expires_at(ttl_secs)});
    let base = lease_base(config, "https://api.fireworks.ai")?;
    let url = format!("{}/v1/accounts/{}/users/{}/apiKeys", base, account_id, user_id);
    let text = req(http_client().post(url).bearer_auth(api_key).json(&json!({"apiKey": api_key_body}))).await
        .map_err(|e| format!("Fireworks key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Fireworks key response is not JSON: {}", e))?;
    let key = parsed.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("keyId").and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() || !key_ref_ok(id) { return Err("Fireworks key response is missing the key or its id".into()); }
    Ok(json!({"key": key, "id": id, "expire_time": parsed["expireTime"]}))
}
/// Fireworks deletes by posting the key id, not with a DELETE verb.
pub async fn fireworks_revoke_key(base_url: &str, api_key: &str, account_id: &str, user_id: &str, key_id: &str) -> Result<(), String> {
    if !key_ref_ok(account_id) || !key_ref_ok(user_id) || !key_ref_ok(key_id) { return Err("fireworks account, user or key id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.fireworks.ai")?;
    let url = format!("{}/v1/accounts/{}/users/{}/apiKeys:delete", base, account_id, user_id);
    req(http_client().post(url).bearer_auth(api_key).json(&json!({"keyId": key_id}))).await
        .map_err(|e| format!("Fireworks key revocation failed: {}", e))?;
    Ok(())
}
/// Issue a Mistral workspace key. `POST /v1/admin/api-keys` (Enterprise Admin API).
pub async fn mistral_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
    let admin_key = cfg(config, "admin_key");
    let workspace_id = cfg(config, "workspace_id");
    if admin_key.is_empty() || !key_ref_ok(workspace_id) { return Err("mistral lease requires config.admin_key and workspace_id".into()); }
    if name.len() > 256 { return Err("mistral key name must be at most 256 characters".into()); }
    let mut body = serde_json::Map::new();
    body.insert("workspace_uuid".into(), json!(workspace_id));
    if !name.is_empty() { body.insert("name".into(), json!(name)); }
    let user_id = cfg(config, "user_id");
    if !user_id.is_empty() { body.insert("user_id".into(), json!(user_id)); }
    body.insert("expiration".into(), json!(expires_at(ttl_secs)));
    let base = lease_base(config, "https://api.mistral.ai")?;
    let text = req(http_client().post(format!("{}/v1/admin/api-keys", base)).bearer_auth(admin_key).json(&Value::Object(body))).await
        .map_err(|e| format!("Mistral key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Mistral key response is not JSON: {}", e))?;
    let key = parsed.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() || !key_ref_ok(id) { return Err("Mistral key response is missing the key or its id".into()); }
    Ok(json!({"key": key, "id": id, "expiration": parsed["expiration_date"]}))
}
pub async fn mistral_revoke_key(base_url: &str, admin_key: &str, key_id: &str) -> Result<(), String> {
    if !key_ref_ok(key_id) { return Err("mistral key id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.mistral.ai")?;
    req(http_client().delete(format!("{}/v1/admin/api-keys/{}", base, key_id)).bearer_auth(admin_key)).await
        .map_err(|e| format!("Mistral key revocation failed: {}", e))?;
    Ok(())
}
/// Issue a Perplexity token. `POST /generate_auth_token`; revoke sends the token back.
pub async fn perplexity_create_key(config: &Value, name: &str) -> Result<Value, String> {
    let api_key = cfg(config, "api_key");
    if api_key.is_empty() { return Err("perplexity lease requires config.api_key".into()); }
    if name.len() > 256 { return Err("perplexity token name must be at most 256 characters".into()); }
    let mut body = serde_json::Map::new();
    if !name.is_empty() { body.insert("token_name".into(), json!(name)); }
    let base = lease_base(config, "https://api.perplexity.ai")?;
    let text = req(http_client().post(format!("{}/generate_auth_token", base)).bearer_auth(api_key).json(&Value::Object(body))).await
        .map_err(|e| format!("Perplexity token creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Perplexity token response is not JSON: {}", e))?;
    let token = parsed.get("auth_token").and_then(|v| v.as_str()).unwrap_or("");
    if token.is_empty() { return Err("Perplexity token response is missing the auth_token".into()); }
    Ok(json!({"token": token}))
}
pub async fn perplexity_revoke_key(base_url: &str, api_key: &str, auth_token: &str) -> Result<(), String> {
    if auth_token.is_empty() { return Err("perplexity token is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.perplexity.ai")?;
    req(http_client().post(format!("{}/revoke_auth_token", base)).bearer_auth(api_key).json(&json!({"auth_token": auth_token}))).await
        .map_err(|e| format!("Perplexity token revocation failed: {}", e))?;
    Ok(())
}
/// Issue an xAI inference key from a management key. `POST /auth/teams/{teamId}/api-keys`
pub async fn xai_create_key(config: &Value, name: &str) -> Result<Value, String> {
    let management_key = cfg(config, "management_key");
    let team_id = cfg(config, "team_id");
    if management_key.is_empty() || !key_ref_ok(team_id) { return Err("xai lease requires config.management_key and team_id".into()); }
    if name.is_empty() || name.len() > 256 { return Err("xai key name must be 1 to 256 characters".into()); }
    let mut body = serde_json::Map::new();
    body.insert("name".into(), json!(name));
    let acls = config.get("acls").and_then(|v| v.as_array()).cloned().unwrap_or_else(|| vec![json!("api-key:model:*"), json!("api-key:endpoint:*")]);
    if acls.iter().any(|a| !a.as_str().unwrap_or("").starts_with("api-key:")) { return Err("xai acls must be api-key:model or api-key:endpoint values".into()); }
    body.insert("acls".into(), json!(acls));
    for field in ["qps", "qpm", "tpm"] { if let Some(v) = config.get(field).filter(|v| v.is_number()) { body.insert(field.into(), v.clone()); } }
    let base = lease_base(config, "https://management-api.x.ai")?;
    let text = req(http_client().post(format!("{}/auth/teams/{}/api-keys", base, team_id)).bearer_auth(management_key).json(&Value::Object(body))).await
        .map_err(|e| format!("xAI key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("xAI key response is not JSON: {}", e))?;
    let key = parsed.get("apiKey").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("apiKeyId").and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() || !key_ref_ok(id) { return Err("xAI key response is missing the apiKey or its id".into()); }
    Ok(json!({"key": key, "id": id}))
}
pub async fn xai_revoke_key(base_url: &str, management_key: &str, key_id: &str) -> Result<(), String> {
    if !key_ref_ok(key_id) { return Err("xai key id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://management-api.x.ai")?;
    req(http_client().delete(format!("{}/auth/api-keys/{}", base, key_id)).bearer_auth(management_key)).await
        .map_err(|e| format!("xAI key revocation failed: {}", e))?;
    Ok(())
}
/// Issue a Google Cloud API key, restricted to the Generative Language API unless told otherwise.
/// `POST https://apikeys.googleapis.com/v2/projects/{project}/locations/global/keys`
pub async fn gemini_create_key(config: &Value, name: &str) -> Result<Value, String> {
    let token = cfg(config, "access_token");
    let project = cfg(config, "project");
    if token.is_empty() || !key_ref_ok(project) { return Err("gemini lease requires config.access_token and project".into()); }
    let display = if name.is_empty() { "openwarp" } else { name };
    if display.len() > 256 { return Err("gemini key name must be 1 to 256 characters".into()); }
    let services = config.get("api_targets").and_then(|v| v.as_array()).cloned()
        .unwrap_or_else(|| vec![json!({"service": "generativelanguage.googleapis.com"})]);
    let body = json!({"displayName": display, "restrictions": {"apiTargets": services}});
    let base = lease_base(config, "https://apikeys.googleapis.com")?;
    let url = format!("{}/v2/projects/{}/locations/global/keys", base, project);
    let text = req(http_client().post(url).bearer_auth(token).json(&body)).await
        .map_err(|e| format!("Gemini key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Gemini key response is not JSON: {}", e))?;
    // CreateKey returns a long-running operation; a finished one carries the key inline.
    let key = parsed.get("response").cloned().unwrap_or(Value::Null);
    let key_string = key.get("keyString").and_then(|v| v.as_str()).unwrap_or("");
    let resource = key.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if key_string.is_empty() || !resource.starts_with("projects/") || !resource.contains("/keys/") {
        return Err("Gemini key creation did not finish; the operation has no key yet".into());
    }
    Ok(json!({"key": key_string, "name": resource}))
}
pub async fn gemini_revoke_key(base_url: &str, token: &str, name: &str) -> Result<(), String> {
    if !name.starts_with("projects/") || name.contains("..") || name.contains('?') { return Err("gemini key name is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://apikeys.googleapis.com")?;
    req(http_client().delete(format!("{}/v2/{}", base, name)).bearer_auth(token)).await
        .map_err(|e| format!("Gemini key revocation failed: {}", e))?;
    Ok(())
}
/// Issue a Cloudflare API token. `POST /client/v4/user/tokens`
pub async fn cloudflare_create_token(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
    let api_token = cfg(config, "api_token");
    if api_token.is_empty() { return Err("cloudflare lease requires config.api_token".into()); }
    let display = if name.is_empty() { "openwarp" } else { name };
    if display.len() > 120 { return Err("cloudflare token name must be 1 to 120 characters".into()); }
    let policies = config.get("policies").and_then(|v| v.as_array()).cloned().ok_or("cloudflare lease requires config.policies")?;
    if policies.is_empty() { return Err("cloudflare policies must not be empty".into()); }
    let mut body = serde_json::Map::new();
    body.insert("name".into(), json!(display));
    body.insert("policies".into(), json!(policies));
    body.insert("expires_on".into(), json!(expires_at(ttl_secs)));
    let base = lease_base(config, "https://api.cloudflare.com/client/v4")?;
    let text = req(http_client().post(format!("{}/user/tokens", base)).bearer_auth(api_token).json(&Value::Object(body))).await
        .map_err(|e| format!("Cloudflare token creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Cloudflare token response is not JSON: {}", e))?;
    if parsed.get("success").and_then(|v| v.as_bool()) != Some(true) { return Err("Cloudflare token creation was not successful".into()); }
    let value = parsed.get("result").and_then(|r| r.get("value")).and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("result").and_then(|r| r.get("id")).and_then(|v| v.as_str()).unwrap_or("");
    if value.is_empty() || !key_ref_ok(id) { return Err("Cloudflare token response is missing the value or its id".into()); }
    Ok(json!({"token": value, "id": id}))
}
pub async fn cloudflare_revoke_token(base_url: &str, api_token: &str, token_id: &str) -> Result<(), String> {
    if !key_ref_ok(token_id) { return Err("cloudflare token id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.cloudflare.com/client/v4")?;
    req(http_client().delete(format!("{}/user/tokens/{}", base, token_id)).bearer_auth(api_token)).await
        .map_err(|e| format!("Cloudflare token revocation failed: {}", e))?;
    Ok(())
}
/// Issue a Deepgram project key. `POST /v1/projects/{project_id}/keys`, `Authorization: Token`.
pub async fn deepgram_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
    let api_key = cfg(config, "api_key");
    let project_id = cfg(config, "project_id");
    if api_key.is_empty() || !key_ref_ok(project_id) { return Err("deepgram lease requires config.api_key and project_id".into()); }
    let comment = if name.is_empty() { "openwarp" } else { name };
    if comment.len() > 256 { return Err("deepgram key comment must be at most 256 characters".into()); }
    let scopes = config.get("scopes").and_then(|v| v.as_array()).cloned().unwrap_or_else(|| vec![json!("member")]);
    if scopes.iter().any(|s| s.as_str().map(|t| t.is_empty()).unwrap_or(true)) { return Err("deepgram scopes must be non-empty strings".into()); }
    let body = json!({"comment": comment, "scopes": scopes, "expiration_date": expires_at(ttl_secs)});
    let base = lease_base(config, "https://api.deepgram.com")?;
    let text = req(http_client().post(format!("{}/v1/projects/{}/keys", base, project_id)).header("Authorization", format!("Token {}", api_key)).json(&body)).await
        .map_err(|e| format!("Deepgram key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Deepgram key response is not JSON: {}", e))?;
    let key = parsed.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("api_key_id").and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() || !key_ref_ok(id) { return Err("Deepgram key response is missing the key or its id".into()); }
    Ok(json!({"key": key, "id": id, "expiration_date": parsed["expiration_date"]}))
}
pub async fn deepgram_revoke_key(base_url: &str, api_key: &str, project_id: &str, key_id: &str) -> Result<(), String> {
    if !key_ref_ok(project_id) || !key_ref_ok(key_id) { return Err("deepgram project or key id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.deepgram.com")?;
    req(http_client().delete(format!("{}/v1/projects/{}/keys/{}", base, project_id, key_id)).header("Authorization", format!("Token {}", api_key))).await
        .map_err(|e| format!("Deepgram key revocation failed: {}", e))?;
    Ok(())
}
const ELEVENLABS_PERMISSIONS: &[&str] = &["text_to_speech","speech_to_speech","speech_to_text","sound_generation","audio_isolation","dubbing","projects","audio_native","voices","voice_generation","forced_alignment","music","models","history","user","workspace"];
/// Issue an ElevenLabs service-account key. `POST /v1/service-accounts/{id}/api-keys`, header `xi-api-key`.
pub async fn elevenlabs_create_key(config: &Value, name: &str) -> Result<Value, String> {
    let api_key = cfg(config, "api_key");
    let service_account_id = cfg(config, "service_account_id");
    if api_key.is_empty() || !key_ref_ok(service_account_id) { return Err("elevenlabs lease requires config.api_key and service_account_id".into()); }
    let display = if name.is_empty() { "openwarp" } else { name };
    if display.len() > 256 { return Err("elevenlabs key name must be 1 to 256 characters".into()); }
    let permissions = config.get("permissions").cloned().unwrap_or(json!("all"));
    match &permissions {
        Value::String(s) if s == "all" => {}
        Value::Array(items) if !items.is_empty() && items.iter().all(|p| ELEVENLABS_PERMISSIONS.contains(&p.as_str().unwrap_or(""))) => {}
        _ => return Err("elevenlabs permissions must be \"all\" or a list of known permissions".into()),
    }
    let mut body = serde_json::Map::new();
    body.insert("name".into(), json!(display));
    body.insert("permissions".into(), permissions);
    if let Some(limit) = config.get("character_limit").and_then(|v| v.as_i64()) { body.insert("character_limit".into(), json!(limit)); }
    let base = lease_base(config, "https://api.elevenlabs.io")?;
    let text = req(http_client().post(format!("{}/v1/service-accounts/{}/api-keys", base, service_account_id)).header("xi-api-key", api_key).json(&Value::Object(body))).await
        .map_err(|e| format!("ElevenLabs key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("ElevenLabs key response is not JSON: {}", e))?;
    let key = parsed.get("xi-api-key").or_else(|| parsed.get("xi_api_key")).and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() || !key_ref_ok(id) { return Err("ElevenLabs key response is missing the key or its id".into()); }
    Ok(json!({"key": key, "id": id}))
}
	pub async fn elevenlabs_revoke_key(base_url: &str, api_key: &str, service_account_id: &str, key_id: &str) -> Result<(), String> {
	    if !key_ref_ok(service_account_id) || !key_ref_ok(key_id) { return Err("elevenlabs service account or key id is missing".into()); }
	    let base = lease_base(&json!({"base_url": base_url}), "https://api.elevenlabs.io")?;
	    req(http_client().delete(format!("{}/v1/service-accounts/{}/api-keys/{}", base, service_account_id, key_id)).header("xi-api-key", api_key)).await
	        .map_err(|e| format!("ElevenLabs key revocation failed: {}", e))?;
	    Ok(())
	}
	/// Issue a DeepInfra token. `POST /v1/api-tokens`; the reply carries the secret once.
	pub async fn deepinfra_create_key(config: &Value, name: &str) -> Result<Value, String> {
	    let api_key = cfg(config, "api_key");
	    if api_key.is_empty() { return Err("deepinfra lease requires config.api_key".into()); }
	    let display = if name.is_empty() { "openwarp" } else { name };
	    if display.len() > 256 { return Err("deepinfra token name must be 1 to 256 characters".into()); }
	    let mut body = serde_json::Map::new();
	    body.insert("name".into(), json!(display));
	    if let Some(scopes) = config.get("scopes").and_then(|v| v.as_array()) {
	        if scopes.iter().any(|s| s.as_str().map(|t| t.is_empty()).unwrap_or(true)) { return Err("deepinfra scopes must be non-empty strings".into()); }
	        body.insert("scopes".into(), json!(scopes));
	    }
	    let base = lease_base(config, "https://api.deepinfra.com")?;
	    let text = req(http_client().post(format!("{}/v1/api-tokens", base)).bearer_auth(api_key).json(&Value::Object(body))).await
	        .map_err(|e| format!("DeepInfra token creation failed: {}", e))?;
	    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("DeepInfra token response is not JSON: {}", e))?;
	    let token = parsed.get("token").and_then(|v| v.as_str()).unwrap_or("");
	    let id = parsed.get("token_id").and_then(|v| v.as_str()).unwrap_or("");
	    if token.is_empty() || !key_ref_ok(id) { return Err("DeepInfra token response is missing the token or its id".into()); }
	    Ok(json!({"token": token, "id": id}))
	}
	pub async fn deepinfra_revoke_key(base_url: &str, api_key: &str, token_id: &str) -> Result<(), String> {
	    if !key_ref_ok(token_id) { return Err("deepinfra token id is missing".into()); }
	    let base = lease_base(&json!({"base_url": base_url}), "https://api.deepinfra.com")?;
	    req(http_client().delete(format!("{}/v1/api-tokens/id/{}", base, token_id)).bearer_auth(api_key)).await
	        .map_err(|e| format!("DeepInfra token revocation failed: {}", e))?;
	    Ok(())
	}
	/// Issue a Baseten key. Personal keys must expire within 90 days, so the TTL is capped.
	pub async fn baseten_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
	    let api_key = cfg(config, "api_key");
	    if api_key.is_empty() { return Err("baseten lease requires config.api_key".into()); }
	    let display = if name.is_empty() { "openwarp" } else { name };
	    if display.len() > 256 { return Err("baseten key name must be 1 to 256 characters".into()); }
	    let key_type = { let t = cfg(config, "key_type"); if t.is_empty() { "PERSONAL" } else { t } };
	    if !matches!(key_type, "PERSONAL" | "ROUTES" | "WORKSPACE_MANAGE_ALL") { return Err("baseten key_type must be PERSONAL, ROUTES or WORKSPACE_MANAGE_ALL".into()); }
	    let mut body = serde_json::Map::new();
	    body.insert("type".into(), json!(key_type));
	    body.insert("name".into(), json!(display));
	    if key_type == "PERSONAL" { body.insert("expires_at".into(), json!(expires_at(ttl_secs.min(90 * 86400)))); }
	    let team_id = cfg(config, "team_id");
	    let base = lease_base(config, "https://api.baseten.co")?;
	    let url = if team_id.is_empty() { format!("{}/v1/api_keys", base) } else {
	        if !key_ref_ok(team_id) { return Err("baseten team_id is not a valid id".into()); }
	        format!("{}/v1/teams/{}/api_keys", base, team_id)
	    };
	    let text = req(http_client().post(url).bearer_auth(api_key).json(&Value::Object(body))).await
	        .map_err(|e| format!("Baseten key creation failed: {}", e))?;
	    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Baseten key response is not JSON: {}", e))?;
	    let key = parsed.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
	    if key.is_empty() { return Err("Baseten key response is missing the api_key".into()); }
	    // Revoke addresses a key by its prefix, which is the only identifier the create call returns.
	    let prefix = key.split('_').next().unwrap_or("").to_string();
	    if !key_ref_ok(&prefix) { return Err("Baseten key has no usable prefix to revoke it by".into()); }
	    Ok(json!({"key": key, "id": prefix}))
	}
	pub async fn baseten_revoke_key(base_url: &str, api_key: &str, prefix: &str) -> Result<(), String> {
	    if !key_ref_ok(prefix) { return Err("baseten key prefix is missing".into()); }
	    let base = lease_base(&json!({"base_url": base_url}), "https://api.baseten.co")?;
	    req(http_client().delete(format!("{}/v1/api_keys/{}", base, prefix)).bearer_auth(api_key)).await
	        .map_err(|e| format!("Baseten key revocation failed: {}", e))?;
	    Ok(())
	}
	/// Issue a fal API key. `POST /v1/keys`; the secret is returned once.
	pub async fn fal_create_key(config: &Value, name: &str) -> Result<Value, String> {
	    let api_key = cfg(config, "api_key");
	    if api_key.is_empty() { return Err("fal lease requires config.api_key".into()); }
	    let display = if name.is_empty() { "openwarp" } else { name };
	    if display.len() > 256 { return Err("fal key alias must be 1 to 256 characters".into()); }
	    let mut body = serde_json::Map::new();
	    body.insert("alias".into(), json!(display));
	    if let Some(preset) = config.get("preset").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) { body.insert("preset".into(), json!(preset)); }
	    if let Some(permissions) = config.get("permissions").and_then(|v| v.as_array()) { body.insert("permissions".into(), json!(permissions)); }
	    let base = lease_base(config, "https://api.fal.ai")?;
	    let text = req(http_client().post(format!("{}/v1/keys", base)).header("Authorization", api_key).json(&Value::Object(body))).await
	        .map_err(|e| format!("fal key creation failed: {}", e))?;
	    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("fal key response is not JSON: {}", e))?;
	    let key = parsed.get("key_secret").and_then(|v| v.as_str()).unwrap_or("");
	    let id = parsed.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
	    if key.is_empty() || !key_ref_ok(id) { return Err("fal key response is missing the key_secret or its id".into()); }
	    Ok(json!({"key": key, "id": id}))
	}
	pub async fn fal_revoke_key(base_url: &str, api_key: &str, key_id: &str) -> Result<(), String> {
	    if !key_ref_ok(key_id) { return Err("fal key id is missing".into()); }
	    let base = lease_base(&json!({"base_url": base_url}), "https://api.fal.ai")?;
	    req(http_client().delete(format!("{}/v1/keys/{}", base, key_id)).header("Authorization", api_key)).await
	        .map_err(|e| format!("fal key revocation failed: {}", e))?;
	    Ok(())
	}
	/// Issue a Speechmatics key. A management token can mint a permanent key; an API key only a temporary one.
	pub async fn speechmatics_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
	    let token = cfg(config, "management_token");
	    if token.is_empty() { return Err("speechmatics lease requires config.management_token".into()); }
	    let display = if name.is_empty() { "openwarp" } else { name };
	    if display.len() > 120 { return Err("speechmatics key name must be 1 to 120 characters".into()); }
	    let product = { let t = cfg(config, "product"); if t.is_empty() { "batch" } else { t } };
	    if !matches!(product, "batch" | "rt" | "tts") { return Err("speechmatics product must be batch, rt or tts".into()); }
	    let mut body = serde_json::Map::new();
	    body.insert("name".into(), json!(display));
	    let project_id = config.get("project_id").and_then(|v| v.as_i64());
	    match project_id {
	        Some(id) => { body.insert("project_id".into(), json!(id)); }
	        None => { body.insert("ttl".into(), json!(ttl_secs.clamp(60, 86400))); }
	    }
	    let base = lease_base(config, "https://mp.speechmatics.com")?;
	    let text = req(http_client().post(format!("{}/v1/api-keys?type={}", base, product)).bearer_auth(token).json(&Value::Object(body))).await
	        .map_err(|e| format!("Speechmatics key creation failed: {}", e))?;
	    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Speechmatics key response is not JSON: {}", e))?;
	    let key = parsed.get("key_value").and_then(|v| v.as_str()).unwrap_or("");
	    let id = parsed.get("apikey_id").and_then(|v| v.as_str()).unwrap_or("");
	    if key.is_empty() || !key_ref_ok(id) { return Err("Speechmatics key response is missing the key_value or its id".into()); }
	    Ok(json!({"key": key, "id": id}))
	}
	pub async fn speechmatics_revoke_key(base_url: &str, token: &str, key_id: &str) -> Result<(), String> {
	    if !key_ref_ok(key_id) { return Err("speechmatics key id is missing".into()); }
	    let base = lease_base(&json!({"base_url": base_url}), "https://mp.speechmatics.com")?;
	    req(http_client().delete(format!("{}/v1/api-keys/{}", base, key_id)).bearer_auth(token)).await
	        .map_err(|e| format!("Speechmatics key revocation failed: {}", e))?;
	    Ok(())
	}
	/// Issue a Chutes key from an existing one. `POST /api_keys/`, `Authorization: Basic`.
	pub async fn chutes_create_key(config: &Value, name: &str) -> Result<Value, String> {
	    let api_key = cfg(config, "api_key");
	    if api_key.is_empty() { return Err("chutes lease requires config.api_key".into()); }
	    let display = if name.is_empty() { "openwarp" } else { name };
	    if display.len() > 256 { return Err("chutes key name must be 1 to 256 characters".into()); }
	    let mut body = serde_json::Map::new();
	    body.insert("name".into(), json!(display));
	    body.insert("admin".into(), json!(config.get("admin").and_then(|v| v.as_bool()).unwrap_or(false)));
	    let base = lease_base(config, "https://api.chutes.ai")?;
	    let text = req(http_client().post(format!("{}/api_keys/", base)).header("Authorization", format!("Basic {}", api_key)).json(&Value::Object(body))).await
	        .map_err(|e| format!("Chutes key creation failed: {}", e))?;
	    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Chutes key response is not JSON: {}", e))?;
	    let key = parsed.get("secret_key").and_then(|v| v.as_str()).unwrap_or("");
	    let id = parsed.get("api_key_id").and_then(|v| v.as_str()).unwrap_or("");
	    if key.is_empty() || !key_ref_ok(id) { return Err("Chutes key response is missing the secret_key or its id".into()); }
	    Ok(json!({"key": key, "id": id}))
	}
	pub async fn chutes_revoke_key(base_url: &str, api_key: &str, key_id: &str) -> Result<(), String> {
	    if !key_ref_ok(key_id) { return Err("chutes key id is missing".into()); }
	    let base = lease_base(&json!({"base_url": base_url}), "https://api.chutes.ai")?;
	    req(http_client().delete(format!("{}/api_keys/{}", base, key_id)).header("Authorization", format!("Basic {}", api_key))).await
	        .map_err(|e| format!("Chutes key revocation failed: {}", e))?;
	    Ok(())
	}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<(String, String, String, String)>>>;

    fn header_end(buf: &[u8]) -> Option<usize> { buf.windows(4).position(|w| w == b"\r\n\r\n") }
    fn content_length(head: &str) -> usize { head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse().ok() } else { None } }).unwrap_or(0) }

    fn start_mock(routes: &[(&str, u16, &str)]) -> (String, Calls) {
        let routes: Vec<(String, u16, String)> = routes.iter().map(|(p, s, b)| (p.to_string(), *s, b.to_string())).collect();
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock bind");
        let addr = listener.local_addr().expect("mock addr");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sink = calls.clone();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let mut stream = match incoming { Ok(s) => s, Err(_) => continue };
                let mut buf = Vec::new(); let mut chunk = [0u8; 4096];
                loop {
                    let read = match stream.read(&mut chunk) { Ok(0) => break, Ok(n) => n, Err(_) => break };
                    buf.extend_from_slice(&chunk[..read]);
                    if let Some(end) = header_end(&buf) { let head = String::from_utf8_lossy(&buf[..end]).to_string(); if buf.len() >= end + 4 + content_length(&head) { break; } }
                }
                let end = header_end(&buf).unwrap_or(buf.len());
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let request_line = head.lines().next().unwrap_or("").to_string();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let len = content_length(&head);
                let body = String::from_utf8_lossy(&buf[end + 4..(end + 4 + len).min(buf.len())]).to_string();
                sink.lock().unwrap().push((method.clone(), path.clone(), head.clone(), body.clone()));
                let key = format!("{} {} {} {}", method, path, head, body);
                let (status, payload) = match routes.iter().find(|(pattern, _, _)| key.contains(pattern)) { Some((_, status, body)) => (*status, body.clone()), None => (200, "{}".to_string()) };
                let status_line = match status { 201 => "201 Created", 204 => "204 No Content", _ => "200 OK" };
                let _ = stream.write_all(format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status_line, payload.len(), payload).as_bytes());
            }
        });
        (format!("http://{}", addr), calls)
    }

    #[tokio::test]
    async fn fireworks_and_mistral_leases_create_and_revoke() {
        let (base, calls) = start_mock(&[
            ("POST /v1/accounts/acct/users/usr/apiKeys", 200, r#"{"keyId":"fw_1","key":"fw-child","expireTime":"2030-01-01T00:00:00Z"}"#),
            ("POST /v1/accounts/acct/users/usr/apiKeys:delete", 200, "{}"),
            ("POST /v1/admin/api-keys", 200, r#"{"key_id":"mk_1","key":"mistral-child","expiration_date":"2030-01-01"}"#),
            ("DELETE /v1/admin/api-keys/mk_1", 200, r#"{"detail":"API key deleted successfully"}"#),
        ]);
        let fireworks = fireworks_create_key(&json!({"api_key": "fw_admin", "account_id": "acct", "user_id": "usr", "base_url": base}), "lease", 3600).await.expect("fireworks");
        assert_eq!(fireworks["key"], "fw-child");
        fireworks_revoke_key(&base, "fw_admin", "acct", "usr", fireworks["id"].as_str().unwrap()).await.expect("fireworks revoke");
        let mistral = mistral_create_key(&json!({"admin_key": "sk-admin", "workspace_id": "ws_1", "base_url": base}), "lease", 3600).await.expect("mistral");
        assert_eq!(mistral["key"], "mistral-child");
        mistral_revoke_key(&base, "sk-admin", mistral["id"].as_str().unwrap()).await.expect("mistral revoke");
        let calls = calls.lock().unwrap();
        let fw_body: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/apiKeys")).unwrap().3).unwrap();
        assert_eq!(fw_body["apiKey"]["displayName"], "lease");
        assert!(fw_body["apiKey"]["expireTime"].as_str().unwrap_or("").ends_with("Z"));
        assert!(calls.iter().any(|(m, p, h, b)| m == "POST" && p.ends_with("/apiKeys:delete") && h.contains("Bearer fw_admin") && b.contains("fw_1")));
        let ms_body: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/admin/api-keys")).unwrap().3).unwrap();
        assert_eq!(ms_body["workspace_uuid"], "ws_1");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/v1/admin/api-keys/mk_1"));
    }

    #[tokio::test]
    async fn perplexity_and_xai_leases_create_and_revoke() {
        let (base, calls) = start_mock(&[
            ("POST /generate_auth_token", 200, r#"{"auth_token":"pplx-child","created_at_epoch_seconds":1735689600,"token_name":"lease"}"#),
            ("POST /revoke_auth_token", 200, r#"{"revoked":true}"#),
            ("POST /auth/teams/team_1/api-keys", 200, r#"{"apiKey":"xai-child","apiKeyId":"key_1"}"#),
            ("DELETE /auth/api-keys/key_1", 200, "{}"),
        ]);
        let perplexity = perplexity_create_key(&json!({"api_key": "pplx-parent", "base_url": base}), "lease").await.expect("perplexity");
        assert_eq!(perplexity["token"], "pplx-child");
        perplexity_revoke_key(&base, "pplx-parent", perplexity["token"].as_str().unwrap()).await.expect("perplexity revoke");
        let xai = xai_create_key(&json!({"management_key": "xai-mgmt", "team_id": "team_1", "qps": 5, "base_url": base}), "lease").await.expect("xai");
        assert_eq!(xai["key"], "xai-child");
        xai_revoke_key(&base, "xai-mgmt", xai["id"].as_str().unwrap()).await.expect("xai revoke");
        let calls = calls.lock().unwrap().clone();
        let revoke = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/revoke_auth_token").expect("revoke");
        assert!(revoke.3.contains("pplx-child"), "revoke must send the child token back");
        let xai_body: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.contains("/teams/")).unwrap().3).unwrap();
        assert_eq!(xai_body["acls"][0], "api-key:model:*");
        assert_eq!(xai_body["qps"], 5);
        let bad = xai_create_key(&json!({"management_key": "k", "team_id": "team_1", "acls": ["not-an-acl"]}), "lease").await.unwrap_err();
        assert!(bad.contains("api-key:"), "{}", bad);
    }

    #[tokio::test]
    async fn gemini_and_cloudflare_leases_create_and_revoke() {
        let (base, calls) = start_mock(&[
            ("POST /v2/projects/proj/locations/global/keys", 200, r#"{"done":true,"response":{"@type":"type.googleapis.com/google.api.apikeys.v2.Key","name":"projects/proj/locations/global/keys/key_1","keyString":"AIza-child"}}"#),
            ("DELETE /v2/projects/proj/locations/global/keys/key_1", 200, r#"{"done":true}"#),
            ("POST /user/tokens", 200, r#"{"success":true,"result":{"id":"tok_1","value":"cf-child"}}"#),
            ("DELETE /user/tokens/tok_1", 200, r#"{"success":true}"#),
        ]);
        let gemini = gemini_create_key(&json!({"access_token": "ya29", "project": "proj", "base_url": base}), "lease").await.expect("gemini");
        assert_eq!(gemini["key"], "AIza-child");
        gemini_revoke_key(&base, "ya29", gemini["name"].as_str().unwrap()).await.expect("gemini revoke");
        let cloudflare = cloudflare_create_token(&json!({"api_token": "cf-parent", "policies": [{"effect": "allow", "permission_groups": [{"id": "pg"}], "resources": {"com.cloudflare.api.account.zone.*": "*"}}], "base_url": base}), "lease", 3600).await.expect("cloudflare");
        assert_eq!(cloudflare["token"], "cf-child");
        cloudflare_revoke_token(&base, "cf-parent", cloudflare["id"].as_str().unwrap()).await.expect("cloudflare revoke");
        let calls = calls.lock().unwrap().clone();
        let gemini_body: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.contains("/keys")).unwrap().3).unwrap();
        assert_eq!(gemini_body["restrictions"]["apiTargets"][0]["service"], "generativelanguage.googleapis.com");
        assert!(calls.iter().any(|(m, p, h, _)| m == "DELETE" && p == "/v2/projects/proj/locations/global/keys/key_1" && h.contains("Bearer ya29")));
        let pending = gemini_create_key(&json!({"access_token": "ya29", "project": "proj", "base_url": base.replace("keys", "nope")}), "lease").await;
        assert!(pending.is_err() || pending.as_ref().unwrap()["key"] == "AIza-child");
        let empty = cloudflare_create_token(&json!({"api_token": "cf-parent", "policies": []}), "lease", 3600).await.unwrap_err();
        assert!(empty.contains("must not be empty"), "{}", empty);
    }

    #[tokio::test]
    async fn deepgram_and_elevenlabs_leases_create_and_revoke() {
        let (base, calls) = start_mock(&[
            ("POST /v1/projects/proj_1/keys", 200, r#"{"api_key_id":"dg_1","key":"dg-child","expiration_date":"2030-01-01T00:00:00Z"}"#),
            ("DELETE /v1/projects/proj_1/keys/dg_1", 200, r#"{"message":"deleted"}"#),
            ("POST /v1/service-accounts/sa_1/api-keys", 200, r#"{"xi-api-key":"xi-child","key_id":"xi_1"}"#),
            ("DELETE /v1/service-accounts/sa_1/api-keys/xi_1", 200, "{}"),
        ]);
        let deepgram = deepgram_create_key(&json!({"api_key": "dg-parent", "project_id": "proj_1", "scopes": ["member"], "base_url": base}), "lease", 3600).await.expect("deepgram");
        assert_eq!(deepgram["key"], "dg-child");
        deepgram_revoke_key(&base, "dg-parent", "proj_1", deepgram["id"].as_str().unwrap()).await.expect("deepgram revoke");
        let eleven = elevenlabs_create_key(&json!({"api_key": "xi-parent", "service_account_id": "sa_1", "permissions": ["text_to_speech"], "base_url": base}), "lease").await.expect("elevenlabs");
        assert_eq!(eleven["key"], "xi-child");
        elevenlabs_revoke_key(&base, "xi-parent", "sa_1", eleven["id"].as_str().unwrap()).await.expect("elevenlabs revoke");
        let calls = calls.lock().unwrap().clone();
        let dg = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/keys")).expect("deepgram create");
        assert!(dg.2.contains("Token dg-parent"), "deepgram authenticates with the Token scheme");
        let dg_body: Value = serde_json::from_str(&dg.3).unwrap();
        assert_eq!(dg_body["scopes"][0], "member");
        assert!(dg_body["expiration_date"].as_str().unwrap_or("").ends_with("Z"));
        let xi = calls.iter().find(|(m, p, _, _)| m == "POST" && p.contains("/service-accounts/")).expect("elevenlabs create");
        assert!(xi.2.to_ascii_lowercase().contains("xi-api-key: xi-parent"), "{}", xi.2);
        let xi_body: Value = serde_json::from_str(&xi.3).unwrap();
        assert_eq!(xi_body["permissions"][0], "text_to_speech");
        let bad = elevenlabs_create_key(&json!({"api_key": "xi-parent", "service_account_id": "sa_1", "permissions": ["not-real"]}), "lease").await.unwrap_err();
        assert!(bad.contains("known permissions"), "{}", bad);
    }

	    #[tokio::test]
	    async fn deepinfra_baseten_fal_and_speechmatics_leases_create_and_revoke() {
	        let (base, calls) = start_mock(&[
	            ("POST /v1/api-tokens", 200, r#"{"token":"di-child","token_id":"tok_1","name":"lease"}"#),
	            ("DELETE /v1/api-tokens/id/tok_1", 200, "{}"),
	            ("POST /v1/api_keys", 200, r#"{"api_key":"abcdef_secret"}"#),
	            ("DELETE /v1/api_keys/abcdef", 200, r#"{"prefix":"abcdef"}"#),
	            ("POST /v1/keys", 200, r#"{"key_id":"fal_1","key_secret":"fal-child"}"#),
	            ("DELETE /v1/keys/fal_1", 204, ""),
	            ("POST /v1/api-keys?type=batch", 201, r#"{"key_value":"sm-child","apikey_id":"sm_1"}"#),
	            ("DELETE /v1/api-keys/sm_1", 200, "{}"),
	            ("POST /api_keys/", 200, r#"{"api_key_id":"ck_1","secret_key":"cpk_child","name":"lease"}"#),
	            ("DELETE /api_keys/ck_1", 200, "{}"),
	        ]);
	        let deepinfra = deepinfra_create_key(&json!({"api_key": "di-parent", "scopes": ["models"], "base_url": base}), "lease").await.expect("deepinfra");
	        assert_eq!(deepinfra["token"], "di-child");
	        deepinfra_revoke_key(&base, "di-parent", deepinfra["id"].as_str().unwrap()).await.expect("deepinfra revoke");
	        let baseten = baseten_create_key(&json!({"api_key": "bt-parent", "base_url": base}), "lease", 3600).await.expect("baseten");
	        assert_eq!(baseten["key"], "abcdef_secret");
	        assert_eq!(baseten["id"], "abcdef", "revoke must address the key by its prefix");
	        baseten_revoke_key(&base, "bt-parent", baseten["id"].as_str().unwrap()).await.expect("baseten revoke");
	        let fal = fal_create_key(&json!({"api_key": "fal-parent", "preset": "API", "base_url": base}), "lease").await.expect("fal");
	        assert_eq!(fal["key"], "fal-child");
	        fal_revoke_key(&base, "fal-parent", fal["id"].as_str().unwrap()).await.expect("fal revoke");
	        let speech = speechmatics_create_key(&json!({"management_token": "sm-mgmt", "project_id": 12345, "base_url": base}), "lease", 3600).await.expect("speechmatics");
	        assert_eq!(speech["key"], "sm-child");
	        speechmatics_revoke_key(&base, "sm-mgmt", speech["id"].as_str().unwrap()).await.expect("speechmatics revoke");
		        { let calls = calls.lock().unwrap().clone();
		        let di: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/v1/api-tokens").unwrap().3).unwrap();
	        assert_eq!(di["scopes"][0], "models");
	        let bt: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/v1/api_keys").unwrap().3).unwrap();
	        assert_eq!(bt["type"], "PERSONAL");
	        assert!(bt["expires_at"].as_str().unwrap_or("").ends_with("Z"));
	        let fal_call = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/v1/keys").unwrap();
	        assert!(fal_call.2.to_ascii_lowercase().lines().any(|l| l == "authorization: fal-parent"), "fal sends the key without a scheme: {}", fal_call.2);
	        let sm: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.starts_with("/v1/api-keys")).unwrap().3).unwrap();
	        assert_eq!(sm["project_id"], 12345);
		        assert!(sm.get("ttl").is_none(), "a project key is permanent and must not carry a ttl");
		        }
		        let chutes = chutes_create_key(&json!({"api_key": "cpk_parent", "base_url": base}), "lease").await.expect("chutes");
	        assert_eq!(chutes["key"], "cpk_child");
		        chutes_revoke_key(&base, "cpk_parent", chutes["id"].as_str().unwrap()).await.expect("chutes revoke");
		        let calls = calls.lock().unwrap().clone();
	        let chutes_call = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/api_keys/").expect("chutes create");
	        assert!(chutes_call.2.to_ascii_lowercase().contains("authorization: basic cpk_parent"), "{}", chutes_call.2);
	        let chutes_body: Value = serde_json::from_str(&chutes_call.3).unwrap();
	        assert_eq!(chutes_body["admin"], false);
	        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/api_keys/ck_1"));
	        let bad = baseten_create_key(&json!({"api_key": "bt-parent", "key_type": "WHATEVER"}), "lease", 3600).await.unwrap_err();
	        assert!(bad.contains("key_type"), "{}", bad);
	    }

	    #[tokio::test]
	    async fn inference_leases_reject_a_loopback_base_url() {
        let err = fireworks_create_key(&json!({"api_key": "k", "account_id": "a", "user_id": "u", "base_url": "http://127.0.0.1:9", "require_public_host": true}), "lease", 3600).await.unwrap_err();
        assert!(err.contains("public host"), "{}", err);
        let err = gemini_revoke_key("https://apikeys.googleapis.com", "t", "../etc/passwd").await.unwrap_err();
        assert!(err.contains("missing"), "{}", err);
    }
}
